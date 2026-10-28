"""Reads logins from Home Assistant's auth manager and turns changes into events.

Home Assistant fires no event when a login is created or removed, so the coordinator
diffs what it saw last time. The first read announces nothing: those logins existed
before Access Guard started.

It also feeds the light detection rules (DESIGN.md 0.2.0): failed logins from the log, camera
live views from the websocket, and actions people run. Findings only notify.
"""

import logging
from collections import OrderedDict

from homeassistant.const import EVENT_CALL_SERVICE, EVENT_COMPONENT_LOADED
from homeassistant.core import Event, HomeAssistant, callback
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from . import alerts, bans
from .camera_watch import CameraWatch
from .const import (ACTIVE_WINDOW, CONF_ALLOWED_COUNTRIES, CONF_BURST_FAILURES, CONF_FAILURES_BEFORE_LOGIN,
                    CONF_GEO_PATH, CONF_HOME_WAN_ENTITY, CONF_RULES, CONF_RULES_OFF,
                    CONF_SENSITIVE_DOMAINS, DEFAULT_GEO_FILE, DOMAIN, EVENT_LOGIN_REMOVED, EVENT_NEW_LOGIN,
                    NOT_A_PERSON, SCAN_INTERVAL)
from .detector import DEFAULT_SENSITIVE, LIVE_VIEW, MAX_COUNTRIES, MAX_TRACKED, Detector, enabled_rules
from .failures import LOGGER_NAME, FailedLogins
from .mfa import MfaWatch
from .sessions import GeoResolver, action_target, event_data, finish, snapshot

_LOGGER = logging.getLogger(__name__)
STORE_VERSION = 1
SAVE_DELAY = 30


def _countries(data):
    """The countries Store as the detector keeps it; anything else in it is dropped."""
    raw = (data or {}).get("countries") if isinstance(data, dict) else None
    if not isinstance(raw, dict):
        return {}
    return {uid: [c for c in codes if isinstance(c, str)][-MAX_COUNTRIES:]
            for uid, codes in raw.items() if isinstance(uid, str) and isinstance(codes, list)}


class AccessGuardCoordinator(DataUpdateCoordinator):
    def __init__(self, hass: HomeAssistant, entry):
        super().__init__(hass, _LOGGER, name=DOMAIN, update_interval=SCAN_INTERVAL, config_entry=entry)
        path = entry.options.get(CONF_GEO_PATH) or hass.config.path(DOMAIN, DEFAULT_GEO_FILE)
        self.geo = GeoResolver(path)
        opts = entry.options
        self.detector = Detector(rules=enabled_rules(opts.get(CONF_RULES_OFF), opts.get(CONF_RULES)),
                                 failures_before_login=int(opts.get(CONF_FAILURES_BEFORE_LOGIN, 1)),
                                 sensitive=opts.get(CONF_SENSITIVE_DOMAINS, DEFAULT_SENSITIVE),
                                 burst_failures=int(opts.get(CONF_BURST_FAILURES, 10)),
                                 allowed_countries=opts.get(CONF_ALLOWED_COUNTRIES, ()))
        self._store = Store(hass, STORE_VERSION, f"{DOMAIN}.countries")
        self._offered = OrderedDict()   # handles a push offered to sign out, newest last
        self._unsaved = False
        self.failed_logins = FailedLogins(self._failure_from_any_thread)
        self.cameras = CameraWatch(hass, self._camera_view)
        self.mfa = MfaWatch(hass)
        self._known = None          # handle -> row; None until the first read
        self._removed_by = {}       # handle -> user id of whoever signed it out through us

    def mark_removed(self, h, caller_id):
        self._removed_by[h] = caller_id

    async def async_load(self):
        self.detector.countries = _countries(await self._store.async_load())

    def _stored(self):
        self._unsaved = False
        return {"countries": self.detector.countries}

    async def async_save_now(self):
        """At unload: a reload within the save delay must not lose what was learnt."""
        if self._unsaved:
            await self._store.async_save(self._stored())

    def offered(self, h):
        """Whether a push offered to sign out `h`: a tap answers a button, nothing else."""
        return h in self._offered

    async def async_tell(self, message):
        """A short reply on the notify action, e.g. the result of a tap."""
        await alerts.async_tell(self.hass, self.config_entry.options, message)

    @callback
    def async_watch(self):
        """Start the detection sources; each one stops when the entry unloads."""
        entry, hass = self.config_entry, self.hass
        log = logging.getLogger(LOGGER_NAME)
        log.addHandler(self.failed_logins)
        entry.async_on_unload(lambda: log.removeHandler(self.failed_logins))
        self.cameras.attach()
        entry.async_on_unload(self.cameras.detach)
        # camera may load after Access Guard.
        entry.async_on_unload(hass.bus.async_listen(
            EVENT_COMPONENT_LOADED, callback(lambda _: self.cameras.attach()),
            event_filter=callback(lambda data: data.get("component") == "camera")))
        entry.async_on_unload(hass.bus.async_listen(EVENT_CALL_SERVICE, self._on_call))
        entry.async_on_unload(self.mfa.clear)
        entry.async_on_unload(self.async_save_now)

    def _failure_from_any_thread(self, ips, at):
        # A log record can come from any thread; the detector lives in the event loop.
        self.hass.loop.call_soon_threadsafe(self._failure, ips, at)

    @callback
    def _failure(self, ips, at):
        self._report(self.detector.failure(ips, at))

    @callback
    def _camera_view(self, user_id, h, entity_id):
        self._report(self.detector.signal(user_id, h, "camera", LIVE_VIEW, entity_id, dt_util.utcnow()))

    @callback
    def _on_call(self, event: Event):
        uid = event.context.user_id
        domain, service = event.data.get("domain"), event.data.get("service")
        if not uid or (domain, service) in NOT_A_PERSON:
            return
        self._report(self.detector.signal(uid, None, domain, "%s.%s" % (domain, service),
                                          action_target(event.data.get("service_data")), dt_util.utcnow()))

    @callback
    def _report(self, findings):
        opts = self.config_entry.options
        for f in findings:
            button = alerts.offers_button(opts, f)
            if button:
                self._offered.pop(f["handle"], None)
                self._offered[f["handle"]] = True
                while len(self._offered) > MAX_TRACKED:
                    self._offered.popitem(last=False)
            self.config_entry.async_create_task(self.hass, alerts.async_alert(self.hass, opts, f, button))

    def _wan(self):
        ent = self.config_entry.options.get(CONF_HOME_WAN_ENTITY)
        st = self.hass.states.get(ent) if ent else None
        return st.state if st else None

    async def _async_update_data(self):
        users = await self.hass.auth.async_get_users()
        names = {u.id: u.name for u in users}
        admins = {u.id for u in users if u.is_admin}
        banned = bans.listing(self.hass)
        try:
            await self.mfa.async_update(users)
        except Exception as err:  # noqa: BLE001 - an MFA module's fault must not stop the sessions sensor
            _LOGGER.warning("could not check administrators' MFA (%s)", type(err).__name__)
        try:
            rows = snapshot(users)
            rows = await self.hass.async_add_executor_job(
                finish, rows, dt_util.utcnow(), ACTIVE_WINDOW, self._wan(), self.geo, banned)
        except Exception as err:  # noqa: BLE001
            # Home Assistant's RefreshToken repr holds its token and JWT key; an exception
            # can carry it. Log the kind only, and break the chain (review 2026-10-28 F6).
            _LOGGER.error("could not read logins (%s)", type(err).__name__)
            raise UpdateFailed("could not read logins") from None
        for r in rows:
            self._report(self.detector.country(event_data(r)))
        if self.detector.countries_changed:
            present = {u.id for u in users}
            for uid in [uid for uid in self.detector.countries if uid not in present]:
                del self.detector.countries[uid]
            self.detector.countries_changed = False
            self._unsaved = True
            self._store.async_delay_save(self._stored, SAVE_DELAY)
        now = {r["handle"]: r for r in rows}
        if self._known is not None:
            for h in now.keys() - self._known.keys():
                data = event_data(now[h])
                self.hass.bus.async_fire(EVENT_NEW_LOGIN, data)
                self._report(self.detector.new_login(data, dt_util.parse_datetime(data["created"]),
                                                     is_admin=data["user_id"] in admins))
            for h in self._known.keys() - now.keys():
                by = self._removed_by.pop(h, None)
                data = event_data(self._known[h])
                data.update(removed_by="access_guard" if by else "unknown", removed_by_user_id=by)
                self.hass.bus.async_fire(EVENT_LOGIN_REMOVED, data)
        self._known = now
        return {"rows": rows, "names": names, "active": sum(r["active"] for r in rows), "bans": banned}
