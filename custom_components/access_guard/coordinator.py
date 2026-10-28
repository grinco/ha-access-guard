"""Reads logins from Home Assistant's auth manager and turns changes into events.

Home Assistant fires no event when a login is created or removed, so the coordinator
diffs what it saw last time. The first read announces nothing: those logins existed
before Access Guard started.

It also feeds the light detection rules (DESIGN.md 0.2.0): failed logins from the log, camera
live views from the websocket, and actions people run. Findings only notify.
"""

import logging

from homeassistant.const import EVENT_CALL_SERVICE, EVENT_COMPONENT_LOADED
from homeassistant.core import Event, HomeAssistant, callback
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from . import alerts, bans
from .camera_watch import CameraWatch
from .const import (ACTIVE_WINDOW, CONF_FAILURES_BEFORE_LOGIN, CONF_GEO_PATH, CONF_HOME_WAN_ENTITY, CONF_RULES,
                    CONF_SENSITIVE_DOMAINS, DEFAULT_GEO_FILE, DOMAIN, EVENT_LOGIN_REMOVED, EVENT_NEW_LOGIN,
                    NOT_A_PERSON, SCAN_INTERVAL)
from .detector import DEFAULT_SENSITIVE, LIVE_VIEW, RULES, Detector
from .failures import LOGGER_NAME, FailedLogins
from .sessions import GeoResolver, action_target, event_data, finish, snapshot

_LOGGER = logging.getLogger(__name__)


class AccessGuardCoordinator(DataUpdateCoordinator):
    def __init__(self, hass: HomeAssistant, entry):
        super().__init__(hass, _LOGGER, name=DOMAIN, update_interval=SCAN_INTERVAL, config_entry=entry)
        path = entry.options.get(CONF_GEO_PATH) or hass.config.path(DOMAIN, DEFAULT_GEO_FILE)
        self.geo = GeoResolver(path)
        self.detector = Detector(rules=entry.options.get(CONF_RULES, RULES),
                                 failures_before_login=int(entry.options.get(CONF_FAILURES_BEFORE_LOGIN, 1)),
                                 sensitive=entry.options.get(CONF_SENSITIVE_DOMAINS, DEFAULT_SENSITIVE))
        self.failed_logins = FailedLogins(self._failure_from_any_thread)
        self.cameras = CameraWatch(hass, self._camera_view)
        self._known = None          # handle -> row; None until the first read
        self._removed_by = {}       # handle -> user id of whoever signed it out through us

    def mark_removed(self, h, caller_id):
        self._removed_by[h] = caller_id

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

    def _failure_from_any_thread(self, ip, at):
        # A log record can come from any thread; the detector lives in the event loop.
        self.hass.loop.call_soon_threadsafe(self.detector.failure, ip, at)

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
        for f in findings:
            self.config_entry.async_create_task(self.hass, alerts.async_alert(self.hass, self.config_entry.options, f))

    def _wan(self):
        ent = self.config_entry.options.get(CONF_HOME_WAN_ENTITY)
        st = self.hass.states.get(ent) if ent else None
        return st.state if st else None

    async def _async_update_data(self):
        users = await self.hass.auth.async_get_users()
        names = {u.id: u.name for u in users}
        banned = bans.listing(self.hass)
        try:
            rows = snapshot(users)
            rows = await self.hass.async_add_executor_job(
                finish, rows, dt_util.utcnow(), ACTIVE_WINDOW, self._wan(), self.geo, banned)
        except Exception as err:  # noqa: BLE001
            # Home Assistant's RefreshToken repr holds its token and JWT key; an exception
            # can carry it. Log the kind only, and break the chain (review 2026-10-28 F6).
            _LOGGER.error("could not read logins (%s)", type(err).__name__)
            raise UpdateFailed("could not read logins") from None
        now = {r["handle"]: r for r in rows}
        if self._known is not None:
            for h in now.keys() - self._known.keys():
                data = event_data(now[h])
                self.hass.bus.async_fire(EVENT_NEW_LOGIN, data)
                self._report(self.detector.new_login(data, dt_util.parse_datetime(data["created"])))
            for h in self._known.keys() - now.keys():
                by = self._removed_by.pop(h, None)
                data = event_data(self._known[h])
                data.update(removed_by="access_guard" if by else "unknown", removed_by_user_id=by)
                self.hass.bus.async_fire(EVENT_LOGIN_REMOVED, data)
        self._known = now
        return {"rows": rows, "names": names, "active": sum(r["active"] for r in rows), "bans": banned}
