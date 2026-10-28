"""Reads logins from Home Assistant's auth manager and turns changes into events.

Home Assistant fires no event when a login is created or removed, so the coordinator
diffs what it saw last time. The first read announces nothing: those logins existed
before Access Guard started.
"""

import logging

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .const import (ACTIVE_WINDOW, CONF_GEO_PATH, CONF_HOME_WAN_ENTITY, DEFAULT_GEO_FILE, DOMAIN,
                    EVENT_LOGIN_REMOVED, EVENT_NEW_LOGIN, SCAN_INTERVAL)
from .sessions import GeoResolver, event_data, finish, snapshot

_LOGGER = logging.getLogger(__name__)


class AccessGuardCoordinator(DataUpdateCoordinator):
    def __init__(self, hass: HomeAssistant, entry):
        super().__init__(hass, _LOGGER, name=DOMAIN, update_interval=SCAN_INTERVAL, config_entry=entry)
        path = entry.options.get(CONF_GEO_PATH) or hass.config.path(DOMAIN, DEFAULT_GEO_FILE)
        self.geo = GeoResolver(path)
        self._known = None          # handle -> row; None until the first read
        self._removed_by = {}       # handle -> user id of whoever signed it out through us

    def mark_removed(self, h, caller_id):
        self._removed_by[h] = caller_id

    def _wan(self):
        ent = self.config_entry.options.get(CONF_HOME_WAN_ENTITY)
        st = self.hass.states.get(ent) if ent else None
        return st.state if st else None

    async def _async_update_data(self):
        users = await self.hass.auth.async_get_users()
        names = {u.id: u.name for u in users}
        try:
            rows = snapshot(users)
            rows = await self.hass.async_add_executor_job(
                finish, rows, dt_util.utcnow(), ACTIVE_WINDOW, self._wan(), self.geo)
        except Exception as err:  # noqa: BLE001
            # Home Assistant's RefreshToken repr holds its token and JWT key; an exception
            # can carry it. Log the kind only, and break the chain (review 2026-10-28 F6).
            _LOGGER.error("could not read logins (%s)", type(err).__name__)
            raise UpdateFailed("could not read logins") from None
        now = {r["handle"]: r for r in rows}
        if self._known is not None:
            for h in now.keys() - self._known.keys():
                self.hass.bus.async_fire(EVENT_NEW_LOGIN, event_data(now[h]))
            for h in self._known.keys() - now.keys():
                by = self._removed_by.pop(h, None)
                data = event_data(self._known[h])
                data.update(removed_by="access_guard" if by else "unknown", removed_by_user_id=by)
                self.hass.bus.async_fire(EVENT_LOGIN_REMOVED, data)
        self._known = now
        return {"rows": rows, "names": names, "active": sum(r["active"] for r in rows)}
