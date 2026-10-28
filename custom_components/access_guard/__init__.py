"""Access Guard: who is signed in to Home Assistant, from where, and ending a session.

Phase 1 and 0.2.0 of docs/DESIGN.md. Every action checks its caller in policy.py: any account
can call an action through the API, not only from a dashboard that shows the button.
"""

import logging

import voluptuous as vol
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers import config_validation as cv

from . import bans, policy, response
from .const import DOMAIN, EVENT_UNBANNED, SERVICE_SIGN_OUT, SERVICE_SIGN_OUT_USER, SERVICE_UNBAN
from .coordinator import AccessGuardCoordinator

_LOGGER = logging.getLogger(__name__)
PLATFORMS = [Platform.SENSOR]
CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


async def async_setup(hass: HomeAssistant, config) -> bool:
    async def caller(call: ServiceCall):
        uid = call.context.user_id
        return await hass.auth.async_get_user(uid) if uid else None

    def coordinator() -> AccessGuardCoordinator:
        coord = hass.data.get(DOMAIN)
        if coord is None:
            raise ServiceValidationError("Access Guard is not set up")
        return coord

    def session_ender() -> AccessGuardCoordinator:
        coord = coordinator()
        if not hasattr(hass.auth, "async_remove_refresh_token"):
            # An internal API: refuse rather than silently do nothing (DESIGN.md).
            raise ServiceValidationError("this Home Assistant version cannot end sessions")
        return coord

    async def sign_out(call: ServiceCall) -> None:
        coord = session_ender()
        who = await caller(call)
        try:
            await response.async_sign_out(hass, coord, who, call.data["handle"])
        except policy.Refused as err:
            raise ServiceValidationError(str(err)) from err

    async def sign_out_user(call: ServiceCall) -> None:
        coord = session_ender()
        who = await caller(call)
        try:
            policy.check_caller(who)
        except policy.Refused as err:
            raise ServiceValidationError(str(err)) from err
        target = await hass.auth.async_get_user(call.data["user_id"])
        if target is None:
            raise ServiceValidationError("no such user")
        try:
            policy.check_sign_out(who, target)
        except policy.Refused as err:
            raise ServiceValidationError(str(err)) from err
        # Sessions only: the account stays active and its person signs in again.
        await response.async_remove(hass, coord, who, list(target.refresh_tokens.values()))

    async def unban(call: ServiceCall) -> None:
        coord = coordinator()
        who = await caller(call)
        try:
            addr = policy.check_unban(who, bans.banned(hass), call.data["ip"])
        except policy.Refused as err:
            raise ServiceValidationError(str(err)) from err
        await bans.async_unban(hass, addr)
        _LOGGER.info("%s (%s) lifted the ban on %s", who.name, who.id, addr)
        hass.bus.async_fire(EVENT_UNBANNED, {"ip": str(addr), "by_user_id": who.id})
        await coord.async_refresh()

    hass.services.async_register(DOMAIN, SERVICE_SIGN_OUT, sign_out,
                                 schema=vol.Schema({vol.Required("handle"): vol.All(cv.string, vol.Length(12, 12))}))
    hass.services.async_register(DOMAIN, SERVICE_SIGN_OUT_USER, sign_out_user,
                                 schema=vol.Schema({vol.Required("user_id"): cv.string}))
    hass.services.async_register(DOMAIN, SERVICE_UNBAN, unban, schema=vol.Schema({vol.Required("ip"): cv.string}))
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    coord = AccessGuardCoordinator(hass, entry)
    await coord.async_load()        # before the first poll: a restart is not an empty Store
    await coord.async_config_entry_first_refresh()
    entry.runtime_data = coord
    hass.data[DOMAIN] = coord
    coord.async_watch()
    entry.async_on_unload(response.async_listen_for_taps(hass, coord))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_reload))
    return True


async def _reload(hass: HomeAssistant, entry: ConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if ok:
        hass.data.pop(DOMAIN, None)
    return ok
