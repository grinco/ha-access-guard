"""Access Guard: who is signed in to Home Assistant, from where, and ending a session.

Phase 1 of docs/DESIGN.md. Every action checks its caller in policy.py: any account can
call an action through the API, not only from a dashboard that shows the button.
"""

import logging

import voluptuous as vol
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers import config_validation as cv

from . import policy
from .const import DOMAIN, SERVICE_SIGN_OUT, SERVICE_SIGN_OUT_USER
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
        if not hasattr(hass.auth, "async_remove_refresh_token"):
            # An internal API: refuse rather than silently do nothing (DESIGN.md).
            raise ServiceValidationError("this Home Assistant version cannot end sessions")
        return coord

    async def remove(coord, who, tokens):
        # async_remove_refresh_token is a synchronous @callback in Home Assistant: the login
        # is gone and its connections closed when it returns (DESIGN.md).
        handles = [policy.handle(t.id) for t in tokens]
        for h, t in zip(handles, tokens):
            coord.mark_removed(h, who.id)
            hass.auth.async_remove_refresh_token(t)
        _LOGGER.info("%s (%s) signed out %d login(s): %s", who.name, who.id, len(handles), ", ".join(handles))
        await coord.async_refresh()

    async def sign_out(call: ServiceCall) -> None:
        coord = coordinator()
        who = await caller(call)
        tokens = [t for u in await hass.auth.async_get_users() for t in u.refresh_tokens.values()]
        try:
            policy.check_caller(who)
            token = policy.resolve(tokens, call.data["handle"])
            policy.check_sign_out(who, token.user)
        except policy.Refused as err:
            raise ServiceValidationError(str(err)) from err
        await remove(coord, who, [token])

    async def sign_out_user(call: ServiceCall) -> None:
        coord = coordinator()
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
        await remove(coord, who, list(target.refresh_tokens.values()))

    hass.services.async_register(DOMAIN, SERVICE_SIGN_OUT, sign_out,
                                 schema=vol.Schema({vol.Required("handle"): vol.All(cv.string, vol.Length(12, 12))}))
    hass.services.async_register(DOMAIN, SERVICE_SIGN_OUT_USER, sign_out_user,
                                 schema=vol.Schema({vol.Required("user_id"): cv.string}))
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    coord = AccessGuardCoordinator(hass, entry)
    await coord.async_config_entry_first_refresh()
    entry.runtime_data = coord
    hass.data[DOMAIN] = coord
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
