"""Ending one login: by the `sign_out` action, or by *Sign out this login* tapped on a push.

Both go through the same code and the same policy (DESIGN.md 0.3.0, #6). A tap only answers a
button Access Guard sent; it adds no power an administrator does not already have.
"""

import logging
import re

from homeassistant.core import Event, callback

from . import policy
from .sessions import client

_LOGGER = logging.getLogger(__name__)
EVENT_ACTION = "mobile_app_notification_action"
ACTION_PREFIX = "ACCESS_GUARD_SIGN_OUT_"
_ACTION = re.compile(re.escape(ACTION_PREFIX) + r"([0-9a-f]{%d})" % policy.HANDLE_LEN)


async def async_remove(hass, coord, who, tokens):
    # async_remove_refresh_token is a synchronous @callback in Home Assistant: the login
    # is gone and its connections closed when it returns (DESIGN.md).
    handles = [policy.handle(t.id) for t in tokens]
    for h, t in zip(handles, tokens, strict=True):
        coord.mark_removed(h, who.id)
        hass.auth.async_remove_refresh_token(t)
    _LOGGER.info("%s (%s) signed out %d login(s): %s", who.name, who.id, len(handles), ", ".join(handles))
    await coord.async_refresh()


async def async_sign_out(hass, coord, who, h):
    """End the one login named `h`; raises policy.Refused. Returns the login that was ended."""
    policy.check_caller(who)           # first, so a refusal reveals nothing about the handle
    tokens = [t for u in await hass.auth.async_get_users() for t in u.refresh_tokens.values()]
    token = policy.resolve(tokens, h)
    policy.check_sign_out(who, token.user)
    await async_remove(hass, coord, who, [token])
    return token


def action_for(h):
    return ACTION_PREFIX + h


@callback
def async_listen_for_taps(hass, coord):
    """Returns the unsubscribe."""

    async def on_action(event: Event):
        m = _ACTION.fullmatch(str(event.data.get("action", "")))
        if not m:
            return
        h = m.group(1)
        uid = event.context.user_id
        who = await hass.auth.async_get_user(uid) if uid else None
        try:
            policy.check_tap(who)
            if not hasattr(hass.auth, "async_remove_refresh_token"):
                raise policy.Refused("this Home Assistant version cannot end sessions")
            if not coord.offered(h):
                raise policy.Refused("that alert is not one Access Guard can still act on")
            token = await async_sign_out(hass, coord, who, h)
            message = "Signed out %s's %s." % (token.user.name, client(token.token_type, token.client_id,
                                                                     token.client_name))
        except policy.Refused as err:
            _LOGGER.info("a tapped sign-out was refused: %s", err)
            message = "Could not sign out: %s." % err
        await coord.async_tell(message)

    return hass.bus.async_listen(EVENT_ACTION, on_action)
