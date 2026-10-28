"""Home Assistant's IP bans: list them, lift one. Home Assistant itself has no remove.

The ban manager is internal, like hass.auth (DESIGN.md 0.2.0). It keeps the bans in memory and
appends each new one to ip_bans.yaml from the executor; lifting one means rewriting that file
while Home Assistant may be appending to it.
"""

import logging
import os

from homeassistant.exceptions import HomeAssistantError
from homeassistant.util import yaml as yaml_util

_LOGGER = logging.getLogger(__name__)
try:
    from homeassistant.components.http.ban import ATTR_BANNED_AT, KEY_BAN_MANAGER, KEY_FAILED_LOGIN_ATTEMPTS
except ImportError:  # internal: without it bans are off, and the rest of Access Guard still runs
    KEY_BAN_MANAGER = None
MAX_ROUNDS = 10


def _app(hass):
    return getattr(getattr(hass, "http", None), "app", None)


def _manager(hass):
    app = _app(hass)
    return app.get(KEY_BAN_MANAGER) if app is not None and KEY_BAN_MANAGER is not None else None


def banned(hass):
    """The banned addresses (ip_address -> IpBan), or None when bans are not loaded."""
    lookup = getattr(_manager(hass), "ip_bans_lookup", None)
    return lookup if isinstance(lookup, dict) else None


def listing(hass):
    """Plain rows, newest first; None when bans are not loaded or not the shape expected.

    It runs on every poll: a change in Home Assistant's ban manager must not take the
    sessions sensor down with it.
    """
    lookup = banned(hass)
    if lookup is None:
        return None
    try:
        rows = [{"ip": str(b.ip_address), "banned_at": b.banned_at.isoformat()} for b in lookup.values()]
    except AttributeError:
        return None
    return sorted(rows, key=lambda r: r["banned_at"], reverse=True)


def _write(path, bans):
    """Home Assistant's own format, replaced in one step so a reader never sees half a file."""
    text = "".join("\n" + yaml_util.dump({str(b.ip_address): {ATTR_BANNED_AT: b.banned_at.isoformat()}})
                   for b in bans)
    tmp = path + ".access_guard"
    with open(tmp, "w", encoding="utf8") as out:
        out.write(text)
    os.replace(tmp, path)


async def async_unban(hass, addr):
    """Lift the ban on `addr` (already checked by policy.check_unban).

    The address is popped before the first write, so no file written here holds it: an unban is
    never undone at restart. Home Assistant adds a ban to memory before appending it to the file,
    so a ban added meanwhile shows as a changed lookup and the file is written again.
    """
    m = _manager(hass)
    attempts = _app(hass)[KEY_FAILED_LOGIN_ATTEMPTS]
    ban = m.ip_bans_lookup.pop(addr)
    failures = attempts.pop(addr, None)      # else its next mistake bans it again at once
    written = False
    try:
        for _ in range(MAX_ROUNDS):
            snapshot = list(m.ip_bans_lookup.values())
            await hass.async_add_executor_job(_write, m.path, snapshot)
            written = True
            if m.ip_bans_lookup.keys() == {b.ip_address for b in snapshot}:
                return
        _LOGGER.warning("bans added while lifting one may be saved only until Home Assistant restarts")
    except OSError as err:
        if written:
            # The file already lacks it; putting it back in memory alone would undo it at restart.
            _LOGGER.warning("could not save bans added while lifting one (%s)", type(err).__name__)
            return
        m.ip_bans_lookup[addr] = ban
        if failures is not None:
            attempts[addr] = failures
        raise HomeAssistantError("could not write ip_bans.yaml (%s); the ban stays" % type(err).__name__) from None
