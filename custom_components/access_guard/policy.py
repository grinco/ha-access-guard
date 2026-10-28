"""Who may sign out or disable whom. No Home Assistant imports, so it is tested on its own.

Home Assistant lets any signed-in account call an action through its API, not only from
the dashboard that shows the button, so these checks are the whole security of the
integration.

It ends SESSIONS, never accounts: a signed-out person signs in again. Disabling an account
is deliberately not offered (operator 2026-10-28); that stays in Settings -> People.
"""

import hashlib
import ipaddress

HANDLE_LEN = 12
# The client ids of Home Assistant's own phone apps.
APP_CLIENTS = frozenset({"https://home-assistant.io/iOS", "https://home-assistant.io/android"})


class Refused(Exception):
    """The caller may not do this; the message says why."""


def handle(token_id):
    """A short, stable name for a login: shown on dashboards instead of its id."""
    return hashlib.sha256(token_id.encode()).hexdigest()[:HANDLE_LEN]


def resolve(tokens, h):
    """The one login whose handle is `h`."""
    found = [t for t in tokens if handle(t.id) == h]
    if len(found) != 1:
        raise Refused("no login with handle %s" % h)
    return found[0]


def check_caller(caller):
    """Checked before anything about the target, so a refusal reveals nothing about it."""
    if caller is None:
        raise Refused("only a signed-in person can do this, not an automation or script")
    if not caller.is_admin:
        raise Refused("%s is not an administrator" % caller.name)


def check_sign_out(caller, owner):
    """`caller` signs out one login belonging to `owner`."""
    check_caller(caller)
    if owner.system_generated:
        raise Refused("%s is a system account; add-ons sign in through it" % owner.name)


def check_unban(caller, banned, ip):
    """`caller` lifts the ban on `ip`; `banned` holds the banned addresses, None if bans are off.

    Returns the address as Home Assistant keys it.
    """
    check_caller(caller)
    if banned is None:
        raise Refused("Home Assistant's IP bans are not enabled")
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise Refused("%s is not an IP address" % ip) from None
    if addr not in banned:
        raise Refused("%s is not banned" % addr)
    return addr


def check_tap(caller):
    """`caller` tapped *Sign out this login* on a push (DESIGN.md 0.3.0, #6).

    The phone's webhook outlives its login, so a phone signed out (lost, say) could still tap.
    The person must still have a live login from a Home Assistant app.
    """
    check_caller(caller)
    if not any(t.client_id in APP_CLIENTS for t in caller.refresh_tokens.values()):
        raise Refused("%s has no signed-in Home Assistant app" % caller.name)
