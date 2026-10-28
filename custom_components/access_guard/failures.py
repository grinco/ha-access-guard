"""Failed logins, read from Home Assistant's own warning line. No Home Assistant imports.

Home Assistant fires no event for a failed login; `http.ban.process_wrong_login` logs one
warning per failure, bans enabled or not (DESIGN.md 0.2.0):

    Login attempt or request with invalid authentication from {host} ({ip}). Requested URL: '{url}'. ({agent})

The host is reverse DNS, which the attacker controls (musl, which Home Assistant OS uses, does
not reject a PTR name holding spaces), and so are the URL and the agent. A forged name can
therefore put a second "(address). Requested URL: '/auth/login_flow/" in front of the real one,
and no parse can tell which is real. Every such address is taken: the real one is always among
them, so a failure cannot be hidden, and a forged one can only cause a wrong notification,
never an action (DESIGN.md 0.2.0). Nothing from the line is logged again.
"""

import ipaddress
import logging
import re
from datetime import datetime, timezone

LOGGER_NAME = "homeassistant.components.http.ban"
PREFIX = "Login attempt or request with invalid authentication from "
# Only the login flow counts: a wrong password or MFA code. Other 401s are stale tokens, not guesses.
MARK = re.compile(r"\(([0-9A-Fa-f:.]+)\)\. Requested URL: '/auth/login_flow/")
# A reverse name is at most 255 bytes, room for six forged marks before the real one; the cap
# keeps an agent stuffed with addresses from pushing the real one out of the detector.
MAX_CANDIDATES = 8


def addresses(message):
    """The address of a failed login: one, or several when the line is ambiguous, else none."""
    if not message.startswith(PREFIX):
        return []
    out = []
    for candidate in MARK.findall(message):
        try:
            ip = str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
        if ip not in out:
            out.append(ip)
    return out[:MAX_CANDIDATES]


class FailedLogins(logging.Handler):
    """Calls `on_failure(ip, at)` for each failed login's address; counts lines for diagnostics."""

    def __init__(self, on_failure):
        super().__init__(logging.WARNING)
        self._on_failure = on_failure
        self.seen = 0
        self.ambiguous = 0

    def emit(self, record):
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - a broken record is not ours to report
            return
        if not (found := addresses(message)):
            return
        self.seen += 1
        self.ambiguous += len(found) > 1
        at = datetime.fromtimestamp(record.created, timezone.utc)
        for ip in found:
            self._on_failure(ip, at)
