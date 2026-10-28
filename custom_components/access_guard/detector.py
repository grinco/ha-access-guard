"""Light detection rules (DESIGN.md 0.2.0). No Home Assistant imports, so it is tested on its own.

It only reports: every finding notifies, none acts. Everything it holds is bounded, so an
attacker spraying from many addresses cannot grow it.

A finding is an event_data() row (the fixed event contract) plus `kind`, `message` and the
kind's own fields.
"""

import ipaddress
from collections import OrderedDict, deque
from datetime import timedelta

LOGIN_AFTER_FAILURES = "login_after_failures"
SENSITIVE_FIRST = "sensitive_first"
LONG_LIVED_TOKEN = "long_lived_token"
RULES = (LOGIN_AFTER_FAILURES, SENSITIVE_FIRST, LONG_LIVED_TOKEN)
DEFAULT_SENSITIVE = ("camera", "lock", "alarm_control_panel")
LIVE_VIEW = "live_view"            # the action of a camera watched over the websocket

FAILURE_WINDOW = timedelta(minutes=15)
FIRST_WINDOW = timedelta(minutes=5)
MAX_TRACKED = 256
RECENT_PER_KEY = 8
# The house itself is home, tailscale and add-on; only a login from outside is watched.
OUTSIDE = ("internet", "home via internet")


def _addr(ip):
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return None


def _where(row):
    extra = ", ".join(x for x in (row["origin"], row["country"]) if x)
    return "%s (%s)" % (row["ip"] or "no address", extra)


def _put(od, key, value):
    """Insert as the newest entry and evict the oldest beyond MAX_TRACKED."""
    od.pop(key, None)
    od[key] = value
    while len(od) > MAX_TRACKED:
        od.popitem(last=False)


class Detector:
    def __init__(self, rules=RULES, failures_before_login=1, sensitive=DEFAULT_SENSITIVE):
        self.rules = frozenset(rules)
        self.failures_before_login = failures_before_login
        self.sensitive = frozenset(sensitive)
        self._failures = OrderedDict()   # address -> deque of failure times
        self._watched = OrderedDict()    # handle -> (row, created): new outside logins, first move unseen
        self._recent = OrderedDict()     # ("h", handle) | ("u", user id) -> deque of recent signals

    def failure(self, ip, at):
        if (key := _addr(ip)) is None:
            return
        times = self._failures.get(key) or deque()
        times.append(at)
        while times and times[0] < at - FAILURE_WINDOW:
            times.popleft()
        _put(self._failures, key, times)

    def new_login(self, row, created):
        """`row` is a new login's event data; returns its findings."""
        found = []
        if LONG_LIVED_TOKEN in self.rules and row["token_type"] == "long_lived_access_token":
            found.append(dict(row, kind=LONG_LIVED_TOKEN, message=(
                "%s created a long-lived access token (%s) from %s." % (row["user_name"], row["client"], _where(row)))))
        if LOGIN_AFTER_FAILURES in self.rules and (key := _addr(row["ip"])) in self._failures:
            n = sum(1 for t in self._failures[key] if created - FAILURE_WINDOW <= t <= created)
            if n >= self.failures_before_login:
                del self._failures[key]        # one burst, one alert
                found.append(dict(row, kind=LOGIN_AFTER_FAILURES, failures=n, message=(
                    "%s signed in on %s from %s after %d failed attempt%s from that address." % (
                        row["user_name"], row["client"], _where(row), n, "" if n == 1 else "s"))))
        if SENSITIVE_FIRST in self.rules and row["origin"] in OUTSIDE:
            # Polling sees a login up to 30 s late; its first move may already have happened.
            seen = [(s, by) for k, by in ((("h", row["handle"]), "login"), (("u", row["user_id"]), "person"))
                    for s in self._recent.get(k, ()) if created <= s[0] <= created + FIRST_WINDOW]
            if seen:
                found += self._judge(row, *min(seen, key=lambda x: x[0][0]))
            else:
                _put(self._watched, row["handle"], (row, created))
        return found

    def signal(self, user_id, handle, domain, action, target, at):
        """A person did something: watched a camera (`handle` known) or ran an action (user only).

        An action names only the person, so one made on their other device within the window
        counts as the new login's first move (DESIGN.md 0.2.0).
        """
        sig = (at, domain, action, target)
        # Kept under what it names, so a camera on another login is never this one's, early or late.
        key = ("h", handle) if handle else ("u", user_id)
        recent = self._recent.get(key) or deque(maxlen=RECENT_PER_KEY)
        recent.append(sig)
        _put(self._recent, key, recent)
        for h in [h for h, (_, created) in self._watched.items() if at - created > FIRST_WINDOW]:
            del self._watched[h]
        if handle:
            hit = handle if handle in self._watched else None
        else:
            # Their most recent watched login made it.
            hit = next((h for h, (row, _) in reversed(self._watched.items()) if row["user_id"] == user_id), None)
        if hit is None:
            return []
        row, _ = self._watched.pop(hit)
        return self._judge(row, sig, "login" if handle else "person")

    def _judge(self, row, sig, attribution):
        """Only the first move counts: sensitive, it is a finding; otherwise nothing.

        `attribution` is "login" when the move named this exact login, "person" when it named only
        its user: phase 4 may act on the first only (DESIGN.md 0.2.0, R3).
        """
        _, domain, action, target = sig
        if domain not in self.sensitive:
            return []
        did = "watched %s live" % target if action == LIVE_VIEW else "ran %s on %s" % (action, target or "-")
        return [dict(row, kind=SENSITIVE_FIRST, domain=domain, action=action, target=target,
                     attribution=attribution, message=(
            "%s's new login on %s from %s first %s." % (row["user_name"], row["client"], _where(row), did)))]
