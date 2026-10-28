"""Light detection rules (DESIGN.md 0.2.0, 0.3.0). No Home Assistant imports, so it is tested on its own.

It only reports: every finding notifies, none acts. Everything it holds is bounded, so an
attacker spraying from many addresses cannot grow it.

A finding is an event_data() row (the fixed event contract) plus `kind`, `message` and the
kind's own fields. A finding about failed logins has no login: its login fields are None.
"""

import ipaddress
from collections import OrderedDict, deque
from datetime import timedelta

LOGIN_AFTER_FAILURES = "login_after_failures"
SENSITIVE_FIRST = "sensitive_first"
LONG_LIVED_TOKEN = "long_lived_token"
NON_ADMIN_INTERNET = "non_admin_internet"
NEW_COUNTRY = "new_country"
FAILED_LOGIN_BURST = "failed_login_burst"
RULES_0_2 = (LOGIN_AFTER_FAILURES, SENSITIVE_FIRST, LONG_LIVED_TOKEN)
RULES = RULES_0_2 + (NON_ADMIN_INTERNET, NEW_COUNTRY, FAILED_LOGIN_BURST)
# Attackers can make these name someone else's login: they never offer a sign-out (policy).
FROM_FAILED_LOGINS = (LOGIN_AFTER_FAILURES, FAILED_LOGIN_BURST)
# The event contract's login fields, for a finding that has no login.
NO_LOGIN = dict.fromkeys(("handle", "user_id", "user_name", "token_type", "client", "created", "last_used", "ip",
                          "origin", "country"))
DEFAULT_SENSITIVE = ("camera", "lock", "alarm_control_panel")
LIVE_VIEW = "live_view"            # the action of a camera watched over the websocket

FAILURE_WINDOW = timedelta(minutes=15)
FIRST_WINDOW = timedelta(minutes=5)
BURST_WINDOW = timedelta(minutes=5)
BURST_COOLDOWN = timedelta(hours=1)
BURST_SPREAD = 3                   # addresses, for a burst across addresses
MAX_EVENTS = 1024
ACROSS = "*"                       # the cool-down key of the burst across addresses
MAX_TRACKED = 256
MAX_COUNTRIES = 32                 # per person
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


def enabled_rules(rules_off=None, rules=None):
    """The rules on. 0.3.0 stores the rules off; 0.2.0 stored the rules on, and a rule it did not
    know is on (DESIGN.md 0.3.0, options)."""
    if rules_off is None and rules is not None:
        rules_off = set(RULES_0_2) - set(rules)
    return frozenset(RULES) - set(rules_off or ())


def offers_sign_out(finding):
    """A push may offer *Sign out this login* only for a finding about one exact login."""
    return (bool(finding.get("handle")) and finding["kind"] not in FROM_FAILED_LOGINS
            and finding.get("attribution", "login") == "login")


def _put(od, key, value):
    """Insert as the newest entry and evict the oldest beyond MAX_TRACKED."""
    od.pop(key, None)
    od[key] = value
    while len(od) > MAX_TRACKED:
        od.popitem(last=False)


class Detector:
    def __init__(self, rules=RULES, failures_before_login=1, sensitive=DEFAULT_SENSITIVE, burst_failures=10,
                 allowed_countries=()):
        self.rules = frozenset(rules)
        self.failures_before_login = failures_before_login
        self.sensitive = frozenset(sensitive)
        self.burst_failures = burst_failures
        self.allowed_countries = frozenset(c.upper() for c in allowed_countries)
        self.countries = {}              # user id -> country codes seen, learnt longest ago first
        self.countries_changed = False
        self.bursts_alerted = 0
        self._failures = OrderedDict()   # address -> deque of failure times
        self._events = deque(maxlen=MAX_EVENTS)   # (time, addresses) per failed login, for bursts across
        self._quiet = OrderedDict()      # address | ACROSS -> time its burst alert was sent
        self._watched = OrderedDict()    # handle -> (row, created): new outside logins, first move unseen
        self._recent = OrderedDict()     # ("h", handle) | ("u", user id) -> deque of recent signals

    def failure(self, ips, at):
        """One failed login; `ips` are its candidate addresses (one, or several when the line was
        ambiguous). Returns burst findings."""
        keys = [k for k in map(_addr, ips) if k is not None]
        for key in keys:
            times = self._failures.get(key) or deque()
            times.append(at)
            while times and times[0] < at - FAILURE_WINDOW:
                times.popleft()
            _put(self._failures, key, times)
        if not keys:
            return []
        self._events.append((at, tuple(keys)))
        if FAILED_LOGIN_BURST not in self.rules:
            return []
        found = []
        for key in keys:
            n = sum(1 for t in self._failures[key] if t > at - BURST_WINDOW)
            if n >= self.burst_failures and self._may_alert(key, at):
                found.append(self._burst(key, n, 1, "%d failed sign-in attempts from %s in 5 minutes." % (n, key)))
        recent = [ips for t, ips in self._events if t > at - BURST_WINDOW]
        spread = len({ip for ips in recent for ip in ips})
        if len(recent) >= self.burst_failures and spread >= BURST_SPREAD and self._may_alert(ACROSS, at):
            found.append(self._burst(None, len(recent), spread, "%d failed sign-in attempts from %d addresses in "
                                     "5 minutes." % (len(recent), spread)))
        return found

    def _may_alert(self, key, at):
        """One alert per burst: the key then stays quiet for an hour."""
        last = self._quiet.get(key)
        if last is not None and at - last < BURST_COOLDOWN:
            return False
        _put(self._quiet, key, at)
        return True

    def _burst(self, ip, failures, addresses, message):
        self.bursts_alerted += 1
        return dict(NO_LOGIN, ip=ip, kind=FAILED_LOGIN_BURST, failures=failures, addresses=addresses,
                    message=message)

    def country(self, row):
        """A login seen in use; returns a finding if it is in a country new for its person.

        The first country a person is seen in is their baseline, learnt silently. Countries are
        learnt whether or not the rule is on, so turning it on later has a history.
        """
        cc, uid = row["country"], row["user_id"]
        if not cc:
            return []
        seen = self.countries.get(uid)
        if seen is not None and cc in seen:
            return []
        self.countries_changed = True
        if seen is None:
            self.countries[uid] = [cc]
            return []
        seen.append(cc)
        del seen[:-MAX_COUNTRIES]       # forget the oldest; else a 33rd would alert on every poll
        if NEW_COUNTRY not in self.rules or cc in self.allowed_countries:
            return []
        return [dict(row, kind=NEW_COUNTRY, message="%s used %s from %s, a country new for them." % (
            row["user_name"], row["client"], _where(row)))]

    def new_login(self, row, created, is_admin=True):
        """`row` is a new login's event data; returns its findings."""
        found = []
        if NON_ADMIN_INTERNET in self.rules and not is_admin and row["origin"] == "internet":
            found.append(dict(row, kind=NON_ADMIN_INTERNET, message=(
                "%s signed in on %s from the internet: %s." % (row["user_name"], row["client"], _where(row)))))
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
