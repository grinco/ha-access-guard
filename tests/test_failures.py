"""The failed-login line: its host, URL and agent are the attacker's, so no failure may be hidden."""

import logging

from custom_components.access_guard.failures import MAX_CANDIDATES, FailedLogins, addresses

OK = ("Login attempt or request with invalid authentication from {host} ({ip}). "
      "Requested URL: '/auth/login_flow/0d1e2f'. ({agent})")
MARK = "(%s). Requested URL: '/auth/login_flow/x'. ("


def line(host="203.0.113.9", ip="203.0.113.9", agent="Mozilla/5.0"):
    return OK.format(host=host, ip=ip, agent=agent)


def test_a_wrong_password_names_its_address():
    assert addresses(line()) == ["203.0.113.9"]
    assert addresses(line(host="dsl-9.example.net")) == ["203.0.113.9"]


def test_ipv6_is_normalised():
    assert addresses(line(host="2001:db8:0::9", ip="2001:db8:0::9")) == ["2001:db8::9"]


def test_a_forged_reverse_name_cannot_hide_the_real_address():
    """The attacker owns their PTR record: the forged address is taken too, never instead."""
    forged = "x " + MARK % "192.168.1.5" + "y"
    assert addresses(line(host=forged)) == ["192.168.1.5", "203.0.113.9"]


def test_an_agent_stuffed_with_addresses_cannot_push_the_real_one_out():
    # Six is the most a 255-byte reverse name can hold, with the shortest marks ("(::1).").
    forged_host = "x" + "".join((MARK % ("::%d" % i))[:-len("x'. (")] for i in range(6))
    assert len(forged_host) <= 255
    stuffed = "".join(MARK % ("10.0.%d.%d" % (i // 250, i % 250)) for i in range(500))
    found = addresses(line(host=forged_host, agent=stuffed))
    assert len(found) == MAX_CANDIDATES and "203.0.113.9" in found


def test_only_the_login_flow_counts():
    """A stale browser tab's expired token is a 401 too, but nobody is guessing."""
    assert addresses(line().replace("/auth/login_flow/0d1e2f", "/api/states")) == []


def test_not_an_address_or_another_line():
    assert addresses(line(ip="999.1.1.1")) == []
    assert addresses(line(ip="::::")) == []
    assert addresses("Banned IP 203.0.113.9 for too many login attempts") == []
    assert addresses(MARK % "203.0.113.9") == [], "the line must be Home Assistant's own"
    assert addresses("") == []


def _record(msg, *args):
    return logging.LogRecord("homeassistant.components.http.ban", logging.WARNING, __file__, 1, msg, args, None)


def test_the_handler_reports_each_address_and_counts_lines():
    got = []
    h = FailedLogins(lambda ip, at: got.append((ip, at.tzinfo is not None)))
    h.emit(_record(line()))
    h.emit(_record(line(host="x " + MARK % "192.168.1.5")))
    h.emit(_record(line().replace("/auth/login_flow/0d1e2f", "/api/")))
    h.emit(_record("Banned IP %s for too many login attempts", "203.0.113.9"))
    h.emit(_record("%d", "not a number"))      # a broken record is skipped, not raised
    assert got == [("203.0.113.9", True), ("192.168.1.5", True), ("203.0.113.9", True)]
    assert (h.seen, h.ambiguous) == (2, 1)
