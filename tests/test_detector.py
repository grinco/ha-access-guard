"""The light detection rules (DESIGN.md 0.2.0), pure Python: thresholds, windows, the first move."""

from datetime import datetime, timedelta, timezone

from custom_components.access_guard import detector as d
from custom_components.access_guard.detector import Detector

T0 = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)
MIN = timedelta(minutes=1)


def row(handle="aaaaaaaaaaaa", user_id="u-robin", ip="203.0.113.9", origin="internet", token_type="normal", **kw):
    r = {"handle": handle, "user_id": user_id, "user_name": "Robin", "token_type": token_type,
         "client": "Android app", "created": T0.isoformat(), "last_used": T0.isoformat(),
         "ip": ip, "origin": origin, "country": "NL"}
    r.update(kw)
    return r


def kinds(found):
    return [f["kind"] for f in found]


# --- login after failures


def test_a_login_after_one_failure_from_its_address_is_reported():
    det = Detector()
    det.failure(["203.0.113.9"], T0 - 2 * MIN)
    [f] = det.new_login(row(), T0)
    assert f["kind"] == d.LOGIN_AFTER_FAILURES and f["failures"] == 1 and f["handle"] == "aaaaaaaaaaaa"
    assert "after 1 failed attempt from" in f["message"] and "203.0.113.9 (internet, NL)" in f["message"]


def test_failures_from_another_address_or_none_report_nothing():
    det = Detector()
    det.failure(["198.51.100.7"], T0 - MIN)
    assert det.new_login(row(), T0) == []
    assert Detector().new_login(row(), T0) == []


def test_the_threshold_is_an_option():
    det = Detector(failures_before_login=3)
    for i in (3, 2):
        det.failure(["203.0.113.9"], T0 - i * MIN)
    assert det.new_login(row(), T0) == []
    det.failure(["203.0.113.9"], T0 - MIN)
    [f] = det.new_login(row(handle="bbbbbbbbbbbb"), T0)
    assert f["failures"] == 3 and "3 failed attempts" in f["message"]


def test_only_failures_in_the_fifteen_minutes_before_the_login_count():
    det = Detector()
    det.failure(["203.0.113.9"], T0 - d.FAILURE_WINDOW - timedelta(seconds=1))
    det.failure(["203.0.113.9"], T0 + timedelta(seconds=1))        # after the login: not before it
    assert det.new_login(row(), T0) == []
    det.failure(["203.0.113.9"], T0 - d.FAILURE_WINDOW)              # the edge counts
    assert kinds(det.new_login(row(handle="bbbbbbbbbbbb"), T0)) == [d.LOGIN_AFTER_FAILURES]


def test_one_burst_gives_one_alert():
    det = Detector()
    det.failure(["203.0.113.9"], T0 - MIN)
    assert kinds(det.new_login(row(), T0)) == [d.LOGIN_AFTER_FAILURES]
    assert det.new_login(row(handle="bbbbbbbbbbbb"), T0) == []


def test_addresses_are_compared_as_addresses():
    det = Detector()
    det.failure(["2001:db8:0::9"], T0 - MIN)
    assert kinds(det.new_login(row(ip="2001:db8::9"), T0)) == [d.LOGIN_AFTER_FAILURES]


def test_garbage_addresses_are_ignored():
    det = Detector()
    det.failure(["not an ip"], T0)
    assert det.new_login(row(ip=None, origin="never used"), T0) == []


def test_tracking_is_bounded_oldest_out():
    det = Detector()
    det.failure(["203.0.113.9"], T0 - MIN)
    for i in range(d.MAX_TRACKED):
        det.failure(["10.1.%d.%d" % (i // 250, i % 250)], T0 - MIN)
    assert len(det._failures) == d.MAX_TRACKED
    assert det.new_login(row(), T0) == [], "the oldest address should have been evicted"


def test_old_failures_of_one_address_are_dropped_as_new_ones_arrive():
    det = Detector()
    det.failure(["203.0.113.9"], T0 - 20 * MIN)
    det.failure(["203.0.113.9"], T0)
    assert list(det._failures["203.0.113.9"]) == [T0]


# --- long-lived token


def test_a_long_lived_token_is_reported_wherever_it_comes_from():
    [f] = Detector().new_login(row(token_type="long_lived_access_token", client="token: ha-mcp", origin="home",
                                   ip="192.168.1.5", country=None), T0)
    assert f["kind"] == d.LONG_LIVED_TOKEN and "token: ha-mcp" in f["message"] and "(home)" in f["message"]


# --- the first move of a new outside login


def test_a_camera_watched_first_is_reported_by_its_exact_login():
    det = Detector()
    assert det.new_login(row(), T0) == []
    [f] = det.signal("u-robin", "aaaaaaaaaaaa", "camera", d.LIVE_VIEW, "camera.door", T0 + MIN)
    assert f["kind"] == d.SENSITIVE_FIRST and f["target"] == "camera.door" and f["domain"] == "camera"
    assert "first watched camera.door live" in f["message"] and f["attribution"] == "login"


def test_an_action_on_a_sensitive_domain_first_is_reported():
    det = Detector()
    det.new_login(row(), T0)
    [f] = det.signal("u-robin", None, "lock", "lock.unlock", "lock.front", T0 + MIN)
    assert f["action"] == "lock.unlock" and "first ran lock.unlock on lock.front" in f["message"]
    assert f["attribution"] == "person", "an action names only the person (review R3)"


def test_only_the_first_move_counts():
    det = Detector()
    det.new_login(row(), T0)
    assert det.signal("u-robin", None, "light", "light.turn_on", "light.lamp", T0 + MIN) == []
    assert det.signal("u-robin", "aaaaaaaaaaaa", "camera", d.LIVE_VIEW, "camera.door", T0 + 2 * MIN) == []


def test_after_five_minutes_nothing_is_first_any_more():
    det = Detector()
    det.new_login(row(), T0)
    assert det.signal("u-robin", "aaaaaaaaaaaa", "camera", d.LIVE_VIEW, "camera.door",
                      T0 + d.FIRST_WINDOW + timedelta(seconds=1)) == []
    assert det._watched == {}


def test_logins_from_the_house_are_not_watched():
    det = Detector()
    for i, o in enumerate(("home", "tailscale", "add-on")):
        det.new_login(row(handle="%012d" % i, origin=o, ip="192.168.1.5"), T0)
    assert det.signal("u-robin", None, "camera", d.LIVE_VIEW, "camera.door", T0 + MIN) == []


def test_home_via_internet_is_watched():
    det = Detector()
    det.new_login(row(origin="home via internet"), T0)
    assert kinds(det.signal("u-robin", "aaaaaaaaaaaa", "camera", d.LIVE_VIEW, "camera.door", T0 + MIN)) == [
        d.SENSITIVE_FIRST]


def test_a_camera_on_another_login_of_the_same_person_is_not_this_ones():
    det = Detector()
    det.new_login(row(), T0)
    assert det.signal("u-robin", "cccccccccccc", "camera", d.LIVE_VIEW, "camera.door", T0 + MIN) == []
    assert "aaaaaaaaaaaa" in det._watched


def test_a_camera_on_another_login_before_polling_is_not_this_ones_either():
    """The order in which the login and the move arrive never changes the result."""
    det = Detector()
    det.signal("u-robin", "cccccccccccc", "camera", d.LIVE_VIEW, "camera.door", T0 + timedelta(seconds=10))
    assert det.new_login(row(), T0) == []
    assert "aaaaaaaaaaaa" in det._watched


def test_another_persons_action_is_not_this_logins():
    det = Detector()
    det.new_login(row(), T0)
    assert det.signal("u-pat", None, "lock", "lock.unlock", "lock.front", T0 + MIN) == []
    assert "aaaaaaaaaaaa" in det._watched


def test_an_action_goes_to_the_persons_most_recent_new_login():
    det = Detector()
    det.new_login(row(handle="aaaaaaaaaaaa"), T0)
    det.new_login(row(handle="bbbbbbbbbbbb"), T0 + MIN)
    [f] = det.signal("u-robin", None, "lock", "lock.unlock", "lock.front", T0 + 2 * MIN)
    assert f["handle"] == "bbbbbbbbbbbb"


def test_a_first_move_made_before_polling_saw_the_login_still_counts():
    """The coordinator sees a login up to 30 s after it is created."""
    det = Detector()
    det.signal("u-robin", "aaaaaaaaaaaa", "camera", d.LIVE_VIEW, "camera.door", T0 + timedelta(seconds=10))
    det.signal("u-robin", None, "light", "light.turn_on", "light.lamp", T0 + timedelta(seconds=20))
    [f] = det.new_login(row(), T0)
    assert f["kind"] == d.SENSITIVE_FIRST and f["target"] == "camera.door" and f["attribution"] == "login"
    assert det._watched == {}, "a judged login is not watched again"


def test_a_person_level_move_before_polling_is_attributed_to_the_person():
    det = Detector()
    det.signal("u-robin", None, "lock", "lock.unlock", "lock.front", T0 + timedelta(seconds=10))
    [f] = det.new_login(row(), T0)
    assert f["attribution"] == "person"


def test_a_harmless_first_move_before_polling_ends_the_watch():
    det = Detector()
    det.signal("u-robin", None, "light", "light.turn_on", "light.lamp", T0 + timedelta(seconds=5))
    assert det.new_login(row(), T0) == []
    assert det.signal("u-robin", "aaaaaaaaaaaa", "camera", d.LIVE_VIEW, "camera.door", T0 + MIN) == []


def test_a_login_found_after_its_window_has_no_first_move():
    """Polling can fail for a while; a move six minutes in is not 'first thing' any more."""
    det = Detector()
    det.signal("u-robin", "aaaaaaaaaaaa", "camera", d.LIVE_VIEW, "camera.door", T0 + 6 * MIN)
    assert det.new_login(row(), T0) == []


def test_moves_before_the_login_existed_are_not_its_moves():
    det = Detector()
    det.signal("u-robin", None, "lock", "lock.unlock", "lock.front", T0 - MIN)
    assert det.new_login(row(), T0) == []
    assert "aaaaaaaaaaaa" in det._watched


def test_sensitive_domains_are_an_option():
    det = Detector(sensitive=("cover",))
    det.new_login(row(), T0)
    assert kinds(det.signal("u-robin", None, "cover", "cover.open_cover", "cover.garage", T0 + MIN)) == [
        d.SENSITIVE_FIRST]
    det.new_login(row(handle="bbbbbbbbbbbb"), T0)
    assert det.signal("u-robin", "bbbbbbbbbbbb", "camera", d.LIVE_VIEW, "camera.door", T0 + MIN) == []


def test_rules_can_be_turned_off():
    det = Detector(rules=())
    det.failure(["203.0.113.9"], T0 - MIN)
    assert det.new_login(row(token_type="long_lived_access_token"), T0) == []
    assert det.signal("u-robin", "aaaaaaaaaaaa", "camera", d.LIVE_VIEW, "camera.door", T0 + MIN) == []


def test_findings_carry_the_event_contract_and_no_more():
    det = Detector()
    det.failure(["203.0.113.9"], T0 - MIN)
    [f] = det.new_login(row(), T0)
    assert set(f) == set(row()) | {"kind", "message", "failures"}


def test_recent_signals_are_bounded():
    det = Detector()
    for i in range(d.MAX_TRACKED + 10):
        det.signal("u-%d" % i, None, "light", "light.turn_on", "light.x", T0)
    for _ in range(d.RECENT_PER_KEY + 5):
        det.signal("u-robin", None, "light", "light.turn_on", "light.x", T0)
    assert len(det._recent) == d.MAX_TRACKED and len(det._recent[("u", "u-robin")]) == d.RECENT_PER_KEY


# --- a non-admin login used from the internet (issue #3)


def test_a_non_admins_login_from_the_internet_alerts():
    [f] = Detector().new_login(row(), T0, is_admin=False)
    assert f["kind"] == d.NON_ADMIN_INTERNET and "from the internet: 203.0.113.9 (internet, NL)" in f["message"]


def test_an_admin_or_a_login_from_elsewhere_does_not():
    assert Detector().new_login(row(), T0, is_admin=True) == []
    for origin in ("home", "home via internet", "tailscale", "add-on", "never used"):
        assert d.NON_ADMIN_INTERNET not in kinds(Detector().new_login(row(origin=origin), T0, is_admin=False))


# --- a burst of failed logins (issue #5)


def burst(det, ip, n, start=T0, step=timedelta(seconds=10)):
    found = []
    for i in range(n):
        found += det.failure([ip], start + i * step)
    return found


def test_a_burst_from_one_address_alerts_once():
    det = Detector(burst_failures=10)
    assert burst(det, "203.0.113.9", 9) == []
    [f] = burst(det, "203.0.113.9", 1, start=T0 + 90 * timedelta(seconds=1))
    assert (f["kind"], f["ip"], f["failures"], f["addresses"]) == (d.FAILED_LOGIN_BURST, "203.0.113.9", 10, 1)
    assert "10 failed sign-in attempts from 203.0.113.9 in 5 minutes" in f["message"]
    assert burst(det, "203.0.113.9", 20, start=T0 + 2 * MIN) == [], "one burst, one alert"
    assert det.bursts_alerted == 1


def test_a_burst_finding_has_no_login():
    det = Detector(burst_failures=2)
    [f] = burst(det, "203.0.113.9", 2)
    assert all(f[k] is None for k in d.NO_LOGIN if k != "ip")
    assert set(f) == set(row()) | {"kind", "message", "failures", "addresses"}


def test_failures_spread_over_more_than_five_minutes_are_no_burst():
    det = Detector(burst_failures=10)
    assert burst(det, "203.0.113.9", 12, step=timedelta(seconds=35)) == []


def test_after_an_hour_of_quiet_a_new_burst_alerts_again():
    det = Detector(burst_failures=3)
    assert len(burst(det, "203.0.113.9", 3)) == 1
    assert burst(det, "203.0.113.9", 3, start=T0 + 59 * MIN) == []
    assert len(burst(det, "203.0.113.9", 3, start=T0 + 61 * MIN)) == 1


def test_a_burst_across_addresses_alerts_once():
    """Password spraying from many places, each below the per-address threshold."""
    det = Detector(burst_failures=10)
    found = []
    for i in range(10):
        found += det.failure(["198.51.100.%d" % (i % 5)], T0 + i * timedelta(seconds=5))
    [f] = found
    assert (f["kind"], f["ip"], f["failures"], f["addresses"]) == (d.FAILED_LOGIN_BURST, None, 10, 5)
    assert "10 failed sign-in attempts from 5 addresses" in f["message"]
    assert burst(det, "198.51.100.9", 5, start=T0 + MIN) == []


def test_two_addresses_are_not_a_spread():
    det = Detector(burst_failures=10)
    found = []
    for i in range(10):
        found += det.failure(["198.51.100.%d" % (i % 2)], T0 + i * timedelta(seconds=5))
    assert found == []


def test_an_ambiguous_line_is_one_failure_across_addresses():
    """A forged reverse name adds addresses to a line; it must not multiply the failures."""
    det = Detector(burst_failures=3)
    found = []
    for i in range(2):
        found += det.failure(["192.168.1.5", "203.0.113.9", "10.0.0.%d" % i], T0 + i * MIN)
    assert found == [], "two failed logins are not a burst of three"


def test_garbage_only_is_no_failure():
    det = Detector(burst_failures=1)
    assert det.failure(["not an ip"], T0) == [] and not det._events


def test_the_burst_rule_can_be_turned_off_and_failures_still_count():
    det = Detector(rules=(d.LOGIN_AFTER_FAILURES,), burst_failures=1)
    assert burst(det, "203.0.113.9", 3) == []
    assert kinds(det.new_login(row(), T0 + MIN)) == [d.LOGIN_AFTER_FAILURES]


def test_failure_events_and_cooldowns_are_bounded():
    det = Detector(burst_failures=1)
    for i in range(d.MAX_EVENTS + 50):
        det.failure(["10.%d.%d.%d" % (i // 65536, (i // 256) % 256, i % 256)], T0 + i * timedelta(minutes=10))
    assert len(det._events) == d.MAX_EVENTS and len(det._quiet) == d.MAX_TRACKED


# --- a new country for a person (issue #4)


def test_the_first_country_is_a_baseline_and_a_second_alerts_once():
    det = Detector()
    assert det.country(row(country="CZ")) == [] and det.countries == {"u-robin": ["CZ"]}
    assert det.country(row(country="CZ")) == []
    [f] = det.country(row(country="NL", handle="bbbbbbbbbbbb"))
    assert (f["kind"], f["handle"]) == (d.NEW_COUNTRY, "bbbbbbbbbbbb") and "a country new for them" in f["message"]
    assert det.country(row(country="NL")) == [], "learnt"
    assert det.countries_changed


def test_countries_are_per_person():
    det = Detector()
    det.country(row(country="CZ"))
    assert det.country(row(country="NL", user_id="u-pat")) == []        # Pat's baseline
    assert det.countries == {"u-robin": ["CZ"], "u-pat": ["NL"]}


def test_no_country_never_counts_and_changes_nothing():
    det = Detector()
    assert det.country(row(country=None, origin="home")) == [] and det.countries == {}
    assert not det.countries_changed


def test_allowed_countries_are_learnt_but_never_alert():
    det = Detector(allowed_countries=("nl",))
    det.country(row(country="CZ"))
    assert det.country(row(country="NL")) == [] and det.countries["u-robin"] == ["CZ", "NL"]


def test_with_the_rule_off_countries_are_still_learnt():
    det = Detector(rules=())
    det.country(row(country="CZ"))
    assert det.country(row(country="NL")) == [] and det.countries["u-robin"] == ["CZ", "NL"]


def test_beyond_the_bound_the_oldest_country_is_forgotten_and_nothing_repeats():
    det = Detector()
    codes = ["C%02d" % i for i in range(d.MAX_COUNTRIES + 1)]
    for cc in codes:
        det.country(row(country=cc))
    assert det.countries["u-robin"] == codes[1:]
    assert det.country(row(country=codes[-1])) == [], "a 33rd country must not alert on every poll"


# --- options: the rules on (0.2.0) and the rules off (0.3.0)


def test_new_rules_are_on_by_default_and_for_a_saved_0_2_form():
    assert d.enabled_rules() == frozenset(d.RULES)
    on = d.enabled_rules(rules=[d.LOGIN_AFTER_FAILURES])          # 0.2.0 options: only this one on
    assert on == frozenset(d.RULES) - {d.SENSITIVE_FIRST, d.LONG_LIVED_TOKEN}
    assert d.enabled_rules(rules_off=[d.NEW_COUNTRY], rules=[]) == frozenset(d.RULES) - {d.NEW_COUNTRY}


# --- which findings offer "Sign out this login" (issue #6)


def test_only_findings_about_one_exact_login_offer_a_sign_out():
    base = row()
    assert d.offers_sign_out(dict(base, kind=d.LONG_LIVED_TOKEN))
    assert d.offers_sign_out(dict(base, kind=d.NON_ADMIN_INTERNET))
    assert d.offers_sign_out(dict(base, kind=d.NEW_COUNTRY))
    assert d.offers_sign_out(dict(base, kind=d.SENSITIVE_FIRST, attribution="login"))
    assert not d.offers_sign_out(dict(base, kind=d.SENSITIVE_FIRST, attribution="person"))
    assert not d.offers_sign_out(dict(base, kind=d.LOGIN_AFTER_FAILURES))
    assert not d.offers_sign_out(dict(d.NO_LOGIN, kind=d.FAILED_LOGIN_BURST))
    assert not d.offers_sign_out(dict(d.NO_LOGIN, kind=d.LONG_LIVED_TOKEN)), "no login, nothing to sign out"
