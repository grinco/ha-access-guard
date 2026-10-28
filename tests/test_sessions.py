"""sessions.py without Home Assistant: classification, the offline country lookup, rows."""

import json
from datetime import datetime, timedelta, timezone

from custom_components.access_guard.sessions import GeoResolver, client, finish, origin

GEO = "198.51.100.0,198.51.100.255,CZ\n203.0.113.0,203.0.113.255,NL\n2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,DE\n"


def geo(tmp_path, extra=""):
    p = tmp_path / "geo.csv"
    p.write_text(GEO + extra)
    return GeoResolver(str(p))


def test_origin_names_home_ranges_explicitly():
    """Python's is_private also covers documentation ranges; those are the internet here."""
    assert origin("192.168.1.20") == "home"
    assert origin("2001:db8::1") == "internet"
    assert origin("100.88.1.2") == "tailscale"
    assert origin("172.30.32.5") == "add-on"
    assert origin("198.51.100.7", wan="198.51.100.7") == "home via internet"
    assert origin(None) == "never used" and origin(None, used="2026-10-28T09:00:00+00:00") == "no address"


def test_wan_is_compared_as_an_address():
    assert origin("2001:db8::0:1", wan="2001:db8::1") == "home via internet"
    assert origin("2001:db8::1", wan="unavailable") == "internet"


def test_clients():
    assert client("normal", "https://home-assistant.io/iOS", None) == "iOS app"
    assert client("normal", "https://home.example.org/", None) == "browser: home.example.org"
    assert client("long_lived_access_token", None, "ha-mcp") == "token: ha-mcp"


def test_country_v4_v6_and_none(tmp_path):
    g = geo(tmp_path)
    assert g.country("203.0.113.9") == "NL" and g.country("2001:db8::5") == "DE"
    assert g.country("192.0.2.1") is None


def test_bad_lines_are_skipped_and_do_not_shadow_a_range(tmp_path):
    g = geo(tmp_path, "not,an,address\n2001:db8::,10.0.0.1,XX\n")
    assert g.country("2001:db8::5") == "DE"


def test_the_cache_is_json_not_code(tmp_path):
    g = geo(tmp_path)
    g.country("203.0.113.9")
    json.loads((tmp_path / "geo.csv.idx").read_text())


def test_no_file_no_country(tmp_path):
    assert GeoResolver(str(tmp_path / "missing.csv")).country("203.0.113.9") is None


def test_rows_most_recent_first_with_connected_now(tmp_path):
    now = datetime(2026, 10, 28, 9, 30, tzinfo=timezone.utc)
    rows = [{"ip": "203.0.113.9", "last_used": "2026-10-28T08:50:00+00:00"},
            {"ip": "192.168.1.1", "last_used": "2026-10-28T09:00:00+00:00"},
            {"ip": None, "last_used": None}]
    out = finish(rows, now, timedelta(minutes=35), None, geo(tmp_path))
    assert [r["ip"] for r in out] == ["192.168.1.1", "203.0.113.9", None]
    assert [r["active"] for r in out] == [True, False, False]       # 30 min in, 40 min out
    assert [r["country"] for r in out] == [None, "NL", None]
