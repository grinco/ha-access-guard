"""Lifting an IP ban against Home Assistant's real ban manager (DESIGN.md 0.2.0, Bans)."""

from ipaddress import ip_address

import pytest
from homeassistant.components.http.ban import KEY_BAN_MANAGER, KEY_FAILED_LOGIN_ATTEMPTS
from homeassistant.config import load_yaml_config_file
from homeassistant.core import Context
from homeassistant.exceptions import HomeAssistantError
from pytest_homeassistant_custom_component.common import async_capture_events

from custom_components.access_guard import bans
from custom_components.access_guard.const import DOMAIN
from custom_components.access_guard.diagnostics import async_get_config_entry_diagnostics

BANS = "sensor.access_guard_bans"
ATTACKER, OTHER = ip_address("203.0.113.9"), ip_address("198.51.100.7")


@pytest.fixture
async def banned(hass, loaded, tmp_path, monkeypatch):
    """Two real bans, written by Home Assistant itself to a file of the test's own."""
    manager = hass.http.app[KEY_BAN_MANAGER]
    monkeypatch.setattr(manager, "path", str(tmp_path / "ip_bans.yaml"))
    for addr in (OTHER, ATTACKER):
        await manager.async_add_ban(addr)
    hass.http.app[KEY_FAILED_LOGIN_ATTEMPTS][ATTACKER] = 5
    await loaded.runtime_data.async_refresh()
    return manager


async def unban(hass, ip, user):
    await hass.services.async_call(DOMAIN, "unban", {"ip": ip}, blocking=True, context=Context(user_id=user.id))


async def test_the_bans_sensor_lists_them_newest_first(hass, banned):
    st = hass.states.get(BANS)
    assert st.state == "2"
    assert [b["ip"] for b in st.attributes["bans"]] == [str(ATTACKER), str(OTHER)]
    assert st.attributes["bans"][0]["origin"] == "internet"


async def test_an_admin_lifts_one_ban_and_the_others_stay(hass, banned, hass_admin_user):
    events = async_capture_events(hass, f"{DOMAIN}_unbanned")
    await unban(hass, "203.0.113.9", hass_admin_user)
    assert ATTACKER not in banned.ip_bans_lookup and OTHER in banned.ip_bans_lookup
    assert ATTACKER not in hass.http.app[KEY_FAILED_LOGIN_ATTEMPTS], "its next mistake would ban it again"
    assert set(load_yaml_config_file(banned.path)) == {str(OTHER)}, "the file still bans it at restart"
    assert [(e.data["ip"], e.data["by_user_id"]) for e in events] == [(str(ATTACKER), hass_admin_user.id)]
    assert hass.states.get(BANS).state == "1"


async def test_home_assistant_reloads_what_was_written(hass, banned, hass_admin_user):
    await unban(hass, "203.0.113.9", hass_admin_user)
    await unban(hass, "198.51.100.7", hass_admin_user)
    await banned.async_load()
    assert banned.ip_bans_lookup == {}


@pytest.mark.parametrize("who", ["child", "nobody"])
async def test_only_a_signed_in_admin_lifts_a_ban(hass, banned, child, who):
    ctx = Context(user_id=child[0].id) if who == "child" else Context()
    with pytest.raises(HomeAssistantError):
        await hass.services.async_call(DOMAIN, "unban", {"ip": "203.0.113.9"}, blocking=True, context=ctx)
    assert ATTACKER in banned.ip_bans_lookup


async def test_an_address_that_is_not_banned_is_refused(hass, banned, hass_admin_user):
    for ip in ("192.0.2.1", "not-an-ip"):
        with pytest.raises(HomeAssistantError):
            await unban(hass, ip, hass_admin_user)


async def test_with_bans_off_unban_is_refused_and_the_sensor_is_unknown(hass, loaded, hass_admin_user, monkeypatch):
    monkeypatch.setattr(bans, "_manager", lambda hass: None)
    await loaded.runtime_data.async_refresh()
    assert hass.states.get(BANS).state == "unknown"
    with pytest.raises(HomeAssistantError, match="not enabled"):
        await unban(hass, "203.0.113.9", hass_admin_user)


async def test_a_failed_write_keeps_the_ban(hass, banned, hass_admin_user, monkeypatch):
    def full_disk(path, snapshot):
        raise OSError("no space")
    monkeypatch.setattr(bans, "_write", full_disk)
    with pytest.raises(HomeAssistantError, match="the ban stays"):
        await unban(hass, "203.0.113.9", hass_admin_user)
    assert ATTACKER in banned.ip_bans_lookup and hass.http.app[KEY_FAILED_LOGIN_ATTEMPTS][ATTACKER] == 5
    assert str(ATTACKER) in load_yaml_config_file(banned.path)


async def test_a_ban_added_while_writing_is_written_too(hass, banned, hass_admin_user, monkeypatch):
    """Home Assistant puts a ban in memory before it appends; one racing the replace is kept."""
    real, late = bans._write, ip_address("192.0.2.77")
    calls = []

    def racing(path, snapshot):
        real(path, snapshot)
        if not calls:
            banned.ip_bans_lookup[late] = type(next(iter(banned.ip_bans_lookup.values())))(late)
        calls.append(len(snapshot))
    monkeypatch.setattr(bans, "_write", racing)
    await unban(hass, "203.0.113.9", hass_admin_user)
    assert calls == [1, 2]
    assert set(load_yaml_config_file(banned.path)) == {str(OTHER), str(late)}


async def test_endless_new_bans_end_after_a_bounded_number_of_rounds(hass, banned, hass_admin_user, monkeypatch,
                                                                     caplog):
    real, n = bans._write, iter(range(1, 255))
    ban_type = type(next(iter(banned.ip_bans_lookup.values())))

    def flood(path, snapshot):
        real(path, snapshot)
        addr = ip_address("192.0.2.%d" % next(n))
        banned.ip_bans_lookup[addr] = ban_type(addr)
    monkeypatch.setattr(bans, "_write", flood)
    await unban(hass, "203.0.113.9", hass_admin_user)
    assert str(ATTACKER) not in load_yaml_config_file(banned.path), "an unban was undone"
    assert "may be saved only until Home Assistant restarts" in caplog.text


async def test_a_later_failed_write_never_restores_the_lifted_ban(hass, banned, hass_admin_user, monkeypatch):
    """The first write already dropped it; putting it back in memory alone would diverge."""
    real, late = bans._write, ip_address("192.0.2.77")
    ban_type = type(next(iter(banned.ip_bans_lookup.values())))
    calls = []

    def then_fail(path, snapshot):
        calls.append(1)
        if len(calls) > 1:
            raise OSError("gone")
        real(path, snapshot)
        banned.ip_bans_lookup[late] = ban_type(late)
    monkeypatch.setattr(bans, "_write", then_fail)
    await unban(hass, "203.0.113.9", hass_admin_user)
    assert ATTACKER not in banned.ip_bans_lookup
    assert str(ATTACKER) not in load_yaml_config_file(banned.path)


async def test_diagnostics_count_bans_but_hold_no_address(hass, banned, loaded):
    diag = await async_get_config_entry_diagnostics(hass, loaded)
    assert diag["bans"] == 2
    assert "203.0.113.9" not in repr(diag) and "198.51.100.7" not in repr(diag)
