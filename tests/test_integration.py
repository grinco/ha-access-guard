"""Phase 1 against a real Home Assistant: sessions, events, sign-out, activity, diagnostics."""

from datetime import timedelta

import pytest
from homeassistant.core import Context
from homeassistant.exceptions import HomeAssistantError
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import async_capture_events, async_fire_time_changed

from custom_components.access_guard.const import DOMAIN, SCAN_INTERVAL
from custom_components.access_guard.diagnostics import async_get_config_entry_diagnostics
from custom_components.access_guard.policy import handle

SESSIONS = "sensor.access_guard_sessions"
ACTIVITY = "sensor.access_guard_activity"


def rows(hass):
    return hass.states.get(SESSIONS).attributes["sessions"]


async def tick(hass):
    async_fire_time_changed(hass, dt_util.utcnow() + SCAN_INTERVAL + timedelta(seconds=1))
    await hass.async_block_till_done()


async def test_sessions_are_listed_by_handle(hass, loaded, child):
    user, token = child
    row = next(r for r in rows(hass) if r["user"] == "Robin Example")
    assert row["handle"] == handle(token.id)
    assert row["client"] == "Android app" and row["origin"] == "internet" and row["ip"] == "203.0.113.9"


async def test_no_credential_reaches_state_events_or_diagnostics(hass, loaded, child, hass_admin_user):
    """Principle 1. Every login's token, JWT key and id is a secret; none may surface."""
    events = async_capture_events(hass, f"{DOMAIN}_new_login")
    user, _ = child
    await hass.auth.async_create_refresh_token(user, client_id="https://home.example.org/")
    await tick(hass)
    secrets = [s for u in await hass.auth.async_get_users() for t in u.refresh_tokens.values()
               for s in (t.token, t.jwt_key, t.id)]
    blob = repr(hass.states.get(SESSIONS).as_dict()) + repr(hass.states.get(ACTIVITY).as_dict())
    blob += repr([e.data for e in events]) + repr(await async_get_config_entry_diagnostics(hass, loaded))
    assert events, "the new login fired no event"
    assert not [s for s in secrets if s in blob]


async def test_diagnostics_hold_no_address_or_name(hass, loaded, child):
    """Diagnostics get attached to public bug reports: an allowlist, not a blocklist."""
    diag = repr(await async_get_config_entry_diagnostics(hass, loaded))
    assert "203.0.113.9" not in diag and "Robin" not in diag and handle(child[1].id) not in diag


async def test_new_login_fires_once_and_not_at_startup(hass, child):
    events = async_capture_events(hass, f"{DOMAIN}_new_login")
    from pytest_homeassistant_custom_component.common import MockConfigEntry
    entry = MockConfigEntry(domain=DOMAIN, data={}, options={})
    entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    await tick(hass)
    assert events == [], "existing logins were announced as new"
    user, _ = child
    new = await hass.auth.async_create_refresh_token(user, client_id="https://home.example.org/")
    await tick(hass)
    await tick(hass)
    assert [e.data["handle"] for e in events] == [handle(new.id)]
    d = events[0].data
    assert d["user_name"] == "Robin Example" and d["client"] == "browser: home.example.org"
    assert d["token_type"] == "normal"


async def test_admin_signs_out_one_login_and_the_account_stays(hass, loaded, child, hass_admin_user):
    """Operator 2026-10-28: remove specific sessions, never lock the account out."""
    user, token = child
    other = await hass.auth.async_create_refresh_token(user, client_id="https://home.example.org/")
    removed = async_capture_events(hass, f"{DOMAIN}_login_removed")
    await hass.services.async_call(DOMAIN, "sign_out", {"handle": handle(token.id)}, blocking=True,
                                   context=Context(user_id=hass_admin_user.id))
    await hass.async_block_till_done()
    assert hass.auth.async_get_refresh_token(token.id) is None
    assert hass.auth.async_get_refresh_token(other.id) is not None, "another session was ended too"
    assert (await hass.auth.async_get_user(user.id)).is_active
    again = await hass.auth.async_create_refresh_token(user, client_id="https://home-assistant.io/android")
    assert again is not None
    assert handle(token.id) not in [r["handle"] for r in rows(hass)], "the sensor still lists it"
    assert [(e.data["handle"], e.data["removed_by"]) for e in removed] == [(handle(token.id), "access_guard")]


async def test_sign_out_user_ends_every_session_of_one_person_only(hass, loaded, child, hass_admin_user):
    user, token = child
    other = await hass.auth.async_create_refresh_token(user, client_id="https://home.example.org/")
    admin_tok = await hass.auth.async_create_refresh_token(hass_admin_user, client_id="https://home-assistant.io/iOS")
    await hass.services.async_call(DOMAIN, "sign_out_user", {"user_id": user.id}, blocking=True,
                                   context=Context(user_id=hass_admin_user.id))
    assert hass.auth.async_get_refresh_token(token.id) is None
    assert hass.auth.async_get_refresh_token(other.id) is None
    assert hass.auth.async_get_refresh_token(admin_tok.id) is not None
    assert (await hass.auth.async_get_user(user.id)).is_active


@pytest.mark.parametrize("who", ["child", "nobody"])
async def test_sign_out_is_refused_without_an_admin_caller(hass, loaded, child, hass_admin_user, who):
    """The integration is the boundary: any account can call an action through the API."""
    user, token = child
    admin_tok = await hass.auth.async_create_refresh_token(hass_admin_user, client_id="https://home-assistant.io/iOS")
    ctx = Context(user_id=user.id) if who == "child" else Context()
    with pytest.raises(HomeAssistantError):
        await hass.services.async_call(DOMAIN, "sign_out", {"handle": handle(admin_tok.id)}, blocking=True, context=ctx)
    assert hass.auth.async_get_refresh_token(admin_tok.id) is not None


async def test_system_logins_are_never_signed_out(hass, loaded, hass_admin_user):
    sysuser = await hass.auth.async_create_system_user("Supervisor", group_ids=["system-admin"])
    tok = await hass.auth.async_create_refresh_token(sysuser)
    with pytest.raises(HomeAssistantError):
        await hass.services.async_call(DOMAIN, "sign_out", {"handle": handle(tok.id)}, blocking=True,
                                       context=Context(user_id=hass_admin_user.id))
    with pytest.raises(HomeAssistantError):
        await hass.services.async_call(DOMAIN, "sign_out_user", {"user_id": sysuser.id}, blocking=True,
                                       context=Context(user_id=hass_admin_user.id))
    assert hass.auth.async_get_refresh_token(tok.id) is not None


async def test_unknown_handle_is_an_error_not_a_silent_success(hass, loaded, hass_admin_user):
    with pytest.raises(HomeAssistantError):
        await hass.services.async_call(DOMAIN, "sign_out", {"handle": "000000000000"}, blocking=True,
                                       context=Context(user_id=hass_admin_user.id))


async def test_activity_names_the_person_and_skips_automations(hass, loaded, child, caplog):
    user, _ = child
    hass.services.async_register("light", "turn_on", lambda call: None)
    await hass.services.async_call("light", "turn_on", {"entity_id": "light.lamp"}, blocking=True,
                                   context=Context(user_id=user.id))
    await hass.services.async_call("light", "turn_on", {"entity_id": "light.other"}, blocking=True,
                                   context=Context())
    await hass.async_block_till_done()
    log = hass.states.get(ACTIVITY).attributes["log"]
    assert [(r["who"], r["action"], r["target"]) for r in log] == [("Robin Example", "light.turn_on", "light.lamp")]
    assert "Traceback" not in caplog.text and "Error" not in caplog.text, caplog.text


async def test_a_non_admin_learns_nothing_about_handles(hass, loaded, child):
    """The caller is checked before the handle: a real and a made-up handle refuse alike."""
    user, token = child
    msgs = []
    for h in (handle(token.id), "000000000000"):
        with pytest.raises(HomeAssistantError) as err:
            await hass.services.async_call(DOMAIN, "sign_out", {"handle": h}, blocking=True,
                                           context=Context(user_id=user.id))
        msgs.append(str(err.value))
    assert msgs[0] == msgs[1], msgs


async def test_a_sign_out_is_logged_with_who_and_which(hass, loaded, child, hass_admin_user, caplog):
    """Review 2026-10-28 F4: the only mutating action leaves a log line (no secret in it)."""
    import logging
    caplog.set_level(logging.INFO, logger="custom_components.access_guard")
    user, token = child
    await hass.services.async_call(DOMAIN, "sign_out", {"handle": handle(token.id)}, blocking=True,
                                   context=Context(user_id=hass_admin_user.id))
    line = [r.getMessage() for r in caplog.records if "signed out" in r.getMessage()]
    assert line and hass_admin_user.id in line[0] and handle(token.id) in line[0], line
    assert token.token not in caplog.text and token.jwt_key not in caplog.text


async def test_a_failure_reading_logins_never_logs_a_login(hass, loaded, child, caplog, monkeypatch):
    """Review F6: Home Assistant's RefreshToken repr holds its token and JWT key, so an
    exception that carries one must not reach the log."""
    user, token = child
    import custom_components.access_guard.coordinator as co

    def boom(users):
        raise AttributeError(repr(token))
    monkeypatch.setattr(co, "snapshot", boom)
    await tick(hass)
    assert token.token not in caplog.text and token.jwt_key not in caplog.text
    assert "could not read" in caplog.text


async def test_restored_activity_keeps_only_well_formed_rows(hass, child):
    """Review F7: whatever the recorder held is checked before it is shown again."""
    from homeassistant.core import State
    from pytest_homeassistant_custom_component.common import MockConfigEntry, mock_restore_cache
    good = {"t": "2026-10-28T10:00:00+00:00", "who": "Robin Example", "action": "light.turn_on", "target": "light.lamp"}
    mock_restore_cache(hass, [State(ACTIVITY, "2026-10-28T10:00:00+00:00",
                                    {"log": [good, {"who": 1}, "junk", dict(good, extra="x" * 500)]})])
    entry = MockConfigEntry(domain=DOMAIN, data={}, options={})
    entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    assert hass.states.get(ACTIVITY).attributes["log"] == [good]
