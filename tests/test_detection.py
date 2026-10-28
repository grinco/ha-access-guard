"""0.2.0 against a real Home Assistant: failed logins, first moves, tokens, alerts (notify only)."""

import logging
from datetime import timedelta

import pytest
from homeassistant.auth.models import TOKEN_TYPE_LONG_LIVED_ACCESS_TOKEN
from homeassistant.core import Context
from homeassistant.setup import async_setup_component
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import (CLIENT_ID, CLIENT_REDIRECT_URI, MockConfigEntry,
                                                          async_capture_events, async_fire_time_changed)

from custom_components.access_guard.camera_watch import COMMANDS, MARK
from custom_components.access_guard.const import DOMAIN, SCAN_INTERVAL
from custom_components.access_guard.diagnostics import async_get_config_entry_diagnostics
from custom_components.access_guard.policy import handle

ANOMALY = f"{DOMAIN}_anomaly"


async def tick(hass):
    async_fire_time_changed(hass, dt_util.utcnow() + SCAN_INTERVAL + timedelta(seconds=1))
    await hass.async_block_till_done()


async def setup(hass, **options):
    entry = MockConfigEntry(domain=DOMAIN, title="Access Guard", data={}, options=options)
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return entry


async def outside_login(hass, user, ip="203.0.113.9", **kw):
    """A new login of `user`, used from `ip`, as the app's token exchange leaves it."""
    token = await hass.auth.async_create_refresh_token(user, client_id="https://home-assistant.io/android", **kw)
    access = hass.auth.async_create_access_token(token, ip)
    return token, access


# --- login after failures, through Home Assistant's real login flow


async def login_flow(client, password):
    flow = await (await client.post("/auth/login_flow", json={
        "client_id": CLIENT_ID, "handler": ["homeassistant", None], "redirect_uri": CLIENT_REDIRECT_URI})).json()
    return await (await client.post(f"/auth/login_flow/{flow['flow_id']}", json={
        "client_id": CLIENT_ID, "username": "robin", "password": password})).json()


@pytest.fixture
async def robin_can_sign_in(hass, local_auth, hass_owner_user):
    assert await async_setup_component(hass, "auth", {})
    local_auth.data.add_auth("robin", "right-pass")
    await local_auth.data.async_save()


async def test_a_login_after_a_wrong_password_alerts(hass, robin_can_sign_in, hass_client_no_auth):
    await setup(hass)
    events = async_capture_events(hass, ANOMALY)
    client = await hass_client_no_auth()
    assert (await login_flow(client, "wrong"))["errors"] == {"base": "invalid_auth"}
    ok = await login_flow(client, "right-pass")
    tokens = await (await client.post("/auth/token", data={
        "grant_type": "authorization_code", "code": ok["result"], "client_id": CLIENT_ID})).json()
    assert "refresh_token" in tokens
    await tick(hass)
    [e] = events
    assert e.data["kind"] == "login_after_failures" and e.data["failures"] == 1
    assert e.data["ip"] == "127.0.0.1" and e.data["origin"] == "home"
    notes = hass.data["persistent_notification"]
    assert any("1 failed attempt" in n["message"] for n in notes.values())


async def test_an_expired_token_is_not_a_failed_login(hass, robin_can_sign_in, hass_client_no_auth, caplog):
    """A stale browser tab gets a 401 too; nobody is guessing a password."""
    assert await async_setup_component(hass, "api", {})
    entry = await setup(hass)
    client = await hass_client_no_auth()
    resp = await client.get("/api/states", headers={"Authorization": "Bearer not-a-token"})
    assert resp.status == 401
    await hass.async_block_till_done()
    assert "invalid authentication from" in caplog.text, "Home Assistant logged no failure at all"
    assert entry.runtime_data.failed_logins.seen == 0


# --- the first move of a new outside login


async def test_a_camera_watched_first_alerts_with_the_exact_login(hass, child, hass_ws_client):
    """camera loads after Access Guard here: the late wrap is what is tested."""
    await setup(hass)
    assert await async_setup_component(hass, "camera", {})
    await hass.async_block_till_done()
    user, _ = child
    events = async_capture_events(hass, ANOMALY)
    token, access = await outside_login(hass, user)
    await tick(hass)
    ws = await hass_ws_client(hass, access)
    await ws.send_json_auto_id({"type": "camera/stream", "entity_id": "camera.door"})
    await ws.receive_json()
    await hass.async_block_till_done()
    [e] = events
    assert (e.data["kind"], e.data["handle"], e.data["target"], e.data["attribution"]) == (
        "sensitive_first", handle(token.id), "camera.door", "login")


async def test_an_unlock_first_alerts_by_person(hass, child):
    await setup(hass)
    user, _ = child
    hass.services.async_register("lock", "unlock", lambda call: None)
    events = async_capture_events(hass, ANOMALY)
    token, _ = await outside_login(hass, user)
    await tick(hass)
    await hass.services.async_call("lock", "unlock", {"entity_id": "lock.front"}, blocking=True,
                                   context=Context(user_id=user.id))
    await hass.async_block_till_done()
    [e] = events
    assert (e.data["action"], e.data["handle"], e.data["attribution"]) == ("lock.unlock", handle(token.id), "person")


async def test_a_harmless_first_move_alerts_nothing(hass, child):
    await setup(hass)
    user, _ = child
    for svc in (("light", "turn_on"), ("lock", "unlock")):
        hass.services.async_register(*svc, lambda call: None)
    events = async_capture_events(hass, ANOMALY)
    await outside_login(hass, user)
    await tick(hass)
    for domain, service in (("light", "turn_on"), ("lock", "unlock")):
        await hass.services.async_call(domain, service, {"entity_id": f"{domain}.x"}, blocking=True,
                                       context=Context(user_id=user.id))
    await hass.async_block_till_done()
    assert events == []


async def test_a_fault_in_reporting_never_breaks_the_camera(hass, child, hass_ws_client, monkeypatch):
    assert await async_setup_component(hass, "camera", {})
    entry = await setup(hass)
    user, _ = child
    _, access = await outside_login(hass, user)
    ws = await hass_ws_client(hass, access)
    await ws.send_json_auto_id({"type": "camera/stream", "entity_id": "camera.door"})
    normal = await ws.receive_json()

    def boom(*a):
        raise RuntimeError("detector fault")
    monkeypatch.setattr(entry.runtime_data.detector, "signal", boom)
    await ws.send_json_auto_id({"type": "camera/stream", "entity_id": "camera.door"})
    faulty = await ws.receive_json()
    assert faulty["error"] == normal["error"], "the camera command answered differently"


async def test_a_connection_without_a_login_is_skipped_quietly(hass, caplog):
    """R5: nothing to report is not a fault; the command runs as always."""
    from types import SimpleNamespace as NS

    from custom_components.access_guard.camera_watch import CameraWatch
    caplog.set_level(logging.DEBUG, logger="custom_components.access_guard")
    seen, ran = [], []
    hass.data["websocket_api"] = {"camera/stream": (lambda h, c, m: ran.append(m), None)}
    watch = CameraWatch(hass, lambda *a: seen.append(a))
    watch.attach()
    handler = hass.data["websocket_api"]["camera/stream"][0]
    for conn in (NS(user=None, refresh_token_id="t"), NS(user=NS(id="u"), refresh_token_id=None)):
        handler(hass, conn, {"entity_id": "camera.door"})
    assert seen == [] and len(ran) == 2 and "could not report" not in caplog.text


async def test_the_camera_commands_are_restored_at_unload(hass):
    assert await async_setup_component(hass, "camera", {})
    table = hass.data["websocket_api"]
    originals = {c: table[c][0] for c in COMMANDS}
    entry = await setup(hass)
    assert all(hasattr(table[c][0], MARK) for c in COMMANDS)
    assert (await async_get_config_entry_diagnostics(hass, entry))["camera_watch"] == sorted(COMMANDS)
    entry.runtime_data.cameras.attach()                   # again: never wrapped twice
    assert all(getattr(table[c][0], MARK) is originals[c] for c in COMMANDS)
    assert await hass.config_entries.async_unload(entry.entry_id)
    assert {c: table[c][0] for c in COMMANDS} == originals


# --- long-lived tokens and the alert itself


async def test_a_long_lived_token_alerts_and_its_name_cannot_inject_a_link(hass, child):
    """A person names their own token, and persistent notifications render Markdown."""
    await setup(hass)
    user, _ = child
    events = async_capture_events(hass, ANOMALY)
    await hass.auth.async_create_refresh_token(user, client_name="[sign in again](https://evil.example)",
                                               token_type=TOKEN_TYPE_LONG_LIVED_ACCESS_TOKEN,
                                               access_token_expiration=timedelta(days=3650))
    await tick(hass)
    [e] = events
    assert e.data["kind"] == "long_lived_token"
    [note] = [n for n in hass.data["persistent_notification"].values() if "long-lived" in n["message"]]
    assert "](" not in note["message"] and r"\[sign in again\]\(https://evil.example\)" in note["message"]


async def test_alerts_go_to_the_notify_action_and_a_broken_one_is_tolerated(hass, child, caplog):
    sent = []
    hass.services.async_register("notify", "phone", lambda call: sent.append(call.data))
    entry = await setup(hass, notify_service="notify.phone", persistent_notification=False)
    user, _ = child
    events = async_capture_events(hass, ANOMALY)
    await outside_login(hass, user, token_type=TOKEN_TYPE_LONG_LIVED_ACCESS_TOKEN, client_name="a",
                        access_token_expiration=timedelta(days=1))
    await tick(hass)
    assert [s["title"] for s in sent] == ["Access Guard"] and "long-lived" in sent[0]["message"]
    assert not hass.data.get("persistent_notification")

    hass.config_entries.async_update_entry(entry, options={"notify_service": "notify.gone"})
    await hass.async_block_till_done()
    await outside_login(hass, user, token_type=TOKEN_TYPE_LONG_LIVED_ACCESS_TOKEN, client_name="b",
                        access_token_expiration=timedelta(days=1))
    await tick(hass)
    await tick(hass)
    assert len(events) == 2, "a broken notify action stopped the event"
    assert "could not send an alert through notify.gone" in caplog.text


async def test_rules_switched_off_stay_silent(hass, child):
    await setup(hass, rules=[])
    user, _ = child
    events = async_capture_events(hass, ANOMALY)
    await outside_login(hass, user, token_type=TOKEN_TYPE_LONG_LIVED_ACCESS_TOKEN, client_name="a",
                        access_token_expiration=timedelta(days=1))
    await tick(hass)
    assert events == []


async def test_no_credential_reaches_an_anomaly(hass, child, hass_ws_client):
    """Principle 1, for the new event."""
    assert await async_setup_component(hass, "camera", {})
    await setup(hass)
    user, _ = child
    events = async_capture_events(hass, ANOMALY)
    token, access = await outside_login(hass, user)
    await tick(hass)
    ws = await hass_ws_client(hass, access)
    await ws.send_json_auto_id({"type": "camera/webrtc/offer", "entity_id": "camera.door", "offer": "v=0"})
    await ws.receive_json()
    await hass.async_block_till_done()
    secrets = [s for u in await hass.auth.async_get_users() for t in u.refresh_tokens.values()
               for s in (t.token, t.jwt_key, t.id)] + [access]
    blob = repr([e.data for e in events]) + repr(hass.data.get("persistent_notification"))
    assert events and not [s for s in secrets if s in blob]


async def test_failed_logins_are_counted_in_diagnostics_without_an_address(hass, child):
    entry = await setup(hass)
    logging.getLogger("homeassistant.components.http.ban").warning(
        "Login attempt or request with invalid authentication from h (198.51.100.4). "
        "Requested URL: '/auth/login_flow/x'. (agent)")
    await hass.async_block_till_done()
    diag = await async_get_config_entry_diagnostics(hass, entry)
    assert diag["failed_logins_seen"] == 1 and diag["failed_login_capture"] is True
    assert "198.51.100.4" not in repr(diag)


async def test_the_log_handler_is_removed_at_unload(hass):
    handler = (await setup(hass)).runtime_data.failed_logins
    log = logging.getLogger("homeassistant.components.http.ban")
    assert handler in log.handlers
    assert await hass.config_entries.async_unload(hass.config_entries.async_entries(DOMAIN)[0].entry_id)
    assert handler not in log.handlers


async def test_the_options_form_refuses_a_notify_action_that_is_not_one(hass):
    entry = await setup(hass)
    flow = await hass.config_entries.options.async_init(entry.entry_id)
    form = {"rules": ["long_lived_token"], "failures_before_login": 3.0, "sensitive_domains": ["lock"],
            "persistent_notification": False}
    res = await hass.config_entries.options.async_configure(flow["flow_id"], dict(form, notify_service="light.lamp"))
    assert res["errors"] == {"notify_service": "invalid_notify_service"}
    res = await hass.config_entries.options.async_configure(flow["flow_id"], dict(form, notify_service="notify.phone"))
    assert res["type"] == "create_entry"
    await hass.async_block_till_done()
    assert entry.options["failures_before_login"] == 3 and entry.options["notify_service"] == "notify.phone"
    det = entry.runtime_data.detector
    assert (det.rules, det.failures_before_login, det.sensitive) == ({"long_lived_token"}, 3, {"lock"})
