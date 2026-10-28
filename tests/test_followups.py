"""0.3.0 against a real Home Assistant: new countries, failed-login bursts, the tapped sign-out."""

import logging
from datetime import timedelta

import pytest
from homeassistant.core import Context
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import (MockConfigEntry, async_capture_events,
                                                          async_fire_time_changed, flush_store)

from custom_components.access_guard.const import DOMAIN, SCAN_INTERVAL
from custom_components.access_guard.diagnostics import async_get_config_entry_diagnostics
from custom_components.access_guard.policy import handle
from custom_components.access_guard.response import ACTION_PREFIX, EVENT_ACTION

ANOMALY = f"{DOMAIN}_anomaly"
GEO = "198.51.100.0,198.51.100.255,CZ\n203.0.113.0,203.0.113.255,NL\n"     # ascending, as DB-IP ships it
BAN_LOG = logging.getLogger("homeassistant.components.http.ban")


async def tick(hass):
    async_fire_time_changed(hass, dt_util.utcnow() + SCAN_INTERVAL + timedelta(seconds=1))
    # The coordinator polls in a background task, which block_till_done does not wait for by default.
    await hass.async_block_till_done(wait_background_tasks=True)


def of(events, kind):
    return [e for e in events if e.data["kind"] == kind]


async def setup(hass, **options):
    entry = MockConfigEntry(domain=DOMAIN, title="Access Guard", data={}, options=options)
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return entry


async def outside_login(hass, user, ip="203.0.113.9"):
    token = await hass.auth.async_create_refresh_token(user, client_id="https://home-assistant.io/android")
    hass.auth.async_create_access_token(token, ip)
    return token


@pytest.fixture
def geo(tmp_path):
    p = tmp_path / "geo.csv"
    p.write_text(GEO)
    return str(p)


# --- a new country for a person (issue #4)


async def test_a_login_used_from_a_new_country_alerts_once_and_is_remembered(hass, child, geo):
    entry = await setup(hass, geo_path=geo)
    user, token = child                              # used from NL: Robin's baseline, silently
    events = async_capture_events(hass, ANOMALY)
    await tick(hass)
    assert of(events, "new_country") == []
    token.last_used_ip = "198.51.100.7"              # the same login, now used from CZ
    await tick(hass)
    await tick(hass)
    [e] = of(events, "new_country")
    assert (e.data["handle"], e.data["country"]) == (handle(token.id), "CZ")

    assert await hass.config_entries.async_reload(entry.entry_id)    # within the save delay
    await hass.async_block_till_done()
    assert entry.runtime_data.detector.countries == {user.id: ["NL", "CZ"]}
    await tick(hass)
    assert len(of(events, "new_country")) == 1, "a restart must not alert again"


async def test_what_was_learnt_is_saved_at_unload_not_30_seconds_later(hass, child, geo, hass_storage):
    entry = await setup(hass, geo_path=geo)
    assert f"{DOMAIN}.countries" not in hass_storage, "the save is delayed"
    assert await hass.config_entries.async_unload(entry.entry_id)
    assert hass_storage[f"{DOMAIN}.countries"]["data"] == {"countries": {child[0].id: ["NL"]}}


async def test_an_upgrade_learns_everyone_without_alerting(hass, child, geo):
    events = async_capture_events(hass, ANOMALY)
    await setup(hass, geo_path=geo)
    await tick(hass)
    assert of(events, "new_country") == []


async def test_a_garbled_store_is_ignored_not_fatal(hass, child, geo, hass_storage):
    robin = child[0].id
    hass_storage[f"{DOMAIN}.countries"] = {"version": 1, "data": {"countries": {"u": "NL", 3: ["CZ"],
                                                                              robin: [1, "NL"]}}}
    entry = await setup(hass, geo_path=geo)
    assert entry.runtime_data.last_update_success
    assert entry.runtime_data.detector.countries == {robin: ["NL"]}, "only well-formed entries of real people"


async def test_deleted_people_leave_the_store(hass, child, geo, hass_storage):
    entry = await setup(hass, geo_path=geo)
    await hass.auth.async_remove_user(child[0])
    other = await hass.auth.async_create_user("Sam Example")
    await outside_login(hass, other)
    await tick(hass)
    await flush_store(entry.runtime_data._store)
    assert set(hass_storage[f"{DOMAIN}.countries"]["data"]["countries"]) == {other.id}


# --- a burst of failed logins (issue #5), through the real log handler


async def test_a_burst_of_failed_logins_alerts_once_without_a_login(hass):
    entry = await setup(hass, burst_failures=3)
    events = async_capture_events(hass, ANOMALY)
    for _ in range(5):
        BAN_LOG.warning("Login attempt or request with invalid authentication from h (198.51.100.4). "
                        "Requested URL: '/auth/login_flow/x'. (agent)")
    await hass.async_block_till_done()
    [e] = of(events, "failed_login_burst")
    assert (e.data["ip"], e.data["failures"], e.data["handle"]) == ("198.51.100.4", 3, None)
    diag = await async_get_config_entry_diagnostics(hass, entry)
    assert diag["bursts_alerted"] == 1 and "198.51.100.4" not in repr(diag)


# --- Sign out this login, tapped on a phone (issue #6)


@pytest.fixture
def phone(hass):
    sent = []
    hass.services.async_register("notify", "mobile_app_pat", lambda call: sent.append(dict(call.data)))
    return sent


@pytest.fixture
async def admin_app(hass, hass_admin_user):
    """The administrator's own phone app is signed in."""
    return await hass.auth.async_create_refresh_token(hass_admin_user, client_id="https://home-assistant.io/iOS")


async def alert_with_button(hass, child, phone):
    """Robin, not an administrator, signs in from the internet: one exact login."""
    events = async_capture_events(hass, ANOMALY)
    token = await outside_login(hass, child[0])
    await tick(hass)
    [e] = of(events, "non_admin_internet")
    [push] = [p for p in phone if "from the internet" in p["message"]]
    return token, push


async def tap(hass, action, user=None):
    hass.bus.async_fire(EVENT_ACTION, {"action": action}, context=Context(user_id=user.id if user else None))
    await hass.async_block_till_done()


async def test_the_tap_signs_out_exactly_that_login(hass, child, phone, admin_app, hass_admin_user):
    await setup(hass, notify_service="notify.mobile_app_pat")
    token, push = await alert_with_button(hass, child, phone)
    [button] = push["data"]["actions"]
    assert button == {"action": ACTION_PREFIX + handle(token.id), "title": "Sign out this login"}
    removed = async_capture_events(hass, f"{DOMAIN}_login_removed")
    await tap(hass, button["action"], hass_admin_user)
    assert hass.auth.async_get_refresh_token(token.id) is None
    assert hass.auth.async_get_refresh_token(child[1].id) is not None, "only that login"
    assert [(e.data["handle"], e.data["removed_by"]) for e in removed] == [(handle(token.id), "access_guard")]
    assert phone[-1]["message"] == "Signed out Robin Example's Android app."


@pytest.mark.parametrize("who", ["child", "nobody", "admin_without_app"])
async def test_a_tap_is_refused_unless_an_admin_with_a_live_app(hass, child, phone, hass_admin_user, who):
    await setup(hass, notify_service="notify.mobile_app_pat")
    token, push = await alert_with_button(hass, child, phone)
    user = {"child": child[0], "nobody": None, "admin_without_app": hass_admin_user}[who]
    await tap(hass, push["data"]["actions"][0]["action"], user)
    assert hass.auth.async_get_refresh_token(token.id) is not None
    assert phone[-1]["message"].startswith("Could not sign out:")


async def test_a_signed_out_phone_cannot_tap_any_more(hass, child, phone, admin_app, hass_admin_user):
    """Review S1: the webhook outlives the login, so the login is what is checked."""
    await setup(hass, notify_service="notify.mobile_app_pat")
    token, push = await alert_with_button(hass, child, phone)
    hass.auth.async_remove_refresh_token(admin_app)
    await tap(hass, push["data"]["actions"][0]["action"], hass_admin_user)
    assert hass.auth.async_get_refresh_token(token.id) is not None
    assert "has no signed-in Home Assistant app" in phone[-1]["message"]


async def test_a_tap_answers_only_a_button_that_was_sent(hass, child, phone, admin_app, hass_admin_user):
    await setup(hass, notify_service="notify.mobile_app_pat")
    _, token = child                                  # a login no alert offered
    await tap(hass, ACTION_PREFIX + handle(token.id), hass_admin_user)
    assert hass.auth.async_get_refresh_token(token.id) is not None
    assert "not one Access Guard can still act on" in phone[-1]["message"]


async def test_other_actions_are_ignored(hass, child, phone, admin_app, hass_admin_user):
    await setup(hass, notify_service="notify.mobile_app_pat")
    for action in ("OPEN_GARAGE", ACTION_PREFIX + "XYZ", ACTION_PREFIX + handle(child[1].id) + "0", None):
        await tap(hass, action, hass_admin_user)
    assert phone == [] and hass.auth.async_get_refresh_token(child[1].id) is not None


async def test_failed_login_alerts_never_carry_a_button(hass, child, phone):
    await setup(hass, notify_service="notify.mobile_app_pat", burst_failures=2)
    for _ in range(2):
        BAN_LOG.warning("Login attempt or request with invalid authentication from h (203.0.113.9). "
                        "Requested URL: '/auth/login_flow/x'. (agent)")
    await hass.async_block_till_done()
    await outside_login(hass, child[0])               # a login after those failures
    await tick(hass)
    failed = [p for p in phone if "failed" in p["message"]]
    assert len(failed) == 2 and not [p for p in failed if "data" in p]


async def test_the_button_can_be_turned_off_and_other_notify_actions_get_no_data(hass, child):
    sent = []
    hass.services.async_register("notify", "telegram", lambda call: sent.append(dict(call.data)))
    hass.services.async_register("notify", "mobile_app_pat", lambda call: sent.append(dict(call.data)))
    entry = await setup(hass, notify_service="notify.telegram")
    await outside_login(hass, child[0])
    await tick(hass)
    hass.config_entries.async_update_entry(entry, options={"notify_service": "notify.mobile_app_pat",
                                                           "actionable": False})
    await hass.async_block_till_done()
    await outside_login(hass, child[0])
    await tick(hass)
    assert len(sent) == 2 and not [p for p in sent if "data" in p]


async def test_no_credential_reaches_a_push_or_a_reply(hass, child, phone, admin_app, hass_admin_user):
    await setup(hass, notify_service="notify.mobile_app_pat")
    token, push = await alert_with_button(hass, child, phone)
    await tap(hass, push["data"]["actions"][0]["action"], hass_admin_user)
    secrets = [s for u in await hass.auth.async_get_users() for t in u.refresh_tokens.values()
               for s in (t.token, t.jwt_key, t.id)] + [token.token, token.jwt_key, token.id]
    assert not [s for s in secrets if s in repr(phone)]
