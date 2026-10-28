"""Issue #2: a repairs issue for each administrator without MFA, cleared once it is not true."""

from types import SimpleNamespace as U

import pytest
from homeassistant.auth.mfa_modules import auth_mfa_module_from_config
from homeassistant.helpers import issue_registry as ir
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.access_guard.const import DOMAIN
from custom_components.access_guard.diagnostics import async_get_config_entry_diagnostics
from custom_components.access_guard.mfa import ISSUE_PREFIX, admins_without_mfa


def person(uid, admin=True, active=True, system=False):
    return U(id=uid, name=uid, is_admin=admin, is_active=active, system_generated=system)


def test_only_active_people_who_administer_and_lack_mfa():
    users = [person("pat"), person("sam"), person("robin", admin=False), person("old", active=False),
             person("supervisor", system=True)]
    assert [u.id for u in admins_without_mfa(users, {"sam": True})] == ["pat"]


@pytest.fixture
async def pin_module(hass):
    """Home Assistant's example MFA module, as `totp` would be."""
    module = await auth_mfa_module_from_config(hass, {"type": "insecure_example", "data": []})
    hass.auth._mfa_modules[module.id] = module
    yield module
    hass.auth._mfa_modules.pop(module.id)


async def setup(hass):
    entry = MockConfigEntry(domain=DOMAIN, title="Access Guard", data={}, options={})
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return entry


def issues(hass):
    return {i for (d, i) in ir.async_get(hass).issues if d == DOMAIN}


async def test_an_admin_without_mfa_gets_an_issue_until_they_enable_it(hass, pin_module, hass_admin_user, child):
    entry = await setup(hass)
    assert ISSUE_PREFIX + hass_admin_user.id in issues(hass)
    assert ISSUE_PREFIX + child[0].id not in issues(hass), "not an administrator"
    issue = ir.async_get(hass).async_get_issue(DOMAIN, ISSUE_PREFIX + hass_admin_user.id)
    assert issue.translation_placeholders == {"name": hass_admin_user.name} and not issue.is_fixable
    await pin_module.async_setup_user(hass_admin_user.id, {"pin": "123456"})
    await entry.runtime_data.async_refresh()
    assert ISSUE_PREFIX + hass_admin_user.id not in issues(hass)


async def test_an_admin_who_is_no_longer_one_loses_the_issue(hass, pin_module, hass_admin_user):
    entry = await setup(hass)
    assert ISSUE_PREFIX + hass_admin_user.id in issues(hass)
    await hass.auth.async_update_user(hass_admin_user, group_ids=["system-users"])
    await entry.runtime_data.async_refresh()
    assert ISSUE_PREFIX + hass_admin_user.id not in issues(hass)


async def test_without_an_mfa_module_nobody_gets_an_unfixable_issue(hass, hass_admin_user):
    entry = await setup(hass)
    assert issues(hass) == set()
    assert (await async_get_config_entry_diagnostics(hass, entry))["mfa_modules"] == 0


async def test_the_issues_go_with_access_guard(hass, pin_module, hass_admin_user):
    entry = await setup(hass)
    assert issues(hass)
    assert await hass.config_entries.async_unload(entry.entry_id)
    assert issues(hass) == set()


async def test_a_faulty_mfa_module_never_stops_the_sessions_sensor(hass, pin_module, hass_admin_user, child,
                                                                   monkeypatch, caplog):
    async def broken(user_id):
        raise RuntimeError("module fault")
    monkeypatch.setattr(pin_module, "async_is_user_setup", broken)
    entry = await setup(hass)
    assert entry.runtime_data.last_update_success
    assert "could not check administrators' MFA (RuntimeError)" in caplog.text


async def test_diagnostics_count_but_never_name(hass, pin_module, hass_admin_user):
    entry = await setup(hass)
    diag = await async_get_config_entry_diagnostics(hass, entry)
    assert (diag["mfa_modules"], diag["admins_without_mfa"]) == (1, 1)
    assert hass_admin_user.id not in repr(diag) and hass_admin_user.name not in repr(diag)
