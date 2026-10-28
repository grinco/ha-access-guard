"""Shared fixtures: the integration loaded against a real Home Assistant auth manager."""

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.access_guard.const import DOMAIN


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    yield


@pytest.fixture
async def child(hass, hass_owner_user):
    """A non-admin person with a phone login used from the internet.

    Depends on the owner so it is not the first person created: Home Assistant makes that
    one the owner, an administrator.
    """
    user = await hass.auth.async_create_user("Robin Example", group_ids=["system-users"])
    token = await hass.auth.async_create_refresh_token(user, client_id="https://home-assistant.io/android")
    token.last_used_ip = "203.0.113.9"
    return user, token


@pytest.fixture
async def loaded(hass, child):
    entry = MockConfigEntry(domain=DOMAIN, title="Access Guard", data={}, options={})
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return entry
