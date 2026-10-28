"""One Access Guard per instance; options for the country file and the home WAN address."""

import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, OptionsFlow
from homeassistant.core import callback
from homeassistant.helpers import selector

from .const import CONF_GEO_PATH, CONF_HOME_WAN_ENTITY, DEFAULT_GEO_FILE, DOMAIN


class AccessGuardConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        if self._async_current_entries():
            return self.async_abort(reason="single_instance_allowed")
        if user_input is not None:
            return self.async_create_entry(title="Access Guard", data={})
        return self.async_show_form(step_id="user")

    @staticmethod
    @callback
    def async_get_options_flow(entry):
        return AccessGuardOptionsFlow()


class AccessGuardOptionsFlow(OptionsFlow):
    async def async_step_init(self, user_input=None):
        if user_input is not None:
            return self.async_create_entry(data=user_input)
        opts = self.config_entry.options
        default_geo = self.hass.config.path(DOMAIN, DEFAULT_GEO_FILE)
        schema = vol.Schema({
            vol.Optional(CONF_GEO_PATH, default=opts.get(CONF_GEO_PATH, default_geo)): selector.TextSelector(),
            vol.Optional(CONF_HOME_WAN_ENTITY, description={"suggested_value": opts.get(CONF_HOME_WAN_ENTITY)}):
                selector.EntitySelector(selector.EntitySelectorConfig(domain="sensor")),
        })
        return self.async_show_form(step_id="init", data_schema=schema)
