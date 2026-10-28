"""One Access Guard per instance; options for the country file, the home WAN address and alerts."""

import re

import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, OptionsFlow
from homeassistant.core import callback
from homeassistant.helpers import selector

from .const import (CONF_FAILURES_BEFORE_LOGIN, CONF_GEO_PATH, CONF_HOME_WAN_ENTITY, CONF_NOTIFY_SERVICE,
                    CONF_PERSISTENT_NOTIFICATION, CONF_RULES, CONF_SENSITIVE_DOMAINS, DEFAULT_GEO_FILE, DOMAIN)
from .detector import DEFAULT_SENSITIVE, RULES

NOTIFY_SERVICE = re.compile(r"^notify\.[a-z0-9_]+$")
# Offered in the list; any other domain can be typed in.
SENSITIVE_CHOICES = sorted({*DEFAULT_SENSITIVE, "cover", "valve", "siren"})


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
        errors = {}
        if user_input is not None:
            if (svc := user_input.get(CONF_NOTIFY_SERVICE)) and not NOTIFY_SERVICE.match(svc):
                errors[CONF_NOTIFY_SERVICE] = "invalid_notify_service"
            else:
                user_input[CONF_FAILURES_BEFORE_LOGIN] = int(user_input.get(CONF_FAILURES_BEFORE_LOGIN, 1))
                return self.async_create_entry(data=user_input)
        opts = user_input or self.config_entry.options
        default_geo = self.hass.config.path(DOMAIN, DEFAULT_GEO_FILE)
        schema = vol.Schema({
            vol.Optional(CONF_GEO_PATH, default=opts.get(CONF_GEO_PATH, default_geo)): selector.TextSelector(),
            vol.Optional(CONF_HOME_WAN_ENTITY, description={"suggested_value": opts.get(CONF_HOME_WAN_ENTITY)}):
                selector.EntitySelector(selector.EntitySelectorConfig(domain="sensor")),
            vol.Optional(CONF_RULES, default=list(opts.get(CONF_RULES, RULES))): selector.SelectSelector(
                selector.SelectSelectorConfig(options=list(RULES), multiple=True, translation_key=CONF_RULES)),
            vol.Optional(CONF_FAILURES_BEFORE_LOGIN, default=opts.get(CONF_FAILURES_BEFORE_LOGIN, 1)):
                selector.NumberSelector(selector.NumberSelectorConfig(min=1, max=20, mode="box")),
            vol.Optional(CONF_SENSITIVE_DOMAINS, default=list(opts.get(CONF_SENSITIVE_DOMAINS, DEFAULT_SENSITIVE))):
                selector.SelectSelector(selector.SelectSelectorConfig(
                    options=SENSITIVE_CHOICES, multiple=True, custom_value=True)),
            vol.Optional(CONF_PERSISTENT_NOTIFICATION, default=opts.get(CONF_PERSISTENT_NOTIFICATION, True)):
                selector.BooleanSelector(),
            vol.Optional(CONF_NOTIFY_SERVICE, description={"suggested_value": opts.get(CONF_NOTIFY_SERVICE)}):
                selector.TextSelector(),
        })
        return self.async_show_form(step_id="init", data_schema=schema, errors=errors)
