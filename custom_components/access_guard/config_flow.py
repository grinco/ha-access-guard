"""One Access Guard per instance; options for the country file, the home WAN address and alerts."""

import re

import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, OptionsFlow
from homeassistant.core import callback
from homeassistant.helpers import selector

from .const import (CONF_ACTIONABLE, CONF_ALLOWED_COUNTRIES, CONF_BURST_FAILURES, CONF_FAILURES_BEFORE_LOGIN,
                    CONF_GEO_PATH, CONF_HOME_WAN_ENTITY, CONF_NOTIFY_SERVICE, CONF_PERSISTENT_NOTIFICATION, CONF_RULES,
                    CONF_RULES_OFF, CONF_SENSITIVE_DOMAINS, DEFAULT_GEO_FILE, DOMAIN)
from .detector import DEFAULT_SENSITIVE, RULES, enabled_rules

NOTIFY_SERVICE = re.compile(r"^notify\.[a-z0-9_]+$")
COUNTRY = re.compile(r"^[A-Za-z]{2}$")
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
            if not all(COUNTRY.match(c) for c in user_input.get(CONF_ALLOWED_COUNTRIES, ())):
                errors[CONF_ALLOWED_COUNTRIES] = "invalid_country"
            if not errors:
                data = dict(user_input)
                # The form shows the rules on; the rules off are stored, so a rule added later is on.
                data[CONF_RULES_OFF] = sorted(set(RULES) - set(data.pop(CONF_RULES, RULES)))
                data[CONF_ALLOWED_COUNTRIES] = sorted(c.upper() for c in data.get(CONF_ALLOWED_COUNTRIES, ()))
                for key, default in ((CONF_FAILURES_BEFORE_LOGIN, 1), (CONF_BURST_FAILURES, 10)):
                    data[key] = int(data.get(key, default))
                return self.async_create_entry(data=data)
        opts = dict(self.config_entry.options, **(user_input or {}))
        rules_on = (opts[CONF_RULES] if user_input and CONF_RULES in user_input
                    else sorted(enabled_rules(opts.get(CONF_RULES_OFF), opts.get(CONF_RULES))))
        default_geo = self.hass.config.path(DOMAIN, DEFAULT_GEO_FILE)
        schema = vol.Schema({
            vol.Optional(CONF_GEO_PATH, default=opts.get(CONF_GEO_PATH, default_geo)): selector.TextSelector(),
            vol.Optional(CONF_HOME_WAN_ENTITY, description={"suggested_value": opts.get(CONF_HOME_WAN_ENTITY)}):
                selector.EntitySelector(selector.EntitySelectorConfig(domain="sensor")),
            vol.Optional(CONF_RULES, default=rules_on): selector.SelectSelector(
                selector.SelectSelectorConfig(options=list(RULES), multiple=True, translation_key=CONF_RULES)),
            vol.Optional(CONF_FAILURES_BEFORE_LOGIN, default=opts.get(CONF_FAILURES_BEFORE_LOGIN, 1)):
                selector.NumberSelector(selector.NumberSelectorConfig(min=1, max=20, mode="box")),
            vol.Optional(CONF_SENSITIVE_DOMAINS, default=list(opts.get(CONF_SENSITIVE_DOMAINS, DEFAULT_SENSITIVE))):
                selector.SelectSelector(selector.SelectSelectorConfig(
                    options=SENSITIVE_CHOICES, multiple=True, custom_value=True)),
            vol.Optional(CONF_BURST_FAILURES, default=opts.get(CONF_BURST_FAILURES, 10)):
                selector.NumberSelector(selector.NumberSelectorConfig(min=2, max=1000, mode="box")),
            vol.Optional(CONF_ALLOWED_COUNTRIES, default=list(opts.get(CONF_ALLOWED_COUNTRIES, ()))):
                selector.SelectSelector(selector.SelectSelectorConfig(options=[], multiple=True, custom_value=True)),
            vol.Optional(CONF_PERSISTENT_NOTIFICATION, default=opts.get(CONF_PERSISTENT_NOTIFICATION, True)):
                selector.BooleanSelector(),
            vol.Optional(CONF_NOTIFY_SERVICE, description={"suggested_value": opts.get(CONF_NOTIFY_SERVICE)}):
                selector.TextSelector(),
            vol.Optional(CONF_ACTIONABLE, default=opts.get(CONF_ACTIONABLE, True)): selector.BooleanSelector(),
        })
        return self.async_show_form(step_id="init", data_schema=schema, errors=errors)
