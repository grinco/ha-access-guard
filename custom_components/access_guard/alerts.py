"""A finding becomes an event and, by option, a persistent notification and a push.

Notify only. A push to a phone app may carry *Sign out this login* (DESIGN.md 0.3.0, #6); the
tap is handled in response.py, by the same policy as the `sign_out` action.
"""

import logging
import re

from homeassistant.components import persistent_notification

from .const import CONF_ACTIONABLE, CONF_NOTIFY_SERVICE, CONF_PERSISTENT_NOTIFICATION, DOMAIN, EVENT_ANOMALY
from .detector import offers_sign_out
from .response import action_for

_LOGGER = logging.getLogger(__name__)
TITLE = "Access Guard"
MOBILE_APP = "notify.mobile_app_"
# A person names their own token and the notification renders Markdown: no link, no image.
_MARKDOWN = re.compile(r"([\\`*_{}\[\]()<>#+!|~])")


def markdown_escape(text):
    return _MARKDOWN.sub(r"\\\1", text)


def offers_button(options, finding):
    """Only a phone app shows buttons; other notify platforms may refuse a push with `data`."""
    target = options.get(CONF_NOTIFY_SERVICE) or ""
    return target.startswith(MOBILE_APP) and options.get(CONF_ACTIONABLE, True) and offers_sign_out(finding)


async def _async_push(hass, options, message, data=None):
    if not (target := options.get(CONF_NOTIFY_SERVICE)):
        return
    domain, _, service = target.partition(".")
    payload = {"title": TITLE, "message": message}
    if data:
        payload["data"] = data
    try:
        await hass.services.async_call(domain, service, payload, blocking=True)
    except Exception as err:  # noqa: BLE001 - a removed phone must not stop the next alert
        _LOGGER.warning("could not send an alert through %s (%s)", target, type(err).__name__)


async def async_alert(hass, options, finding, button=False):
    hass.bus.async_fire(EVENT_ANOMALY, finding)
    if options.get(CONF_PERSISTENT_NOTIFICATION, True):
        about = finding["handle"] or finding["ip"] or "across"      # a burst has no login
        persistent_notification.async_create(hass, markdown_escape(finding["message"]), TITLE,
                                             f"{DOMAIN}_{finding['kind']}_{about}")
    actions = [{"action": action_for(finding["handle"]), "title": "Sign out this login"}] if button else None
    await _async_push(hass, options, finding["message"], actions and {"actions": actions})


async def async_tell(hass, options, message):
    await _async_push(hass, options, message)
