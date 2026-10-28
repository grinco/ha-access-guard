"""A finding becomes an event and, by option, a persistent notification and a push. Notify only."""

import logging
import re

from homeassistant.components import persistent_notification

from .const import CONF_NOTIFY_SERVICE, CONF_PERSISTENT_NOTIFICATION, DOMAIN, EVENT_ANOMALY

_LOGGER = logging.getLogger(__name__)
TITLE = "Access Guard"
# A person names their own token and the notification renders Markdown: no link, no image.
_MARKDOWN = re.compile(r"([\\`*_{}\[\]()<>#+!|~])")


def markdown_escape(text):
    return _MARKDOWN.sub(r"\\\1", text)


async def async_alert(hass, options, finding):
    hass.bus.async_fire(EVENT_ANOMALY, finding)
    if options.get(CONF_PERSISTENT_NOTIFICATION, True):
        persistent_notification.async_create(hass, markdown_escape(finding["message"]), TITLE,
                                             f"{DOMAIN}_{finding['kind']}_{finding['handle']}")
    if target := options.get(CONF_NOTIFY_SERVICE):
        domain, _, service = target.partition(".")
        try:
            await hass.services.async_call(domain, service, {"title": TITLE, "message": finding["message"]},
                                           blocking=True)
        except Exception as err:  # noqa: BLE001 - a removed phone must not stop the next alert
            _LOGGER.warning("could not send an alert through %s (%s)", target, type(err).__name__)
