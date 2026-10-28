"""Diagnostics end up attached to public bug reports: an allowlist of counts only.

Never an IP address, a name, a user id or a handle.
"""

import logging
from collections import Counter

from .const import (CONF_FAILURES_BEFORE_LOGIN, CONF_GEO_PATH, CONF_HOME_WAN_ENTITY, CONF_NOTIFY_SERVICE,
                    CONF_PERSISTENT_NOTIFICATION, CONF_RULES, CONF_SENSITIVE_DOMAINS)
from .failures import LOGGER_NAME

OPTIONS = (CONF_GEO_PATH, CONF_HOME_WAN_ENTITY, CONF_RULES, CONF_FAILURES_BEFORE_LOGIN, CONF_SENSITIVE_DOMAINS,
           CONF_PERSISTENT_NOTIFICATION, CONF_NOTIFY_SERVICE)


async def async_get_config_entry_diagnostics(hass, entry):
    coord = entry.runtime_data
    rows = coord.data["rows"]
    banned = coord.data["bans"]
    return {
        "logins": len(rows),
        "connected_now": coord.data["active"],
        "by_origin": dict(Counter(r["origin"] for r in rows)),
        "by_country": dict(Counter(r["country"] or "-" for r in rows)),
        "by_token_type": dict(Counter(r["token_type"] for r in rows)),
        "geo_file_present": coord.geo.available(),
        "options_set": sorted(k for k in OPTIONS if k in entry.options),
        "rules": sorted(coord.detector.rules),
        "bans": None if banned is None else len(banned),
        # Off when the log level hides Home Assistant's warning; then no failed login is seen.
        "failed_login_capture": logging.getLogger(LOGGER_NAME).isEnabledFor(logging.WARNING),
        "failed_logins_seen": coord.failed_logins.seen,
        "failed_logins_ambiguous": coord.failed_logins.ambiguous,
        "camera_watch": coord.cameras.watching(),
    }
