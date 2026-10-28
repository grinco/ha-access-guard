"""Diagnostics end up attached to public bug reports: an allowlist of counts only.

Never an IP address, a name, a user id or a handle.
"""

from collections import Counter

from .const import CONF_GEO_PATH, CONF_HOME_WAN_ENTITY


async def async_get_config_entry_diagnostics(hass, entry):
    coord = entry.runtime_data
    rows = coord.data["rows"]
    return {
        "logins": len(rows),
        "connected_now": coord.data["active"],
        "by_origin": dict(Counter(r["origin"] for r in rows)),
        "by_country": dict(Counter(r["country"] or "-" for r in rows)),
        "by_token_type": dict(Counter(r["token_type"] for r in rows)),
        "geo_file_present": coord.geo.available(),
        "options_set": sorted(k for k in (CONF_GEO_PATH, CONF_HOME_WAN_ENTITY) if entry.options.get(k)),
    }
