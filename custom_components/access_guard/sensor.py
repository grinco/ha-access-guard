"""Two sensors: the logins (state = connected now) and the last actions people took."""

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.const import EVENT_CALL_SERVICE
from homeassistant.core import Event, callback
from homeassistant.helpers.restore_state import RestoreEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import dt as dt_util

from .const import ACTIVITY_LEN, MAX_ROWS

ROW_KEYS = {"t", "who", "action", "target"}


def _well_formed(row):
    """A restored activity row is shown again only if it is exactly what this sensor writes."""
    return (isinstance(row, dict) and set(row) == ROW_KEYS
            and all(isinstance(v, str) and len(v) <= 200 for v in row.values()))


async def async_setup_entry(hass, entry, async_add_entities):
    coord = entry.runtime_data
    async_add_entities([SessionsSensor(coord, entry), ActivitySensor(coord, entry)])


class SessionsSensor(CoordinatorEntity, SensorEntity):
    _attr_name = "Access Guard sessions"
    _attr_icon = "mdi:account-key"
    _attr_native_unit_of_measurement = "sessions"

    def __init__(self, coord, entry):
        super().__init__(coord)
        self._attr_unique_id = f"{entry.entry_id}_sessions"

    @property
    def native_value(self):
        return self.coordinator.data["active"]

    @property
    def extra_state_attributes(self):
        rows = self.coordinator.data["rows"]
        return {"count": len(rows), "sessions": rows[:MAX_ROWS]}


class ActivitySensor(RestoreEntity, SensorEntity):
    """Best-effort: actions that carry a user. A physical switch or an automation has none."""

    _attr_name = "Access Guard activity"
    _attr_icon = "mdi:history"
    _attr_device_class = SensorDeviceClass.TIMESTAMP
    _attr_should_poll = False

    def __init__(self, coord, entry):
        self._coord = coord
        self._attr_unique_id = f"{entry.entry_id}_activity"
        self._log = []
        self._last = None

    async def async_added_to_hass(self):
        await super().async_added_to_hass()
        if (old := await self.async_get_last_state()) is not None:
            self._log = [r for r in (old.attributes.get("log") or []) if _well_formed(r)][:ACTIVITY_LEN]
            self._last = dt_util.parse_datetime(old.state) if old.state not in ("unknown", "unavailable") else None
        self.async_on_remove(self.hass.bus.async_listen(EVENT_CALL_SERVICE, self._on_call))

    @callback
    def _on_call(self, event: Event):
        uid = event.context.user_id
        if not uid:
            return
        data = event.data.get("service_data") or {}
        tgt = data.get("entity_id") or data.get("area_id") or data.get("device_id") or ""
        if not isinstance(tgt, str):
            tgt = ", ".join(tgt)
        names = (self._coord.data or {}).get("names", {})
        self._last = dt_util.utcnow()
        self._log = [{"t": self._last.isoformat(), "who": names.get(uid) or uid[:8],
                      "action": "%s.%s" % (event.data.get("domain"), event.data.get("service")),
                      "target": tgt[:80]}] + self._log[:ACTIVITY_LEN - 1]
        self.async_write_ha_state()

    @property
    def native_value(self):
        return self._last

    @property
    def extra_state_attributes(self):
        return {"log": self._log}
