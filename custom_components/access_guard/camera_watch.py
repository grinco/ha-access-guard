"""Camera live views, by login (DESIGN.md 0.2.0).

Watching a camera is not an action, so Home Assistant records nothing. The two websocket
commands that start a live view are wrapped in Home Assistant's command table. That table is
internal, like hass.auth: when it is not the shape expected, the signal is off and nothing else
changes. The wrapper only reports; the original handler always runs, unchanged.
"""

import functools
import logging

from homeassistant.core import callback

from .policy import handle

_LOGGER = logging.getLogger(__name__)
COMMANDS = ("camera/stream", "camera/webrtc/offer")
TABLE = "websocket_api"         # websocket_api.const.DOMAIN: {type: (handler, schema)}
MARK = "_access_guard_wraps"


class CameraWatch:
    def __init__(self, hass, on_view):
        """`on_view(user_id, handle, entity_id)` is called in the event loop for each live view."""
        self.hass = hass
        self._on_view = on_view
        self._mine = {}

    def _table(self):
        table = self.hass.data.get(TABLE)
        return table if isinstance(table, dict) else {}

    @callback
    def attach(self):
        """Wrap the commands that are registered and not wrapped yet; safe to call again."""
        table = self._table()
        for cmd in COMMANDS:
            entry = table.get(cmd)
            if not (isinstance(entry, tuple) and len(entry) == 2 and callable(entry[0])):
                continue
            if hasattr(entry[0], MARK):
                continue
            self._mine[cmd] = wrapped = self._wrap(entry[0])
            table[cmd] = (wrapped, entry[1])

    @callback
    def detach(self):
        """Put back the original handler, only where the entry is still this wrapper."""
        table = self._table()
        for cmd, wrapped in self._mine.items():
            entry = table.get(cmd)
            if isinstance(entry, tuple) and entry[0] is wrapped:
                table[cmd] = (getattr(wrapped, MARK), entry[1])
        self._mine = {}

    def watching(self):
        """The commands wrapped right now: read from the table, not remembered."""
        table = self._table()
        return sorted(c for c, w in self._mine.items() if isinstance(table.get(c), tuple) and table[c][0] is w)

    def _wrap(self, handler):
        @functools.wraps(handler)
        def wrapped(hass, connection, msg):
            try:
                user, token_id = connection.user, connection.refresh_token_id
                if user is not None and token_id:
                    self._on_view(user.id, handle(token_id), msg.get("entity_id"))
            except Exception as err:  # noqa: BLE001 - reporting must never break the camera
                _LOGGER.debug("could not report a camera view (%s)", type(err).__name__)
            return handler(hass, connection, msg)

        setattr(wrapped, MARK, handler)
        return wrapped
