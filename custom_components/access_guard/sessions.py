"""Logins as rows: who, which app, from where. No Home Assistant imports.

A row never holds a token, a JWT key or a token id: logins are named by their handle.
"""

import bisect
import gzip
import ipaddress
import json
import os
from datetime import datetime, timezone

from .policy import handle

TAILSCALE = [ipaddress.ip_network("100.64.0.0/10"), ipaddress.ip_network("fd7a:115c:a1e0::/48")]
ADDON = [ipaddress.ip_network("172.30.32.0/23"), ipaddress.ip_network("fd0c:ac1e:2100::/48")]
# Named, not `is_private`: that also covers documentation and reserved ranges.
LAN = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                                         "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128")]
APPS = {"https://home-assistant.io/iOS": "iOS app", "https://home-assistant.io/android": "Android app"}
ROW_FIELDS = ("handle", "user_id", "user", "client", "token_type", "created", "last_used", "ip", "origin", "country")


def event_data(row):
    """The fixed event contract (DESIGN.md): the row's fields, with the person as user_name."""
    data = {k: row[k] for k in ROW_FIELDS if k != "user"}
    data["user_name"] = row["user"]
    return data


def action_target(service_data):
    """What an action ran on, for a person's activity: entities, else an area or a device."""
    data = service_data or {}
    tgt = data.get("entity_id") or data.get("area_id") or data.get("device_id") or ""
    return (tgt if isinstance(tgt, str) else ", ".join(tgt))[:80]


def client(token_type, client_id, client_name):
    if token_type == "long_lived_access_token":
        return "token: %s" % (client_name or "unnamed")
    cid = client_id or ""
    if cid in APPS:
        return APPS[cid]
    host = cid.split("://", 1)[-1].split("/", 1)[0].rsplit(":", 1)[0] if cid else "?"
    return "browser: %s" % host


def same_ip(a, b):
    try:
        return ipaddress.ip_address(a) == ipaddress.ip_address(b)
    except ValueError:
        return False


def origin(ip, wan=None, used=None):
    if not ip:
        return "no address" if used else "never used"
    a = ipaddress.ip_address(ip)
    if any(a in n for n in TAILSCALE):
        return "tailscale"
    if any(a in n for n in ADDON):
        return "add-on"
    if wan and same_ip(ip, wan):
        return "home via internet"
    if any(a in n for n in LAN):
        return "home"
    return "internet"


def iso(t):
    if t is None:
        return None
    return (t if t.tzinfo else t.replace(tzinfo=timezone.utc)).isoformat()


class GeoResolver:
    """Country by IP from an operator-supplied DB-IP Lite CSV (first,last,country).

    Blocking: call from an executor. The index is cached beside the CSV as JSON, never
    pickle - it sits next to a process that can read the auth store.
    """

    def __init__(self, path):
        self.path = path
        self._idx = None
        self._mtime = None

    def available(self):
        return bool(self.path) and os.path.exists(self.path)

    def _load(self):
        mtime = os.path.getmtime(self.path)
        if self._idx is not None and self._mtime == mtime:
            return
        cache = self.path + ".idx"
        try:
            if os.path.getmtime(cache) > mtime:
                with open(cache) as fh:
                    self._idx, self._mtime = {int(k): v for k, v in json.load(fh).items()}, mtime
                    return
        except (OSError, ValueError):
            pass
        idx = {4: ([], [], []), 6: ([], [], [])}
        opener = gzip.open if self.path.endswith(".gz") else open
        with opener(self.path, "rt") as fh:
            for line in fh:
                parts = line.strip().split(",")
                if len(parts) < 3:
                    continue
                try:
                    lo, hi = ipaddress.ip_address(parts[0]), ipaddress.ip_address(parts[1])
                except ValueError:
                    continue
                if lo.version != hi.version:
                    continue
                starts, ends, cc = idx[lo.version]
                starts.append(int(lo))
                ends.append(int(hi))
                cc.append(parts[2])
        try:
            with open(cache, "w") as fh:
                json.dump(idx, fh)
        except OSError:
            pass
        self._idx, self._mtime = idx, mtime

    def country(self, ip):
        if not ip or not self.available():
            return None
        self._load()
        a = ipaddress.ip_address(ip)
        starts, ends, cc = self._idx[a.version]
        i = bisect.bisect_right(starts, int(a)) - 1
        return cc[i] if i >= 0 and int(a) <= ends[i] else None


def snapshot(users):
    """Plain data from Home Assistant's User/RefreshToken objects (run in the event loop)."""
    out = []
    for u in users:
        for t in u.refresh_tokens.values():
            # A system account can only hold system logins (Home Assistant refuses others),
            # so this also keeps the Supervisor's logins out.
            if t.token_type == "system":
                continue
            out.append({"handle": handle(t.id), "user_id": u.id, "user": u.name, "token_type": t.token_type,
                        "client": client(t.token_type, t.client_id, t.client_name),
                        "created": iso(t.created_at), "last_used": iso(t.last_used_at),
                        "ip": t.last_used_ip})
    return out


def finish(rows, now, active_window, wan=None, geo=None, bans=None):
    """Origin, country and 'connected now' for each row; most recent use first.

    `bans` rows get origin and country too, in the same executor job (the country file is blocking).
    """
    for r in rows + (bans or []):
        r["origin"] = origin(r["ip"], wan, r.get("last_used"))
        r["country"] = geo.country(r["ip"]) if geo and r["origin"] in ("internet", "home via internet") else None
    for r in rows:
        used = datetime.fromisoformat(r["last_used"]) if r["last_used"] else None
        r["active"] = bool(used) and now - used <= active_window
    never = "0000"
    rows.sort(key=lambda r: r["last_used"] or never, reverse=True)
    return rows
