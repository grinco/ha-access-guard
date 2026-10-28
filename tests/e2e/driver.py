"""End to end: drive a real Home Assistant as a household and its phone would (tests/e2e/run.sh).

Runs inside the Home Assistant container, which has aiohttp:

    python3 driver.py install   # onboard, add Access Guard (whichever version is installed)
    python3 driver.py check     # after the upgrade: everything the current version promises

Exits non-zero if any check fails. Prints no token, only what was checked.
"""

import asyncio
import json
import sys

import aiohttp
from aiohttp import web

BASE = "http://127.0.0.1:8123"
CID = BASE + "/"
ANDROID = "https://home-assistant.io/android"
USER, PASSWORD = "pat", "pat-pass-1"
SEEDED_BAN = "203.0.113.9"           # run.sh writes it to ip_bans.yaml before the upgrade
PUSH_PORT = 8099
RULES = ["login_after_failures", "sensitive_first", "long_lived_token", "non_admin_internet", "new_country",
         "failed_login_burst"]
failed = []


def check(ok, what):
    print(("  ok    " if ok else "  FAIL  ") + what, flush=True)
    if not ok:
        failed.append(what)


class HA:
    def __init__(self, session):
        self.s = session
        self.token = None

    async def call(self, method, path, body=None, form=False, token=True):
        kw = {"data": body} if form else ({"json": body} if body is not None else {})
        headers = {"Authorization": "Bearer " + self.token} if token and self.token else {}
        async with self.s.request(method, BASE + path, headers=headers, **kw) as r:
            text = await r.text()
            try:
                return r.status, json.loads(text) if text else None
            except ValueError:
                return r.status, text

    async def login(self, password, client_id=CID, redirect_uri=CID):
        _, flow = await self.call("POST", "/auth/login_flow", {"client_id": client_id, "redirect_uri": redirect_uri,
                                                              "handler": ["homeassistant", None]}, token=False)
        _, res = await self.call("POST", "/auth/login_flow/" + flow["flow_id"],
                                 {"client_id": client_id, "username": USER, "password": password}, token=False)
        return res

    async def token_for(self, code, client_id=CID):
        _, res = await self.call("POST", "/auth/token", {"grant_type": "authorization_code", "code": code,
                                                         "client_id": client_id}, form=True, token=False)
        return res["access_token"]

    async def state(self, eid):
        code, st = await self.call("GET", "/api/states/" + eid)
        return st if code == 200 else None

    async def attribute(self, eid, name):
        """An attribute, or [] when the entity is missing or unavailable: the checks go on and say so."""
        return ((await self.state(eid)) or {}).get("attributes", {}).get(name, [])

    async def sessions(self):
        return await self.attribute("sensor.access_guard_sessions", "sessions")

    async def ws(self, *messages):
        out = []
        async with self.s.ws_connect(BASE + "/api/websocket") as ws:
            await ws.receive_json()
            await ws.send_json({"type": "auth", "access_token": self.token})
            assert (await ws.receive_json())["type"] == "auth_ok"
            for i, m in enumerate(messages, 1):
                await ws.send_json(dict(m, id=i))
                out.append(await ws.receive_json())
        return out

    async def entry_id(self):
        _, entries = await self.call("GET", "/api/config/config_entries/entry?domain=access_guard")
        return entries[0]["entry_id"] if entries else None

    async def save_options(self, values):
        _, flow = await self.call("POST", "/api/config/config_entries/options/flow", {"handler": await self.entry_id()})
        _, res = await self.call("POST", "/api/config/config_entries/options/flow/" + flow["flow_id"], values)
        await asyncio.sleep(3)                          # the entry reloads
        return res.get("type") == "create_entry"


async def until(probe, seconds=60):
    for _ in range(seconds):
        if result := await probe():
            return result
        await asyncio.sleep(1)
    return None


async def up(ha):
    async def answers():
        try:
            return (await ha.call("GET", "/manifest.json", token=False))[0] == 200
        except aiohttp.ClientError:
            return False
    if not await until(answers, 300):
        sys.exit("Home Assistant did not come up")


async def install(ha):
    code, res = await ha.call("POST", "/api/onboarding/users", {"client_id": CID, "name": "Pat", "username": USER,
                                                                "password": PASSWORD, "language": "en"})
    check(code == 200, "onboarded")
    ha.token = await ha.token_for(res["auth_code"])
    _, flow = await ha.call("POST", "/api/config/config_entries/flow", {"handler": "access_guard"})
    _, res = await ha.call("POST", "/api/config/config_entries/flow/" + flow["flow_id"], {})
    check(res.get("type") == "create_entry", "Access Guard added through the config flow")
    check(await ha.save_options({}), "its options form saved with its defaults")
    st = await until(lambda: ha.state("sensor.access_guard_sessions"))
    check(st is not None and st["state"] != "unavailable", "sessions sensor: %s" % (st and st["state"]))


class PushServer:
    """Stands in for the phone's push provider: keeps what Home Assistant sends."""

    def __init__(self):
        self.pushes = []

    async def start(self):
        app = web.Application()
        app.router.add_post("/push", self._push)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        await web.TCPSite(self.runner, "127.0.0.1", PUSH_PORT).start()

    async def _push(self, request):
        self.pushes.append(await request.json())
        return web.json_response({}, status=201)


async def check_upgraded(ha):
    ha.token = await ha.token_for((await ha.login(PASSWORD))["result"])
    st = await until(lambda: ha.state("sensor.access_guard_bans"), 120)
    check(st is not None, "Access Guard is up after the upgrade")
    for eid in ("sensor.access_guard_sessions", "sensor.access_guard_bans"):
        st = await ha.state(eid)
        check(st is not None and st["state"] not in ("unavailable", "unknown"), "%s = %s" % (eid, st and st["state"]))
    _, entries = await ha.call("GET", "/api/config/config_entries/entry?domain=access_guard")
    check([e["state"] for e in entries] == ["loaded"], "the entry from before the upgrade is loaded")
    check(any(s["user"] == "Pat" for s in await ha.sessions()), "the login from before the upgrade is listed")
    bans = await ha.attribute("sensor.access_guard_bans", "bans")
    check([b["ip"] for b in bans] == [SEEDED_BAN], "the ban seeded before the upgrade is listed")

    entry_id = await ha.entry_id()
    _, diag = await ha.call("GET", "/api/diagnostics/config_entry/" + entry_id)
    data = diag["data"]
    check(data["camera_watch"] == ["camera/stream", "camera/webrtc/offer"], "camera live views are watched")
    check(data["failed_login_capture"] is True, "failed logins are captured")
    check(SEEDED_BAN not in json.dumps(diag) and "Pat" not in json.dumps(diag), "diagnostics hold no address or name")
    check(data["mfa_modules"] >= 1 and data["admins_without_mfa"] == 1, "Pat, an administrator, has no MFA")
    [res] = await ha.ws({"type": "repairs/list_issues"})
    mine = [i for i in res["result"]["issues"] if i["domain"] == "access_guard"]
    check([(i["translation_key"], i["translation_placeholders"]) for i in mine] == [("admin_without_mfa",
                                                                                      {"name": "Pat"})],
          "a repairs issue names Pat")

    check(await ha.save_options({"rules": RULES}), "the options form saves, every alert on")

    # A wrong password, then the right one, from this address.
    check((await ha.login("wrong"))["errors"] == {"base": "invalid_auth"}, "a wrong password is refused")
    await ha.token_for((await ha.login(PASSWORD))["result"])

    async def failed_login_alert():
        [res] = await ha.ws({"type": "persistent_notification/get"})
        return [n for n in res["result"] if n["notification_id"].startswith("access_guard_login_after_failures")]
    check(bool(await until(failed_login_alert)), "a login after a failed attempt alerts")

    [res] = await ha.ws({"type": "camera/stream", "entity_id": "camera.none"})
    check(res["type"] == "result" and not res["success"], "camera/stream still answers as before")

    code, _ = await ha.call("POST", "/api/services/access_guard/unban", {"ip": SEEDED_BAN})
    check(code == 200, "the owner lifts the ban")
    check(await until(lambda: _is(ha.state("sensor.access_guard_bans"), "0"), 10), "the ban is gone")
    code, _ = await ha.call("POST", "/api/services/access_guard/unban", {"ip": SEEDED_BAN})
    check(code == 400, "lifting a ban that is not there is refused")

    await check_tap(ha)


async def _is(state_coro, value):
    st = await state_coro
    return st is not None and st["state"] == value


async def check_tap(ha):
    """Sign out this login: a real mobile_app registration, a push, and a tap through its webhook."""
    push = PushServer()
    await push.start()
    browser = ha.token
    res = await ha.login(PASSWORD, client_id=ANDROID, redirect_uri="homeassistant://auth-callback")
    ha.token = await ha.token_for(res["result"], client_id=ANDROID)
    code, reg = await ha.call("POST", "/api/mobile_app/registrations", {
        "app_id": "io.homeassistant.companion.android", "app_name": "Home Assistant", "app_version": "2026.10",
        "device_name": "pats_phone", "manufacturer": "Google", "model": "Pixel", "os_name": "Android",
        "os_version": "16", "supports_encryption": False,
        "app_data": {"push_token": "e2e", "push_url": "http://127.0.0.1:%d/push" % PUSH_PORT}})
    check(code == 201, "Pat's phone app signs in and registers")
    webhook = reg["webhook_id"]
    ha.token = browser
    check(await ha.save_options({"notify_service": "notify.mobile_app_pats_phone"}), "alerts go to Pat's phone")

    async def new_token(name):
        await ha.ws({"type": "auth/long_lived_access_token", "client_name": name, "lifespan": 30})

        async def listed():
            return next((s["handle"] for s in await ha.sessions() if s["client"] == "token: " + name), None)
        return await until(listed)

    async def tap(h):
        before = len(push.pushes)
        code, _ = await ha.call("POST", "/api/webhook/" + webhook, {"type": "fire_event", "data": {
            "event_type": "mobile_app_notification_action",
            "event_data": {"action": "ACCESS_GUARD_SIGN_OUT_" + h}}}, token=False)
        reply = await until(lambda: _reply(push, before), 15)
        return code, reply, h in [s["handle"] for s in await ha.sessions()]

    h = await new_token("e2e-one")
    sent = await until(lambda: _push_for(push, "e2e-one"), 40)
    actions = (sent or {}).get("data", {}).get("actions", [])
    check(actions == [{"action": "ACCESS_GUARD_SIGN_OUT_" + h, "title": "Sign out this login"}],
          "the alert's push carries Sign out this login")
    code, reply, still = await tap(h)
    check(code == 200 and not still, "a tap from Pat's signed-in phone signs that token out")
    check(reply == "Signed out Pat's token: e2e-one.", "the phone is told: %s" % reply)

    app = [s["handle"] for s in await ha.sessions() if s["client"] == "Android app"]
    code, _ = await ha.call("POST", "/api/services/access_guard/sign_out", {"handle": app[0]})
    check(code == 200 and len(app) == 1, "the phone's own login is signed out; it keeps its webhook")
    h = await new_token("e2e-two")
    await until(lambda: _push_for(push, "e2e-two"), 40)
    code, reply, still = await tap(h)
    check(code == 200 and still, "a tap from the signed-out phone is refused; the token stays")
    check(reply == "Could not sign out: Pat has no signed-in Home Assistant app.", "the phone is told: %s" % reply)
    await push.runner.cleanup()


async def _push_for(push, token_name):
    return next((p for p in push.pushes if "(token: %s)" % token_name in p.get("message", "")), None)


async def _reply(push, after):
    return next((p["message"] for p in push.pushes[after:] if p["message"].startswith(("Signed out", "Could not"))),
                None)


async def main(step):
    async with aiohttp.ClientSession() as s:
        ha = HA(s)
        await up(ha)
        await {"install": install, "check": check_upgraded}[step](ha)
    if failed:
        sys.exit("%d check(s) failed" % len(failed))


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
