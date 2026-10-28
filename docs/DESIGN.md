# Access Guard for Home Assistant — design

Status: phase 1 in progress, 2026-10-28; reviewed (companion review 2026-10-28, findings folded in). Owner: grinco.

## Why

Home Assistant knows every login, but shows none of it in one place, keeps only the
**last** address per login, and gives an administrator no way to end anyone else's
session. A household cannot answer "who switched this on, from where?" without
reading the recorder database, and cannot act on the answer without stopping Home
Assistant and editing `.storage/auth`.

Access Guard makes access **visible**, **auditable** and **actionable**, and then
**automatic**: it notices what is unusual and responds by rules the owner sets.

It ends **sessions, never accounts** (operator, 2026-10-28): a signed-out person signs in
again. Disabling an account is not offered; that stays in Settings → People.

## Principles

1. **Never a credential.** No token, JWT key or token id leaves the auth manager.
   Logins are named by a *handle* (first 12 hex characters of SHA-256 of the id).
   A test plants recognisable secrets and fails if any reaches an entity, an event,
   a log line or diagnostics.
2. **The integration is the security boundary.** Any signed-in account can call any
   action through the API. Every action checks its caller itself (`policy.py`, pure
   Python, tested without Home Assistant); a dashboard that hides a button is not
   protection.
3. **Never lock the house out.** Only sessions are ended, never accounts; system
   accounts' sessions are never touched; an automatic response acts on the one login
   that triggered it, never on a person's other sessions.
4. **Native, in-process.** Read logins from `hass.auth`, not from files; entities,
   events, repairs and diagnostics the way Home Assistant does them; config flow, no YAML.
5. **Private by default.** Geolocation is offline. Nothing about the household leaves
   the instance.
6. **Test first.** A case before every behaviour; mutation-check the policy.

## Policy (`policy.py`, every case mutation-checked)

| Action | Allowed when | Always refused |
|---|---|---|
| `sign_out(handle)` — end one login | the caller is a signed-in **administrator** | no caller (automation, script); a system account's login (Supervisor: add-ons sign in through it); a handle matching no login or more than one |
| `sign_out_user(user)` — end all of one person's logins | as above, per login | as above; the account itself stays active |
| automatic response (phase 4) | a rule's configured action, on **the login that triggered it** | any action on a person's other logins; any action from a failed-login rule (those notify only: usernames are not secret, so acting on them would let anyone sign a household member out) |

| `unban(ip)` — lift one IP ban (0.2.0) | the caller is a signed-in **administrator** | no caller; an address that is not banned; Home Assistant's bans not loaded |
| light detection rules (0.2.0) | always: they **notify only** | any action at all; signing out is phase 4 |

An administrator may sign out their own other devices, or the owner's: it is a session,
and they sign in again.

## What a sign-out actually does (verified against Home Assistant 2026.10.4)

`AuthManager.async_remove_refresh_token` deletes the login and runs its revoke callbacks;
the websocket API registers one per connection (`websocket_api/auth.py`), so an open app or
browser is disconnected at once. Its short-lived access tokens die with it:
`async_validate_access_token` looks the login up by the token's `iss` claim and returns
nothing when the login is gone or the account inactive (`auth/__init__.py`, lines 665-684).
A sign-out is therefore immediate, not "after the 30-minute access token expires" (review
2026-10-28, finding F2, checked and refuted). These are internal APIs: the minimum Home
Assistant version is pinned, and the actions refuse to run if the methods are missing
rather than silently doing nothing.

## Architecture

```
hass.auth ──► SessionTracker ──► sensor.access_guard_sessions  (state: connected now; attrs: logins)
   (in-process, │  diff every 30 s     sensor.access_guard_activity  (last N person actions)
    read-only)  │                       event  access_guard_new_login / access_guard_login_removed
                ├─► GeoResolver (offline DB-IP Lite, JSON index)
                ├─► Detector (rules) ──► Responder (notify / sign out / disable, by policy)
                └─► AuditLog (phase 2: Store, every address and action, retained N days)
actions: access_guard.sign_out(handle) · access_guard.sign_out_user(user)   ── policy.py
```

- **SessionTracker** polls `hass.auth` (cheap, in memory) and diffs: a new refresh
  token → `access_guard_new_login`; a removed one → `access_guard_login_removed`;
  a changed `last_used_ip` → an address-history entry. This replaces both the
  `command_line` reader and the template condition that inferred "new" from creation
  times. Home Assistant fires no event when a login is created, hence the diff.
- **Activity** listens to `call_service` events that carry a user, as the template
  sensor does today, and names users from `hass.auth` directly. It is **best-effort**:
  it answers "who ran an action", not "who caused this change". A physical switch, a
  device reporting late, or an integration acting on its own carries no user.

### Event contract (fixed in phase 1; later phases add fields, never rename)

`access_guard_new_login` and `access_guard_login_removed` carry: `handle`, `user_id`,
`user_name`, `token_type` (`normal` / `long_lived_access_token`), `client`, `created`,
`last_used`, `ip`, `origin` (`home`, `tailscale`, `add-on`, `home via internet`,
`internet`, `no address`, `never used`), `country`. A removal also carries `removed_by`
(`access_guard` with the caller's user id, or `unknown` for Home Assistant's own expiry or
the profile page). `access_guard_anomaly` is defined in phase 3, not reserved now.

Events stay inside the instance, but the recorder stores them and other automations can
forward them; they carry the IP because the new-login push needs it. **Diagnostics use an
allowlist**: counts, origins, countries, token types — never an IP, a name or a handle, since
diagnostics are what people attach to public bug reports.

Phase 1 keeps no history of its own: the sensor's recorded attributes are the only
timeline until the phase-2 AuditLog.
- **AuditLog** keeps what Home Assistant forgets: every address a login has used, and
  every sign-out or disable with who did it. It is a `Store`, not entity attributes,
  so it is not bounded by the recorder's 16 KB attribute limit or its 10-day purge.

## 0.2.0 — light detection and bans (low-level design)

Status: 2026-10-28; companion review 2026-10-28 (review-20261028-d13d) folded in as R1–R8. It brings forward the cheapest parts of
phases 2 and 3: failed logins are captured in memory only (the AuditLog Store stays phase 2), and
every rule **notifies only**. Nothing here ends a session.

### What it adds

| | Delivers |
|---|---|
| **Failed-login capture** | `FailedLogins`: a `logging.Handler` on `homeassistant.components.http.ban` that keeps, per address, the times of recent wrong passwords and wrong MFA codes |
| **Rule `login_after_failures`** | a new login from an address that failed at least *N* times (option, default 1) within 15 minutes before the login was created |
| **Rule `sensitive_first`** | the first thing a new login from outside the home does, within 5 minutes, is to watch a camera live or run an action on a sensitive domain (option, default `camera`, `lock`, `alarm_control_panel`) |
| **Rule `long_lived_token`** | a long-lived access token was created: it never expires and works from anywhere |
| **Alerts** | each finding fires `access_guard_anomaly`. It also raises a persistent notification (option, default on) and calls one notify action if one is set (option, e.g. `notify.mobile_app_pat`) |
| **Bans** | `sensor.access_guard_bans` (state: number banned; attribute `bans`: newest first, each with `ip`, `banned_at`, `origin`, `country`) and `access_guard.unban(ip)` |
| **Options** | rules on/off (multi-select, all on), failures before a login, sensitive domains, persistent notification on/off, notify action |

### Failed-login capture (`failures.py`)

Home Assistant fires no event for a failed login. `http.ban.process_wrong_login` logs one WARNING per
failure, whether or not bans are enabled (verified 2026.10.4):

    Login attempt or request with invalid authentication from {host} ({ip}). Requested URL: '{url}'. ({user agent})

Alternatives considered:
- `app[KEY_FAILED_LOGIN_ATTEMPTS]` exists only when `login_attempts_threshold` is set, which is off by
  default, and a successful login **clears** it: exactly the moment this rule needs it.
- The `http-login` persistent notification holds only the latest failure.

The log record is therefore the only source. Three of its parts are attacker-controlled: `host` is
reverse DNS, and the attacker owns their PTR record. musl, which Home Assistant OS uses, does not
reject a PTR name holding spaces or parentheses. The URL and the user agent are the attacker's too.
A forged PTR such as `x (192.168.1.5). Requested URL: '/auth/login_flow/a'. (y` puts a second,
false address *in front of* the real one. No parse can tell which is real: a strict host class
only makes the regex stop at `x`. (The first draft claimed it could; its own test disproved it.)

So no parse picks one address. `failures.addresses()` takes **every** address in the line:

- The line must start with Home Assistant's prefix. Then every match of
  `\(([0-9A-Fa-f:.]+)\)\. Requested URL: '/auth/login_flow/` (unanchored, `findall`) that parses as
  an `ip_address` is taken, normalised and de-duplicated, in order.
- The real address is always among them, so **a failure cannot be hidden**. A forged one can only
  cause a wrong *notification*, never an action.
- The list is capped at 8. A reverse name is at most 255 bytes, which holds at most six marks
  (`(::1). Requested URL: '/auth/login_flow/`), so the real address is within the first seven. A user
  agent stuffed with marks cannot push it out of the detector's bounded map.
- Only `/auth/login_flow/` counts. That is a wrong password or MFA code (`auth/login_flow.py` calls
  `process_wrong_login` for `invalid_auth` / `invalid_code`). Any other 401 has no such mark and is
  ignored, for example a browser tab holding an expired token. Those are noise, not someone guessing.
- A line with more than one address is counted as `ambiguous` for diagnostics.

Nothing from the line is ever logged again, since it holds the attacker's text. Memory is bounded: at most 256 addresses, oldest evicted first, and each address keeps only failures
inside the window. An attacker spraying from many addresses cannot grow it. The handler holds no reference to `hass`. It hands each address to a callback that moves to
the event loop (`call_soon_threadsafe`), so the detector is only ever touched from the loop (R8).
It is attached at setup and detached at unload.

### Detection (`detector.py`, no Home Assistant imports, tested like `policy.py`)

A `Detector` holds the rule options and three bounded maps. Its methods return finding dicts and
never touch Home Assistant:

- `failure(ip, at)`: records a failure.
- `new_login(row, created)`: called when the coordinator sees a new handle. Returns
  `login_after_failures` and `long_lived_token` findings. For `sensitive_first`, it remembers the login
  for 5 minutes if its origin is `internet` or `home via internet`. `home`, `tailscale` and `add-on` are
  the house itself.
- `signal(user_id, handle, kind, what, at)`: a person did something (see below). If it is the first
  signal for a remembered login and it is sensitive, the result is a `sensitive_first` finding. Either
  way the login is then forgotten: only the **first** thing counts.

**Polling lag.** A login is seen up to 30 s after it is created, and a person can open a camera
before that. `signal` therefore also keeps each user's and handle's first signal for 5 minutes, and
`new_login` checks for one made after `created`. The order of arrival does not change the result.

**Which login did it.** A camera live view comes over the websocket, whose connection carries
`refresh_token_id`, so it names the exact login (its handle). An action (`call_service`) carries only
a user id: it is attributed to that user's most recent remembered login. One person's phone at home
and new laptop abroad are both theirs: a false attribution names the right person, but it can
name the wrong *login*. Every `sensitive_first` finding therefore says how it was attributed:
`attribution: login` (the exact login, from the websocket) or `attribution: person` (their most
recent new login). Phase 4 may act only on `login` (R3).

`login_after_failures` clears that address's failures when it fires: one burst gives one alert.

### Camera live views (`camera_watch.py`)

Watching a camera is not an action. The frontend starts a live view with the websocket commands
`camera/stream` (HLS) or `camera/webrtc/offer`. Access Guard wraps those two handlers in Home
Assistant's command table (`hass.data["websocket_api"]`, `{type: (handler, schema)}`). The wrapper
reports `(connection.user.id, handle(connection.refresh_token_id), "camera", entity_id)` and then calls
the original handler unchanged. It never blocks or alters the command. The report is best-effort:
a connection without a user or login is skipped, any exception is logged at DEBUG, and the original
handler is always called (R5).

- This is an internal table, like `hass.auth`. Access Guard wraps an entry only if it exists and is a
  2-tuple. Otherwise the camera signal is off, said once at INFO and shown in diagnostics
  (`camera_watch: false`); the weekly CI run against the newest Home Assistant catches a change.
- `camera` may load after Access Guard, so the wrap is retried on `EVENT_COMPONENT_LOADED` for
  `camera`. An entry that is already Access Guard's wrapper is not wrapped again. At unload an entry
  is restored only if it is still Access Guard's wrapper. Diagnostics read the table at that moment
  rather than remembering the last attempt: if anything re-registers a command, it shows (R6).
- **Not covered:** still images and MJPEG are fetched by URL with the camera's own short token, not
  the person's, so no account is known. A dashboard with a live camera card starts a stream when it
  opens, and that counts as watching. That is true, but on such a dashboard the rule fires on every
  new outside login (documented in the README; the rule can be turned off).

### Alerts (`alerts.py`)

`access_guard_anomaly` (the contract, fixed from 0.2.0): `kind` (`login_after_failures`,
`sensitive_first`, `long_lived_token`), `handle`, `user_id`, `user_name`, `client`, `token_type`, `ip`,
`origin`, `country`, `message` (one human-readable sentence). Depending on the kind it adds `failures`
(a count), or `domain`, `action`, `target` and `attribution` (`login` / `person`). As with every event: no credential, and the planted-secret
test covers it.

The persistent notification and the push carry `message` only. In the persistent notification it is
Markdown-escaped: a person names their own long-lived token, and a name such as
`[sign in again](https://…)` would otherwise put a link in the administrator's notification (found
while implementing). Persistent notifications are visible to
every account. The same data is already in `sensor.access_guard_sessions`, which every account can
read, so nothing new is exposed. A notify action is the operator's choice and is off by default. It can
take the message out of the house (a phone push goes through Google or Apple), and the options form
says so (principle 5). A notify action that fails (removed phone, typo) is logged as a
warning and does not stop the event. Rate: each kind fires at most once per login, and logins are what
they are; no extra throttle.

### Bans (`bans.py`)

The ban manager is `hass.http.app[KEY_BAN_MANAGER]` (internal, as above). It keeps `ip_bans_lookup` in
memory and **appends** to `ip_bans.yaml`, and has no remove.

`unban(ip)` (admin only, policy). Everything up to the executor write runs in the event loop, as Home
Assistant's own `async_add_ban` does:
1. Pop the address from `ip_bans_lookup` and from `KEY_FAILED_LOGIN_ATTEMPTS`, keeping both. Without
   the second, the address's next mistake bans it again at once.
2. Snapshot the lookup. Write it in Home Assistant's own format (`yaml_util.dump({ip: {banned_at:
   iso}})`) to a temporary file and `os.replace` it, in the executor.
3. If the write fails, put both entries back and refuse. Memory and file then still agree, and the
   address stays banned.
4. Home Assistant adds a ban to the lookup *before* its executor append. If the lookup differs from
   the snapshot, go back to 2, at most 10 times. An append that raced the replace and landed in the
   unlinked old file is written again this way.
5. Log who lifted which address and fire `access_guard_unbanned` (`ip`, `by_user_id`).

Why this stays correct under a burst of new bans (R1, R2): the address being lifted is popped
before the first write, so **no file this writes contains it**. An unban can never be undone at
restart. What a burst can still cost:
- After 10 rounds, a ban added in the last few milliseconds may be in memory only. It still applies,
  until Home Assistant restarts. This is logged as a warning.
- An append that lands in the new file after a snapshot that already holds it leaves a duplicate key.
  Home Assistant loads that with a warning and keeps the last value (verified 2026.10.4).
- An empty file loads as no bans (verified).

It is refused with a clear message when the address is not banned or bans are not loaded
(`ip_ban_enabled: false`). The sensor reads the lookup on the coordinator's 30-s poll. A ban takes
effect at once in Home Assistant, so the sensor showing it up to 30 s later is fine. Bans are not
household data, but a household member can get banned, so they get the same visibility as the
sessions sensor's addresses. Diagnostics carry only their count, never an address (R7).

### Tests (each behaviour has a case first)

- Parser: real lines, forged PTR (the real address still taken), a user agent stuffed with marks
  (the cap keeps the real one), IPv6, non-login URLs, garbage.
- Detector (plain Python and under pytest; mutation-checked like the policy):
  - thresholds and the 15-min window edges;
  - the first signal only;
  - signal before discovery and after;
  - origin filter;
  - eviction bounds;
  - failures cleared after firing.
- Integration against real Home Assistant:
  - a wrong password through the real login flow, then a login from the same address, fires
    `login_after_failures`;
  - a non-login 401 does not count;
  - `camera/stream` over a real websocket from a new outside login fires `sensitive_first`, and an
    action first does not;
  - the wrapper is restored at unload;
  - a fault in the report still lets `camera/stream` run;
  - a long-lived token fires;
  - notify action called, and its failure tolerated;
  - unban through a real ban: lookup, counter and file all updated, other bans kept; refusals;
  - a failed write puts the ban back;
  - planted secrets in anomaly and unban events;
  - diagnostics stay counts only.

### Further light features (proposed, not in 0.2.0)

1. **Repairs issue: an administrator without MFA.** `hass.auth.async_get_enabled_mfa(user)`; about 30
   lines. It was phase 2.
2. **Non-admin login from the internet**: a one-line rule on `new_login`. It needs `use_x_forwarded_for`
   behind a proxy, as phase 3 says.
3. **New country for a person**: needs a small Store of countries seen per user.
4. **Failed-login burst without success** (e.g. 10 in 5 min): reuses `FailedLogins`. Home Assistant's own
   ban covers it only when a threshold is configured.
5. **Actionable push "Sign out this login"**: the handle is already in the anomaly event. It is phase 4.

## Phases

| Phase | Delivers | Replaces in the operator's instance |
|---|---|---|
| **1 — Visibility + control** | config flow; sessions + activity sensors; new-login / removed events; `sign_out`, `sign_out_user`; offline country from an operator-supplied file; diagnostics (allowlist); HACS packaging; minimum HA 2026.10 | `command_line` sensor, `ha_sessions.py`, the activity template sensor, the creation-time template condition |
| **0.2.0 — Light detection + bans** | see above: failed-login capture (in memory), three notify-only rules, alerts, bans sensor and `unban` | the operator's "login after a failure" automation, hand edits of `ip_bans.yaml` |
| **2 — Audit** | AuditLog store; per-login address history; failed-login history kept across restarts; repairs issue for an owner account without MFA | — |
| **3 — Detection** | `access_guard_anomaly`; rules, each an option: new country for a login's user; a non-admin's login used from the internet (needs `use_x_forwarded_for` behind a proxy, else every address is the proxy's); use outside allowed hours; impossible travel **per login**, with a minimum distance and time and an allow-list (one person's phone and laptop are two logins in two places); long-lived token created; burst of failed logins (only if phase-2 capture works; a repairs issue says when it does not) | — |
| **4 — Response** | per rule: notify (actionable push with a *Sign out this login* button), or act automatically on **that login only**; failed-login rules notify only; a **dry-run** mode that reports what it would have done | — |

## Open questions

- Activity source: `call_service` misses changes made without an action. Is
  `state_changed` with a user context worth the volume?
- ~~Country database~~ decided: the operator supplies DB-IP Lite (CC BY 4.0, attribution
  shown) at a configured path; it is not bundled. Without it, no country.
- Failed logins: Home Assistant logs them and raises a notification but fires no event.
  0.2.0 hooks the `http.ban` logger, strictly parsed (see above); a core feature request for a
  `login_failed` event and an unban API remains the better long-term route.
