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

## Phases

| Phase | Delivers | Replaces in the operator's instance |
|---|---|---|
| **1 — Visibility + control** | config flow; sessions + activity sensors; new-login / removed events; `sign_out`, `sign_out_user`; offline country from an operator-supplied file; diagnostics (allowlist); HACS packaging; minimum HA 2026.10 | `command_line` sensor, `ha_sessions.py`, the activity template sensor, the creation-time template condition |
| **2 — Audit** | AuditLog store; per-login address history; failed-login capture (hook `http.ban` warnings); repairs issue for an owner account without MFA | — |
| **3 — Detection** | `access_guard_anomaly`; rules, each an option: new country for a login's user; a non-admin's login used from the internet (needs `use_x_forwarded_for` behind a proxy, else every address is the proxy's); use outside allowed hours; impossible travel **per login**, with a minimum distance and time and an allow-list (one person's phone and laptop are two logins in two places); long-lived token created; burst of failed logins (only if phase-2 capture works; a repairs issue says when it does not) | — |
| **4 — Response** | per rule: notify (actionable push with a *Sign out this login* button), or act automatically on **that login only**; failed-login rules notify only; a **dry-run** mode that reports what it would have done | — |

## Open questions

- Activity source: `call_service` misses changes made without an action. Is
  `state_changed` with a user context worth the volume?
- ~~Country database~~ decided: the operator supplies DB-IP Lite (CC BY 4.0, attribution
  shown) at a configured path; it is not bundled. Without it, no country.
- Failed logins: Home Assistant logs them and raises a notification but fires no event.
  Hooking the `http.ban` logger is fragile; is a core feature request the better route?
