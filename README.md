# Access Guard for Home Assistant

See who is signed in to your Home Assistant and from where, and end a single session
from a dashboard. Built for households: a family member's phone, a browser left signed
in at a friend's, a token an add-on uses — all in one list, each one removable on its own.

**Sessions, never accounts.** Signing out ends one login (one app or browser) immediately;
the account stays active and its person can sign in again. Access Guard cannot disable an
account and cannot lock you out.

## What you get

| | |
|---|---|
| `sensor.access_guard_sessions` | state: logins used in the last 35 minutes ("connected now"). Attribute `sessions`: every person's login with `handle`, `user`, `user_id`, `client` (iOS app, Android app, `browser: host`, `token: name`), `created`, `last_used`, `ip`, `origin` and `country` |
| `sensor.access_guard_activity` | the last 25 actions a person ran: when, who, which action, on what |
| `access_guard_new_login` event | a login was created — a new phone, browser or token |
| `access_guard_login_removed` event | a login was removed; `removed_by` says whether Access Guard did it |
| `access_guard.sign_out` | end one login, by its `handle` |
| `access_guard.sign_out_user` | end all of one person's logins, by `user_id` |
| `sensor.access_guard_bans` | state: addresses Home Assistant has banned. Attribute `bans`: `ip`, `banned_at`, `origin`, `country`, newest first |
| `access_guard.unban` | lift one IP ban, by `ip`: removed from `ip_bans.yaml` and its failed-login count reset |
| `access_guard_anomaly` event | an alert (below), with the login's fields plus `kind` and `message` |

`origin` is `home` (your LAN), `tailscale`, `add-on`, `home via internet` (your own public
address, e.g. through a tunnel), `internet`, `no address` or `never used`.

## Install

HACS → ⋮ → *Custom repositories* → `https://github.com/grinco/ha-access-guard`, category
*Integration* → install **Access Guard** → restart → *Settings → Devices & services → Add
integration → Access Guard*. Requires Home Assistant 2026.10 or newer.

### Options

- **Country database** (optional): download *IP to Country Lite* (CSV) from
  [db-ip.com](https://db-ip.com/db/download/ip-to-country-lite) and point the option at it
  (default `/config/access_guard/dbip-country-lite.csv.gz`). Lookups are offline; no
  address ever leaves your instance. IP geolocation by [DB-IP](https://db-ip.com), CC BY 4.0.
- **Home public IP sensor** (optional): a sensor holding your public address, so logins
  from it read `home via internet`.

## Alerts

Each alert fires `access_guard_anomaly`, shows a notification in Home Assistant (option) and, if you
set one, goes to a notify action such as `notify.mobile_app_pat_phone`. Alerts **only notify**:
Access Guard never signs anyone out by itself.

| Alert (`kind`) | When |
|---|---|
| `login_after_failures` | a login from an address that failed to sign in at least *N* times (option, default 1) in the 15 minutes before |
| `sensitive_first` | a new login from outside the home whose first move, within 5 minutes, is a live camera view or an action on a sensitive domain (option: `camera`, `lock`, `alarm_control_panel` by default). `attribution` says whether the exact login (`login`) or only the person (`person`) is known |
| `long_lived_token` | a long-lived access token was created |

Good to know:
- Failed logins are read from Home Assistant's own warning line. If you set
  `homeassistant.components.http.ban` to `error` in `logger:`, Access Guard sees none. Diagnostics
  show `failed_login_capture`.
- With *N* = 1, one mistyped password before a login alerts too. Raise it if that is noisy.
- Still camera pictures are fetched without a person's login, so only **live** views count. A
  dashboard that opens with a live camera card counts as watching it.
- A push to a phone leaves your instance through its provider (Google or Apple) with the person's
  name and address. It is off unless you set a notify action.

## Security model

- **Only administrators** can sign anyone out or lift a ban, and only as a signed-in person: an
  automation or a script (no user) is refused. Any account can call an action through the
  API, so the integration checks the caller itself — hiding a button is not protection.
- **System accounts are never touched** (the Supervisor's login is how add-ons connect).
- **No credential ever leaves the auth store.** Logins are named by a *handle*, the first
  12 hex characters of a SHA-256 of the login's id. The tests plant secrets and fail if any
  appears in a state, an event or diagnostics.
- **Diagnostics are counts only** — no address, name or handle — because they get attached
  to public bug reports.
- A sign-out is **immediate**: Home Assistant drops the login, closes its open connection,
  and rejects its short-lived access tokens (they are checked against the login).

## Dashboard example

A sign-out button per login with
[auto-entities](https://github.com/thomasloven/lovelace-auto-entities) and
[button-card](https://github.com/custom-cards/button-card):

```yaml
type: custom:auto-entities
card: {type: vertical-stack}
card_param: cards
filter:
  template: >-
    {%- set ns = namespace(l=[]) -%}
    {%- for s in state_attr('sensor.access_guard_sessions', 'sessions') or [] -%}
    {%- set ns.l = ns.l + [{'type': 'custom:button-card', 'icon': 'mdi:logout',
        'name': s.user ~ ' · ' ~ s.client,
        'label': s.origin ~ (' ' ~ s.country if s.country else '') ~ ' · ' ~ (s.ip or ''),
        'show_label': true,
        'tap_action': {'action': 'perform-action', 'perform_action': 'access_guard.sign_out',
                       'data': {'handle': s.handle},
                       'confirmation': {'text': 'Sign out ' ~ s.user ~ ' on ' ~ s.client ~ '?'}}}] -%}
    {%- endfor -%}
    {{ ns.l }}
```

## Roadmap

Audit history, more detection rules (new country, impossible travel per login, off-hours use, an
administrator without MFA) and automatic response with a dry-run mode — see [docs/DESIGN.md](docs/DESIGN.md).

## Development

```bash
python3 tests/test_policy.py          # the security rules, plain Python
python3 -m pytest -q                  # against Home Assistant (pytest-homeassistant-custom-component)
```
