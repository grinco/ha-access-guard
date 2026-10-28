#!/usr/bin/env python3
"""Cases for custom_components/access_guard/policy.py: who may sign out or disable whom.

The policy is the whole security of the feature. Home Assistant lets ANY signed-in
account call an action through its API, not only through the admin dashboard, so the
integration itself must refuse - and must not let an admin lock the house out.

    python3 tests/test_policy.py
"""

import importlib.util
import os
import sys
from types import SimpleNamespace as U

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "policy", os.path.join(HERE, "..", "custom_components", "access_guard", "policy.py"))
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

OWNER = U(id="u-owner", name="Pat", is_admin=True, is_owner=True, system_generated=False, is_active=True)
ADMIN = U(id="u-admin", name="Sam", is_admin=True, is_owner=False, system_generated=False, is_active=True)
CHILD = U(id="u-child", name="Robin", is_admin=False, is_owner=False, system_generated=False, is_active=True)
SUPER = U(id="u-super", name="Supervisor", is_admin=True, is_owner=False, system_generated=True, is_active=True)

CASES = []


def case(fn):
    CASES.append(fn)
    return fn


def refused(fn, *a):
    try:
        fn(*a)
    except policy.Refused:
        return True
    return False


@case
def a_non_admin_cannot_sign_anyone_out():
    """The child's own account calling the action through the API."""
    assert refused(policy.check_sign_out, CHILD, OWNER)
    assert refused(policy.check_sign_out, CHILD, CHILD)


@case
def no_caller_is_refused():
    """An automation or script has no user; this action is for a person at the dashboard."""
    assert refused(policy.check_sign_out, None, CHILD)


@case
def an_admin_can_sign_out_a_person():
    policy.check_sign_out(ADMIN, CHILD)
    policy.check_sign_out(OWNER, ADMIN)
    policy.check_sign_out(ADMIN, ADMIN)      # their own other device: harmless, they sign in again
    policy.check_sign_out(ADMIN, OWNER)      # a session, not the account: the owner signs in again


@case
def system_logins_are_never_signed_out():
    """The Supervisor's login is how add-ons reach Home Assistant."""
    assert refused(policy.check_sign_out, OWNER, SUPER)


@case
def there_is_no_way_to_disable_an_account():
    """Operator 2026-10-28: remove specific sessions, never lock an account out.
    Disabling accounts stays Home Assistant's own (Settings -> People)."""
    assert not [n for n in dir(policy) if "active" in n.lower() or "disable" in n.lower()], dir(policy)


@case
def the_handle_is_stable_short_and_not_the_id():
    """The dashboard shows a handle; the token id stays in the auth store."""
    h = policy.handle("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
    assert h == policy.handle("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
    assert h != policy.handle("0f1e2d3c4b5a69788796a5b4c3d2e1f1")
    assert len(h) == 12 and "0f1e2d3c" not in h, h


@case
def a_handle_resolves_to_exactly_one_login():
    toks = [U(id="a" * 32), U(id="b" * 32)]
    assert policy.resolve(toks, policy.handle("b" * 32)).id == "b" * 32
    assert refused(policy.resolve, toks, "000000000000")
    # Twelve hex characters can collide; never guess which login was meant.
    assert refused(policy.resolve, toks + [U(id="b" * 32)], policy.handle("b" * 32))


def main():
    bad = 0
    for fn in CASES:
        try:
            fn()
            print("  ok    %s" % fn.__name__)
        except Exception as e:  # noqa: BLE001 - a crash is a failure too
            bad += 1
            print("  FAIL  %s: %r" % (fn.__name__, e))
    print("\n%d/%d passed" % (len(CASES) - bad, len(CASES)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
