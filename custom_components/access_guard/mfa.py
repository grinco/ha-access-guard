"""Administrators without multi-factor authentication, as repairs issues (DESIGN.md 0.3.0, #2).

Repairs are shown to administrators only. Access Guard keeps the set of issues it raised and
deletes those no longer true, so nothing lingers.
"""

from homeassistant.helpers import issue_registry as ir

from .const import DOMAIN

ISSUE_PREFIX = "admin_without_mfa_"


def admins_without_mfa(users, enabled):
    """The active, non-system administrators whose `enabled[user.id]` is false."""
    return [u for u in users if u.is_active and u.is_admin and not u.system_generated and not enabled.get(u.id)]


class MfaWatch:
    def __init__(self, hass):
        self.hass = hass
        self.modules = 0
        self._raised = set()

    async def async_update(self, users):
        auth = self.hass.auth
        self.modules = len(auth.auth_mfa_modules)
        missing = []
        if self.modules:        # without a module nobody can enable MFA: an issue would be noise
            admins = admins_without_mfa(users, {})
            enabled = {u.id: bool(await auth.async_get_enabled_mfa(u)) for u in admins}
            missing = admins_without_mfa(admins, enabled)
        for u in missing:
            ir.async_create_issue(self.hass, DOMAIN, ISSUE_PREFIX + u.id, is_fixable=False,
                                  severity=ir.IssueSeverity.WARNING, translation_key="admin_without_mfa",
                                  translation_placeholders={"name": u.name})
        now = {u.id for u in missing}
        for uid in self._raised - now:
            ir.async_delete_issue(self.hass, DOMAIN, ISSUE_PREFIX + uid)
        self._raised = now

    def count(self):
        return len(self._raised)

    def clear(self):
        """At unload: Access Guard's issues go with it."""
        for uid in self._raised:
            ir.async_delete_issue(self.hass, DOMAIN, ISSUE_PREFIX + uid)
        self._raised = set()
