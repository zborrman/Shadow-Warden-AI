"""
warden/tests/test_rbac.py
══════════════════════════
Tests for Role-Based Access Control (warden.rbac + analytics.auth RBAC layer).
"""
from __future__ import annotations

from warden.rbac import (
    DashboardRole,
    has_permission,
    role_from_saml_groups,
)

# ── role_from_saml_groups ─────────────────────────────────────────────────────

class TestRoleFromSamlGroups:
    def test_admin_group_returns_admin(self):
        assert role_from_saml_groups(["warden_role_admin"]) == DashboardRole.ADMIN

    def test_auditor_group_returns_auditor(self):
        assert role_from_saml_groups(["warden_role_auditor"]) == DashboardRole.AUDITOR

    def test_viewer_group_returns_viewer(self):
        assert role_from_saml_groups(["warden_role_viewer"]) == DashboardRole.VIEWER

    def test_no_matching_group_returns_viewer(self):
        assert role_from_saml_groups(["some-other-group", "engineering"]) == DashboardRole.VIEWER

    def test_empty_groups_returns_viewer(self):
        assert role_from_saml_groups([]) == DashboardRole.VIEWER

    def test_highest_privilege_wins(self):
        # Both auditor and admin present — should return admin
        assert role_from_saml_groups(
            ["warden_role_auditor", "warden_role_admin"]
        ) == DashboardRole.ADMIN

    def test_admin_beats_viewer(self):
        assert role_from_saml_groups(
            ["warden_role_viewer", "warden_role_admin"]
        ) == DashboardRole.ADMIN

    def test_auditor_beats_viewer(self):
        assert role_from_saml_groups(
            ["warden_role_viewer", "warden_role_auditor"]
        ) == DashboardRole.AUDITOR

    def test_extra_groups_ignored(self):
        assert role_from_saml_groups(
            ["eng", "warden_role_auditor", "devops"]
        ) == DashboardRole.AUDITOR


# ── role_from_password_login ──────────────────────────────────────────────────

class TestRoleFromPasswordLogin:
    def test_default_is_admin(self, monkeypatch):
        monkeypatch.delenv("DASHBOARD_ROLE", raising=False)
        # Re-import to pick up env change — or just test the function logic
        # The function reads module-level constant; test the default value
        import importlib

        import warden.rbac as mod
        importlib.reload(mod)
        assert mod.role_from_password_login() == DashboardRole.ADMIN

    def test_env_override_auditor(self, monkeypatch):
        monkeypatch.setenv("DASHBOARD_ROLE", "auditor")
        import importlib

        import warden.rbac as mod
        importlib.reload(mod)
        assert mod.role_from_password_login() == DashboardRole.AUDITOR

    def test_env_override_viewer(self, monkeypatch):
        monkeypatch.setenv("DASHBOARD_ROLE", "viewer")
        import importlib

        import warden.rbac as mod
        importlib.reload(mod)
        assert mod.role_from_password_login() == DashboardRole.VIEWER

    def test_invalid_env_defaults_to_admin(self, monkeypatch):
        monkeypatch.setenv("DASHBOARD_ROLE", "superuser")
        import importlib

        import warden.rbac as mod
        importlib.reload(mod)
        assert mod.role_from_password_login() == DashboardRole.ADMIN


# ── has_permission ────────────────────────────────────────────────────────────

class TestHasPermission:
    def test_admin_has_admin(self):
        assert has_permission(DashboardRole.ADMIN, DashboardRole.ADMIN)

    def test_admin_has_auditor(self):
        assert has_permission(DashboardRole.ADMIN, DashboardRole.AUDITOR)

    def test_admin_has_viewer(self):
        assert has_permission(DashboardRole.ADMIN, DashboardRole.VIEWER)

    def test_auditor_lacks_admin(self):
        assert not has_permission(DashboardRole.AUDITOR, DashboardRole.ADMIN)

    def test_auditor_has_auditor(self):
        assert has_permission(DashboardRole.AUDITOR, DashboardRole.AUDITOR)

    def test_auditor_has_viewer(self):
        assert has_permission(DashboardRole.AUDITOR, DashboardRole.VIEWER)

    def test_viewer_lacks_admin(self):
        assert not has_permission(DashboardRole.VIEWER, DashboardRole.ADMIN)

    def test_viewer_lacks_auditor(self):
        assert not has_permission(DashboardRole.VIEWER, DashboardRole.AUDITOR)

    def test_viewer_has_viewer(self):
        assert has_permission(DashboardRole.VIEWER, DashboardRole.VIEWER)

    def test_string_values_accepted(self):
        assert has_permission("admin", "auditor")
        assert not has_permission("viewer", "admin")
