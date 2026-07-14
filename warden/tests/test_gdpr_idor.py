"""
SR-1.4b — GDPR tenant IDOR.

`DELETE /gdpr/purge/tenant/{tenant_id}` and `GET /gdpr/audit/{tenant_id}` trusted the
tenant in the URL, so any *valid* API key could erase or read ANOTHER tenant's data.
`DELETE /gdpr/purge/before/{date}` erases EVERY tenant's data before a date with only a
per-tenant key. These pin the authorization dependencies shut.

Own-tenant callers pass; cross-tenant callers are denied unless they present X-Admin-Key
(the operator path). Bulk cross-tenant purge is admin-only. All fail-closed.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from warden.api.gdpr import (
    _is_admin,
    require_admin_only,
    require_tenant_owner_or_admin,
)
from warden.auth_guard import AuthResult


def _auth(tenant_id: str) -> AuthResult:
    return AuthResult(api_key="k", tenant_id=tenant_id)


class TestTenantOwnerOrAdmin:
    def test_own_tenant_allowed(self):
        # no exception == authorized
        require_tenant_owner_or_admin("acme", auth=_auth("acme"), x_admin_key="")

    def test_cross_tenant_denied(self, monkeypatch):
        monkeypatch.delenv("ADMIN_KEY", raising=False)
        with pytest.raises(HTTPException) as exc:
            require_tenant_owner_or_admin("victim", auth=_auth("attacker"), x_admin_key="")
        assert exc.value.status_code == 403

    def test_cross_tenant_allowed_with_admin_key(self, monkeypatch):
        monkeypatch.setenv("ADMIN_KEY", "s3cret-admin")
        require_tenant_owner_or_admin("victim", auth=_auth("attacker"), x_admin_key="s3cret-admin")

    def test_wrong_admin_key_still_denied(self, monkeypatch):
        monkeypatch.setenv("ADMIN_KEY", "s3cret-admin")
        with pytest.raises(HTTPException):
            require_tenant_owner_or_admin("victim", auth=_auth("attacker"), x_admin_key="guess")


class TestAdminOnly:
    def test_valid_admin_key_allowed(self, monkeypatch):
        monkeypatch.setenv("ADMIN_KEY", "s3cret-admin")
        require_admin_only(x_admin_key="s3cret-admin")

    def test_no_admin_key_denied(self, monkeypatch):
        monkeypatch.setenv("ADMIN_KEY", "s3cret-admin")
        with pytest.raises(HTTPException) as exc:
            require_admin_only(x_admin_key="")
        assert exc.value.status_code == 403


class TestAdminFailClosed:
    def test_unset_admin_key_never_authorises(self, monkeypatch):
        """An unset ADMIN_KEY must not turn an empty header into a valid admin."""
        monkeypatch.delenv("ADMIN_KEY", raising=False)
        assert _is_admin("") is False
        assert _is_admin("anything") is False
        # and the dependency that relies on it also denies
        with pytest.raises(HTTPException):
            require_admin_only(x_admin_key="")

    def test_empty_string_admin_key_not_matchable(self, monkeypatch):
        monkeypatch.setenv("ADMIN_KEY", "")
        assert _is_admin("") is False
