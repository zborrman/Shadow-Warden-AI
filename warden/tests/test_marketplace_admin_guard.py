"""
warden/tests/test_marketplace_admin_guard.py — MP-1c.

``POST /marketplace/agents/{id}/kya/revoke`` guarded itself with::

    admin_key = os.getenv("ADMIN_KEY", "")
    if admin_key and provided != admin_key:
        raise HTTPException(403, ...)

When ``ADMIN_KEY`` was unset the condition short-circuited to False and the
endpoint ran for anybody — an empty secret silently disabled the check instead
of denying. These tests pin the corrected posture so it cannot regress.
"""
from __future__ import annotations

import hmac

import pytest
from fastapi import HTTPException

from warden.marketplace.admin_guard import require_admin_key


class TestRequireAdminKey:
    def test_unset_key_denies_with_503(self, monkeypatch):
        """The bug: unset ADMIN_KEY used to mean 'allow everyone'. It must deny."""
        monkeypatch.delenv("ADMIN_KEY", raising=False)
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED", "false")
        with pytest.raises(HTTPException) as exc:
            require_admin_key("anything")
        assert exc.value.status_code == 503

    def test_unset_key_denies_even_when_caller_sends_nothing(self, monkeypatch):
        monkeypatch.delenv("ADMIN_KEY", raising=False)
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED", "false")
        with pytest.raises(HTTPException) as exc:
            require_admin_key(None)
        assert exc.value.status_code == 503

    def test_empty_string_key_is_treated_as_unset(self, monkeypatch):
        """ADMIN_KEY="" is the exact shape that made the old check vanish."""
        monkeypatch.setenv("ADMIN_KEY", "")
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED", "false")
        with pytest.raises(HTTPException) as exc:
            require_admin_key("")
        assert exc.value.status_code == 503

    def test_dev_escape_is_explicit_and_opt_in(self, monkeypatch):
        monkeypatch.delenv("ADMIN_KEY", raising=False)
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED", "true")
        require_admin_key(None)  # must not raise

    def test_correct_key_passes(self, monkeypatch):
        monkeypatch.setenv("ADMIN_KEY", "s3cret")
        require_admin_key("s3cret")

    def test_wrong_key_is_403_not_503(self, monkeypatch):
        """403 vs 503 distinguishes 'you are not admin' from 'admin is unconfigured'."""
        monkeypatch.setenv("ADMIN_KEY", "s3cret")
        with pytest.raises(HTTPException) as exc:
            require_admin_key("wrong")
        assert exc.value.status_code == 403

    def test_missing_header_with_key_configured_is_403(self, monkeypatch):
        monkeypatch.setenv("ADMIN_KEY", "s3cret")
        with pytest.raises(HTTPException) as exc:
            require_admin_key(None)
        assert exc.value.status_code == 403

    def test_dev_escape_does_not_override_a_configured_key(self, monkeypatch):
        """ALLOW_UNAUTHENTICATED must not downgrade a deployment that HAS a key."""
        monkeypatch.setenv("ADMIN_KEY", "s3cret")
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED", "true")
        with pytest.raises(HTTPException) as exc:
            require_admin_key("wrong")
        assert exc.value.status_code == 403

    def test_key_is_read_fresh_not_snapshotted_at_import(self, monkeypatch):
        """A module-level _ADMIN_KEY = os.getenv(...) captures "" before env setup."""
        monkeypatch.setenv("ADMIN_KEY", "first")
        require_admin_key("first")
        monkeypatch.setenv("ADMIN_KEY", "second")
        require_admin_key("second")
        with pytest.raises(HTTPException):
            require_admin_key("first")

    def test_comparison_is_constant_time(self):
        """Guards against a refactor back to `provided != admin_key`."""
        import inspect

        from warden.marketplace import admin_guard
        src = inspect.getsource(admin_guard.require_admin_key)
        assert "compare_digest" in src, "admin key comparison must be constant-time"
        assert hmac.compare_digest("a", "a")
