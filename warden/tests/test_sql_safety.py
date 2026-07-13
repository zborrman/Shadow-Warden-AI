"""
SR-7 — allowlisted SET-clause builder (warden/db/sql_safety.py).

The dynamic UPDATE endpoints (`/monitors/{id}`, portal profile, portal API keys) build
`SET col=:col, ...` from whichever fields the caller supplied. They were never injectable
— the column names are code literals and the values are bound parameters — but that held
only because nobody had yet built the update dict from user-supplied keys. semgrep flags
this shape, correctly.

safe_set_clause makes the property structural: only developer-declared columns can reach
the f-string, so the safety survives a future refactor.
"""
from __future__ import annotations

import pytest

from warden.db.sql_safety import UnsafeColumnError, safe_set_clause

_ALLOWED = {"name", "interval_s", "is_active"}


class TestHappyPath:
    def test_builds_bound_clause(self):
        got = safe_set_clause({"name": "x", "is_active": True}, _ALLOWED)
        assert got == "name = :name, is_active = :is_active"

    def test_custom_assign_format(self):
        got = safe_set_clause({"name": "x"}, _ALLOWED, assign="{col}=:{col}")
        assert got == "name=:name"

    def test_values_are_never_interpolated(self):
        """Only column NAMES appear; the value never reaches the SQL string."""
        got = safe_set_clause({"name": "'; DROP TABLE monitors; --"}, _ALLOWED)
        assert got == "name = :name"
        assert "DROP" not in got


class TestAllowlistEnforced:
    def test_unknown_column_rejected(self):
        with pytest.raises(UnsafeColumnError):
            safe_set_clause({"tenant_id": "other"}, _ALLOWED)

    def test_injected_column_name_rejected(self):
        """A column name carrying SQL is exactly what the allowlist exists to stop."""
        with pytest.raises(UnsafeColumnError) as exc:
            safe_set_clause({"is_active=1; DROP TABLE monitors--": 1}, _ALLOWED)
        assert "not allowed" in str(exc.value)

    def test_partial_overlap_rejected(self):
        with pytest.raises(UnsafeColumnError):
            safe_set_clause({"name": "ok", "evil": 1}, _ALLOWED)

    def test_empty_updates_rejected(self):
        with pytest.raises(UnsafeColumnError):
            safe_set_clause({}, _ALLOWED)


class TestRealAllowlists:
    def test_endpoint_allowlists_match_their_models(self):
        from warden.api.monitor import _MONITOR_UPDATE_COLS
        from warden.portal_router import _PORTAL_KEY_UPDATE_COLS, _PORTAL_USER_UPDATE_COLS

        assert _MONITOR_UPDATE_COLS == {"name", "interval_s", "is_active"}
        assert _PORTAL_USER_UPDATE_COLS == {"display_name", "notify_high", "notify_block"}
        assert _PORTAL_KEY_UPDATE_COLS == {"label", "rate_limit"}
