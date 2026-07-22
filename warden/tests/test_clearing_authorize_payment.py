"""FT-6 — clearing.py wiring into the authorize_payment() chokepoint.

Mirrors test_listing_authorize_payment.py: default-off behavior is
unchanged, and only a clean DENY/REQUIRE_APPROVAL verdict blocks a clearing
once an operator turns AUTHORIZE_PAYMENT_ENFORCED on. The check must run
BEFORE losing negotiations are auto-rejected — a denied clearing must not
have already mutated other negotiations' state.
"""
from __future__ import annotations

import sqlite3

import pytest

from warden.marketplace.clearing import ClearingEngine


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "mkt.db")
    con = sqlite3.connect(path)
    con.execute("""
        CREATE TABLE marketplace_negotiations (
            negotiation_id TEXT PRIMARY KEY,
            buyer_agent_id TEXT,
            status TEXT,
            agreed_price REAL
        )
    """)
    con.execute(
        "INSERT INTO marketplace_negotiations VALUES (?,?,?,?)",
        ("neg-winner", "buyer-1", "active", 100.0),
    )
    con.execute(
        "INSERT INTO marketplace_negotiations VALUES (?,?,?,?)",
        ("neg-loser", "buyer-1", "pending", 80.0),
    )
    con.commit()
    con.close()
    return path


class TestAuthorizeClearingWiringDisabled:
    def test_clear_succeeds_unchanged_by_default(self, db, monkeypatch):
        monkeypatch.setattr("warden.marketplace.clearing._PG_DSN", "")
        engine = ClearingEngine(db_path=db)
        rec = engine.clear("neg-winner", "buyer-1")
        assert rec.replayed is False
        assert rec.clearing_id == "clear-neg-winner"


class TestAuthorizeClearingWiringEnabled:
    def test_deny_blocks_clearing(self, db, monkeypatch):
        monkeypatch.setenv("AUTHORIZE_PAYMENT_ENFORCED", "true")
        import warden.payments.authorize as authz_mod
        from warden.payments.authorize import AuthorizationResult
        monkeypatch.setattr(
            authz_mod, "authorize_payment",
            lambda *a, **k: AuthorizationResult(verdict="DENY", reasons=["budget=block:x"]),
        )
        engine = ClearingEngine(db_path=db)
        with pytest.raises(ValueError, match="not authorized"):
            engine.clear("neg-winner", "buyer-1")

    def test_require_approval_blocks_clearing(self, db, monkeypatch):
        monkeypatch.setenv("AUTHORIZE_PAYMENT_ENFORCED", "true")
        import warden.payments.authorize as authz_mod
        from warden.payments.authorize import AuthorizationResult
        monkeypatch.setattr(
            authz_mod, "authorize_payment",
            lambda *a, **k: AuthorizationResult(verdict="REQUIRE_APPROVAL",
                                                 reasons=["autonomy=REQUIRE_APPROVAL"]),
        )
        engine = ClearingEngine(db_path=db)
        with pytest.raises(ValueError, match="not authorized"):
            engine.clear("neg-winner", "buyer-1")

    def test_deny_leaves_other_negotiations_unrejected(self, db, monkeypatch):
        """A blocked clearing must not have already mutated sibling negotiations."""
        monkeypatch.setenv("AUTHORIZE_PAYMENT_ENFORCED", "true")
        import warden.payments.authorize as authz_mod
        from warden.payments.authorize import AuthorizationResult
        monkeypatch.setattr(
            authz_mod, "authorize_payment",
            lambda *a, **k: AuthorizationResult(verdict="DENY", reasons=["budget=block:x"]),
        )
        engine = ClearingEngine(db_path=db)
        with pytest.raises(ValueError):
            engine.clear("neg-winner", "buyer-1")

        con = sqlite3.connect(db)
        status = con.execute(
            "SELECT status FROM marketplace_negotiations WHERE negotiation_id='neg-loser'"
        ).fetchone()[0]
        con.close()
        assert status == "pending"   # NOT rejected — clearing never got that far

    def test_allow_permits_clearing(self, db, monkeypatch):
        monkeypatch.setenv("AUTHORIZE_PAYMENT_ENFORCED", "true")
        import warden.payments.authorize as authz_mod
        from warden.payments.authorize import AuthorizationResult
        monkeypatch.setattr(
            authz_mod, "authorize_payment",
            lambda *a, **k: AuthorizationResult(verdict="ALLOW", reasons=["autonomy=ALLOW"]),
        )
        engine = ClearingEngine(db_path=db)
        rec = engine.clear("neg-winner", "buyer-1")
        assert rec.clearing_id == "clear-neg-winner"

    def test_authorize_call_failure_fails_open(self, db, monkeypatch):
        """A bug in the authorization plumbing itself must not brick clearing."""
        monkeypatch.setenv("AUTHORIZE_PAYMENT_ENFORCED", "true")
        import warden.payments.authorize as authz_mod
        def _boom(*a, **k):
            raise RuntimeError("authorize_payment module exploded")
        monkeypatch.setattr(authz_mod, "authorize_payment", _boom)
        engine = ClearingEngine(db_path=db)
        rec = engine.clear("neg-winner", "buyer-1")
        assert rec.clearing_id == "clear-neg-winner"

    def test_replay_of_denied_clearing_reattempts_authorization(self, db, monkeypatch):
        """No row was ever written on DENY, so a retry re-checks (not a stuck replay)."""
        monkeypatch.setenv("AUTHORIZE_PAYMENT_ENFORCED", "true")
        import warden.payments.authorize as authz_mod
        from warden.payments.authorize import AuthorizationResult
        calls = {"n": 0}
        def _deny_once_then_allow(*a, **k):
            calls["n"] += 1
            if calls["n"] == 1:
                return AuthorizationResult(verdict="DENY", reasons=["budget=block:x"])
            return AuthorizationResult(verdict="ALLOW")
        monkeypatch.setattr(authz_mod, "authorize_payment", _deny_once_then_allow)

        engine = ClearingEngine(db_path=db)
        with pytest.raises(ValueError):
            engine.clear("neg-winner", "buyer-1")

        rec = engine.clear("neg-winner", "buyer-1")
        assert rec.replayed is False
        assert calls["n"] == 2

    def test_uses_kya_owner_tenant_when_available(self, db, monkeypatch):
        monkeypatch.setenv("AUTHORIZE_PAYMENT_ENFORCED", "true")
        import warden.marketplace.kya as kya_mod

        class _Rec:
            owner_tenant_id = "owner-tenant-42"
        monkeypatch.setattr(kya_mod, "get_kya_record", lambda agent_id: _Rec())

        captured = {}
        import warden.payments.authorize as authz_mod
        from warden.payments.authorize import AuthorizationResult
        def _capture(tenant_id, agent_id, action, amount_usd, **kw):
            captured["tenant_id"] = tenant_id
            captured["action"] = action
            return AuthorizationResult(verdict="ALLOW")
        monkeypatch.setattr(authz_mod, "authorize_payment", _capture)

        engine = ClearingEngine(db_path=db)
        engine.clear("neg-winner", "buyer-1")
        assert captured["tenant_id"] == "owner-tenant-42"
        assert captured["action"] == "clear"
