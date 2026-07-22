"""FT-6 — listing.py wiring into the authorize_payment() chokepoint.

Before this, purchase_listing() ran ZERO money-authorization checks. This
verifies the wiring is additive/opt-in: default-off behavior is unchanged,
and only a clean DENY/REQUIRE_APPROVAL verdict blocks a purchase once an
operator turns AUTHORIZE_PAYMENT_ENFORCED on.
"""
from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

import pytest

from warden.db.ddl_registry import ensure_schema
from warden.marketplace import listing


@pytest.fixture()
def db(tmp_path):
    path = str(tmp_path / "mkt.db")
    con = sqlite3.connect(path)
    ensure_schema(con, "marketplace", path)
    now = datetime.now(UTC).isoformat()
    con.execute(
        """INSERT INTO marketplace_listings
           (listing_id, asset_id, seller_agent, community_id, tenant_id,
            asset_type, price_usd, currency, pricing_strategy, status,
            demand_score, listed_at, chain)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        ("lst-1", "asset-1", "seller-1", "cid", "tenant-1",
         "rule", 9.99, "USD", "fixed", "active", 0.5, now, "sepolia"),
    )
    con.commit()
    con.close()
    return path


class TestAuthorizePurchaseWiringDisabled:
    def test_purchase_succeeds_unchanged_by_default(self, db):
        """AUTHORIZE_PAYMENT_ENFORCED is off by default — zero behavior change."""
        result = listing.purchase_listing("lst-1", "buyer-1", db_path=db)
        assert result["replayed"] is False
        assert result["purchase_id"]


class TestAuthorizePurchaseWiringEnabled:
    def test_deny_blocks_purchase(self, db, monkeypatch):
        monkeypatch.setenv("AUTHORIZE_PAYMENT_ENFORCED", "true")
        import warden.payments.authorize as authz_mod
        from warden.payments.authorize import AuthorizationResult
        monkeypatch.setattr(
            authz_mod, "authorize_payment",
            lambda *a, **k: AuthorizationResult(verdict="DENY", reasons=["budget=block:x"]),
        )
        with pytest.raises(ValueError, match="not authorized"):
            listing.purchase_listing("lst-1", "buyer-1", db_path=db)

    def test_require_approval_blocks_purchase(self, db, monkeypatch):
        monkeypatch.setenv("AUTHORIZE_PAYMENT_ENFORCED", "true")
        import warden.payments.authorize as authz_mod
        from warden.payments.authorize import AuthorizationResult
        monkeypatch.setattr(
            authz_mod, "authorize_payment",
            lambda *a, **k: AuthorizationResult(verdict="REQUIRE_APPROVAL",
                                                 reasons=["autonomy=REQUIRE_APPROVAL"]),
        )
        with pytest.raises(ValueError, match="not authorized"):
            listing.purchase_listing("lst-1", "buyer-1", db_path=db)

    def test_allow_permits_purchase(self, db, monkeypatch):
        monkeypatch.setenv("AUTHORIZE_PAYMENT_ENFORCED", "true")
        import warden.payments.authorize as authz_mod
        from warden.payments.authorize import AuthorizationResult
        monkeypatch.setattr(
            authz_mod, "authorize_payment",
            lambda *a, **k: AuthorizationResult(verdict="ALLOW", reasons=["autonomy=ALLOW"]),
        )
        result = listing.purchase_listing("lst-1", "buyer-1", db_path=db)
        assert result["purchase_id"]

    def test_authorize_call_failure_fails_open(self, db, monkeypatch):
        """A bug in the authorization plumbing itself must not brick purchases."""
        monkeypatch.setenv("AUTHORIZE_PAYMENT_ENFORCED", "true")
        import warden.payments.authorize as authz_mod
        def _boom(*a, **k):
            raise RuntimeError("authorize_payment module exploded")
        monkeypatch.setattr(authz_mod, "authorize_payment", _boom)
        result = listing.purchase_listing("lst-1", "buyer-1", db_path=db)
        assert result["purchase_id"]

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
            return AuthorizationResult(verdict="ALLOW")
        monkeypatch.setattr(authz_mod, "authorize_payment", _capture)

        listing.purchase_listing("lst-1", "buyer-1", db_path=db)
        assert captured["tenant_id"] == "owner-tenant-42"

    def test_falls_back_to_agent_id_without_kya(self, db, monkeypatch):
        monkeypatch.setenv("AUTHORIZE_PAYMENT_ENFORCED", "true")
        import warden.marketplace.kya as kya_mod
        monkeypatch.setattr(kya_mod, "get_kya_record", lambda agent_id: None)

        captured = {}
        import warden.payments.authorize as authz_mod
        from warden.payments.authorize import AuthorizationResult
        def _capture(tenant_id, agent_id, action, amount_usd, **kw):
            captured["tenant_id"] = tenant_id
            return AuthorizationResult(verdict="ALLOW")
        monkeypatch.setattr(authz_mod, "authorize_payment", _capture)

        listing.purchase_listing("lst-1", "buyer-1", db_path=db)
        assert captured["tenant_id"] == "buyer-1"
