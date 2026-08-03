"""FT-6 prerequisite — the autonomy policy an agent gets when it passes KYA.

Before this, nothing in the codebase ever called `set_policy()` except an admin
endpoint. `check_action()` treats "no policy" as L1 REQUIRE_APPROVAL (the correct
safe default for an unknown agent), so every agent was permanently at L1 and
`AUTHORIZE_PAYMENT_ENFORCED=true` blocked 100% of purchases and clearings.

These tests pin the onboarding grant and, just as importantly, the things it must
NOT do: grant to unscreened agents, overwrite an operator's policy, or survive
revocation.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MARKETPLACE_DB_PATH", str(tmp_path / "mkt.db"))
    monkeypatch.setenv("REDIS_URL", "memory://")


class TestDefaultPolicyShape:
    def test_default_is_l2_supervised(self):
        from warden.marketplace.autonomy import build_default_policy
        pol = build_default_policy("did:shadow:a1")
        assert pol.level == 2, "L1 would mean 'verified agent can still do nothing'"

    def test_purchase_is_an_allowed_action(self):
        """listing.py passes the literal action 'purchase' to authorize_payment()."""
        from warden.marketplace.autonomy import build_default_policy
        assert "purchase" in build_default_policy("did:shadow:a1").allowed_actions

    def test_clear_is_an_allowed_action(self):
        """clearing.py passes the literal action 'clear'."""
        from warden.marketplace.autonomy import build_default_policy
        assert "clear" in build_default_policy("did:shadow:a1").allowed_actions

    def test_thresholds_are_env_tunable(self, monkeypatch):
        from warden.marketplace.autonomy import build_default_policy
        monkeypatch.setenv("KYA_DEFAULT_APPROVAL_ABOVE_USD", "2.50")
        monkeypatch.setenv("KYA_DEFAULT_DAILY_USD", "42.0")
        pol = build_default_policy("did:shadow:a1")
        assert pol.require_approval_above_usd == 2.50
        assert pol.daily_spend_usd == 42.0

    def test_malformed_env_falls_back_rather_than_raising(self, monkeypatch):
        from warden.marketplace.autonomy import build_default_policy
        monkeypatch.setenv("KYA_DEFAULT_APPROVAL_ABOVE_USD", "not-a-number")
        monkeypatch.setenv("KYA_DEFAULT_AUTONOMY_LEVEL", "banana")
        pol = build_default_policy("did:shadow:a1")
        assert pol.level == 2
        assert pol.require_approval_above_usd == 10.0

    def test_out_of_range_level_falls_back_to_two(self, monkeypatch):
        from warden.marketplace.autonomy import build_default_policy
        monkeypatch.setenv("KYA_DEFAULT_AUTONOMY_LEVEL", "7")
        assert build_default_policy("did:shadow:a1").level == 2


class TestEnsureDefaultPolicy:
    def test_grants_when_absent(self):
        from warden.marketplace.autonomy import ensure_default_policy, get_policy
        assert ensure_default_policy("did:shadow:new") is True
        assert get_policy("did:shadow:new") is not None

    def test_never_overwrites_an_operator_policy(self):
        """An explicit lock-down to L1 must survive the onboarding grant."""
        from warden.marketplace.autonomy import (
            AutonomyPolicy,
            ensure_default_policy,
            get_policy,
            set_policy,
        )
        set_policy(AutonomyPolicy("did:shadow:locked", 1, 0.0, 0.0, created_by="ops"))
        assert ensure_default_policy("did:shadow:locked") is False
        pol = get_policy("did:shadow:locked")
        assert pol.level == 1
        assert pol.created_by == "ops"

    def test_disabled_by_level_zero(self, monkeypatch):
        from warden.marketplace.autonomy import ensure_default_policy, get_policy
        monkeypatch.setenv("KYA_DEFAULT_AUTONOMY_LEVEL", "0")
        assert ensure_default_policy("did:shadow:off") is False
        assert get_policy("did:shadow:off") is None

    def test_is_idempotent(self):
        from warden.marketplace.autonomy import ensure_default_policy
        assert ensure_default_policy("did:shadow:twice") is True
        assert ensure_default_policy("did:shadow:twice") is False


class TestKYALifecycle:
    def test_registration_alone_grants_nothing(self):
        """PENDING is not verified — no spend rights until screening passes."""
        from warden.marketplace.autonomy import get_policy
        from warden.marketplace.kya import register_agent
        register_agent("did:shadow:pending", "tenant-1")
        assert get_policy("did:shadow:pending") is None

    def test_screening_to_verified_grants_policy(self):
        from warden.marketplace.autonomy import get_policy
        from warden.marketplace.kya import register_agent, screen_agent
        register_agent("did:shadow:ok", "tenant-1")
        rec = screen_agent("did:shadow:ok")
        assert rec.kya_status == "VERIFIED"
        assert get_policy("did:shadow:ok") is not None

    def test_revoke_drops_the_policy(self):
        """check_action() reads the policy, not the KYA status — a revoked agent
        holding a stale policy would keep its spend rights."""
        from warden.marketplace.autonomy import get_policy
        from warden.marketplace.kya import register_agent, revoke_agent, screen_agent
        register_agent("did:shadow:bye", "tenant-1")
        screen_agent("did:shadow:bye")
        assert get_policy("did:shadow:bye") is not None
        revoke_agent("did:shadow:bye", "test")
        assert get_policy("did:shadow:bye") is None

    def test_screening_failure_does_not_break_kya(self, monkeypatch):
        """The grant is fail-soft: losing it leaves the agent at L1, not broken."""
        import warden.marketplace.autonomy as autonomy_mod
        from warden.marketplace.kya import register_agent, screen_agent

        def boom(*a, **kw):
            raise RuntimeError("policy store down")

        monkeypatch.setattr(autonomy_mod, "set_policy", boom)
        register_agent("did:shadow:soft", "tenant-1")
        rec = screen_agent("did:shadow:soft")
        assert rec.kya_status == "VERIFIED"   # screening still succeeded


class TestEnforcementNowUsable:
    """The point of the slice: AUTHORIZE_PAYMENT_ENFORCED=true must stop being a
    kill switch for verified agents while still blocking everyone else."""

    def _listing(self, db, listing_id, price=5.0):
        import sqlite3
        from datetime import UTC, datetime

        from warden.db.ddl_registry import ensure_schema
        con = sqlite3.connect(db)
        ensure_schema(con, "marketplace", db)
        con.execute(
            """INSERT INTO marketplace_listings (listing_id, asset_id, seller_agent,
               community_id, tenant_id, asset_type, price_usd, currency,
               pricing_strategy, status, demand_score, listed_at, chain)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (listing_id, "a1", "seller", "cid", "t1", "rule", price, "USD",
             "fixed", "active", 0.5, datetime.now(UTC).isoformat(), "sepolia"),
        )
        con.commit()
        con.close()

    def test_verified_agent_can_purchase_under_enforcement(self, tmp_path, monkeypatch):
        from warden.marketplace import listing
        from warden.marketplace.kya import register_agent, screen_agent
        db = str(tmp_path / "mkt.db")
        self._listing(db, "lst-ok")
        monkeypatch.setenv("AUTHORIZE_PAYMENT_ENFORCED", "true")
        register_agent("did:shadow:buyer", "tenant-1")
        screen_agent("did:shadow:buyer")
        result = listing.purchase_listing("lst-ok", "did:shadow:buyer",
                                          db_path=db, idempotency_key="k1")
        assert result["purchase_id"]

    def test_unverified_agent_still_blocked(self, tmp_path, monkeypatch):
        from warden.marketplace import listing
        db = str(tmp_path / "mkt.db")
        self._listing(db, "lst-no")
        monkeypatch.setenv("AUTHORIZE_PAYMENT_ENFORCED", "true")
        with pytest.raises(ValueError, match="not authorized"):
            listing.purchase_listing("lst-no", "did:shadow:stranger",
                                     db_path=db, idempotency_key="k2")

    def test_spend_above_threshold_still_requires_approval(self, tmp_path, monkeypatch):
        """The grant is L2, not a blank cheque — big spends still route to a human."""
        from warden.marketplace import listing
        from warden.marketplace.kya import register_agent, screen_agent
        db = str(tmp_path / "mkt.db")
        self._listing(db, "lst-big", price=9_999.0)
        monkeypatch.setenv("AUTHORIZE_PAYMENT_ENFORCED", "true")
        monkeypatch.setenv("KYA_DEFAULT_APPROVAL_ABOVE_USD", "10.0")
        register_agent("did:shadow:whale", "tenant-1")
        screen_agent("did:shadow:whale")
        with pytest.raises(ValueError, match="not authorized"):
            listing.purchase_listing("lst-big", "did:shadow:whale",
                                     db_path=db, idempotency_key="k3")
