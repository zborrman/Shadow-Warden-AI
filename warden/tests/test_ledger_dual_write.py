"""
FT-2 slice 2a — dual-run bridge (`warden/ledger/dual_write.py`) + spend_credits.

The bridge must be (1) gated — no ledger writes unless opted in, (2) fail-OPEN —
a ledger error never propagates to the live money path, and (3) reconcilable —
the ledger balance can be checked against an authoritative counter. Credits map
1 credit = 1000 µUSD.
"""
from __future__ import annotations

import pytest

from warden.config import settings
from warden.ledger import accounts, dual_write, journal, operations
from warden.ledger.money import Money


@pytest.fixture()
def db(tmp_path):
    return str(tmp_path / "ledger.db")


@pytest.fixture()
def dual_on(monkeypatch):
    monkeypatch.setattr(settings, "ledger_dual_write", True)


# ── spend_credits ─────────────────────────────────────────────────────────────
class TestSpendCredits:
    def test_spend_recognizes_revenue(self, db):
        operations.grant_credits("t1", Money.from_usd("5"), idempotency_key="g1", db_path=db)
        operations.spend_credits("t1", Money.from_usd("1"), idempotency_key="s1", db_path=db)
        assert journal.balance(accounts.tenant_credits("t1"), db_path=db) == Money.from_usd("4")
        assert journal.balance(accounts.platform_fees(), db_path=db) == Money.from_usd("1")

    def test_spend_nonpositive_rejected(self, db):
        with pytest.raises(journal.LedgerError):
            operations.spend_credits("t1", Money.zero(), idempotency_key="s0", db_path=db)


# ── Gating ────────────────────────────────────────────────────────────────────
class TestGating:
    def test_disabled_by_default(self, monkeypatch):
        monkeypatch.setattr(settings, "ledger_dual_write", False)
        assert dual_write.enabled() is False

    def test_mirror_noop_when_disabled(self, db, monkeypatch):
        monkeypatch.setattr(settings, "ledger_dual_write", False)
        dual_write.mirror("grant", operations.grant_credits, "t1", Money.from_usd("5"),
                          idempotency_key="g1", db_path=db)
        assert journal.balance(accounts.tenant_credits("t1"), db_path=db).is_zero()

    def test_mirror_applies_when_enabled(self, db, dual_on):
        dual_write.mirror("grant", operations.grant_credits, "t1", Money.from_usd("5"),
                          idempotency_key="g1", db_path=db)
        assert journal.balance(accounts.tenant_credits("t1"), db_path=db) == Money.from_usd("5")


# ── Fail-open ─────────────────────────────────────────────────────────────────
class TestFailOpen:
    def test_mirror_swallows_ledger_error(self, db, dual_on):
        before = dual_write.mirror_failure_count()
        # unbalanced/invalid op raises LedgerError inside — must NOT propagate
        dual_write.mirror(
            "bad", operations.spend_credits, "t1", Money.zero(),
            idempotency_key="x", db_path=db,
        )
        assert dual_write.mirror_failure_count() == before + 1  # counted, not raised

    def test_mirror_swallows_arbitrary_exception(self, dual_on):
        def boom():
            raise RuntimeError("kaboom")
        dual_write.mirror("boom", boom)  # no raise


# ── Reconciliation ────────────────────────────────────────────────────────────
class TestReconcile:
    def test_reconcile_ok_when_matching(self, db):
        # 5 credits granted (1 credit = 1000 µUSD) → ledger tenant:credits = 5000 µUSD.
        operations.grant_credits("t1", Money.from_micros(5 * 1000), idempotency_key="g1", db_path=db)
        counter_credits = 5
        rep = dual_write.reconcile(accounts.tenant_credits("t1"), counter_credits * 1000, db_path=db)
        assert rep["ok"] is True
        assert rep["drift_micros"] == 0

    def test_reconcile_detects_drift(self, db):
        operations.grant_credits("t1", Money.from_micros(5 * 1000), idempotency_key="g1", db_path=db)
        rep = dual_write.reconcile(accounts.tenant_credits("t1"), 4 * 1000, db_path=db)
        assert rep["ok"] is False
        assert rep["drift_micros"] == 1000  # ledger 5000 − counter 4000
