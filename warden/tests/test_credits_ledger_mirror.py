"""
FT-2 slice 2b — marketplace/credits.py mirrors into the ledger (dual-run).

Verifies the WIRING: with dual-write on, a credit grant/deduct calls the matching
ledger operation with the right µUSD amount (1 credit = 1000 µUSD); with it off
(default) nothing is mirrored; and in every case the credit path's own behaviour
and return values are unchanged, even if the ledger op raises. (Ledger-balance
reconciliation itself is covered by test_ledger_dual_write.py.)
"""
from __future__ import annotations

import pytest

from warden.config import settings
from warden.ledger import operations
from warden.ledger.money import Money
from warden.marketplace import credits


@pytest.fixture()
def iso_credits(tmp_path, monkeypatch):
    # Isolate the credits SQLite file; REDIS_URL=memory:// (conftest) → SQLite path.
    monkeypatch.setattr(credits, "_DB_PATH", str(tmp_path / "mkt.db"))


@pytest.fixture()
def captured_ops(monkeypatch):
    calls: list[tuple[str, str, Money]] = []

    def _grant(tenant_id, amount, *, idempotency_key, db_path=None):
        calls.append(("grant", tenant_id, amount))

    def _spend(tenant_id, amount, *, idempotency_key, db_path=None):
        calls.append(("spend", tenant_id, amount))

    monkeypatch.setattr(operations, "grant_credits", _grant)
    monkeypatch.setattr(operations, "spend_credits", _spend)
    return calls


@pytest.fixture()
def dual_on(monkeypatch):
    monkeypatch.setattr(settings, "ledger_dual_write", True)


@pytest.fixture()
def dual_off(monkeypatch):
    monkeypatch.setattr(settings, "ledger_dual_write", False)


class TestMirrorWhenEnabled:
    def test_purchase_mirrors_grant(self, iso_credits, captured_ops, dual_on):
        bal = credits.purchase_credits("t1", "credits_100")
        assert bal == 100
        assert captured_ops == [("grant", "t1", Money.from_micros(100 * 1000))]

    def test_deduct_mirrors_spend(self, iso_credits, captured_ops, dual_on):
        credits.purchase_credits("t1", "credits_100")
        ok = credits.deduct_credits("t1", 5)
        assert ok is True
        assert ("spend", "t1", Money.from_micros(5 * 1000)) in captured_ops

    def test_amount_maps_credits_to_micros(self, iso_credits, captured_ops, dual_on):
        credits.purchase_credits("t1", "credits_1000")  # 1000 credits
        _, _, amount = captured_ops[0]
        assert amount == Money.from_micros(1000 * 1000)  # == $1.00


class TestNoMirrorWhenDisabled:
    def test_purchase_no_mirror(self, iso_credits, captured_ops, dual_off):
        bal = credits.purchase_credits("t1", "credits_100")
        assert bal == 100          # credit path works normally
        assert captured_ops == []  # nothing mirrored

    def test_deduct_no_mirror(self, iso_credits, captured_ops, dual_off):
        credits.purchase_credits("t1", "credits_100")
        assert credits.deduct_credits("t1", 5) is True
        assert captured_ops == []


class TestBehaviorNeutral:
    def test_balance_unchanged_by_mirroring(self, iso_credits, dual_on):
        credits.purchase_credits("t1", "credits_100")
        credits.deduct_credits("t1", 5)
        assert credits.get_balance("t1") == 95

    def test_insufficient_balance_not_mirrored(self, iso_credits, captured_ops, dual_on):
        credits.purchase_credits("t1", "credits_100")
        captured_ops.clear()
        ok = credits.deduct_credits("t1", 500)  # more than balance
        assert ok is False
        assert captured_ops == []  # a failed deduct mirrors nothing

    def test_mirror_failure_never_breaks_credits(self, iso_credits, dual_on, monkeypatch):
        def _boom(*a, **k):
            raise RuntimeError("ledger down")
        monkeypatch.setattr(operations, "grant_credits", _boom)
        # purchase must still succeed despite the ledger op raising
        assert credits.purchase_credits("t1", "credits_100") == 100
        assert credits.get_balance("t1") == 100
