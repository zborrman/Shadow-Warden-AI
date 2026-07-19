"""
FT-2 — canonical money flows (`warden/ledger/operations.py`).

Each operation must be a balanced, idempotent journal transaction; the suite
checks the resulting balances, whole-ledger conservation, and that a replayed
idempotency key moves value at most once.
"""
from __future__ import annotations

from decimal import Decimal

import pytest

from warden.ledger import accounts, journal, operations
from warden.ledger.money import Money


@pytest.fixture()
def db(tmp_path):
    return str(tmp_path / "ledger.db")


def _total(db, *accts):
    t = Money.zero()
    for a in accts:
        t += journal.balance(a, db_path=db)
    return t


class TestTopup:
    def test_topup_balances(self, db):
        operations.topup("t1", Money.from_usd("10"), idempotency_key="tp-1", db_path=db)
        assert journal.balance(accounts.tenant_cash("t1"), db_path=db) == Money.from_usd("10")
        assert journal.balance(accounts.processor_clearing("stripe"), db_path=db) == Money.from_usd("-10")

    def test_topup_idempotent(self, db):
        a = operations.topup("t1", Money.from_usd("10"), idempotency_key="tp-1", db_path=db)
        b = operations.topup("t1", Money.from_usd("10"), idempotency_key="tp-1", db_path=db)
        assert b.tx_id == a.tx_id and b.replayed
        assert journal.balance(accounts.tenant_cash("t1"), db_path=db) == Money.from_usd("10")

    def test_topup_nonpositive_rejected(self, db):
        with pytest.raises(journal.LedgerError):
            operations.topup("t1", Money.zero(), idempotency_key="tp-0", db_path=db)


class TestGrants:
    def test_grant_trial(self, db):
        operations.grant_trial("t1", Money.from_usd("10"), idempotency_key="tr-1", db_path=db)
        assert journal.balance(accounts.promo_trial("t1"), db_path=db) == Money.from_usd("10")
        assert journal.balance(accounts.platform_promo_expense(), db_path=db) == Money.from_usd("-10")

    def test_grant_bonus(self, db):
        operations.grant_bonus("t1", Money.from_usd("1.50"), idempotency_key="bo-1", db_path=db)
        assert journal.balance(accounts.promo_bonus("t1"), db_path=db) == Money.from_usd("1.50")

    def test_grant_credits(self, db):
        operations.grant_credits("t1", Money.from_usd("5"), idempotency_key="cr-1", db_path=db)
        assert journal.balance(accounts.tenant_credits("t1"), db_path=db) == Money.from_usd("5")
        assert journal.balance(accounts.processor_clearing("stripe"), db_path=db) == Money.from_usd("-5")


class TestPurchase:
    def test_purchase_fee_split(self, db):
        operations.topup("buyer", Money.from_usd("100"), idempotency_key="tp-b", db_path=db)
        operations.purchase("buyer", "seller", Money.from_usd("100"), Decimal("0.015"),
                            idempotency_key="pur-1", db_path=db)
        assert journal.balance(accounts.tenant_cash("seller"), db_path=db) == Money.from_usd("98.50")
        assert journal.balance(accounts.platform_fees(), db_path=db) == Money.from_usd("1.50")
        assert journal.balance(accounts.tenant_cash("buyer"), db_path=db) == Money.zero()

    def test_purchase_zero_fee(self, db):
        operations.purchase("buyer", "seller", Money.from_usd("10"), Decimal("0"),
                            idempotency_key="pur-0", db_path=db)
        assert journal.balance(accounts.tenant_cash("seller"), db_path=db) == Money.from_usd("10")
        assert journal.balance(accounts.platform_fees(), db_path=db).is_zero()

    def test_purchase_same_party_rejected(self, db):
        with pytest.raises(journal.LedgerError):
            operations.purchase("t1", "t1", Money.from_usd("10"), Decimal("0.015"),
                                idempotency_key="pur-x", db_path=db)

    def test_purchase_conserves_whole_ledger(self, db):
        operations.topup("buyer", Money.from_usd("100"), idempotency_key="tp-b", db_path=db)
        operations.purchase("buyer", "seller", Money.from_usd("40"), Decimal("0.025"),
                            idempotency_key="pur-c", db_path=db)
        total = _total(
            db, accounts.tenant_cash("buyer"), accounts.tenant_cash("seller"),
            accounts.platform_fees(), accounts.processor_clearing("stripe"),
        )
        assert total.is_zero()


class TestHoldReExports:
    def test_reserve_capture_via_operations(self, db):
        operations.topup("t1", Money.from_usd("20"), idempotency_key="tp-1", db_path=db)
        operations.reserve("h1", accounts.tenant_cash("t1"), Money.from_usd("10"), db_path=db)
        operations.capture("h1", accounts.platform_fees(), Money.from_usd("4"), db_path=db)
        assert journal.balance(accounts.platform_fees(), db_path=db) == Money.from_usd("4")
        assert journal.balance(accounts.tenant_cash("t1"), db_path=db) == Money.from_usd("16")
