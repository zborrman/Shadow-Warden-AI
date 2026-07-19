"""
FT-1 (follow-on) — two-phase holds + materialized rollup (`warden/ledger/`).

Holds are the SAC-preflight reserve→capture/void defence in double-entry form;
the load-bearing properties are conservation (each phase balances, the whole
ledger stays at zero) and idempotency of every phase. Rollup is a journal-derived
cache that must always agree with `journal.balance()`.
"""
from __future__ import annotations

import pytest

from warden.ledger import accounts, holds, journal, rollup
from warden.ledger.journal import Posting
from warden.ledger.money import Money


@pytest.fixture()
def db(tmp_path):
    return str(tmp_path / "ledger.db")


def _fund(db, tenant, usd):
    """Top up tenant:cash to +usd (balanced against a processor receivable)."""
    journal.post(
        f"topup-{tenant}", "topup",
        [Posting(accounts.tenant_cash(tenant), Money.from_usd(usd)),
         Posting(accounts.processor_clearing("stripe"), Money.from_usd(f"-{usd}"))],
        db_path=db,
    )


def _ledger_total(db, *accts):
    total = Money.zero()
    for a in accts:
        total += journal.balance(a, db_path=db)
    return total


# ── Holds: reserve ────────────────────────────────────────────────────────────
class TestReserve:
    def test_reserve_moves_funds_into_hold(self, db):
        _fund(db, "t1", "20")
        h = holds.reserve("h1", accounts.tenant_cash("t1"), Money.from_usd("10"), db_path=db)
        assert h.status == holds.HELD
        assert journal.balance(accounts.tenant_cash("t1"), db_path=db) == Money.from_usd("10")
        assert journal.balance(accounts.hold("h1"), db_path=db) == Money.from_usd("10")

    def test_reserve_idempotent(self, db):
        _fund(db, "t1", "20")
        a = holds.reserve("h1", accounts.tenant_cash("t1"), Money.from_usd("10"), db_path=db)
        b = holds.reserve("h1", accounts.tenant_cash("t1"), Money.from_usd("10"), db_path=db)
        assert a.reserve_tx == b.reserve_tx
        # not double-moved
        assert journal.balance(accounts.hold("h1"), db_path=db) == Money.from_usd("10")

    def test_reserve_nonpositive_rejected(self, db):
        with pytest.raises(holds.HoldError):
            holds.reserve("h1", accounts.tenant_cash("t1"), Money.zero(), db_path=db)


# ── Holds: capture ────────────────────────────────────────────────────────────
class TestCapture:
    def test_capture_charges_actual_refunds_rest(self, db):
        _fund(db, "t1", "20")
        holds.reserve("h1", accounts.tenant_cash("t1"), Money.from_usd("10"), db_path=db)
        h = holds.capture("h1", accounts.platform_fees(), Money.from_usd("3"), db_path=db)
        assert h.status == holds.CAPTURED
        assert journal.balance(accounts.hold("h1"), db_path=db).is_zero()
        assert journal.balance(accounts.platform_fees(), db_path=db) == Money.from_usd("3")
        assert journal.balance(accounts.tenant_cash("t1"), db_path=db) == Money.from_usd("17")
        # whole ledger conserves
        assert _ledger_total(
            db, accounts.tenant_cash("t1"), accounts.hold("h1"),
            accounts.platform_fees(), accounts.processor_clearing("stripe"),
        ).is_zero()

    def test_capture_full_amount_no_refund(self, db):
        _fund(db, "t1", "20")
        holds.reserve("h1", accounts.tenant_cash("t1"), Money.from_usd("10"), db_path=db)
        holds.capture("h1", accounts.platform_fees(), Money.from_usd("10"), db_path=db)
        assert journal.balance(accounts.platform_fees(), db_path=db) == Money.from_usd("10")
        assert journal.balance(accounts.tenant_cash("t1"), db_path=db) == Money.from_usd("10")

    def test_capture_zero_full_refund(self, db):
        _fund(db, "t1", "20")
        holds.reserve("h1", accounts.tenant_cash("t1"), Money.from_usd("10"), db_path=db)
        holds.capture("h1", accounts.platform_fees(), Money.zero(), db_path=db)
        assert journal.balance(accounts.platform_fees(), db_path=db).is_zero()
        assert journal.balance(accounts.tenant_cash("t1"), db_path=db) == Money.from_usd("20")

    def test_capture_idempotent(self, db):
        _fund(db, "t1", "20")
        holds.reserve("h1", accounts.tenant_cash("t1"), Money.from_usd("10"), db_path=db)
        a = holds.capture("h1", accounts.platform_fees(), Money.from_usd("3"), db_path=db)
        b = holds.capture("h1", accounts.platform_fees(), Money.from_usd("3"), db_path=db)
        assert a.complete_tx == b.complete_tx
        assert journal.balance(accounts.platform_fees(), db_path=db) == Money.from_usd("3")

    def test_capture_over_held_rejected(self, db):
        _fund(db, "t1", "20")
        holds.reserve("h1", accounts.tenant_cash("t1"), Money.from_usd("10"), db_path=db)
        with pytest.raises(holds.HoldError):
            holds.capture("h1", accounts.platform_fees(), Money.from_usd("11"), db_path=db)

    def test_capture_after_void_rejected(self, db):
        _fund(db, "t1", "20")
        holds.reserve("h1", accounts.tenant_cash("t1"), Money.from_usd("10"), db_path=db)
        holds.void("h1", db_path=db)
        with pytest.raises(holds.HoldError):
            holds.capture("h1", accounts.platform_fees(), Money.from_usd("1"), db_path=db)

    def test_capture_unknown_hold(self, db):
        with pytest.raises(holds.HoldError):
            holds.capture("nope", accounts.platform_fees(), Money.zero(), db_path=db)


# ── Holds: void ───────────────────────────────────────────────────────────────
class TestVoid:
    def test_void_full_refund(self, db):
        _fund(db, "t1", "20")
        holds.reserve("h1", accounts.tenant_cash("t1"), Money.from_usd("10"), db_path=db)
        h = holds.void("h1", db_path=db)
        assert h.status == holds.VOIDED
        assert journal.balance(accounts.hold("h1"), db_path=db).is_zero()
        assert journal.balance(accounts.tenant_cash("t1"), db_path=db) == Money.from_usd("20")

    def test_void_idempotent(self, db):
        _fund(db, "t1", "20")
        holds.reserve("h1", accounts.tenant_cash("t1"), Money.from_usd("10"), db_path=db)
        a = holds.void("h1", db_path=db)
        b = holds.void("h1", db_path=db)
        assert a.complete_tx == b.complete_tx

    def test_void_after_capture_rejected(self, db):
        _fund(db, "t1", "20")
        holds.reserve("h1", accounts.tenant_cash("t1"), Money.from_usd("10"), db_path=db)
        holds.capture("h1", accounts.platform_fees(), Money.from_usd("3"), db_path=db)
        with pytest.raises(holds.HoldError):
            holds.void("h1", db_path=db)


# ── Rollup ────────────────────────────────────────────────────────────────────
class TestRollup:
    def test_refresh_materializes_journal_balance(self, db):
        _fund(db, "t1", "15")
        acct = accounts.tenant_cash("t1")
        assert rollup.materialized_balance(acct, db_path=db) is None
        mat = rollup.refresh(acct, db_path=db)
        assert mat == journal.balance(acct, db_path=db) == Money.from_usd("15")
        assert rollup.materialized_balance(acct, db_path=db) == Money.from_usd("15")

    def test_balance_miss_computes_live_then_materializes(self, db):
        _fund(db, "t1", "15")
        acct = accounts.tenant_cash("t1")
        assert rollup.balance(acct, db_path=db) == Money.from_usd("15")   # miss → live+materialize
        assert rollup.materialized_balance(acct, db_path=db) == Money.from_usd("15")

    def test_refresh_updates_after_new_posting(self, db):
        _fund(db, "t1", "15")
        acct = accounts.tenant_cash("t1")
        rollup.refresh(acct, db_path=db)
        holds.reserve("h1", acct, Money.from_usd("5"), db_path=db)  # cash 15 → 10
        # stale until refreshed
        assert rollup.materialized_balance(acct, db_path=db) == Money.from_usd("15")
        assert rollup.refresh(acct, db_path=db) == Money.from_usd("10")
        assert rollup.balance(acct, db_path=db) == Money.from_usd("10")

    def test_refresh_all_counts_accounts(self, db):
        _fund(db, "t1", "10")
        _fund(db, "t2", "10")
        n = rollup.refresh_all(db_path=db)
        # tenant:t1:cash, tenant:t2:cash, processor:stripe:clearing
        assert n == 3
