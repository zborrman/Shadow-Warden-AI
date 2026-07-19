"""
FT-1 — double-entry journal + chart of accounts (`warden/ledger/`).

The load-bearing invariants: conservation (every transaction balances, and the
whole ledger sums to zero), idempotency (a replayed key posts nothing new), and
tamper-evidence (mutating a posting breaks the SHA-256 chain). Property coverage
uses deterministic seeded loops (the repo has no `hypothesis` dependency).
"""
from __future__ import annotations

import random

import pytest

from warden.ledger import accounts, journal
from warden.ledger.journal import LedgerError, Posting
from warden.ledger.money import Money


@pytest.fixture()
def db(tmp_path):
    return str(tmp_path / "ledger.db")


# ── Chart of accounts ─────────────────────────────────────────────────────────
class TestAccounts:
    def test_canonical_constructors(self):
        assert accounts.tenant_cash("t1") == "tenant:t1:cash"
        assert accounts.promo_bonus("t1") == "promo:t1:bonus"
        assert accounts.hold("h9") == "hold:h9"
        assert accounts.platform_fees() == "platform:fees"
        assert accounts.processor_clearing("stripe") == "processor:stripe:clearing"

    def test_parse_roundtrip(self):
        ns, owner, leaf = accounts.parse("tenant:t1:cash")
        assert (ns, owner, leaf) == (accounts.Namespace.TENANT, "t1", "cash")

    def test_unknown_namespace_rejected(self):
        with pytest.raises(accounts.AccountError):
            accounts.validate("wallet:t1:cash")

    def test_malformed_rejected(self):
        for bad in ["", "tenant", "tenant:t1:cash:extra", "tenant::cash", ":t1:cash"]:
            with pytest.raises(accounts.AccountError):
                accounts.validate(bad)

    def test_normal_side(self):
        assert accounts.normal_side("tenant:t1:cash") == accounts.Side.CREDIT
        assert accounts.normal_side("processor:stripe:clearing") == accounts.Side.DEBIT


# ── Posting validation ────────────────────────────────────────────────────────
class TestPosting:
    def test_posting_validates_account(self):
        with pytest.raises(accounts.AccountError):
            Posting("nope:x", Money.from_usd("1"))

    def test_posting_requires_money(self):
        with pytest.raises(LedgerError):
            Posting("tenant:t1:cash", 100)  # type: ignore[arg-type]


# ── Journal: balance & conservation ───────────────────────────────────────────
class TestPostBalance:
    def test_simple_topup_balances(self, db):
        # processor pays in $10 → tenant cash credited $10 (double-entry, sums to 0)
        tx = journal.post(
            "idem-topup-1", "topup",
            [
                Posting(accounts.processor_clearing("stripe"), Money.from_usd("10")),
                Posting(accounts.tenant_cash("t1"), Money.from_usd("-10")),
            ],
            db_path=db,
        )
        assert tx.seq == 1
        assert tx.prev_hash == "0" * 64
        assert not tx.replayed
        assert journal.balance(accounts.tenant_cash("t1"), db_path=db) == Money.from_usd("-10")
        assert journal.balance(accounts.processor_clearing("stripe"), db_path=db) == Money.from_usd("10")

    def test_unbalanced_rejected(self, db):
        with pytest.raises(LedgerError, match="do not balance"):
            journal.post(
                "idem-bad", "topup",
                [
                    Posting(accounts.tenant_cash("t1"), Money.from_usd("10")),
                    Posting(accounts.platform_fees(), Money.from_usd("-9")),
                ],
                db_path=db,
            )

    def test_single_posting_rejected(self, db):
        with pytest.raises(LedgerError, match="at least two"):
            journal.post("idem-1p", "x", [Posting(accounts.tenant_cash("t1"), Money.zero())], db_path=db)

    def test_empty_idempotency_key_rejected(self, db):
        with pytest.raises(LedgerError, match="idempotency_key"):
            journal.post("  ", "x", [
                Posting(accounts.tenant_cash("t1"), Money.from_usd("1")),
                Posting(accounts.platform_fees(), Money.from_usd("-1")),
            ], db_path=db)

    def test_fee_split_conserves_in_ledger(self, db):
        # $100 purchase: buyer cash −100 → seller cash +98.50 + platform fee +1.50
        fee, net = Money.from_usd("100").split_fee(__import__("decimal").Decimal("0.015"))
        journal.post(
            "idem-purchase-1", "purchase",
            [
                Posting(accounts.tenant_cash("buyer"), Money.from_usd("-100")),
                Posting(accounts.tenant_cash("seller"), net),
                Posting(accounts.platform_fees(), fee),
            ],
            db_path=db,
        )
        assert journal.balance(accounts.tenant_cash("seller"), db_path=db) == Money.from_usd("98.50")
        assert journal.balance(accounts.platform_fees(), db_path=db) == Money.from_usd("1.50")


# ── Idempotency ────────────────────────────────────────────────────────────────
class TestIdempotency:
    def test_replay_returns_original_posts_nothing(self, db):
        acct = accounts.tenant_cash("t1")
        postings = [Posting(acct, Money.from_usd("5")), Posting(accounts.platform_fees(), Money.from_usd("-5"))]
        first = journal.post("idem-X", "grant", postings, db_path=db)
        second = journal.post("idem-X", "grant", postings, db_path=db)
        assert second.tx_id == first.tx_id
        assert second.replayed is True
        assert first.replayed is False
        # balance reflects ONE posting, not two
        assert journal.balance(acct, db_path=db) == Money.from_usd("5")


# ── Conservation property ─────────────────────────────────────────────────────
class TestConservationProperty:
    def test_whole_ledger_sums_to_zero(self, db):
        rng = random.Random(4242)
        accts = [accounts.tenant_cash(f"t{i}") for i in range(5)] + [accounts.platform_fees()]
        for n in range(300):
            a, b = rng.sample(accts, 2)
            amt = Money.from_micros(rng.randint(1, 10**9))
            journal.post(
                f"idem-{n}", "xfer",
                [Posting(a, amt), Posting(b, -amt)],
                db_path=db,
            )
        # I1/I7: the signed sum of ALL account balances is exactly zero.
        total = Money.zero()
        for acct in accts:
            total += journal.balance(acct, db_path=db)
        assert total.is_zero()


# ── Tamper-evidence ────────────────────────────────────────────────────────────
class TestChainIntegrity:
    def test_chain_verifies_clean(self, db):
        for n in range(5):
            amt = Money.from_usd("1")
            journal.post(f"idem-{n}", "xfer", [
                Posting(accounts.tenant_cash("t1"), amt),
                Posting(accounts.platform_fees(), -amt),
            ], db_path=db)
        ok, broken = journal.verify_chain(db_path=db)
        assert ok is True and broken is None

    def test_tampered_posting_breaks_chain(self, db):
        for n in range(3):
            amt = Money.from_usd("1")
            journal.post(f"idem-{n}", "xfer", [
                Posting(accounts.tenant_cash("t1"), amt),
                Posting(accounts.platform_fees(), -amt),
            ], db_path=db)
        # Mutate a stored posting amount directly (bypassing the API).
        with journal._conn(db) as con:
            con.execute("UPDATE ledger_postings SET amount_micros = amount_micros + 1 "
                        "WHERE tx_id = (SELECT tx_id FROM ledger_transactions WHERE seq=2)")
        ok, broken = journal.verify_chain(db_path=db)
        assert ok is False
        assert broken == 2
