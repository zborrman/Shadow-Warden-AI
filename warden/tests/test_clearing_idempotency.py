"""
FT-3 slice 3a — ClearingEngine idempotency (`warden/marketplace/clearing.py`).

The bug: `clearing_id = str(uuid.uuid4())` minted a fresh row on every call, and
`INSERT OR REPLACE` masked it (each row had a unique PK, so nothing ever
collided) — a retried `POST /clear` silently double-cleared: a second
auto-reject pass and a second platform_fee_usd/seller_net_usd row for the same
negotiation. `clearing_id` is now derived deterministically from
`winner_neg_id` (a negotiation clears exactly once), so a replay returns the
original record and re-runs nothing.
"""
from __future__ import annotations

import sqlite3

import pytest

from warden.marketplace.clearing import ClearingEngine
from warden.tests.marketplace_schema import create_marketplace_schema, seed_negotiation


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "mkt.db")
    create_marketplace_schema(path)
    seed_negotiation(path, "neg-winner", status="active", price=100.0)
    seed_negotiation(path, "neg-loser", status="pending", price=90.0)
    return path


class TestDeterministicClearingId:
    def test_clearing_id_derived_from_winner(self, db):
        rec = ClearingEngine(db_path=db).clear("neg-winner", "buyer-1")
        assert rec.clearing_id == "clear-neg-winner"
        assert rec.replayed is False


class TestIdempotentReplay:
    def test_retry_returns_same_record_no_new_row(self, db):
        engine = ClearingEngine(db_path=db)
        first = engine.clear("neg-winner", "buyer-1")
        second = engine.clear("neg-winner", "buyer-1")

        assert second.clearing_id == first.clearing_id
        assert second.cleared_at == first.cleared_at          # NOT recomputed
        assert second.platform_fee_usd == first.platform_fee_usd
        assert second.replayed is True
        assert first.replayed is False

        con = sqlite3.connect(db)
        n = con.execute(
            "SELECT COUNT(*) FROM marketplace_clearing_log WHERE winner_neg_id=?",
            ("neg-winner",),
        ).fetchone()[0]
        con.close()
        assert n == 1   # exactly one row, not two

    def test_retry_does_not_double_reject(self, db):
        engine = ClearingEngine(db_path=db)
        first = engine.clear("neg-winner", "buyer-1")
        assert first.rejected_neg_ids == ["neg-loser"]

        # Second call: the loser is already 'cleared_by_market', so a second
        # (skipped) reject pass would find nothing anyway — but we must not
        # even attempt it, and the returned record reflects the ORIGINAL pass.
        second = engine.clear("neg-winner", "buyer-1")
        assert second.rejected_neg_ids == ["neg-loser"]
        assert second.replayed is True

    def test_different_negotiations_get_independent_records(self, db):
        seed_negotiation(db, "neg-other", buyer_agent="buyer-2", status="active", price=50.0)

        engine = ClearingEngine(db_path=db)
        a = engine.clear("neg-winner", "buyer-1")
        b = engine.clear("neg-other", "buyer-2")
        assert a.clearing_id != b.clearing_id
        assert a.replayed is False and b.replayed is False


class TestNoInsertOrReplace:
    def test_source_has_no_insert_or_replace(self):
        with open("warden/marketplace/clearing.py", encoding="utf-8") as f:
            src = f.read()
        assert "INSERT OR REPLACE" not in src


class TestFeeConservation:
    def test_replay_fee_matches_original_not_recomputed(self, db, monkeypatch):
        engine = ClearingEngine(db_path=db)
        first = engine.clear("neg-winner", "buyer-1")
        # Change the take rate after the fact — a naive re-clear would use the
        # NEW rate; the idempotent replay must still return the ORIGINAL fee.
        monkeypatch.setattr("warden.marketplace.clearing._TAKE_RATE", __import__("decimal").Decimal("0.5"))
        second = engine.clear("neg-winner", "buyer-1")
        assert second.platform_fee_usd == first.platform_fee_usd
