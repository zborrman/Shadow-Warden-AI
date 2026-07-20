"""
Tests for warden/workers/x402_settlement.py (FT-4 slice 1).

Seeds real x402_pending_deductions rows via x402_gate.deduct_payment()
(the actual production write path) then exercises the settlement worker
against the same SQLite file — no schema duplication assumptions.
"""
from __future__ import annotations

import sqlite3

import pytest

from warden.workers import x402_settlement as s


@pytest.fixture
def db(tmp_path, monkeypatch):
    path = str(tmp_path / "x402.db")
    from warden.marketplace import x402_gate as g
    monkeypatch.setattr(g, "_DB_PATH", path)
    monkeypatch.setattr(g, "_X402_ENABLED", True)
    return path


async def _seed(agent_id: str, amount: str, resource: str = "search") -> None:
    from warden.marketplace import x402_gate as g
    await g.deduct_payment(agent_id, resource, amount_usd=g.Decimal(amount))


class TestSettlePendingDeductions:
    def test_no_rows_returns_empty_summary(self, db):
        summary = s.settle_pending_deductions(db_path=db)
        assert summary.settled_count == 0
        assert summary.agents_settled == 0
        assert summary.total_usd == "0"
        assert summary.errors == 0

    def test_missing_db_file_is_safe(self, tmp_path):
        summary = s.settle_pending_deductions(db_path=str(tmp_path / "nope.db"))
        assert summary.settled_count == 0

    @pytest.mark.asyncio
    async def test_settles_pending_rows_and_sums_correctly(self, db):
        await _seed("agent-a", "0.5")
        await _seed("agent-a", "0.25")
        await _seed("agent-b", "1.0")

        summary = s.settle_pending_deductions(db_path=db)
        assert summary.settled_count == 3
        assert summary.agents_settled == 2
        assert summary.total_usd == "1.75"
        assert summary.errors == 0

        con = sqlite3.connect(db)
        remaining_pending = con.execute(
            "SELECT COUNT(*) FROM x402_pending_deductions WHERE status='pending'"
        ).fetchone()[0]
        settled = con.execute(
            "SELECT COUNT(*) FROM x402_pending_deductions WHERE status='settled' AND settled_at != ''"
        ).fetchone()[0]
        con.close()
        assert remaining_pending == 0
        assert settled == 3

    @pytest.mark.asyncio
    async def test_idempotent_on_rerun(self, db):
        await _seed("agent-c", "0.1")

        first = s.settle_pending_deductions(db_path=db)
        second = s.settle_pending_deductions(db_path=db)

        assert first.settled_count == 1
        assert second.settled_count == 0   # already settled — nothing left to touch
        assert second.total_usd == "0"

    @pytest.mark.asyncio
    async def test_new_deductions_after_settlement_still_settle(self, db):
        await _seed("agent-d", "0.2")
        s.settle_pending_deductions(db_path=db)

        await _seed("agent-d", "0.3")
        summary = s.settle_pending_deductions(db_path=db)
        assert summary.settled_count == 1
        assert summary.total_usd == "0.3"


class TestArqEntryPoint:
    @pytest.mark.asyncio
    async def test_settle_x402_deductions_returns_dict_summary(self, db, monkeypatch):
        monkeypatch.setattr(s, "_DB_PATH", db)
        await _seed("agent-e", "0.4")

        result = await s.settle_x402_deductions(ctx={})
        assert result == {
            "settled_count":  1,
            "agents_settled": 1,
            "total_usd":      "0.4",
            "errors":         0,
        }
