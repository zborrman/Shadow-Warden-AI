"""
multi_agent/orchestrator.py
MultiAgentOrchestrator — runs procurement auction across Claude/Gemini/GPT.
Integrates with SupplierRisk for vendor scoring.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
import threading
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

log = logging.getLogger("warden.commerce.orchestrator")

_DB_PATH = os.getenv("COMMERCE_DB_PATH", "/tmp/warden_commerce.db")
_db_lock = threading.RLock()


@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    con = sqlite3.connect(_DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    _ensure_schema(con)
    try:
        yield con
        con.commit()
    finally:
        con.close()


def _ensure_schema(con: sqlite3.Connection) -> None:
    con.execute("""
        CREATE TABLE IF NOT EXISTS commerce_auctions (
            id         TEXT PRIMARY KEY,
            tenant_id  TEXT NOT NULL,
            request    TEXT NOT NULL,
            status     TEXT NOT NULL DEFAULT 'running',
            winner     TEXT,
            proposals  TEXT,
            created_at TEXT NOT NULL
        )
    """)


class MultiAgentOrchestrator:

    async def run_auction(
        self,
        tenant_id: str,
        purchase_request: str,
        budget_usd: float | None = None,
    ) -> str:
        auction_id = str(uuid.uuid4())
        with _db_lock, _conn() as con:
            con.execute(
                "INSERT INTO commerce_auctions(id, tenant_id, request, status, created_at) "
                "VALUES(?,?,?,?,?)",
                (auction_id, tenant_id, purchase_request, "running",
                 datetime.now(UTC).isoformat()),
            )

        # Fire all agents concurrently; collect non-None proposals
        from warden.business_community.agentic_commerce.multi_agent.connectors import (
            claude_proposal,
            gemini_proposal,
            gpt_proposal,
        )
        results = await asyncio.gather(
            claude_proposal(purchase_request),
            gemini_proposal(purchase_request),
            gpt_proposal(purchase_request),
            return_exceptions=True,
        )
        proposals = [p for p in results if p and not isinstance(p, Exception)]

        # Apply budget filter
        if budget_usd is not None:
            proposals = [p for p in proposals if p.price <= budget_usd]

        # Enrich with supplier risk if available
        proposals = await self._enrich_with_risk(tenant_id, proposals)

        winner = self.select_winner(proposals)

        with _db_lock, _conn() as con:
            con.execute(
                "UPDATE commerce_auctions SET status=?, winner=?, proposals=? WHERE id=?",
                (
                    "completed",
                    json.dumps(winner.raw) if winner else None,
                    json.dumps([p.raw for p in proposals]),
                    auction_id,
                ),
            )

        log.info("Auction %s complete: %d proposals, winner=%s",
                 auction_id, len(proposals), winner.agent if winner else "none")
        return auction_id

    async def _enrich_with_risk(self, tenant_id: str, proposals) -> list:
        try:
            from warden.communities.supplier_risk import assess_supplier
            for p in proposals:
                if p.vendor:
                    score = assess_supplier(tenant_id, p.vendor)
                    if score and isinstance(score, dict):
                        p.risk = max(p.risk, score.get("composite_score", p.risk))
        except Exception as exc:
            log.debug("Supplier risk enrichment skipped: %s", exc)
        return proposals

    def evaluate_proposals(self, proposals: list) -> list:
        return sorted(proposals, key=lambda p: p.score())

    def select_winner(self, proposals: list) -> Any | None:
        if not proposals:
            return None
        ranked = self.evaluate_proposals(proposals)
        return ranked[0]

    def get_auction(self, auction_id: str, tenant_id: str) -> dict | None:
        with _db_lock, _conn() as con:
            row = con.execute(
                "SELECT * FROM commerce_auctions WHERE id=? AND tenant_id=?",
                (auction_id, tenant_id),
            ).fetchone()
        if not row:
            return None
        return {
            "id":        row["id"],
            "status":    row["status"],
            "request":   row["request"],
            "winner":    json.loads(row["winner"]) if row["winner"] else None,
            "proposals": json.loads(row["proposals"]) if row["proposals"] else [],
            "created_at": row["created_at"],
        }

    def list_auctions(self, tenant_id: str, limit: int = 20) -> list[dict]:
        with _db_lock, _conn() as con:
            rows = con.execute(
                "SELECT id, status, request, winner, created_at FROM commerce_auctions "
                "WHERE tenant_id=? ORDER BY created_at DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]
