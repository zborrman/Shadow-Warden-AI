"""
warden/marketplace/clearing.py
────────────────────────────────
ClearingEngine — final transaction clearing (Stage 4 of the M2M lifecycle).

After the buyer evaluates all collected proposals and selects a winner:
  1. All other pending negotiations for that buyer are auto-rejected
     (status → 'cleared_by_market'), preventing stale open sessions
  2. Clearing record dual-written:
       SQLite → marketplace_clearing_log  (synchronous, always, Layer 1)
       PostgreSQL → marketplace_clearing_log  (async, fail-open, Layer 3)
  3. Structured result returned with winner + list of rejected negotiation IDs

Dual-write rationale: SQLite provides immediate local consistency; PostgreSQL
provides the cross-tenant audit trail needed for the STIX chain and SOC dashboard.

Usage:
    engine = ClearingEngine()
    result = await engine.clear_async(winner_neg_id, buyer_agent_id)
    # result.rejected_neg_ids — IDs auto-rejected
    # result.pg_write_ok     — True if PostgreSQL write succeeded
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal

log = logging.getLogger("warden.marketplace.clearing")

_DB_PATH   = os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")
_PG_DSN    = os.getenv("DATABASE_URL", "")
_TAKE_RATE = Decimal(os.getenv("MARKETPLACE_TAKE_RATE", "0.015"))


@dataclass
class ClearingResult:
    clearing_id:      str
    winner_neg_id:    str
    buyer_agent_id:   str
    rejected_neg_ids: list[str]
    cleared_at:       float
    pg_write_ok:      bool = False
    platform_fee_usd: float = 0.0
    seller_net_usd:   float = 0.0


def _ensure_clearing_table(db_path: str) -> None:
    con = sqlite3.connect(db_path)
    con.execute("""
        CREATE TABLE IF NOT EXISTS marketplace_clearing_log (
            clearing_id      TEXT PRIMARY KEY,
            winner_neg_id    TEXT NOT NULL,
            buyer_agent_id   TEXT NOT NULL,
            rejected_neg_ids TEXT NOT NULL,
            cleared_at       REAL NOT NULL,
            platform_fee_usd REAL NOT NULL DEFAULT 0.0,
            seller_net_usd   REAL NOT NULL DEFAULT 0.0
        )
    """)
    # Additive migration for existing databases
    import contextlib
    with contextlib.suppress(Exception):
        con.execute("ALTER TABLE marketplace_clearing_log ADD COLUMN platform_fee_usd REAL NOT NULL DEFAULT 0.0")
    with contextlib.suppress(Exception):
        con.execute("ALTER TABLE marketplace_clearing_log ADD COLUMN seller_net_usd REAL NOT NULL DEFAULT 0.0")
    con.commit()
    con.close()


class ClearingEngine:
    """Executes final-stage market clearing for a completed negotiation round.

    Thread-safe: each call opens its own SQLite connection.  Safe to instantiate
    per-request.
    """

    def __init__(self, db_path: str = _DB_PATH) -> None:
        self.db_path = db_path
        _ensure_clearing_table(db_path)

    # ── Public API ──────────────────────────────────────────────────────────────

    def clear(
        self,
        winner_neg_id: str,
        buyer_agent_id: str,
    ) -> ClearingResult:
        """Synchronous clearing (safe to call from non-async contexts).

        Rejects all pending/active negotiations for buyer except the winner,
        then records the clearing event in SQLite.
        """
        rejected    = self._reject_losers(winner_neg_id, buyer_agent_id)
        clearing_id = str(uuid.uuid4())

        # Compute platform take rate (Decimal math — float arithmetic is prohibited in billing)
        agreed_price = self._fetch_agreed_price(winner_neg_id)
        agreed_dec   = Decimal(str(agreed_price))
        fee_dec      = (agreed_dec * _TAKE_RATE).quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)
        net_dec      = agreed_dec - fee_dec

        rec = ClearingResult(
            clearing_id=clearing_id,
            winner_neg_id=winner_neg_id,
            buyer_agent_id=buyer_agent_id,
            rejected_neg_ids=rejected,
            cleared_at=time.time(),
            platform_fee_usd=float(fee_dec),
            seller_net_usd=float(net_dec),
        )
        self._write_sqlite(rec)
        log.info(
            "ClearingEngine: buyer=%s winner=%s rejected=%d",
            buyer_agent_id[:32], winner_neg_id[:12], len(rejected),
        )
        return rec

    async def clear_async(
        self,
        winner_neg_id: str,
        buyer_agent_id: str,
    ) -> ClearingResult:
        """Async version — also writes clearing record to PostgreSQL (fail-open)."""
        rec = self.clear(winner_neg_id, buyer_agent_id)
        rec.pg_write_ok = await self._write_postgres(rec)
        return rec

    # ── Internal helpers ────────────────────────────────────────────────────────

    def _fetch_agreed_price(self, winner_neg_id: str) -> float:
        """Return the agreed price from the winner negotiation record, or 0.0 if unavailable."""
        try:
            con = sqlite3.connect(self.db_path)
            row = con.execute(
                "SELECT agreed_price FROM marketplace_negotiations WHERE negotiation_id = ?",
                (winner_neg_id,),
            ).fetchone()
            con.close()
            return float(row[0]) if row and row[0] is not None else 0.0
        except Exception:
            return 0.0

    def _reject_losers(self, winner_neg_id: str, buyer_agent_id: str) -> list[str]:
        """Update all non-winner pending negotiations to 'cleared_by_market'."""
        try:
            con = sqlite3.connect(self.db_path)
            rows = con.execute(
                """
                SELECT negotiation_id FROM marketplace_negotiations
                WHERE  buyer_agent_id = ?
                  AND  negotiation_id != ?
                  AND  status IN ('pending', 'active', 'counter_offered')
                """,
                (buyer_agent_id, winner_neg_id),
            ).fetchall()
            rejected_ids = [r[0] for r in rows]
            if rejected_ids:
                placeholders = ",".join("?" * len(rejected_ids))
                con.execute(
                    f"UPDATE marketplace_negotiations "
                    f"SET status='cleared_by_market' "
                    f"WHERE negotiation_id IN ({placeholders})",
                    rejected_ids,
                )
                con.commit()
            con.close()
            return rejected_ids
        except Exception as exc:
            log.warning("ClearingEngine._reject_losers: %s", exc)
            return []

    def _write_sqlite(self, rec: ClearingResult) -> None:
        try:
            con = sqlite3.connect(self.db_path)
            con.execute(
                """
                INSERT OR REPLACE INTO marketplace_clearing_log
                    (clearing_id, winner_neg_id, buyer_agent_id, rejected_neg_ids,
                     cleared_at, platform_fee_usd, seller_net_usd)
                VALUES (?,?,?,?,?,?,?)
                """,
                (
                    rec.clearing_id,
                    rec.winner_neg_id,
                    rec.buyer_agent_id,
                    json.dumps(rec.rejected_neg_ids),
                    rec.cleared_at,
                    rec.platform_fee_usd,
                    rec.seller_net_usd,
                ),
            )
            con.commit()
            con.close()
        except Exception as exc:
            log.warning("ClearingEngine._write_sqlite: %s", exc)

    async def _write_postgres(self, rec: ClearingResult) -> bool:
        """Write to PostgreSQL marketplace_clearing_log table. Fail-open."""
        if not _PG_DSN:
            return False
        try:
            import asyncpg  # noqa: PLC0415

            conn = await asyncpg.connect(_PG_DSN, timeout=5)
            await conn.execute(
                """
                INSERT INTO marketplace_clearing_log
                    (clearing_id, winner_neg_id, buyer_agent_id,
                     rejected_neg_ids, cleared_at, platform_fee_usd, seller_net_usd)
                VALUES ($1, $2, $3, $4, to_timestamp($5), $6, $7)
                ON CONFLICT (clearing_id) DO NOTHING
                """,
                rec.clearing_id,
                rec.winner_neg_id,
                rec.buyer_agent_id,
                json.dumps(rec.rejected_neg_ids),
                rec.cleared_at,
                rec.platform_fee_usd,
                rec.seller_net_usd,
            )
            await conn.close()
            log.debug("ClearingEngine: pg write ok clearing_id=%s", rec.clearing_id[:8])
            return True
        except Exception as exc:
            log.debug("ClearingEngine._write_postgres fail-open: %s", exc)
            return False
