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
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal

from warden.config import data_path

log = logging.getLogger("warden.marketplace.clearing")

_DB_PATH   = data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")
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
    replayed:         bool = False


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

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        con = sqlite3.connect(self.db_path)
        try:
            yield con
        finally:
            con.close()

    # ── Public API ──────────────────────────────────────────────────────────────

    def clear(
        self,
        winner_neg_id: str,
        buyer_agent_id: str,
    ) -> ClearingResult:
        """Synchronous clearing (safe to call from non-async contexts). Idempotent.

        A negotiation clears exactly once, so ``winner_neg_id`` IS the natural
        idempotency key — ``clearing_id`` is derived from it deterministically
        (never ``uuid.uuid4()``, which made every retry mint a fresh row). A
        retried/duplicate call for an already-cleared negotiation returns the
        original record (``replayed=True``) and re-runs nothing: no second
        auto-reject pass, no second fee computation, no second log line.
        """
        clearing_id = f"clear-{winner_neg_id}"
        existing = self._read_by_id(clearing_id)
        if existing is not None:
            existing.replayed = True
            return existing

        rejected = self._reject_losers(winner_neg_id, buyer_agent_id)

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
        # Re-read: under a concurrent race, another caller's INSERT may have won
        # (ON CONFLICT DO NOTHING made ours a no-op) — the re-read returns
        # whichever row is canonical, so both callers agree on one clearing.
        # cleared_at is a fresh time.time() per call, so a mismatch means our
        # own write lost the race and we are, in effect, the "replay".
        canonical = self._read_by_id(clearing_id)
        if canonical is not None and canonical.cleared_at != rec.cleared_at:
            canonical.replayed = True
        result = canonical or rec
        log.info(
            "ClearingEngine: buyer=%s winner=%s rejected=%d replayed=%s",
            buyer_agent_id[:32], winner_neg_id[:12], len(rejected), result.replayed,
        )
        return result

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
            with self._conn() as con:
                row = con.execute(
                    "SELECT agreed_price FROM marketplace_negotiations WHERE negotiation_id = ?",
                    (winner_neg_id,),
                ).fetchone()
            return float(row[0]) if row and row[0] is not None else 0.0
        except Exception:
            return 0.0

    def _reject_losers(self, winner_neg_id: str, buyer_agent_id: str) -> list[str]:
        """Update all non-winner pending negotiations to 'cleared_by_market'."""
        try:
            with self._conn() as con:
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
            return rejected_ids
        except Exception as exc:
            log.warning("ClearingEngine._reject_losers: %s", exc)
            return []

    def _write_sqlite(self, rec: ClearingResult) -> None:
        try:
            with self._conn() as con:
                con.execute(
                    """
                    INSERT INTO marketplace_clearing_log
                        (clearing_id, winner_neg_id, buyer_agent_id, rejected_neg_ids,
                         cleared_at, platform_fee_usd, seller_net_usd)
                    VALUES (?,?,?,?,?,?,?)
                    ON CONFLICT(clearing_id) DO NOTHING
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
        except Exception as exc:
            log.warning("ClearingEngine._write_sqlite: %s", exc)

    def _read_by_id(self, clearing_id: str) -> ClearingResult | None:
        """Read back a clearing record by its (deterministic) clearing_id."""
        try:
            with self._conn() as con:
                row = con.execute(
                    "SELECT clearing_id, winner_neg_id, buyer_agent_id, rejected_neg_ids, "
                    "cleared_at, platform_fee_usd, seller_net_usd "
                    "FROM marketplace_clearing_log WHERE clearing_id = ?",
                    (clearing_id,),
                ).fetchone()
        except Exception as exc:
            log.warning("ClearingEngine._read_by_id: %s", exc)
            return None
        if row is None:
            return None
        return ClearingResult(
            clearing_id=row[0], winner_neg_id=row[1], buyer_agent_id=row[2],
            rejected_neg_ids=json.loads(row[3]), cleared_at=row[4],
            platform_fee_usd=row[5], seller_net_usd=row[6],
        )

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
