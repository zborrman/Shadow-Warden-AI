"""
warden/marketplace/clearing.py
────────────────────────────────
ClearingEngine — final transaction clearing (Stage 4 of the M2M lifecycle).

After the buyer evaluates all collected proposals and selects a winner:
  1. All other pending negotiations for that buyer are auto-rejected
     (status → 'cleared_by_market'), preventing stale open sessions
  2. Clearing record written to SQLite (synchronous, always, Layer 1) —
     the authoritative local record
  3. Structured result returned with winner + list of rejected negotiation IDs

PostgreSQL relay (FT-4 slice 3 — transactional outbox): the cross-tenant
audit copy PostgreSQL needs for the STIX chain and SOC dashboard used to be
a fire-and-forget async write — a failed attempt vanished silently, no
record it was ever tried. Now every clearing enqueues a durable
`marketplace_clearing_outbox` row (status pending/relayed) *before* the
Postgres attempt; `clear_async()` tries an immediate relay as before, but a
failure just leaves the row pending instead of losing it. `relay_pending()`
drains whatever is still pending — call it from a scheduled worker for
at-least-once delivery. `purge_relayed_outbox()` prunes confirmed-relayed
rows past a retention window so the table doesn't grow forever; it never
touches a 'pending' row regardless of age. Recon (comparing outbox status to
what Postgres actually holds) is a further slice; this one guarantees
nothing silently diverges without at least being recorded as owing a retry.

Usage:
    engine = ClearingEngine()
    result = await engine.clear_async(winner_neg_id, buyer_agent_id)
    # result.rejected_neg_ids — IDs auto-rejected
    # result.pg_write_ok     — True if the immediate relay attempt succeeded
    #                          (False just means it's queued for retry)
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from collections.abc import Generator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal

from warden.config import data_path
from warden.db.connect import open_db
from warden.db.ddl_registry import register

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


_CLEARING_DDL = """
    CREATE TABLE IF NOT EXISTS marketplace_clearing_log (
        clearing_id      TEXT PRIMARY KEY,
        winner_neg_id    TEXT NOT NULL,
        buyer_agent_id   TEXT NOT NULL,
        rejected_neg_ids TEXT NOT NULL,
        cleared_at       REAL NOT NULL,
        platform_fee_usd REAL NOT NULL DEFAULT 0.0,
        seller_net_usd   REAL NOT NULL DEFAULT 0.0
    );
    CREATE TABLE IF NOT EXISTS marketplace_clearing_outbox (
        clearing_id  TEXT PRIMARY KEY,
        payload_json TEXT NOT NULL,
        status       TEXT NOT NULL DEFAULT 'pending',
        attempts     INTEGER NOT NULL DEFAULT 0,
        created_at   REAL NOT NULL,
        relayed_at   REAL
    );
    CREATE INDEX IF NOT EXISTS idx_clearing_outbox_status
        ON marketplace_clearing_outbox(status);
"""
register("marketplace", "warden.marketplace.clearing", _CLEARING_DDL)


@contextmanager
def _conn(db_path: str) -> Generator[sqlite3.Connection, None, None]:
    # ALTER ADD COLUMN is not idempotent (errors on a column that already exists),
    # so it cannot be folded into the registered DDL — stays a suppress-per-connect.
    with open_db(
        "marketplace", db_path, turso_name="marketplace", module_default_path=_DB_PATH
    ) as con:
        with suppress(Exception):
            con.execute("ALTER TABLE marketplace_clearing_log ADD COLUMN platform_fee_usd REAL NOT NULL DEFAULT 0.0")
        with suppress(Exception):
            con.execute("ALTER TABLE marketplace_clearing_log ADD COLUMN seller_net_usd REAL NOT NULL DEFAULT 0.0")
        yield con


class ClearingEngine:
    """Executes final-stage market clearing for a completed negotiation round.

    Thread-safe: each call opens its own SQLite connection.  Safe to instantiate
    per-request.
    """

    def __init__(self, db_path: str = _DB_PATH) -> None:
        self.db_path = db_path
        with _conn(db_path):  # ensure schema exists
            pass

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
        """Async version — also relays the clearing record to PostgreSQL via
        the transactional outbox (enqueue is synchronous and durable; the
        relay attempt itself is fail-open, but a failure leaves the row
        queued rather than losing it), and screens the buyer against the
        sanctions list (FT-5, opt-in via SANCTIONS_SCREENING_ENABLED,
        never blocks — see warden/marketplace/sanctions.py)."""
        rec = self.clear(winner_neg_id, buyer_agent_id)
        self._enqueue_outbox(rec)
        rec.pg_write_ok = await self._relay_outbox_row(rec.clearing_id)
        await self._screen_sanctions(buyer_agent_id, rec.clearing_id)
        return rec

    async def _screen_sanctions(self, buyer_agent_id: str, clearing_id: str) -> None:
        try:
            from warden.marketplace.sanctions import screen_settlement_party
            await screen_settlement_party(buyer_agent_id, clearing_id)
        except Exception as exc:
            log.warning("clearing: sanctions screening failed (non-fatal): %s", exc)

    # ── Internal helpers ────────────────────────────────────────────────────────

    def _fetch_agreed_price(self, winner_neg_id: str) -> float:
        """Return the agreed price from the winner negotiation record, or 0.0 if unavailable."""
        try:
            with _conn(self.db_path) as con:
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
            with _conn(self.db_path) as con:
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
            return rejected_ids
        except Exception as exc:
            log.warning("ClearingEngine._reject_losers: %s", exc)
            return []

    def _write_sqlite(self, rec: ClearingResult) -> None:
        try:
            with _conn(self.db_path) as con:
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
        except Exception as exc:
            log.warning("ClearingEngine._write_sqlite: %s", exc)

    def _read_by_id(self, clearing_id: str) -> ClearingResult | None:
        """Read back a clearing record by its (deterministic) clearing_id."""
        try:
            with _conn(self.db_path) as con:
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

    # ── Transactional outbox (FT-4 slice 3) ───────────────────────────────────

    def _enqueue_outbox(self, rec: ClearingResult) -> None:
        """Durably record that this clearing owes a Postgres relay.

        Idempotent on clearing_id: a replayed clear() re-enqueues nothing new
        (ON CONFLICT DO NOTHING) — one clearing, at most one outbox row.
        """
        payload = {
            "clearing_id":      rec.clearing_id,
            "winner_neg_id":    rec.winner_neg_id,
            "buyer_agent_id":   rec.buyer_agent_id,
            "rejected_neg_ids": rec.rejected_neg_ids,
            "cleared_at":       rec.cleared_at,
            "platform_fee_usd": rec.platform_fee_usd,
            "seller_net_usd":   rec.seller_net_usd,
        }
        try:
            with _conn(self.db_path) as con:
                con.execute(
                    "INSERT INTO marketplace_clearing_outbox "
                    "(clearing_id, payload_json, status, attempts, created_at) "
                    "VALUES (?, ?, 'pending', 0, ?) "
                    "ON CONFLICT(clearing_id) DO NOTHING",
                    (rec.clearing_id, json.dumps(payload), time.time()),
                )
        except Exception as exc:
            log.warning("ClearingEngine._enqueue_outbox: %s", exc)

    async def _pg_insert(self, payload: dict) -> None:
        """Raw Postgres insert. Raises on any failure — callers decide the fallback."""
        if not _PG_DSN:
            raise RuntimeError("DATABASE_URL not configured")
        import asyncpg  # noqa: PLC0415

        conn = await asyncpg.connect(_PG_DSN, timeout=5)
        try:
            await conn.execute(
                """
                INSERT INTO marketplace_clearing_log
                    (clearing_id, winner_neg_id, buyer_agent_id,
                     rejected_neg_ids, cleared_at, platform_fee_usd, seller_net_usd)
                VALUES ($1, $2, $3, $4, to_timestamp($5), $6, $7)
                ON CONFLICT (clearing_id) DO NOTHING
                """,
                payload["clearing_id"],
                payload["winner_neg_id"],
                payload["buyer_agent_id"],
                json.dumps(payload["rejected_neg_ids"]),
                payload["cleared_at"],
                payload["platform_fee_usd"],
                payload["seller_net_usd"],
            )
        finally:
            await conn.close()

    async def _relay_outbox_row(self, clearing_id: str) -> bool:
        """Attempt to relay one outbox row to Postgres. Fail-open: on failure
        the row stays 'pending' (attempts incremented) for a later retry —
        never lost, never raised to the caller."""
        try:
            with _conn(self.db_path) as con:
                row = con.execute(
                    "SELECT payload_json, status FROM marketplace_clearing_outbox "
                    "WHERE clearing_id = ?",
                    (clearing_id,),
                ).fetchone()
        except Exception as exc:
            log.warning("ClearingEngine._relay_outbox_row: read failed: %s", exc)
            return False

        if row is None:
            return False
        if row[1] == "relayed":
            return True  # already relayed — idempotent no-op

        payload = json.loads(row[0])
        try:
            await self._pg_insert(payload)
        except Exception as exc:
            log.debug("ClearingEngine._relay_outbox_row: relay failed (queued for retry): %s", exc)
            try:
                with _conn(self.db_path) as con:
                    con.execute(
                        "UPDATE marketplace_clearing_outbox SET attempts = attempts + 1 "
                        "WHERE clearing_id = ?",
                        (clearing_id,),
                    )
            except Exception as exc2:
                log.warning("ClearingEngine._relay_outbox_row: attempts bump failed: %s", exc2)
            return False

        try:
            with _conn(self.db_path) as con:
                con.execute(
                    "UPDATE marketplace_clearing_outbox SET status='relayed', relayed_at=? "
                    "WHERE clearing_id = ?",
                    (time.time(), clearing_id),
                )
        except Exception as exc:
            log.warning("ClearingEngine._relay_outbox_row: status update failed: %s", exc)
        log.debug("ClearingEngine: relayed clearing_id=%s", clearing_id[:16])
        return True


async def relay_pending(db_path: str = _DB_PATH, limit: int = 50) -> dict:
    """Drain up to `limit` pending outbox rows — the worker-facing entry point.

    Async (the relay itself is asyncpg-based) — await directly from an ARQ
    job function, no nested event loop. Returns
    {"attempted": N, "relayed": N, "still_pending": N}.
    """
    engine = ClearingEngine(db_path=db_path)
    try:
        with _conn(engine.db_path) as con:
            rows = con.execute(
                "SELECT clearing_id FROM marketplace_clearing_outbox "
                "WHERE status = 'pending' ORDER BY created_at ASC LIMIT ?",
                (limit,),
            ).fetchall()
    except Exception as exc:
        log.warning("relay_pending: read failed: %s", exc)
        return {"attempted": 0, "relayed": 0, "still_pending": 0}

    clearing_ids = [r[0] for r in rows]
    relayed = 0
    for cid in clearing_ids:
        if await engine._relay_outbox_row(cid):
            relayed += 1

    return {
        "attempted": len(clearing_ids),
        "relayed": relayed,
        "still_pending": len(clearing_ids) - relayed,
    }


def purge_relayed_outbox(
    db_path: str = _DB_PATH, older_than_days: float = 30.0, limit: int = 1000
) -> dict:
    """Delete confirmed-relayed outbox rows older than `older_than_days`.

    Retention/cleanup for the FT-4 slice 3 outbox — rows accumulated forever
    with no pruning. Only ever deletes status='relayed' rows; a 'pending' row
    is never purged regardless of age, so a stalled relay can't silently lose
    its retry record. Fail-soft: a read/delete error returns a zero summary
    rather than raising.
    """
    cutoff = time.time() - older_than_days * 86400
    engine = ClearingEngine(db_path=db_path)
    try:
        with _conn(engine.db_path) as con:
            cur = con.execute(
                "DELETE FROM marketplace_clearing_outbox WHERE clearing_id IN ("
                "  SELECT clearing_id FROM marketplace_clearing_outbox "
                "  WHERE status = 'relayed' AND relayed_at < ? LIMIT ?"
                ")",
                (cutoff, limit),
            )
            purged = cur.rowcount if cur.rowcount is not None and cur.rowcount > 0 else 0
            remaining = con.execute(
                "SELECT COUNT(*) FROM marketplace_clearing_outbox WHERE status = 'relayed'"
            ).fetchone()[0]
    except Exception as exc:
        log.warning("purge_relayed_outbox: failed: %s", exc)
        return {"purged": 0, "remaining_relayed": 0}

    return {"purged": purged, "remaining_relayed": remaining}
