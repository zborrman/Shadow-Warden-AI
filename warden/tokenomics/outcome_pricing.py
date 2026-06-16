"""
warden/tokenomics/outcome_pricing.py
──────────────────────────────────────
Outcome-based listing type: price is computed post-execution
based on KPI achievement and settled in WAT.

Flow:
  1. Seller creates OutcomeListing with kpi_definition + target_value.
  2. Buyer funds escrow (type="outcome_based").
  3. After escrow confirmed, oracle/admin calls settle_outcome().
  4. settle_outcome() pulls KPI from oracle, computes final_price,
     transfers WAT from buyer to seller, updates escrow.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

log = logging.getLogger("warden.tokenomics.outcome_pricing")

_DB_PATH  = os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")
_db_lock  = threading.RLock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS outcome_listings (
    listing_id      TEXT PRIMARY KEY,
    base_price_usd  REAL NOT NULL DEFAULT 0.0,
    kpi_definition  TEXT NOT NULL DEFAULT '{}',
    oracle_address  TEXT NOT NULL DEFAULT '',
    target_value    REAL NOT NULL DEFAULT 1.0,
    community_id    TEXT NOT NULL DEFAULT '',
    seller_agent_id TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'open',
    settled_price   REAL,
    achieved_value  REAL,
    created_at      TEXT NOT NULL,
    settled_at      TEXT
);
"""


@dataclass
class OutcomeListing:
    listing_id:     str
    base_price_usd: float
    kpi_definition: dict
    oracle_address: str
    target_value:   float
    community_id:   str
    seller_agent_id: str
    status:         str = "open"
    settled_price:  float | None = None
    achieved_value: float | None = None
    created_at:     str = ""
    settled_at:     str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _conn(db_path: str = _DB_PATH) -> sqlite3.Connection:
    con = sqlite3.connect(db_path, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(_SCHEMA)
    return con


class OutcomePricingService:
    """
    Manages outcome-based marketplace listings and WAT settlement.
    """

    def __init__(self, db_path: str = _DB_PATH) -> None:
        self.db_path = db_path
        # Keep a persistent connection for :memory: databases (per-connection scope)
        self._mem_conn: sqlite3.Connection | None = None
        if db_path == ":memory:":
            self._mem_conn = _conn(db_path)
        else:
            with _conn(db_path):
                pass  # ensure schema

    def _get_conn(self) -> sqlite3.Connection:
        if self._mem_conn is not None:
            return self._mem_conn
        return _conn(self.db_path)

    def create_listing(
        self,
        base_price_usd:  float,
        kpi_definition:  str | dict = "",
        target_value:    float = 1.0,
        community_id:    str = "",
        seller_agent_id: str = "",
        oracle_address:  str = "",
    ) -> str:
        """Create an outcome-based listing. Returns listing_id."""
        import json  # noqa: PLC0415
        listing_id = f"OL-{uuid.uuid4().hex[:12].upper()}"
        now = datetime.now(UTC).isoformat()
        kpi_json = json.dumps(kpi_definition) if isinstance(kpi_definition, dict) else json.dumps({"definition": kpi_definition})
        con = self._get_conn()
        with _db_lock:
            con.execute(
                """INSERT INTO outcome_listings
                   (listing_id, base_price_usd, kpi_definition, oracle_address, target_value,
                    community_id, seller_agent_id, status, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    listing_id, base_price_usd, kpi_json, oracle_address,
                    target_value, community_id, seller_agent_id, "open", now,
                ),
            )
            con.commit()
            if self._mem_conn is None:
                con.close()
        log.info("OutcomeListing created: %s seller=%s", listing_id, seller_agent_id)
        return listing_id

    def settle_outcome(
        self,
        listing_id:     str,
        buyer_agent_id: str,
        achieved_value: float,
    ) -> dict:
        """
        Settle an outcome listing.

        final_price = base_price * min(achieved_value / target_value, 1.0)
        Transfers WAT from buyer to seller.
        """
        from warden.tokenomics.agent_token import get_agent_token  # noqa: PLC0415
        listing = self.get_listing(listing_id)
        if listing is None:
            raise ValueError(f"Outcome listing not found: {listing_id!r}")
        if listing["status"] != "open":
            raise ValueError(f"Listing {listing_id!r} is already {listing['status']!r}.")

        ratio        = min(achieved_value / max(listing["target_value"], 1e-9), 1.0)
        final_price  = round(listing["base_price_usd"] * ratio, 4)
        now          = datetime.now(UTC).isoformat()

        # WAT transfer (fail-open on token error)
        tx = {}
        try:
            token = get_agent_token()
            tx    = token.transfer(buyer_agent_id, listing["seller_agent_id"], final_price)
        except Exception as exc:
            log.warning("OutcomePricingService: WAT transfer failed: %s", exc)
            tx = {"error": str(exc)}

        # Persist settlement
        con = self._get_conn()
        with _db_lock:
            con.execute(
                """UPDATE outcome_listings SET
                   status='settled', settled_price=?, achieved_value=?, settled_at=?
                   WHERE listing_id=?""",
                (final_price, achieved_value, now, listing_id),
            )
            con.commit()
            if self._mem_conn is None:
                con.close()

        result = {
            "listing_id":      listing_id,
            "buyer_agent_id":  buyer_agent_id,
            "seller_agent_id": listing["seller_agent_id"],
            "achieved_value":  achieved_value,
            "target_value":    listing["target_value"],
            "ratio":           round(ratio, 4),
            "final_price_wat": final_price,
            "settled_price_usd": final_price,
            "tx":              tx,
            "settled_at":      now,
        }
        log.info("OutcomeListing settled: %s final_price=%.4f WAT", listing_id, final_price)
        return result

    def get_listing(self, listing_id: str) -> dict | None:
        import contextlib  # noqa: PLC0415
        import json  # noqa: PLC0415
        try:
            con = self._get_conn()
            with _db_lock:
                row = con.execute(
                    "SELECT * FROM outcome_listings WHERE listing_id=?", (listing_id,)
                ).fetchone()
                if self._mem_conn is None:
                    con.close()
            if not row:
                return None
            d = dict(row)
            with contextlib.suppress(Exception):
                d["kpi_definition"] = json.loads(d.get("kpi_definition") or "{}")
            return d
        except Exception as exc:
            log.warning("OutcomePricingService.get_listing error: %s", exc)
            return None

    def list_listings(self, community_id: str = "", limit: int = 50) -> list[dict]:
        try:
            con = self._get_conn()
            with _db_lock:
                if community_id:
                    rows = con.execute(
                        "SELECT * FROM outcome_listings WHERE community_id=? ORDER BY created_at DESC LIMIT ?",
                        (community_id, limit),
                    ).fetchall()
                else:
                    rows = con.execute(
                        "SELECT * FROM outcome_listings ORDER BY created_at DESC LIMIT ?",
                        (limit,),
                    ).fetchall()
                if self._mem_conn is None:
                    con.close()
            return [dict(r) for r in rows]
        except Exception:
            return []
