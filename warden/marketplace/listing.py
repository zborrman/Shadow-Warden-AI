"""
warden/marketplace/listing.py
───────────────────────────────
Listing and Purchase registry for the M2M Agentic Marketplace.

Tables (shared MARKETPLACE_DB_PATH)
────────────────────────────────────
  marketplace_listings   — active/sold/delisted asset listings
  marketplace_purchases  — completed/pending purchase records
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
import uuid
from collections.abc import Generator
from contextlib import contextmanager, suppress
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta

from warden.config import data_path
from warden.db.connect import open_db
from warden.db.ddl_registry import register

log = logging.getLogger("warden.marketplace.listing")

_DB_PATH = data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")
_db_lock = threading.RLock()

# Stale signals threshold — signal assets older than this are auto-delisted
_SIGNAL_STALE_HOURS = int(os.getenv("MARKETPLACE_SIGNAL_STALE_HOURS", "48"))


# ── Schema ────────────────────────────────────────────────────────────────────

_LISTING_DDL = """
    CREATE TABLE IF NOT EXISTS marketplace_listings (
        listing_id       TEXT PRIMARY KEY,
        asset_id         TEXT NOT NULL,
        seller_agent     TEXT NOT NULL,
        community_id     TEXT NOT NULL,
        tenant_id        TEXT NOT NULL,
        asset_type       TEXT NOT NULL DEFAULT 'rule',
        price_usd        REAL NOT NULL DEFAULT 0.0,
        currency         TEXT NOT NULL DEFAULT 'USD',
        pricing_strategy TEXT NOT NULL DEFAULT 'fixed',
        status           TEXT NOT NULL DEFAULT 'active',
        demand_score     REAL NOT NULL DEFAULT 0.5,
        listed_at        TEXT NOT NULL,
        expires_at       TEXT,
        sold_at          TEXT,
        chain            TEXT NOT NULL DEFAULT 'sepolia',
        is_sponsored     INTEGER NOT NULL DEFAULT 0,
        sponsored_until  TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_ml_seller   ON marketplace_listings(seller_agent);
    CREATE INDEX IF NOT EXISTS idx_ml_status   ON marketplace_listings(status);
    CREATE INDEX IF NOT EXISTS idx_ml_type     ON marketplace_listings(asset_type);
    CREATE INDEX IF NOT EXISTS idx_ml_community ON marketplace_listings(community_id);
    CREATE INDEX IF NOT EXISTS idx_ml_chain    ON marketplace_listings(chain);

    CREATE TABLE IF NOT EXISTS marketplace_purchases (
        purchase_id    TEXT PRIMARY KEY,
        listing_id     TEXT NOT NULL,
        asset_id       TEXT NOT NULL,
        buyer_agent    TEXT NOT NULL,
        seller_agent   TEXT NOT NULL,
        price_paid     REAL NOT NULL,
        status         TEXT NOT NULL DEFAULT 'pending',
        escrow_id      TEXT NOT NULL DEFAULT '',
        negotiation_id TEXT NOT NULL DEFAULT '',
        purchased_at   TEXT NOT NULL,
        completed_at   TEXT,
        idempotency_key TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_mp_buyer  ON marketplace_purchases(buyer_agent);
    CREATE INDEX IF NOT EXISTS idx_mp_seller ON marketplace_purchases(seller_agent);
    CREATE INDEX IF NOT EXISTS idx_mp_listing ON marketplace_purchases(listing_id);
"""
register("marketplace", "warden.marketplace.listing", _LISTING_DDL)


def _migrate_chain_column(con: sqlite3.Connection) -> None:
    """Add chain column to existing databases that predate cross-chain support."""
    import contextlib
    with contextlib.suppress(Exception):
        con.execute(
            "ALTER TABLE marketplace_listings ADD COLUMN chain TEXT NOT NULL DEFAULT 'sepolia'"
        )


def _migrate_sponsored_columns(con: sqlite3.Connection) -> None:
    """Add sponsored columns to existing databases that predate sponsored-listing support."""
    import contextlib
    with contextlib.suppress(Exception):
        con.execute(
            "ALTER TABLE marketplace_listings ADD COLUMN is_sponsored INTEGER NOT NULL DEFAULT 0"
        )
    with contextlib.suppress(Exception):
        con.execute(
            "ALTER TABLE marketplace_listings ADD COLUMN sponsored_until TEXT"
        )


def _migrate_kya_column(con: sqlite3.Connection) -> None:
    """Add kya_status column to existing databases that predate KYA support."""
    import contextlib
    with contextlib.suppress(Exception):
        con.execute(
            "ALTER TABLE marketplace_listings ADD COLUMN kya_status TEXT NOT NULL DEFAULT 'PENDING'"
        )


def _migrate_idempotency_column(con: sqlite3.Connection) -> None:
    """Add idempotency_key column + unique index to databases that predate FT-3."""
    with suppress(Exception):
        con.execute("ALTER TABLE marketplace_purchases ADD COLUMN idempotency_key TEXT")
    # Partial-unique-by-value: SQLite UNIQUE indexes allow unlimited NULLs, so
    # rows without a key (legacy/no-key callers) are unconstrained; rows WITH a
    # key can be inserted at most once — exactly the dedup semantics needed.
    con.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_mp_idempotency_key "
        "ON marketplace_purchases(idempotency_key) WHERE idempotency_key IS NOT NULL"
    )


@contextmanager
def _conn(db_path: str = _DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    with open_db(
        "marketplace", db_path, turso_name="marketplace", module_default_path=_DB_PATH
    ) as con:
        _migrate_chain_column(con)
        _migrate_sponsored_columns(con)
        _migrate_kya_column(con)
        _migrate_idempotency_column(con)
        yield con


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class Listing:
    listing_id:       str
    asset_id:         str
    seller_agent:     str
    community_id:     str
    tenant_id:        str
    asset_type:       str
    price_usd:        float
    currency:         str
    pricing_strategy: str
    status:           str
    demand_score:     float
    listed_at:        str
    expires_at:      str | None
    sold_at:         str | None
    chain:           str = "sepolia"
    is_sponsored:    bool = False
    sponsored_until: str | None = None
    kya_status:      str = "PENDING"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Purchase:
    purchase_id:    str
    listing_id:     str
    asset_id:       str
    buyer_agent:    str
    seller_agent:   str
    price_paid:     float
    status:         str
    escrow_id:      str
    negotiation_id: str
    purchased_at:   str
    completed_at:   str | None

    def to_dict(self) -> dict:
        return asdict(self)


def _row_to_listing(row: sqlite3.Row) -> Listing:
    keys = row.keys()
    return Listing(
        listing_id=row["listing_id"],
        asset_id=row["asset_id"],
        seller_agent=row["seller_agent"],
        community_id=row["community_id"],
        tenant_id=row["tenant_id"],
        asset_type=row["asset_type"],
        price_usd=row["price_usd"],
        currency=row["currency"],
        pricing_strategy=row["pricing_strategy"],
        status=row["status"],
        demand_score=row["demand_score"],
        listed_at=row["listed_at"],
        expires_at=row["expires_at"],
        sold_at=row["sold_at"],
        chain=row["chain"] if "chain" in keys else "sepolia",
        is_sponsored=bool(row["is_sponsored"]) if "is_sponsored" in keys else False,
        sponsored_until=row["sponsored_until"] if "sponsored_until" in keys else None,
        kya_status=row["kya_status"] if "kya_status" in keys else "PENDING",
    )


def _row_to_purchase(row: sqlite3.Row) -> Purchase:
    return Purchase(
        purchase_id=row["purchase_id"],
        listing_id=row["listing_id"],
        asset_id=row["asset_id"],
        buyer_agent=row["buyer_agent"],
        seller_agent=row["seller_agent"],
        price_paid=row["price_paid"],
        status=row["status"],
        escrow_id=row["escrow_id"],
        negotiation_id=row["negotiation_id"],
        purchased_at=row["purchased_at"],
        completed_at=row["completed_at"],
    )


# ── Listing CRUD ──────────────────────────────────────────────────────────────

def publish_listing(
    asset_id: str,
    seller_agent: str,
    community_id: str,
    tenant_id: str,
    asset_type: str,
    price_usd: float,
    pricing_strategy: str = "fixed",
    demand_score: float = 0.5,
    expires_hours: int | None = None,
    chain: str = "sepolia",
    db_path: str = _DB_PATH,
) -> Listing:
    from warden.web3.chains import VALID_CHAINS  # noqa: PLC0415
    if chain not in VALID_CHAINS:
        raise ValueError(f"Unknown chain '{chain}'. Valid options: {sorted(VALID_CHAINS)}.")

    listing_id = f"LST-{uuid.uuid4().hex[:12].upper()}"
    now = datetime.now(UTC).isoformat()
    expires_at = (
        (datetime.now(UTC) + timedelta(hours=expires_hours)).isoformat()
        if expires_hours else None
    )
    listing = Listing(
        listing_id=listing_id,
        asset_id=asset_id,
        seller_agent=seller_agent,
        community_id=community_id,
        tenant_id=tenant_id,
        asset_type=asset_type,
        price_usd=price_usd,
        currency="USD",
        pricing_strategy=pricing_strategy,
        status="active",
        demand_score=demand_score,
        listed_at=now,
        expires_at=expires_at,
        sold_at=None,
        chain=chain,
    )
    with _db_lock, _conn(db_path) as con:
        con.execute(
            """INSERT OR REPLACE INTO marketplace_listings
               (listing_id, asset_id, seller_agent, community_id, tenant_id,
                asset_type, price_usd, currency, pricing_strategy, status,
                demand_score, listed_at, expires_at, sold_at, chain)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                listing.listing_id, listing.asset_id, listing.seller_agent,
                listing.community_id, listing.tenant_id, listing.asset_type,
                listing.price_usd, listing.currency, listing.pricing_strategy,
                listing.status, listing.demand_score, listing.listed_at,
                listing.expires_at, listing.sold_at, listing.chain,
            ),
        )
    log.info("Listing published: %s asset=%s price=%.2f chain=%s",
             listing_id, asset_id, price_usd, chain)
    return listing


def get_listing(listing_id: str, db_path: str = _DB_PATH) -> Listing | None:
    with _conn(db_path) as con:
        row = con.execute(
            "SELECT * FROM marketplace_listings WHERE listing_id=?", (listing_id,)
        ).fetchone()
    return _row_to_listing(row) if row else None


def get_listings(
    community_id: str | None = None,
    asset_type: str | None = None,
    status: str = "active",
    max_price: float | None = None,
    limit: int = 50,
    db_path: str = _DB_PATH,
) -> list[Listing]:
    query = "SELECT * FROM marketplace_listings WHERE status=?"
    params: list = [status]
    if community_id:
        query += " AND community_id=?"
        params.append(community_id)
    if asset_type:
        query += " AND asset_type=?"
        params.append(asset_type)
    if max_price is not None:
        query += " AND price_usd<=?"
        params.append(max_price)
    query += " ORDER BY demand_score DESC, listed_at DESC LIMIT ?"
    params.append(limit)
    with _conn(db_path) as con:
        rows = con.execute(query, params).fetchall()
    return [_row_to_listing(r) for r in rows]


def update_listing_status(
    listing_id: str,
    status: str,
    db_path: str = _DB_PATH,
) -> bool:
    extras = {}
    if status == "sold":
        extras["sold_at"] = datetime.now(UTC).isoformat()
    with _db_lock, _conn(db_path) as con:
        if extras:
            cur = con.execute(
                "UPDATE marketplace_listings SET status=?, sold_at=? WHERE listing_id=?",
                (status, extras["sold_at"], listing_id),
            )
        else:
            cur = con.execute(
                "UPDATE marketplace_listings SET status=? WHERE listing_id=?",
                (status, listing_id),
            )
        return cur.rowcount > 0


def delist_stale_signals(db_path: str = _DB_PATH) -> int:
    cutoff = (
        datetime.now(UTC) - timedelta(hours=_SIGNAL_STALE_HOURS)
    ).isoformat()
    with _db_lock, _conn(db_path) as con:
        cur = con.execute(
            """UPDATE marketplace_listings SET status='stale'
               WHERE asset_type='signals' AND status='active' AND listed_at<?""",
            (cutoff,),
        )
    count = cur.rowcount
    if count:
        log.info("Delisted %d stale signal listings", count)
    return count


# ── Purchase CRUD ─────────────────────────────────────────────────────────────

def create_purchase(
    listing_id: str,
    asset_id: str,
    buyer_agent: str,
    seller_agent: str,
    price_paid: float,
    negotiation_id: str = "",
    db_path: str = _DB_PATH,
    idempotency_key: str | None = None,
) -> Purchase:
    purchase_id = f"PUR-{uuid.uuid4().hex[:12].upper()}"
    now = datetime.now(UTC).isoformat()
    purchase = Purchase(
        purchase_id=purchase_id,
        listing_id=listing_id,
        asset_id=asset_id,
        buyer_agent=buyer_agent,
        seller_agent=seller_agent,
        price_paid=price_paid,
        status="pending",
        escrow_id="",
        negotiation_id=negotiation_id,
        purchased_at=now,
        completed_at=None,
    )
    with _db_lock, _conn(db_path) as con:
        con.execute(
            """INSERT INTO marketplace_purchases
               (purchase_id, listing_id, asset_id, buyer_agent, seller_agent,
                price_paid, status, escrow_id, negotiation_id, purchased_at, completed_at,
                idempotency_key)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                purchase.purchase_id, purchase.listing_id, purchase.asset_id,
                purchase.buyer_agent, purchase.seller_agent, purchase.price_paid,
                purchase.status, purchase.escrow_id, purchase.negotiation_id,
                purchase.purchased_at, purchase.completed_at, idempotency_key,
            ),
        )
    return purchase


def get_purchase_by_idempotency_key(idempotency_key: str, db_path: str = _DB_PATH) -> Purchase | None:
    """Look up a purchase by its client-supplied idempotency key (FT-3)."""
    with _conn(db_path) as con:
        row = con.execute(
            "SELECT * FROM marketplace_purchases WHERE idempotency_key=?", (idempotency_key,)
        ).fetchone()
    return _row_to_purchase(row) if row else None


def get_purchase(purchase_id: str, db_path: str = _DB_PATH) -> Purchase | None:
    with _conn(db_path) as con:
        row = con.execute(
            "SELECT * FROM marketplace_purchases WHERE purchase_id=?", (purchase_id,)
        ).fetchone()
    return _row_to_purchase(row) if row else None


def finalize_purchase(
    purchase_id: str,
    escrow_id: str = "",
    db_path: str = _DB_PATH,
) -> bool:
    now = datetime.now(UTC).isoformat()
    with _db_lock, _conn(db_path) as con:
        cur = con.execute(
            "UPDATE marketplace_purchases SET status='completed', escrow_id=?, completed_at=? WHERE purchase_id=?",
            (escrow_id, now, purchase_id),
        )
        if cur.rowcount:
            row = con.execute(
                "SELECT listing_id FROM marketplace_purchases WHERE purchase_id=?",
                (purchase_id,),
            ).fetchone()
            if row:
                con.execute(
                    "UPDATE marketplace_listings SET status='sold', sold_at=? WHERE listing_id=?",
                    (now, row["listing_id"]),
                )
    if cur.rowcount:
        _trigger_asset_import(purchase_id=purchase_id, db_path=db_path)
    return cur.rowcount > 0


def list_purchases(
    buyer_agent: str | None = None,
    seller_agent: str | None = None,
    tenant_id: str | None = None,
    limit: int = 50,
    db_path: str = _DB_PATH,
) -> list[Purchase]:
    query = "SELECT * FROM marketplace_purchases WHERE 1=1"
    params: list = []
    if buyer_agent:
        query += " AND buyer_agent=?"
        params.append(buyer_agent)
    if seller_agent:
        query += " AND seller_agent=?"
        params.append(seller_agent)
    query += " ORDER BY purchased_at DESC LIMIT ?"
    params.append(limit)
    with _conn(db_path) as con:
        rows = con.execute(query, params).fetchall()
    return [_row_to_purchase(r) for r in rows]


def purchase_listing(
    listing_id: str,
    buyer_agent_id: str,
    db_path: str = _DB_PATH,
    idempotency_key: str | None = None,
) -> dict:
    """Atomically buy a listing: create purchase record + escrow + trigger import.

    ``idempotency_key`` (FT-3): without one, a retried POST /purchase call (double
    -submit, webhook retry) created a SECOND purchase record + a SECOND escrow for
    the same buyer intent on the same listing — a real double-charge/double-escrow
    bug, not just a duplicate log row. When a key is given, the whole check-then-
    create sequence runs under ``_db_lock`` and a replay returns the original
    purchase's response unchanged, creating nothing new.
    """
    if idempotency_key:
        with _db_lock:
            existing = get_purchase_by_idempotency_key(idempotency_key, db_path=db_path)
            if existing is not None:
                cached_listing = get_listing(existing.listing_id, db_path=db_path)
                log.info("listing: replayed purchase key=%s purchase=%s (nothing created)",
                         idempotency_key, existing.purchase_id)
                return {
                    "purchase_id": existing.purchase_id,
                    "listing_id":  existing.listing_id,
                    "asset_id":    existing.asset_id,
                    "asset_type":  cached_listing.asset_type if cached_listing else "",
                    "price_paid":  existing.price_paid,
                    "escrow_id":   existing.escrow_id,
                    "chain":       cached_listing.chain if cached_listing else "",
                    "status":      existing.status,
                    "replayed":    True,
                }
            return _do_purchase(listing_id, buyer_agent_id, db_path, idempotency_key)
    return _do_purchase(listing_id, buyer_agent_id, db_path, idempotency_key)


def _do_purchase(
    listing_id: str, buyer_agent_id: str, db_path: str, idempotency_key: str | None,
) -> dict:
    listing = get_listing(listing_id, db_path=db_path)
    if listing is None:
        raise ValueError(f"Listing '{listing_id}' not found.")
    if listing.status != "active":
        raise ValueError(f"Listing '{listing_id}' is not active (status={listing.status}).")

    purchase = create_purchase(
        listing_id=listing_id,
        asset_id=listing.asset_id,
        buyer_agent=buyer_agent_id,
        seller_agent=listing.seller_agent,
        price_paid=listing.price_usd,
        db_path=db_path,
        idempotency_key=idempotency_key,
    )

    try:
        from warden.marketplace.escrow import EscrowService  # noqa: PLC0415
        escrow = EscrowService().create_escrow(
            listing_id=listing_id,
            buyer_agent_id=buyer_agent_id,
            seller_agent_id=listing.seller_agent,
            amount_usd=listing.price_usd,
            purchase_id=purchase.purchase_id,
            chain=listing.chain,
            db_path=db_path,
        )
        escrow_id = escrow.escrow_id
    except Exception as exc:
        log.warning("Escrow creation failed for %s: %s", purchase.purchase_id, exc)
        escrow_id = ""

    if escrow_id:
        # Persist so a later replay (or get_purchase/list_purchases) sees the
        # real escrow_id instead of the placeholder "" create_purchase wrote.
        with _db_lock, _conn(db_path) as con:
            con.execute(
                "UPDATE marketplace_purchases SET escrow_id=? WHERE purchase_id=?",
                (escrow_id, purchase.purchase_id),
            )

    return {
        "purchase_id": purchase.purchase_id,
        "listing_id":  listing_id,
        "asset_id":    listing.asset_id,
        "asset_type":  listing.asset_type,
        "price_paid":  listing.price_usd,
        "escrow_id":   escrow_id,
        "chain":       listing.chain,
        "status":      "pending",
        "replayed":    False,
    }


def _trigger_asset_import(purchase_id: str, db_path: str) -> None:
    """Fire-and-forget asset import after escrow confirmation. Always fail-open."""
    try:
        from warden.marketplace.importer import AssetImporter  # noqa: PLC0415
        from warden.marketplace.service import get_asset  # noqa: PLC0415

        purchase = get_purchase(purchase_id, db_path=db_path)
        if purchase is None:
            return

        asset      = get_asset(purchase.asset_id) or {}
        asset_type = asset.get("asset_type", "rule")
        listing    = get_listing(purchase.listing_id, db_path=db_path)
        tenant_id  = listing.tenant_id if listing else ""

        AssetImporter(db_path=db_path).import_asset(
            purchase_id=purchase.purchase_id,
            asset_id=purchase.asset_id,
            asset_type=asset_type,
            asset_data=asset,
            buyer_agent=purchase.buyer_agent,
            tenant_id=tenant_id,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("_trigger_asset_import: skipped purchase=%s: %s", purchase_id, exc)


def list_purchases_by_agent(
    agent_id: str,
    role: str = "buyer",
    limit: int = 50,
    db_path: str = _DB_PATH,
) -> list[Purchase]:
    col = "buyer_agent" if role == "buyer" else "seller_agent"
    with _conn(db_path) as con:
        rows = con.execute(
            f"SELECT * FROM marketplace_purchases WHERE {col}=? ORDER BY purchased_at DESC LIMIT ?",
            (agent_id, limit),
        ).fetchall()
    return [_row_to_purchase(r) for r in rows]
