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


def _migrate_order_consolidation_columns(con: sqlite3.Connection) -> None:
    """FT-6 order-model consolidation, Phase A (docs/order-model-consolidation-plan.md).

    Additive-only: nine nullable columns so m2m_store/agentic_commerce rows can
    eventually mirror into this table without touching any existing row or
    reader. `domain` defaults to 'marketplace' so every pre-existing row is
    correctly attributed without a backfill. Does NOT touch `asset_id`'s NOT
    NULL constraint — relaxing an existing constraint needs a table rebuild
    (SQLite has no ALTER COLUMN), a different risk class than adding a
    column; that rebuild is scoped to Phase B, when agentic_commerce dual-write
    actually needs to insert a NULL asset_id, not run pre-emptively here.
    """
    for column, ddl_type in (
        ("domain", "TEXT NOT NULL DEFAULT 'marketplace'"),
        ("tenant_id", "TEXT"),
        ("mandate_id", "TEXT"),
        ("payment_token", "TEXT"),
        ("reservation_id", "TEXT"),
        ("stix_chain_id", "TEXT"),
        ("shipped_at", "TEXT"),
        ("receipt_json", "TEXT"),
        ("metadata_json", "TEXT"),
    ):
        with suppress(Exception):
            con.execute(f"ALTER TABLE marketplace_purchases ADD COLUMN {column} {ddl_type}")
    con.execute("CREATE INDEX IF NOT EXISTS idx_mp_domain ON marketplace_purchases(domain)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_mp_tenant ON marketplace_purchases(tenant_id)")


def _migrate_relax_asset_id_nullable(con: sqlite3.Connection) -> None:
    """FT-6 order-model consolidation, Phase B — relax asset_id to nullable.

    SQLite has no ALTER COLUMN, so loosening an existing NOT NULL constraint
    means a full table rebuild: create the new shape, copy every row
    byte-for-byte (this only relaxes a constraint — no existing row has a
    NULL asset_id today, so nothing can be lost), drop the old table,
    rename, recreate every index. No explicit BEGIN/COMMIT here — `con` (from
    `open_db()`) already has a transaction open by the time it's yielded to
    us (via `ensure_schema`'s own bookkeeping writes), so issuing a second
    `BEGIN` would raise "cannot start a transaction within a transaction".
    Atomicity instead comes from `open_db()`'s own try/finally: it commits
    once, after this whole `_conn()` body returns; if any statement below
    raises, that commit is skipped and the connection closes uncommitted,
    which SQLite rolls back on its own. Idempotency check via PRAGMA
    table_info runs first, so this executes at most once per database, ever.
    """
    info = con.execute("PRAGMA table_info(marketplace_purchases)").fetchall()
    asset_id_row = next((row for row in info if row[1] == "asset_id"), None)
    if asset_id_row is None or asset_id_row[3] == 0:   # notnull flag already 0
        return
    con.execute(
        """
        CREATE TABLE marketplace_purchases_new (
            purchase_id     TEXT PRIMARY KEY,
            listing_id      TEXT NOT NULL,
            asset_id        TEXT,
            buyer_agent     TEXT NOT NULL,
            seller_agent    TEXT NOT NULL,
            price_paid      REAL NOT NULL,
            status          TEXT NOT NULL DEFAULT 'pending',
            escrow_id       TEXT NOT NULL DEFAULT '',
            negotiation_id  TEXT NOT NULL DEFAULT '',
            purchased_at    TEXT NOT NULL,
            completed_at    TEXT,
            idempotency_key TEXT,
            domain          TEXT NOT NULL DEFAULT 'marketplace',
            tenant_id       TEXT,
            mandate_id      TEXT,
            payment_token   TEXT,
            reservation_id  TEXT,
            stix_chain_id   TEXT,
            shipped_at      TEXT,
            receipt_json    TEXT,
            metadata_json   TEXT
        )
        """
    )
    cols = (
        "purchase_id, listing_id, asset_id, buyer_agent, seller_agent, price_paid, "
        "status, escrow_id, negotiation_id, purchased_at, completed_at, idempotency_key, "
        "domain, tenant_id, mandate_id, payment_token, reservation_id, stix_chain_id, "
        "shipped_at, receipt_json, metadata_json"
    )
    con.execute(
        f"INSERT INTO marketplace_purchases_new ({cols}) "
        f"SELECT {cols} FROM marketplace_purchases"
    )
    con.execute("DROP TABLE marketplace_purchases")
    con.execute("ALTER TABLE marketplace_purchases_new RENAME TO marketplace_purchases")
    con.execute("CREATE INDEX IF NOT EXISTS idx_mp_buyer ON marketplace_purchases(buyer_agent)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_mp_seller ON marketplace_purchases(seller_agent)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_mp_listing ON marketplace_purchases(listing_id)")
    con.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_mp_idempotency_key "
        "ON marketplace_purchases(idempotency_key) WHERE idempotency_key IS NOT NULL"
    )
    con.execute("CREATE INDEX IF NOT EXISTS idx_mp_domain ON marketplace_purchases(domain)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_mp_tenant ON marketplace_purchases(tenant_id)")


def upsert_mirrored_order(
    domain: str,
    purchase_id: str,
    *,
    buyer_agent: str = "",
    seller_agent: str = "",
    asset_id: str | None = None,
    price_paid: float = 0.0,
    status: str = "pending",
    tenant_id: str | None = None,
    mandate_id: str | None = None,
    payment_token: str | None = None,
    reservation_id: str | None = None,
    stix_chain_id: str | None = None,
    shipped_at: str | None = None,
    receipt_json: str | None = None,
    metadata_json: str | None = None,
    purchased_at: str | None = None,
    db_path: str | None = None,
) -> None:
    """FT-6 Phase B dual-write: mirror a non-marketplace order into marketplace_purchases.

    Callers (m2m_store.InventoryManager, agentic_commerce.service) call this
    AFTER their own domain table write already succeeded — this is a mirror,
    not the source of truth, so a mirror failure must never surface as a
    failure of the caller's real write. Upserts on purchase_id (the primary
    key), so a second call with the same purchase_id (e.g. status/shipped_at/
    receipt_json updates) updates the existing mirrored row instead of
    inserting a duplicate.

    ``db_path`` defaults to ``None`` (resolved to the module's ``_DB_PATH``
    inside the function body, not as a bound default) rather than following
    this file's usual ``= _DB_PATH`` pattern — unlike every other function
    here, this one is called from OTHER modules that don't know marketplace's
    path, so it must observe test-time monkeypatching of ``listing._DB_PATH``,
    which a def-time-bound default cannot.
    """
    now = purchased_at or datetime.now(UTC).isoformat()
    try:
        with _conn(db_path or _DB_PATH) as con:
            con.execute(
                "INSERT INTO marketplace_purchases "
                "(purchase_id, listing_id, asset_id, buyer_agent, seller_agent, price_paid, "
                " status, purchased_at, domain, tenant_id, mandate_id, payment_token, "
                " reservation_id, stix_chain_id, shipped_at, receipt_json, metadata_json) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                # price_paid is deliberately NOT in this UPDATE SET: it's set once at
                # order-creation time; a later status/receipt/shipped_at update call
                # (e.g. ap2.py's receipt mirror) omits it and must not zero it out.
                "ON CONFLICT(purchase_id) DO UPDATE SET "
                "status=excluded.status, "
                "shipped_at=COALESCE(excluded.shipped_at, marketplace_purchases.shipped_at), "
                "receipt_json=COALESCE(excluded.receipt_json, marketplace_purchases.receipt_json), "
                "metadata_json=COALESCE(excluded.metadata_json, marketplace_purchases.metadata_json)",
                (
                    purchase_id, "", asset_id, buyer_agent, seller_agent, price_paid,
                    status, now, domain, tenant_id, mandate_id, payment_token,
                    reservation_id, stix_chain_id, shipped_at, receipt_json, metadata_json,
                ),
            )
    except Exception as exc:
        from warden.observability import Reason, record_failopen
        log.warning("marketplace_purchases mirror write failed, source-of-truth write unaffected: %s", exc)
        record_failopen("marketplace_mirror_order", Reason.BACKEND_ERROR, exc)


@contextmanager
def _conn(db_path: str = _DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    with open_db(
        "marketplace", db_path, turso_name="marketplace", module_default_path=_DB_PATH
    ) as con:
        _migrate_chain_column(con)
        _migrate_sponsored_columns(con)
        _migrate_kya_column(con)
        _migrate_idempotency_column(con)
        _migrate_order_consolidation_columns(con)
        _migrate_relax_asset_id_nullable(con)
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


def _resolve_buyer_tenant_id(buyer_agent_id: str) -> str:
    """buyer_agent_id is a DID; the Budget Guardian is tenant-scoped. Falls
    back to the raw agent_id when there's no KYA record (unknown owner) —
    still worth authorizing, just under a less meaningful tenant identity.
    """
    try:
        from warden.marketplace.kya import get_kya_record
        record = get_kya_record(buyer_agent_id)
        if record and record.owner_tenant_id:
            return record.owner_tenant_id
    except Exception as exc:
        log.debug("listing: kya lookup failed for buyer=%s: %s", buyer_agent_id[:32], exc)
    return buyer_agent_id


def _authorize_purchase(buyer_agent_id: str, amount_usd: float) -> None:
    """FT-6 money-authorization chokepoint — see warden/payments/authorize.py.

    No-op unless AUTHORIZE_PAYMENT_ENFORCED=true. When a clean call decides
    DENY or REQUIRE_APPROVAL, raises ValueError so `buy_listing()` maps it to
    HTTP 400 (same convention this function already uses for "not found"/
    "not active"). REQUIRE_APPROVAL blocks rather than proceeding — there is
    no human-approval queue wired into this synchronous purchase flow yet
    (unlike MasterAgent's REQUIRES_APPROVAL/Redis/Slack pattern), so treating
    it as a hard stop is the conservative choice for money movement.

    If the call to authorize_payment() itself fails outright (not a clean
    fail-soft verdict — a bug in this plumbing), fails open: a broken
    authorization import must never retroactively brick a purchase flow
    nobody has opted into yet.
    """
    try:
        from warden.payments.authorize import authorize_payment
        tenant_id = _resolve_buyer_tenant_id(buyer_agent_id)
        result = authorize_payment(tenant_id, buyer_agent_id, "purchase", amount_usd,
                                    merchant=tenant_id)
    except Exception as exc:
        from warden.observability import Reason, record_failopen
        log.warning("listing: authorize_payment call failed, purchase proceeds: %s", exc)
        record_failopen("payments_authorize", Reason.BACKEND_ERROR, exc)
        return

    if result.verdict in ("DENY", "REQUIRE_APPROVAL"):
        raise ValueError(f"Purchase not authorized ({result.verdict}): {'; '.join(result.reasons)}")


def _do_purchase(
    listing_id: str, buyer_agent_id: str, db_path: str, idempotency_key: str | None,
) -> dict:
    listing = get_listing(listing_id, db_path=db_path)
    if listing is None:
        raise ValueError(f"Listing '{listing_id}' not found.")
    if listing.status != "active":
        raise ValueError(f"Listing '{listing_id}' is not active (status={listing.status}).")

    _authorize_purchase(buyer_agent_id, listing.price_usd)

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
