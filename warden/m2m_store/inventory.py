"""
warden/m2m_store/inventory.py
──────────────────────────────
InventoryManager — SQLite-backed product stock, reservations, offers and orders.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

from warden.config import data_path
from warden.db.connect import open_db
from warden.db.ddl_registry import register
from warden.observability import Reason, record_failopen

from .models import Offer, Order, Product

log = logging.getLogger("warden.m2m_store.inventory")

_db_lock = threading.RLock()

_INVENTORY_DDL = """
    CREATE TABLE IF NOT EXISTS m2m_products (
        id TEXT PRIMARY KEY,
        data_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS m2m_reservations (
        reservation_id TEXT PRIMARY KEY,
        product_id TEXT NOT NULL,
        qty INTEGER NOT NULL,
        expires_at TEXT NOT NULL,
        released INTEGER DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_m2m_res_open ON m2m_reservations(released, expires_at);
    CREATE TABLE IF NOT EXISTS m2m_orders (
        id TEXT PRIMARY KEY,
        data_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS m2m_offers (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        valid_until INTEGER NOT NULL,
        consumed INTEGER NOT NULL DEFAULT 0,
        data_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_m2m_offers_valid ON m2m_offers(valid_until);
"""

# Shares warden_m2m_store.db with analytics.py — same db_key, distinct module.
register("m2m_store", "inventory", _INVENTORY_DDL)

# Stock counters live inside data_json. Every change to them is ONE conditional
# UPDATE: production runs four uvicorn workers, and the old read-modify-write
# under a threading lock serialised only a single process, so two workers could
# both see the last unit available and both sell it.
_STOCK = "COALESCE(json_extract(data_json,'$.stock'),0)"
_RESERVED = "COALESCE(json_extract(data_json,'$.reserved'),0)"

_PURGE_INTERVAL_S = 10.0
_last_purge = 0.0


class OwnershipError(PermissionError):
    """A product id that belongs to another seller (or to no seller)."""


def _get_db_path() -> str:
    return data_path("warden_m2m_store.db", "M2M_STORE_DB_PATH")


@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    path = _get_db_path()
    with open_db("m2m_store", path, module_default_path=path) as con:
        yield con


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


class InventoryManager:

    # ── Products ──────────────────────────────────────────────────────────────

    def add_product(self, product: Product, tenant_id: str | None = None) -> Product:
        """
        Create a product owned by ``tenant_id``, or update one it already owns.

        The old ``INSERT OR REPLACE`` let any API key overwrite any product by
        sending its id. A product id owned by another seller — or by nobody, as
        rows written before ownership are — raises :class:`OwnershipError`.
        Reserved stock is never taken from the request body.
        """
        if tenant_id is not None:
            product.tenant_id = tenant_id
        if not product.id:
            product.id = str(uuid.uuid4())
        # Resolved before the lock is taken, and imported here because plans.py
        # imports this module. A product with no owner (rows written before
        # ownership existed, internal seeding) has no plan to be held to.
        plan = None
        if product.tenant_id:
            from .plans import PlanLimitError, get_plan
            plan = get_plan(product.tenant_id)
        with _db_lock, _conn() as con:
            row = con.execute(
                "SELECT json_extract(data_json,'$.tenant_id') AS owner, "
                f"{_RESERVED} AS reserved FROM m2m_products WHERE id=?",
                (product.id,),
            ).fetchone()
            if row is None:
                product.reserved = 0
                try:
                    if plan is None:
                        con.execute(
                            "INSERT INTO m2m_products(id, data_json, created_at) VALUES(?,?,?)",
                            (product.id, product.model_dump_json(), _now_iso()),
                        )
                    else:
                        # One statement, like the stock counters above: the count
                        # and the insert cannot be split across two workers.
                        cur = con.execute(
                            "INSERT INTO m2m_products(id, data_json, created_at) SELECT ?,?,?"
                            " WHERE (SELECT COUNT(*) FROM m2m_products"
                            "        WHERE json_extract(data_json,'$.tenant_id')=?"
                            "        AND COALESCE(json_extract(data_json,'$.deleted_at'),'')='') < ?",
                            (product.id, product.model_dump_json(), _now_iso(),
                             product.tenant_id, plan.limit("products")),
                        )
                        if cur.rowcount != 1:
                            raise PlanLimitError("products", plan.limit("products"), plan.plan)
                except sqlite3.IntegrityError as exc:
                    raise OwnershipError(product.id) from exc
                return product
            if not row["owner"] or row["owner"] != product.tenant_id:
                raise OwnershipError(product.id)
            product.reserved = int(row["reserved"])
            con.execute(
                "UPDATE m2m_products SET data_json=? WHERE id=? "
                "AND json_extract(data_json,'$.tenant_id')=?",
                (product.model_dump_json(), product.id, product.tenant_id),
            )
        return product

    def get_product(self, product_id: str) -> Product | None:
        with _db_lock, _conn() as con:
            row = con.execute(
                "SELECT data_json FROM m2m_products WHERE id=?", (product_id,)
            ).fetchone()
        return Product(**json.loads(row["data_json"])) if row else None

    def list_products(
        self,
        category: str | None = None,
        query: str | None = None,
        active_only: bool = True,
    ) -> list[Product]:
        with _db_lock, _conn() as con:
            rows = con.execute("SELECT data_json FROM m2m_products").fetchall()
        products = [Product(**json.loads(r["data_json"])) for r in rows]
        if active_only:
            products = [p for p in products if p.active]
        if category:
            products = [p for p in products if p.category.lower() == category.lower()]
        if query:
            q = query.lower()
            products = [p for p in products if q in p.name.lower() or q in p.description.lower()]
        return products

    def update_stock(self, product_id: str, delta: int) -> bool:
        """Atomically add delta to stock (use negative delta for deductions)."""
        with _db_lock, _conn() as con:
            cur = con.execute(
                "UPDATE m2m_products SET data_json=json_set(data_json,'$.stock',"
                f" MAX(0, {_STOCK} + ?)) WHERE id=?",
                (delta, product_id),
            )
        return cur.rowcount == 1

    def delete_product(self, product_id: str, tenant_id: str) -> bool:
        """Soft-delete a product the tenant owns: it leaves the catalog, its orders stay."""
        with _db_lock, _conn() as con:
            cur = con.execute(
                "UPDATE m2m_products SET data_json=json_set(data_json,'$.active',json('false'),"
                "'$.deleted_at',?) WHERE id=? AND json_extract(data_json,'$.tenant_id')=?"
                " AND COALESCE(json_extract(data_json,'$.deleted_at'),'')=''",
                (_now_iso(), product_id, tenant_id),
            )
        return cur.rowcount == 1

    # ── Reservations ──────────────────────────────────────────────────────────

    def reserve(self, product_id: str, qty: int, ttl_seconds: int = 45) -> str | None:
        """
        Reserve qty units of product_id for ttl_seconds.
        Returns reservation_id, or None if insufficient stock.
        """
        self._maybe_purge()
        reservation_id = str(uuid.uuid4())
        expires_at = (datetime.now(UTC) + timedelta(seconds=ttl_seconds)).isoformat()
        with _db_lock, _conn() as con:
            cur = con.execute(
                "UPDATE m2m_products SET data_json=json_set(data_json,'$.reserved',"
                f" {_RESERVED} + ?) WHERE id=? AND {_STOCK} - {_RESERVED} >= ?",
                (qty, product_id, qty),
            )
            if cur.rowcount != 1:
                return None
            con.execute(
                "INSERT INTO m2m_reservations(reservation_id, product_id, qty, expires_at)"
                " VALUES(?,?,?,?)",
                (reservation_id, product_id, qty, expires_at),
            )
        log.info("Reserved product=%s qty=%d res=%s ttl=%ds", product_id, qty, reservation_id, ttl_seconds)
        return reservation_id

    def extend(self, reservation_id: str, ttl_seconds: int) -> bool:
        """Push an open reservation's expiry out to now + ttl_seconds."""
        expires_at = (datetime.now(UTC) + timedelta(seconds=ttl_seconds)).isoformat()
        with _db_lock, _conn() as con:
            cur = con.execute(
                "UPDATE m2m_reservations SET expires_at=? WHERE reservation_id=? AND released=0",
                (expires_at, reservation_id),
            )
        return cur.rowcount == 1

    @staticmethod
    def _claim_reservation(con: sqlite3.Connection, reservation_id: str) -> sqlite3.Row | None:
        """Mark a reservation released exactly once; return it, or None if already released."""
        row = con.execute(
            "SELECT product_id, qty FROM m2m_reservations WHERE reservation_id=?",
            (reservation_id,),
        ).fetchone()
        if row is None:
            return None
        cur = con.execute(
            "UPDATE m2m_reservations SET released=1 WHERE reservation_id=? AND released=0",
            (reservation_id,),
        )
        return row if cur.rowcount == 1 else None

    def release(self, reservation_id: str) -> bool:
        """Release a reservation (e.g. on timeout or order cancellation)."""
        with _db_lock, _conn() as con:
            row = self._claim_reservation(con, reservation_id)
            if row is None:
                return False
            con.execute(
                "UPDATE m2m_products SET data_json=json_set(data_json,'$.reserved',"
                f" MAX(0, {_RESERVED} - ?)) WHERE id=?",
                (row["qty"], row["product_id"]),
            )
        return True

    def commit_stock(self, product_id: str, qty: int, reservation_id: str = "") -> bool:
        """
        Take qty units out of stock for a sale, before any money moves.

        With a live reservation the units are already held: consume it. If the
        reservation lapsed (or there is none) the sale needs unreserved stock,
        checked in the same statement that deducts it.
        """
        with _db_lock, _conn() as con:
            held = self._claim_reservation(con, reservation_id) if reservation_id else None
            if held is not None:
                con.execute(
                    "UPDATE m2m_products SET data_json=json_set(json_set(data_json,"
                    f" '$.stock', MAX(0, {_STOCK} - ?)), '$.reserved', MAX(0, {_RESERVED} - ?))"
                    " WHERE id=?",
                    (qty, held["qty"], product_id),
                )
                return True
            cur = con.execute(
                "UPDATE m2m_products SET data_json=json_set(data_json,'$.stock',"
                f" {_STOCK} - ?) WHERE id=? AND {_STOCK} - {_RESERVED} >= ?",
                (qty, product_id, qty),
            )
        return cur.rowcount == 1

    def _maybe_purge(self) -> None:
        # Nothing schedules purge_expired_reservations, so an abandoned offer
        # held its stock forever. Run it lazily from the reserve path instead.
        global _last_purge
        now = time.monotonic()
        if now - _last_purge < _PURGE_INTERVAL_S:
            return
        _last_purge = now
        try:
            self.purge_expired_reservations()
        except Exception as exc:
            record_failopen("m2m_reservation_purge", Reason.BACKEND_ERROR, exc)

    def purge_expired_reservations(self) -> int:
        """Release reservations past their expires_at and drop stale offers."""
        now = _now_iso()
        with _db_lock, _conn() as con:
            rows = con.execute(
                "SELECT reservation_id FROM m2m_reservations WHERE released=0 AND expires_at < ?",
                (now,),
            ).fetchall()
            con.execute(
                "DELETE FROM m2m_offers WHERE valid_until < ?", (int(time.time()) - 3600,)
            )
        count = 0
        for row in rows:
            if self.release(row["reservation_id"]):
                count += 1
        if count:
            log.info("Purged %d expired M2M reservations", count)
        return count

    # ── Offers ────────────────────────────────────────────────────────────────
    # Offers used to live in a per-process TTLCache. Behind four uvicorn workers
    # an offer created in one worker was a 404 in the other three.

    def save_offer(self, offer: Offer) -> None:
        with _db_lock, _conn() as con:
            con.execute(
                "INSERT INTO m2m_offers(id, tenant_id, valid_until, data_json, created_at)"
                " VALUES(?,?,?,?,?)",
                (offer.id, offer.tenant_id, offer.valid_until, offer.model_dump_json(), _now_iso()),
            )

    def get_offer(self, offer_id: str, tenant_id: str) -> Offer | None:
        """An unconsumed offer issued to ``tenant_id``; another tenant's offer is not found."""
        with _db_lock, _conn() as con:
            row = con.execute(
                "SELECT data_json, valid_until FROM m2m_offers"
                " WHERE id=? AND tenant_id=? AND consumed=0",
                (offer_id, tenant_id),
            ).fetchone()
        if row is None:
            return None
        offer = Offer(**json.loads(row["data_json"]))
        offer.valid_until = int(row["valid_until"])
        return offer

    def extend_offer(self, offer_id: str, tenant_id: str, valid_until: int) -> bool:
        with _db_lock, _conn() as con:
            cur = con.execute(
                "UPDATE m2m_offers SET valid_until=? WHERE id=? AND tenant_id=?"
                " AND consumed=0 AND valid_until >= ?",
                (valid_until, offer_id, tenant_id, int(time.time())),
            )
        return cur.rowcount == 1

    def claim_offer(self, offer_id: str, tenant_id: str) -> bool:
        """Consume an offer once. Two concurrent orders on one offer: one wins."""
        with _db_lock, _conn() as con:
            cur = con.execute(
                "UPDATE m2m_offers SET consumed=1 WHERE id=? AND tenant_id=?"
                " AND consumed=0 AND valid_until >= ?",
                (offer_id, tenant_id, int(time.time())),
            )
        return cur.rowcount == 1

    def unclaim_offer(self, offer_id: str, tenant_id: str) -> None:
        with _db_lock, _conn() as con:
            con.execute(
                "UPDATE m2m_offers SET consumed=0 WHERE id=? AND tenant_id=?",
                (offer_id, tenant_id),
            )

    # ── Orders ────────────────────────────────────────────────────────────────

    def save_order(self, order: Order) -> None:
        with _db_lock, _conn() as con:
            con.execute(
                "INSERT OR REPLACE INTO m2m_orders(id, data_json, created_at) VALUES(?,?,?)",
                (order.id, order.model_dump_json(), order.created_at or _now_iso()),
            )
        self._mirror_to_marketplace(order)

    def _mirror_to_marketplace(self, order: Order) -> None:
        """FT-6 Phase B dual-write — m2m_orders stays the source of truth."""
        try:
            import json as _json

            from warden.marketplace.listing import upsert_mirrored_order
            upsert_mirrored_order(
                "m2m_store",
                order.id,
                buyer_agent=order.agent_id,
                asset_id=order.product_id,
                price_paid=order.total,
                status=order.status,
                tenant_id=order.tenant_id or None,
                mandate_id=order.mandate_id or None,
                payment_token=order.payment_token or None,
                reservation_id=order.reservation_id or None,
                stix_chain_id=order.stix_chain_id or None,
                shipped_at=order.shipped_at or None,
                metadata_json=_json.dumps({"offer_id": order.offer_id, "qty": order.qty}),
                purchased_at=order.created_at or None,
            )
        except Exception as exc:
            record_failopen("order_mirror_m2m_store", Reason.BACKEND_ERROR, exc)
            log.debug("m2m_orders -> marketplace_purchases mirror unavailable: %s", exc)

    def get_order(self, order_id: str, tenant_id: str | None = None) -> Order | None:
        """
        One order. With ``tenant_id`` it is returned only to the buyer or the
        seller of record; anyone else gets None, exactly as for a missing id.
        """
        with _db_lock, _conn() as con:
            row = con.execute("SELECT data_json FROM m2m_orders WHERE id=?", (order_id,)).fetchone()
        if row is None:
            return None
        order = Order(**json.loads(row["data_json"]))
        if tenant_id is not None and tenant_id not in (order.tenant_id, order.seller_tenant_id):
            return None
        return order

    def list_orders(
        self,
        agent_id: str | None = None,
        limit: int = 50,
        tenant_id: str | None = None,
    ) -> list[Order]:
        """Newest first. Filters run in SQL, so ``limit`` counts matching orders."""
        sql = "SELECT data_json FROM m2m_orders WHERE 1=1"
        args: list[object] = []
        if tenant_id is not None:
            sql += " AND json_extract(data_json,'$.tenant_id')=?"
            args.append(tenant_id)
        if agent_id:
            sql += " AND json_extract(data_json,'$.agent_id')=?"
            args.append(agent_id)
        sql += " ORDER BY created_at DESC LIMIT ?"
        args.append(limit)
        with _db_lock, _conn() as con:
            rows = con.execute(sql, args).fetchall()
        return [Order(**json.loads(r["data_json"])) for r in rows]

    def ship(self, order_id: str, webhook_url: str | None = None) -> bool:
        """Mark order as SHIPPED and optionally call ERP webhook."""
        order = self.get_order(order_id)
        if order is None or order.status != "PAID":
            return False
        order.status = "SHIPPED"
        order.shipped_at = _now_iso()
        self.save_order(order)
        if webhook_url:
            try:
                import httpx
                httpx.post(webhook_url, json={"order_id": order_id, "status": "SHIPPED"}, timeout=5)
            except Exception as exc:
                log.debug("ERP webhook failed: %s", exc)
        return True


_inventory = InventoryManager()


def get_inventory() -> InventoryManager:
    return _inventory
