"""
warden/m2m_store/inventory.py
──────────────────────────────
InventoryManager — SQLite-backed product stock with Redis reservation layer.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime

from warden.m2m_store.models import Order, Product

log = logging.getLogger("warden.m2m_store.inventory")
_db_lock = threading.RLock()


def _get_db_path() -> str:
    return os.getenv("M2M_STORE_DB_PATH", "/tmp/warden_m2m_store.db")


@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    con = sqlite3.connect(_get_db_path(), check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    _ensure_schema(con)
    try:
        yield con
        con.commit()
    finally:
        con.close()


def _ensure_schema(con: sqlite3.Connection) -> None:
    con.executescript("""
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
        CREATE TABLE IF NOT EXISTS m2m_orders (
            id TEXT PRIMARY KEY,
            data_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
    """)


class InventoryManager:

    # ── Products ──────────────────────────────────────────────────────────────

    def add_product(self, product: Product) -> Product:
        if not product.id:
            product.id = str(uuid.uuid4())
        with _db_lock, _conn() as con:
            con.execute(
                "INSERT OR REPLACE INTO m2m_products(id, data_json, created_at) VALUES(?,?,?)",
                (product.id, product.model_dump_json(), datetime.now(UTC).isoformat()),
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
        p = self.get_product(product_id)
        if p is None:
            return False
        p.stock = max(0, p.stock + delta)
        with _db_lock, _conn() as con:
            con.execute(
                "UPDATE m2m_products SET data_json=? WHERE id=?",
                (p.model_dump_json(), product_id),
            )
        return True

    # ── Reservations ──────────────────────────────────────────────────────────

    def reserve(self, product_id: str, qty: int, ttl_seconds: int = 45) -> str | None:
        """
        Reserve qty units of product_id for ttl_seconds.
        Returns reservation_id, or None if insufficient stock.
        """
        from datetime import timedelta
        p = self.get_product(product_id)
        if p is None or p.available < qty:
            return None
        reservation_id = str(uuid.uuid4())
        expires_at = (datetime.now(UTC) + timedelta(seconds=ttl_seconds)).isoformat()

        # Increment reserved count on product
        p.reserved = p.reserved + qty
        with _db_lock, _conn() as con:
            con.execute(
                "INSERT INTO m2m_reservations(reservation_id, product_id, qty, expires_at) VALUES(?,?,?,?)",
                (reservation_id, product_id, qty, expires_at),
            )
            con.execute(
                "UPDATE m2m_products SET data_json=? WHERE id=?",
                (p.model_dump_json(), product_id),
            )
        log.info("Reserved product=%s qty=%d res=%s ttl=%ds", product_id, qty, reservation_id, ttl_seconds)
        return reservation_id

    def release(self, reservation_id: str) -> bool:
        """Release a reservation (e.g. on timeout or order cancellation)."""
        with _db_lock, _conn() as con:
            row = con.execute(
                "SELECT product_id, qty, released FROM m2m_reservations WHERE reservation_id=?",
                (reservation_id,),
            ).fetchone()
            if not row or row["released"]:
                return False
            p = self.get_product(row["product_id"])
            if p:
                p.reserved = max(0, p.reserved - row["qty"])
                con.execute(
                    "UPDATE m2m_products SET data_json=? WHERE id=?",
                    (p.model_dump_json(), row["product_id"]),
                )
            con.execute(
                "UPDATE m2m_reservations SET released=1 WHERE reservation_id=?",
                (reservation_id,),
            )
        return True

    def purge_expired_reservations(self) -> int:
        """Release all reservations past their expires_at. Call from ARQ cron."""
        now = datetime.now(UTC).isoformat()
        with _db_lock, _conn() as con:
            rows = con.execute(
                "SELECT reservation_id FROM m2m_reservations WHERE released=0 AND expires_at < ?",
                (now,),
            ).fetchall()
        count = 0
        for row in rows:
            if self.release(row["reservation_id"]):
                count += 1
        if count:
            log.info("Purged %d expired M2M reservations", count)
        return count

    # ── Orders ────────────────────────────────────────────────────────────────

    def save_order(self, order: Order) -> None:
        with _db_lock, _conn() as con:
            con.execute(
                "INSERT OR REPLACE INTO m2m_orders(id, data_json, created_at) VALUES(?,?,?)",
                (order.id, order.model_dump_json(), order.created_at or datetime.now(UTC).isoformat()),
            )

    def get_order(self, order_id: str) -> Order | None:
        with _db_lock, _conn() as con:
            row = con.execute("SELECT data_json FROM m2m_orders WHERE id=?", (order_id,)).fetchone()
        return Order(**json.loads(row["data_json"])) if row else None

    def list_orders(self, agent_id: str | None = None, limit: int = 50) -> list[Order]:
        with _db_lock, _conn() as con:
            rows = con.execute(
                "SELECT data_json FROM m2m_orders ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        orders = [Order(**json.loads(r["data_json"])) for r in rows]
        if agent_id:
            orders = [o for o in orders if o.agent_id == agent_id]
        return orders

    def ship(self, order_id: str, webhook_url: str | None = None) -> bool:
        """Mark order as SHIPPED and optionally call ERP webhook."""
        order = self.get_order(order_id)
        if order is None or order.status != "PAID":
            return False
        order.status = "SHIPPED"
        order.shipped_at = datetime.now(UTC).isoformat()
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
