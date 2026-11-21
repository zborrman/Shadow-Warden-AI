"""
warden/m2m_store/closure.py
───────────────────────────
A seller closing their account: everything the store holds for that tenant,
first as one export (GDPR Art. 15/20 for the seller; Art. 28(3)(g) for the
buyers' data the seller is controller of), then gone.

What ``purge_tenant`` removes, for one tenant:
* products, their prices, translations, reservations and photos (rows and the
  objects in the media bucket, best-effort);
* categories and shipping zones;
* order requests where the tenant is the seller, with the buyers' sealed
  contact details, the customer cards built from them, their links and the
  journal;
* the tenant's own agent offers and orders, and its plan.

What stays: each store row, with name and description blanked and marked
deleted, so its slug stays reserved (no one may later trade under an address
buyers knew), plus the plan events and the one-trial marker, which hold no
personal data and stop a trial being taken twice.
"""
from __future__ import annotations

import contextlib
import json
from datetime import UTC, datetime
from typing import Any

from . import customers as cust
from . import order_requests as orq
from . import storefront as sf
from .inventory import _conn, _db_lock

# Literal statements, one per table: nothing here is built from input.
_BY_PRODUCT = {
    "prices": "DELETE FROM m2m_product_prices WHERE product_id=?",
    "translations": "DELETE FROM m2m_product_i18n WHERE product_id=?",
    "reservations": "DELETE FROM m2m_reservations WHERE product_id=?",
}
_BY_TENANT = {
    "categories": "DELETE FROM m2m_categories WHERE tenant_id=?",
    "shipping_zones": "DELETE FROM m2m_shipping_zones WHERE tenant_id=?",
    "offers": "DELETE FROM m2m_offers WHERE tenant_id=?",
    "orders": "DELETE FROM m2m_orders WHERE json_extract(data_json,'$.tenant_id')=?",
    "plan": "DELETE FROM m2m_store_plans WHERE tenant_id=?",
}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _product_ids(con: Any, tenant_id: str) -> list[str]:
    return [r["id"] for r in con.execute(
        "SELECT id FROM m2m_products WHERE json_extract(data_json,'$.tenant_id')=?", (tenant_id,),
    ).fetchall()]


def export_tenant(tenant_id: str) -> dict[str, Any]:
    """Every store the tenant has, with catalog, shipping, order requests and customers."""
    stores = []
    for store in sf.list_stores(tenant_id):
        sid = store["id"]
        customers = [cust.export_customer(sid, tenant_id, c["id"])
                     for c in cust.list_customers(sid, tenant_id)]
        stores.append(store | {
            "categories": sf.category_tree(sid),
            "products": sf.list_store_products(sid, tenant_id),
            "shipping_zones": sf.list_zones(sid),
            "order_requests": orq.list_for_seller(sid, tenant_id),
            "customers": customers,
        })
    return {"tenant_id": tenant_id, "exported_at": _now(), "stores": stores}


def purge_tenant(tenant_id: str) -> dict[str, int]:
    """Delete the tenant's store data. Returns row counts per kind; never raises on an empty tenant."""
    removed: dict[str, int] = {}
    object_keys: list[str] = []
    with _db_lock, _conn() as con:
        pids = _product_ids(con, tenant_id)
        object_keys = [r["object_key"] for r in con.execute(
            "SELECT object_key FROM m2m_product_images WHERE tenant_id=?", (tenant_id,)).fetchall()]
        removed["images"] = con.execute(
            "DELETE FROM m2m_product_images WHERE tenant_id=?", (tenant_id,)).rowcount
        for kind, sql in _BY_PRODUCT.items():
            removed[kind] = sum(con.execute(sql, (pid,)).rowcount for pid in pids)
        removed["products"] = sum(
            con.execute("DELETE FROM m2m_products WHERE id=?", (pid,)).rowcount for pid in pids)

        # Customers first: their links point at the order requests deleted next.
        cids = [r["id"] for r in con.execute(
            "SELECT id FROM m2m_customers WHERE seller_tenant_id=?", (tenant_id,)).fetchall()]
        removed["journal"] = con.execute(
            "DELETE FROM m2m_customer_journal WHERE seller_tenant_id=?", (tenant_id,)).rowcount
        removed["customer_links"] = con.execute(
            "DELETE FROM m2m_customer_orders WHERE request_id IN"
            " (SELECT id FROM m2m_order_requests WHERE seller_tenant_id=?)", (tenant_id,)).rowcount
        removed["customers"] = sum(
            con.execute("DELETE FROM m2m_customers WHERE id=?", (c,)).rowcount for c in cids)
        removed["order_requests"] = con.execute(
            "DELETE FROM m2m_order_requests WHERE seller_tenant_id=?", (tenant_id,)).rowcount

        for kind, sql in _BY_TENANT.items():
            removed[kind] = con.execute(sql, (tenant_id,)).rowcount

        removed["stores"] = con.execute(
            "UPDATE m2m_stores SET name='', description='', active=0,"
            " deleted_at=CASE WHEN deleted_at='' THEN ? ELSE deleted_at END WHERE tenant_id=?",
            (_now(), tenant_id)).rowcount

    if object_keys:
        # The rows are gone, so nothing serves these any more; removing the
        # objects is housekeeping and must not undo the closure if storage is down.
        from . import media
        with contextlib.suppress(Exception):
            client = media._client()
            for key in object_keys:
                media._remove_object(client, key)
    return removed


def dumps(export: dict[str, Any]) -> str:
    return json.dumps(export, indent=2, ensure_ascii=False, default=str)
