"""
warden/m2m_store/storefront.py
───────────────────────────────
Store builder data model (plan stage M2): stores, a category tree, a price per
currency, per-locale product text and shipping zones.

Every row carries the seller's ``tenant_id`` and every write checks it. A row
owned by another tenant reads as absent (404), so its existence is not
disclosed. Deletes are soft: ``deleted_at`` is set and the row stays, which
keeps old orders resolvable and keeps a store's slug from being taken over by
another seller after it is deleted.

Prices are integer minor units next to an ISO 4217 code, set by the seller per
currency. Nothing converts between currencies and nothing here knows a tariff
schedule: a duty figure is the seller's own rate, returned as an estimate.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from decimal import ROUND_HALF_EVEN, Decimal
from typing import Any

from warden.db.ddl_registry import register

from . import plans
from .inventory import _conn, _db_lock, _now_iso, get_inventory
from .models import (
    SETTLEMENT_CURRENCIES,
    CategoryIn,
    CategoryPatch,
    PriceIn,
    Product,
    ShippingZoneIn,
    StoreIn,
    StorePatch,
    TranslationIn,
    from_minor,
)

_STOREFRONT_DDL = """
    CREATE TABLE IF NOT EXISTS m2m_stores (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        slug TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        default_currency TEXT NOT NULL,
        currencies_json TEXT NOT NULL,
        locales_json TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        deleted_at TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_m2m_stores_tenant ON m2m_stores(tenant_id);
    CREATE TABLE IF NOT EXISTS m2m_categories (
        id TEXT PRIMARY KEY,
        store_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        parent_id TEXT NOT NULL DEFAULT '',
        slug TEXT NOT NULL,
        name TEXT NOT NULL,
        position INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        deleted_at TEXT NOT NULL DEFAULT ''
    );
    CREATE UNIQUE INDEX IF NOT EXISTS uq_m2m_categories_slug
        ON m2m_categories(store_id, slug) WHERE deleted_at = '';
    CREATE TABLE IF NOT EXISTS m2m_product_prices (
        product_id TEXT NOT NULL,
        currency TEXT NOT NULL,
        amount_minor INTEGER NOT NULL CHECK (amount_minor >= 0),
        PRIMARY KEY (product_id, currency)
    );
    CREATE TABLE IF NOT EXISTS m2m_product_i18n (
        product_id TEXT NOT NULL,
        locale TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (product_id, locale)
    );
    CREATE TABLE IF NOT EXISTS m2m_shipping_zones (
        id TEXT PRIMARY KEY,
        store_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        name TEXT NOT NULL,
        countries_json TEXT NOT NULL,
        currency TEXT NOT NULL,
        rate_minor INTEGER NOT NULL,
        free_over_minor INTEGER,
        duty_estimate_bps INTEGER NOT NULL DEFAULT 0,
        min_days INTEGER NOT NULL,
        max_days INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        deleted_at TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_m2m_zones_store ON m2m_shipping_zones(store_id);
"""

register("m2m_store", "storefront", _STOREFRONT_DDL)

# Slugs the portal routes under /s/ or /store/ would shadow.
RESERVED_SLUGS = frozenset({"admin", "api", "manage", "new", "settings", "store", "www"})
MAX_CATEGORY_DEPTH = 5


class StoreNotFoundError(LookupError):
    """Absent, deleted, or owned by another tenant — indistinguishable on purpose."""


class StoreConflictError(Exception):
    """The write would break a uniqueness or tree invariant."""


class StoreInvalidError(ValueError):
    """The write names something that does not fit the store it belongs to."""


# ── Stores ────────────────────────────────────────────────────────────────────

def _store_row(r: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": r["id"],
        "slug": r["slug"],
        "name": r["name"],
        "description": r["description"],
        "default_currency": r["default_currency"],
        "currencies": json.loads(r["currencies_json"]),
        "locales": json.loads(r["locales_json"]),
        "active": bool(r["active"]),
        "created_at": r["created_at"],
    }


def create_store(tenant_id: str, body: StoreIn) -> dict[str, Any]:
    if body.slug in RESERVED_SLUGS:
        raise StoreConflictError(f"slug {body.slug!r} is reserved")
    # The plan is enforced here, in the function that writes the row, and not in
    # the route: a caller that reaches this function cannot forget to check.
    plan = plans.get_plan(tenant_id)
    if len(body.locales) > plan.limit("locales"):
        raise plans.PlanLimitError("locales", plan.limit("locales"), plan.plan)
    store_id = str(uuid.uuid4())
    try:
        with _db_lock, _conn() as con:
            # Count and insert are one statement. Four workers each running
            # "count, then insert" would all see room for the last store.
            cur = con.execute(
                "INSERT INTO m2m_stores(id, tenant_id, slug, name, description, default_currency,"
                " currencies_json, locales_json, created_at) SELECT ?,?,?,?,?,?,?,?,?"
                " WHERE (SELECT COUNT(*) FROM m2m_stores"
                "        WHERE tenant_id=? AND deleted_at='') < ?",
                (store_id, tenant_id, body.slug, body.name, body.description,
                 body.default_currency, json.dumps(body.currencies), json.dumps(body.locales),
                 _now_iso(), tenant_id, plan.limit("stores")),
            )
    except sqlite3.IntegrityError as exc:
        # A deleted store keeps its slug: no one else may trade under it.
        raise StoreConflictError(f"slug {body.slug!r} is taken") from exc
    if cur.rowcount != 1:
        raise plans.PlanLimitError("stores", plan.limit("stores"), plan.plan)
    return get_store(store_id, tenant_id)


def get_store(store_id: str, tenant_id: str) -> dict[str, Any]:
    """The owner's view of a store: inactive stores included, deleted ones not."""
    with _db_lock, _conn() as con:
        r = con.execute(
            "SELECT * FROM m2m_stores WHERE id=? AND tenant_id=? AND deleted_at=''",
            (store_id, tenant_id),
        ).fetchone()
    if r is None:
        raise StoreNotFoundError("store")
    return _store_row(r)


def get_public_store(slug: str) -> dict[str, Any]:
    """The buyer's view: active, not deleted, no owner fields."""
    with _db_lock, _conn() as con:
        r = con.execute(
            "SELECT * FROM m2m_stores WHERE slug=? AND active=1 AND deleted_at=''", (slug,),
        ).fetchone()
    if r is None:
        raise StoreNotFoundError("store")
    return _store_row(r)


def list_stores(tenant_id: str) -> list[dict[str, Any]]:
    with _db_lock, _conn() as con:
        rows = con.execute(
            "SELECT * FROM m2m_stores WHERE tenant_id=? AND deleted_at='' ORDER BY created_at",
            (tenant_id,),
        ).fetchall()
    return [_store_row(r) for r in rows]


def patch_store(store_id: str, tenant_id: str, body: StorePatch) -> dict[str, Any]:
    fields = body.model_dump(exclude_none=True)
    if fields:
        if "active" in fields:
            fields["active"] = int(fields["active"])
        sets = ", ".join(f"{k}=?" for k in fields)
        with _db_lock, _conn() as con:
            cur = con.execute(
                f"UPDATE m2m_stores SET {sets} WHERE id=? AND tenant_id=? AND deleted_at=''",
                (*fields.values(), store_id, tenant_id),
            )
        if cur.rowcount != 1:
            raise StoreNotFoundError("store")
    return get_store(store_id, tenant_id)


def delete_store(store_id: str, tenant_id: str) -> None:
    """Soft-delete a store and take its products off sale."""
    now = _now_iso()
    with _db_lock, _conn() as con:
        cur = con.execute(
            "UPDATE m2m_stores SET deleted_at=?, active=0 WHERE id=? AND tenant_id=? AND deleted_at=''",
            (now, store_id, tenant_id),
        )
        if cur.rowcount != 1:
            raise StoreNotFoundError("store")
        con.execute(
            "UPDATE m2m_products SET data_json=json_set(data_json,'$.active',json('false'),"
            "'$.deleted_at',?) WHERE json_extract(data_json,'$.store_id')=?"
            " AND COALESCE(json_extract(data_json,'$.deleted_at'),'')=''",
            (now, store_id),
        )


# ── Categories ────────────────────────────────────────────────────────────────

def _category_row(r: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": r["id"], "store_id": r["store_id"], "parent_id": r["parent_id"],
        "slug": r["slug"], "name": r["name"], "position": r["position"],
    }


def _live_category(con: sqlite3.Connection, category_id: str, store_id: str) -> sqlite3.Row | None:
    return con.execute(
        "SELECT * FROM m2m_categories WHERE id=? AND store_id=? AND deleted_at=''",
        (category_id, store_id),
    ).fetchone()


def _ancestors(con: sqlite3.Connection, category_id: str, store_id: str) -> list[str]:
    """Ids from ``category_id`` up to the root, inclusive."""
    chain: list[str] = []
    current = category_id
    while current:
        if current in chain or len(chain) > MAX_CATEGORY_DEPTH:
            break
        chain.append(current)
        row = _live_category(con, current, store_id)
        current = row["parent_id"] if row else ""
    return chain


def _subtree_height(con: sqlite3.Connection, category_id: str) -> int:
    """Levels below ``category_id`` (0 for a leaf)."""
    kids = con.execute(
        "SELECT id FROM m2m_categories WHERE parent_id=? AND deleted_at=''", (category_id,),
    ).fetchall()
    return 1 + max((_subtree_height(con, k["id"]) for k in kids), default=-1)


def create_category(store_id: str, tenant_id: str, body: CategoryIn) -> dict[str, Any]:
    get_store(store_id, tenant_id)
    cat_id = str(uuid.uuid4())
    try:
        with _db_lock, _conn() as con:
            if body.parent_id:
                if _live_category(con, body.parent_id, store_id) is None:
                    raise StoreInvalidError("parent_id is not a category of this store")
                if len(_ancestors(con, body.parent_id, store_id)) >= MAX_CATEGORY_DEPTH:
                    raise StoreInvalidError(f"categories nest at most {MAX_CATEGORY_DEPTH} deep")
            con.execute(
                "INSERT INTO m2m_categories(id, store_id, tenant_id, parent_id, slug, name,"
                " position, created_at) VALUES(?,?,?,?,?,?,?,?)",
                (cat_id, store_id, tenant_id, body.parent_id, body.slug, body.name,
                 body.position, _now_iso()),
            )
    except sqlite3.IntegrityError as exc:
        raise StoreConflictError(f"category slug {body.slug!r} exists in this store") from exc
    return {"id": cat_id, "store_id": store_id, "parent_id": body.parent_id,
            "slug": body.slug, "name": body.name, "position": body.position}


def patch_category(category_id: str, tenant_id: str, body: CategoryPatch) -> dict[str, Any]:
    with _db_lock, _conn() as con:
        row = con.execute(
            "SELECT * FROM m2m_categories WHERE id=? AND tenant_id=? AND deleted_at=''",
            (category_id, tenant_id),
        ).fetchone()
        if row is None:
            raise StoreNotFoundError("category")
        store_id = row["store_id"]
        fields = body.model_dump(exclude_none=True)
        new_parent = fields.get("parent_id")
        if new_parent:
            if _live_category(con, new_parent, store_id) is None:
                raise StoreInvalidError("parent_id is not a category of this store")
            above = _ancestors(con, new_parent, store_id)
            if category_id in above:
                raise StoreConflictError("a category cannot move under itself or its descendants")
            if len(above) + 1 + _subtree_height(con, category_id) > MAX_CATEGORY_DEPTH:
                raise StoreInvalidError(f"categories nest at most {MAX_CATEGORY_DEPTH} deep")
        if fields:
            sets = ", ".join(f"{k}=?" for k in fields)
            con.execute(f"UPDATE m2m_categories SET {sets} WHERE id=?",
                        (*fields.values(), category_id))
        row = con.execute("SELECT * FROM m2m_categories WHERE id=?", (category_id,)).fetchone()
    return _category_row(row)


def delete_category(category_id: str, tenant_id: str) -> None:
    """Soft-delete an empty category. One with subcategories or products is refused."""
    with _db_lock, _conn() as con:
        row = con.execute(
            "SELECT store_id FROM m2m_categories WHERE id=? AND tenant_id=? AND deleted_at=''",
            (category_id, tenant_id),
        ).fetchone()
        if row is None:
            raise StoreNotFoundError("category")
        if con.execute(
            "SELECT 1 FROM m2m_categories WHERE parent_id=? AND deleted_at='' LIMIT 1",
            (category_id,),
        ).fetchone():
            raise StoreConflictError("category has subcategories")
        if con.execute(
            "SELECT 1 FROM m2m_products WHERE json_extract(data_json,'$.category_id')=?"
            " AND COALESCE(json_extract(data_json,'$.deleted_at'),'')='' LIMIT 1",
            (category_id,),
        ).fetchone():
            raise StoreConflictError("category has products")
        con.execute("UPDATE m2m_categories SET deleted_at=? WHERE id=?", (_now_iso(), category_id))


def category_tree(store_id: str) -> list[dict[str, Any]]:
    """Live categories of a store as nested ``children`` lists, ordered by position."""
    with _db_lock, _conn() as con:
        rows = con.execute(
            "SELECT * FROM m2m_categories WHERE store_id=? AND deleted_at=''"
            " ORDER BY position, slug",
            (store_id,),
        ).fetchall()
    nodes = {r["id"]: _category_row(r) | {"children": []} for r in rows}
    roots: list[dict[str, Any]] = []
    for node in nodes.values():
        parent = nodes.get(node["parent_id"])
        (parent["children"] if parent else roots).append(node)
    return roots


# ── Products in a store ───────────────────────────────────────────────────────

def check_placement(tenant_id: str, store_id: str, category_id: str) -> None:
    """A product may only be placed in the caller's own store and its categories."""
    if not store_id:
        if category_id:
            raise StoreInvalidError("category_id needs a store_id")
        return
    try:
        get_store(store_id, tenant_id)
    except StoreNotFoundError as exc:
        raise StoreInvalidError("store_id is not one of your stores") from exc
    if category_id:
        with _db_lock, _conn() as con:
            if _live_category(con, category_id, store_id) is None:
                raise StoreInvalidError("category_id is not a category of this store")


def _owned_product(product_id: str, tenant_id: str) -> Product:
    p = get_inventory().get_product(product_id)
    if p is None or p.tenant_id != tenant_id or p.deleted_at:
        raise StoreNotFoundError("product")
    return p


def _store_settings(store_id: str) -> dict[str, Any] | None:
    if not store_id:
        return None
    with _db_lock, _conn() as con:
        r = con.execute("SELECT * FROM m2m_stores WHERE id=?", (store_id,)).fetchone()
    return _store_row(r) if r else None


def set_prices(product_id: str, tenant_id: str, prices: list[PriceIn]) -> list[dict[str, Any]]:
    """
    Replace a product's price list.

    The USD price is required, because agent orders settle in it. It is stored
    in the product record itself — the one the offer path reads and the one a
    product update writes — and only the other currencies live in
    ``m2m_product_prices``. One home per number, so the two cannot disagree.
    """
    p = _owned_product(product_id, tenant_id)
    by_currency = {pr.currency: pr.amount_minor for pr in prices}
    if len(by_currency) != len(prices):
        raise StoreInvalidError("one price per currency")
    missing = SETTLEMENT_CURRENCIES - set(by_currency)
    if missing:
        raise StoreInvalidError(f"a {sorted(missing)[0]} price is required: agent orders settle in it")
    store = _store_settings(p.store_id)
    if store is not None:
        outside = sorted(set(by_currency) - set(store["currencies"]))
        if outside:
            raise StoreInvalidError(f"store does not sell in {outside}")
    usd = by_currency.pop("USD")
    with _db_lock, _conn() as con:
        con.execute("DELETE FROM m2m_product_prices WHERE product_id=?", (product_id,))
        con.executemany(
            "INSERT INTO m2m_product_prices(product_id, currency, amount_minor) VALUES(?,?,?)",
            [(product_id, c, a) for c, a in sorted(by_currency.items())],
        )
        con.execute(
            "UPDATE m2m_products SET data_json=json_set(data_json,'$.price_minor',?,"
            "'$.price_base',?) WHERE id=?",
            (usd, from_minor(usd, "USD"), product_id),
        )
    return get_prices(product_id)


def get_prices(product_id: str) -> list[dict[str, Any]]:
    """Every price of a product: its USD base price, then the seller's other currencies."""
    p = get_inventory().get_product(product_id)
    if p is None:
        return []
    with _db_lock, _conn() as con:
        rows = con.execute(
            "SELECT currency, amount_minor FROM m2m_product_prices WHERE product_id=?",
            (product_id,),
        ).fetchall()
    prices = {r["currency"]: r["amount_minor"] for r in rows} | {p.currency: p.price_minor}
    return [{"currency": c, "amount_minor": a} for c, a in sorted(prices.items())]


def set_translation(product_id: str, tenant_id: str, locale: str,
                    body: TranslationIn) -> dict[str, Any]:
    p = _owned_product(product_id, tenant_id)
    locale = locale.lower()
    store = _store_settings(p.store_id)
    allowed = store["locales"] if store else ["en"]
    if locale not in allowed:
        raise StoreInvalidError(f"store locales are {allowed}")
    with _db_lock, _conn() as con:
        con.execute(
            "INSERT INTO m2m_product_i18n(product_id, locale, name, description) VALUES(?,?,?,?)"
            " ON CONFLICT(product_id, locale) DO UPDATE SET name=excluded.name,"
            " description=excluded.description",
            (product_id, locale, body.name, body.description),
        )
    return {"locale": locale, "name": body.name, "description": body.description}


def get_translations(product_id: str) -> dict[str, dict[str, str]]:
    with _db_lock, _conn() as con:
        rows = con.execute(
            "SELECT locale, name, description FROM m2m_product_i18n WHERE product_id=?",
            (product_id,),
        ).fetchall()
    return {r["locale"]: {"name": r["name"], "description": r["description"]} for r in rows}


def list_store_products(store_id: str, tenant_id: str) -> list[dict[str, Any]]:
    """The owner's view of a store's products: inactive ones included, deleted ones not."""
    get_store(store_id, tenant_id)
    products = [p for p in get_inventory().list_products(active_only=False)
                if p.store_id == store_id and p.tenant_id == tenant_id and not p.deleted_at]
    return [
        p.model_dump(exclude={"tenant_id", "deleted_at", "price_base"})
        | {"available": p.available, "prices": get_prices(p.id),
           "translations": get_translations(p.id)}
        for p in sorted(products, key=lambda p: p.name.lower())
    ]


# ── Shipping zones ────────────────────────────────────────────────────────────

def _zone_row(r: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": r["id"], "store_id": r["store_id"], "name": r["name"],
        "countries": json.loads(r["countries_json"]), "currency": r["currency"],
        "rate_minor": r["rate_minor"], "free_over_minor": r["free_over_minor"],
        "duty_estimate_bps": r["duty_estimate_bps"],
        "min_days": r["min_days"], "max_days": r["max_days"],
    }


def create_zone(store_id: str, tenant_id: str, body: ShippingZoneIn) -> dict[str, Any]:
    store = get_store(store_id, tenant_id)
    if body.currency not in store["currencies"]:
        raise StoreInvalidError(f"store does not sell in {body.currency}")
    zone_id = str(uuid.uuid4())
    with _db_lock, _conn() as con:
        con.execute(
            "INSERT INTO m2m_shipping_zones(id, store_id, tenant_id, name, countries_json,"
            " currency, rate_minor, free_over_minor, duty_estimate_bps, min_days, max_days,"
            " created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (zone_id, store_id, tenant_id, body.name, json.dumps(body.countries), body.currency,
             body.rate_minor, body.free_over_minor, body.duty_estimate_bps, body.min_days,
             body.max_days, _now_iso()),
        )
        row = con.execute("SELECT * FROM m2m_shipping_zones WHERE id=?", (zone_id,)).fetchone()
    return _zone_row(row)


def list_zones(store_id: str) -> list[dict[str, Any]]:
    with _db_lock, _conn() as con:
        rows = con.execute(
            "SELECT * FROM m2m_shipping_zones WHERE store_id=? AND deleted_at=''"
            " ORDER BY created_at",
            (store_id,),
        ).fetchall()
    return [_zone_row(r) for r in rows]


def delete_zone(zone_id: str, tenant_id: str) -> None:
    with _db_lock, _conn() as con:
        cur = con.execute(
            "UPDATE m2m_shipping_zones SET deleted_at=? WHERE id=? AND tenant_id=?"
            " AND deleted_at=''",
            (_now_iso(), zone_id, tenant_id),
        )
    if cur.rowcount != 1:
        raise StoreNotFoundError("zone")


def quote_shipping(slug: str, country: str, currency: str, subtotal_minor: int) -> dict[str, Any]:
    """
    Shipping for one destination: a zone naming the country beats the ``*``
    zone, and among equals the cheapest rate wins. The duty figure is the
    seller's own rate applied to the subtotal and is labelled an estimate.
    """
    store = get_public_store(slug)
    country = country.strip().upper()
    currency = currency.strip().upper()
    zones = [z for z in list_zones(store["id"]) if z["currency"] == currency]
    exact = [z for z in zones if country in z["countries"]]
    candidates = exact or [z for z in zones if "*" in z["countries"]]
    if not candidates:
        raise StoreNotFoundError("no shipping zone covers this destination in this currency")
    zone = min(candidates, key=lambda z: (z["rate_minor"], z["name"]))
    free = zone["free_over_minor"] is not None and subtotal_minor >= zone["free_over_minor"]
    duty = int((Decimal(subtotal_minor) * zone["duty_estimate_bps"] / 10_000)
               .quantize(Decimal(1), ROUND_HALF_EVEN))
    return {
        "zone_id": zone["id"], "zone": zone["name"], "country": country, "currency": currency,
        "shipping_minor": 0 if free else zone["rate_minor"],
        "duty_estimate_minor": duty, "duty_is_estimate": True,
        "min_days": zone["min_days"], "max_days": zone["max_days"],
    }


# ── Feed ──────────────────────────────────────────────────────────────────────

def store_ucp_catalog(slug: str) -> dict[str, Any]:
    """UCP feed for one store: live products with every price, translation and photo."""
    from .media import public_images

    store = get_public_store(slug)
    products = [p for p in get_inventory().list_products(active_only=True)
                if p.store_id == store["id"] and not p.deleted_at and p.available > 0]
    return {
        "version": "1.1",
        "store": store["slug"],
        "name": store["name"],
        "default_currency": store["default_currency"],
        "settlement_currencies": sorted(SETTLEMENT_CURRENCIES),
        "locales": store["locales"],
        "categories": category_tree(store["id"]),
        "products": [
            {
                "id": p.id, "name": p.name, "description": p.description,
                "category_id": p.category_id, "unit": p.unit, "available": p.available,
                "prices": get_prices(p.id), "translations": get_translations(p.id),
                "images": public_images(store["slug"], p.id),
            }
            for p in products
        ],
        "count": len(products),
    }
