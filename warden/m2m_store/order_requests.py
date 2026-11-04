"""
warden/m2m_store/order_requests.py
───────────────────────────────────
Plan stage M5: a human buyer's order request. No money moves (live payments
are M7, blocked); the buyer asks, the seller accepts or rejects, and the
request carries an immutable snapshot of what was asked for at what price.

* Prices, shipping and duty are recomputed here from the seller's own data.
  Nothing the browser sends is trusted except product ids and quantities.
* The buyer's contact details are personal data: Fernet-encrypted at rest with
  a key from ``resolve_key`` (fail CLOSED: no key, no request), never logged,
  never in a webhook, and never in the buyer's own status view.
* The buyer holds a random token; only its SHA-256 is stored.
* Every status change is one conditional UPDATE, so two workers (or a seller
  and a buyer) cannot both move the same request.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import uuid
from datetime import UTC, datetime
from typing import Any
from zoneinfo import ZoneInfo

from cryptography.fernet import Fernet, InvalidToken
from pydantic import BaseModel, Field, field_validator

from warden.db.ddl_registry import register

from . import storefront as sf
from .inventory import _conn, _db_lock, get_inventory
from .security import PromptInjectionError, validate_content_string

_DDL = """
    CREATE TABLE IF NOT EXISTS m2m_order_requests (
        id                  TEXT PRIMARY KEY,
        store_id            TEXT NOT NULL,
        seller_tenant_id    TEXT NOT NULL,
        status              TEXT NOT NULL,
        currency            TEXT NOT NULL,
        subtotal_minor      INTEGER NOT NULL,
        shipping_minor      INTEGER NOT NULL,
        duty_estimate_minor INTEGER NOT NULL,
        total_minor         INTEGER NOT NULL,
        country             TEXT NOT NULL,
        locale              TEXT NOT NULL DEFAULT 'en',
        buyer_tz            TEXT NOT NULL DEFAULT 'UTC',
        items_json          TEXT NOT NULL,
        contact_enc         TEXT NOT NULL,
        buyer_token_hash    TEXT NOT NULL,
        history_json        TEXT NOT NULL,
        created_at          TEXT NOT NULL,
        updated_at          TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_m2m_order_requests_store
        ON m2m_order_requests(store_id, created_at);
"""

# Same physical DB as inventory.py, so the same db_key.
register("m2m_store", "order_requests", _DDL)

PENDING = "PENDING_MERCHANT"
ACCEPTED = "ACCEPTED"
REJECTED = "REJECTED"
SHIPPED = "SHIPPED"
COMPLETED = "COMPLETED"
CANCELLED = "CANCELLED"
STATUSES = (PENDING, ACCEPTED, REJECTED, SHIPPED, COMPLETED, CANCELLED)

# Who may move a request from which status to which.
SELLER_MOVES: dict[str, tuple[str, ...]] = {
    PENDING: (ACCEPTED, REJECTED),
    ACCEPTED: (SHIPPED, CANCELLED),
    SHIPPED: (COMPLETED,),
}
BUYER_MOVES: dict[str, tuple[str, ...]] = {PENDING: (CANCELLED,)}

# A store with this many unanswered requests takes no more: the request route
# is anonymous, and a flood must not bury the seller's real ones.
MAX_PENDING_PER_STORE = 200
MAX_ITEMS = 50


class OrderRequestUnavailableError(RuntimeError):
    """Personal data cannot be protected right now (no encryption key)."""


# ── Input ─────────────────────────────────────────────────────────────────────

_EMAIL = r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,63}$"


class ItemIn(BaseModel):
    product_id: str = Field(..., min_length=1, max_length=64)
    qty: int = Field(..., ge=1, le=999)


class ContactIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    email: str = Field(..., max_length=254, pattern=_EMAIL)
    phone: str = Field(default="", max_length=40)
    address_line1: str = Field(..., min_length=1, max_length=200)
    address_line2: str = Field(default="", max_length=200)
    city: str = Field(..., min_length=1, max_length=100)
    postal_code: str = Field(default="", max_length=20)
    region: str = Field(default="", max_length=100)


class OrderRequestIn(BaseModel):
    items: list[ItemIn] = Field(..., min_length=1, max_length=MAX_ITEMS)
    currency: str = Field(..., min_length=3, max_length=3)
    country: str = Field(..., min_length=2, max_length=2)
    contact: ContactIn
    note: str = Field(default="", max_length=1000)
    locale: str = Field(default="en", max_length=5)
    timezone: str = Field(default="UTC", max_length=64)

    @field_validator("timezone")
    @classmethod
    def _known_zone(cls, v: str) -> str:
        try:
            ZoneInfo(v)
        except Exception:
            return "UTC"
        return v


class StatusChangeIn(BaseModel):
    status: str = Field(..., max_length=20)
    note: str = Field(default="", max_length=500)


# ── Personal data ─────────────────────────────────────────────────────────────

def _fernet() -> Fernet:
    from warden.secret_keys import resolve_key
    try:
        key = resolve_key("M2M_STORE_PII_KEY", purpose="m2m_store_pii")
    except Exception as exc:
        raise OrderRequestUnavailableError("order requests are unavailable") from exc
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(key).digest()))


def _seal(contact: dict[str, Any]) -> str:
    return _fernet().encrypt(json.dumps(contact, separators=(",", ":")).encode()).decode()


def _open(token: str) -> dict[str, Any]:
    try:
        return dict(json.loads(_fernet().decrypt(token.encode())))
    except InvalidToken as exc:
        raise OrderRequestUnavailableError("contact details cannot be decrypted") from exc


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()


# ── Create ────────────────────────────────────────────────────────────────────

def _price_items(store: dict[str, Any], body: OrderRequestIn) -> list[dict[str, Any]]:
    """The snapshot: the seller's current names and prices, never the browser's."""
    qty_by_id: dict[str, int] = {}
    for it in body.items:
        qty_by_id[it.product_id] = qty_by_id.get(it.product_id, 0) + it.qty
    inv = get_inventory()
    lines: list[dict[str, Any]] = []
    for pid, qty in qty_by_id.items():
        p = inv.get_product(pid)
        if p is None or p.deleted_at or not p.active or p.store_id != store["id"]:
            raise sf.StoreInvalidError(f"product {pid} is not on sale in this store")
        if qty > p.available:
            raise sf.StoreConflictError(f"only {p.available} of {pid} available")
        price = next((x for x in sf.get_prices(pid) if x["currency"] == body.currency), None)
        if price is None:
            raise sf.StoreInvalidError(f"product {pid} has no price in {body.currency}")
        name = sf.get_translations(pid).get(body.locale, {}).get("name") or p.name
        lines.append({"product_id": pid, "name": name, "unit": p.unit, "qty": qty,
                      "unit_minor": price["amount_minor"],
                      "line_minor": price["amount_minor"] * qty})
    return lines


def create_request(slug: str, body: OrderRequestIn) -> tuple[dict[str, Any], str, str]:
    """Returns (buyer view, buyer token, seller tenant). The token is shown once."""
    store = sf.get_public_store(slug)
    currency = body.currency.upper()
    country = body.country.upper()
    if currency not in store["currencies"]:
        raise sf.StoreInvalidError(f"this store does not sell in {currency}")
    if body.note:
        try:
            validate_content_string(body.note, "note")
        except PromptInjectionError as exc:
            raise sf.StoreInvalidError("the note was refused") from exc
    body = body.model_copy(update={"currency": currency, "country": country})
    lines = _price_items(store, body)
    subtotal = sum(line["line_minor"] for line in lines)
    try:
        quote = sf.quote_shipping(slug, country, currency, subtotal)
    except sf.StoreNotFoundError as exc:
        raise sf.StoreInvalidError(f"this store does not ship to {country} in {currency}") from exc
    contact = _seal(body.contact.model_dump() | {"note": body.note})

    token = secrets.token_urlsafe(32)
    now = _now()
    rid = uuid.uuid4().hex
    history = [{"status": PENDING, "at": now, "by": "buyer"}]
    with _db_lock, _conn() as con:
        # The cap and the insert are one statement, so concurrent requests
        # cannot each see room for one more.
        cur = con.execute(
            "INSERT INTO m2m_order_requests(id, store_id, seller_tenant_id, status, currency,"
            " subtotal_minor, shipping_minor, duty_estimate_minor, total_minor, country, locale,"
            " buyer_tz, items_json, contact_enc, buyer_token_hash, history_json, created_at,"
            " updated_at)"
            " SELECT ?,?,(SELECT tenant_id FROM m2m_stores WHERE id=?),?,?,?,?,?,?,?,?,?,?,?,?,?,?,?"
            " WHERE (SELECT COUNT(*) FROM m2m_order_requests WHERE store_id=? AND status=?) < ?",
            (rid, store["id"], store["id"], PENDING, currency, subtotal, quote["shipping_minor"],
             quote["duty_estimate_minor"], subtotal + quote["shipping_minor"], country,
             body.locale, body.timezone, json.dumps(lines), contact, _token_hash(token),
             json.dumps(history), now, now, store["id"], PENDING, MAX_PENDING_PER_STORE),
        )
        if cur.rowcount != 1:
            raise sf.StoreConflictError("this store is not taking new requests right now")
        row = con.execute("SELECT * FROM m2m_order_requests WHERE id=?", (rid,)).fetchone()
    return _buyer_view(row, store["slug"]), token, row["seller_tenant_id"]


# ── Views ─────────────────────────────────────────────────────────────────────

def _base_view(r: Any) -> dict[str, Any]:
    return {
        "id": r["id"], "status": r["status"], "currency": r["currency"],
        "subtotal_minor": r["subtotal_minor"], "shipping_minor": r["shipping_minor"],
        "duty_estimate_minor": r["duty_estimate_minor"], "duty_is_estimate": True,
        "total_minor": r["total_minor"], "country": r["country"], "locale": r["locale"],
        "buyer_tz": r["buyer_tz"], "items": json.loads(r["items_json"]),
        "history": json.loads(r["history_json"]),
        "created_at": r["created_at"], "updated_at": r["updated_at"],
    }


def _buyer_view(r: Any, slug: str) -> dict[str, Any]:
    # No contact details: whoever holds the link sees the order, not the address.
    return _base_view(r) | {"store": slug}


def _seller_view(r: Any) -> dict[str, Any]:
    contact = _open(r["contact_enc"])
    note = contact.pop("note", "")
    return _base_view(r) | {"store_id": r["store_id"], "contact": contact, "note": note}


def _row_for_buyer(slug: str, request_id: str, token: str) -> tuple[Any, dict[str, Any]]:
    store = sf.get_public_store(slug)
    with _db_lock, _conn() as con:
        r = con.execute(
            "SELECT * FROM m2m_order_requests WHERE id=? AND store_id=?", (request_id, store["id"]),
        ).fetchone()
    # A wrong token reads exactly like a missing request.
    if r is None or not token or not hmac.compare_digest(r["buyer_token_hash"], _token_hash(token)):
        raise sf.StoreNotFoundError("order request")
    return r, store


def get_for_buyer(slug: str, request_id: str, token: str) -> dict[str, Any]:
    r, store = _row_for_buyer(slug, request_id, token)
    return _buyer_view(r, store["slug"])


def list_for_seller(store_id: str, tenant_id: str, status: str = "") -> list[dict[str, Any]]:
    sf.get_store(store_id, tenant_id)
    sql = "SELECT * FROM m2m_order_requests WHERE store_id=? AND seller_tenant_id=?"
    args: list[Any] = [store_id, tenant_id]
    if status:
        sql += " AND status=?"
        args.append(status)
    with _db_lock, _conn() as con:
        rows = con.execute(sql + " ORDER BY created_at DESC LIMIT 500", args).fetchall()
    return [_seller_view(r) for r in rows]


# ── Status changes ────────────────────────────────────────────────────────────

def _move(r: Any, new: str, by: str, note: str = "") -> Any:
    old = r["status"]
    history = json.loads(r["history_json"])
    entry: dict[str, Any] = {"status": new, "at": _now(), "by": by}
    if note:
        entry["note"] = note
    history.append(entry)
    with _db_lock, _conn() as con:
        cur = con.execute(
            "UPDATE m2m_order_requests SET status=?, history_json=?, updated_at=?"
            " WHERE id=? AND status=?",
            (new, json.dumps(history), entry["at"], r["id"], old),
        )
        if cur.rowcount != 1:
            raise sf.StoreConflictError("the request changed meanwhile; reload it")
        return con.execute("SELECT * FROM m2m_order_requests WHERE id=?", (r["id"],)).fetchone()


def _take_stock(items: list[dict[str, Any]]) -> None:
    """All lines or none: accepting takes the units, in one statement per line."""
    inv = get_inventory()
    taken: list[dict[str, Any]] = []
    for line in items:
        if not inv.commit_stock(line["product_id"], line["qty"]):
            for t in taken:
                inv.update_stock(t["product_id"], t["qty"])
            raise sf.StoreConflictError(f"not enough stock for {line['name']}")
        taken.append(line)


def _return_stock(items: list[dict[str, Any]]) -> None:
    inv = get_inventory()
    for line in items:
        inv.update_stock(line["product_id"], line["qty"])


def seller_move(request_id: str, tenant_id: str, body: StatusChangeIn) -> dict[str, Any]:
    new = body.status.strip().upper()
    with _db_lock, _conn() as con:
        r = con.execute(
            "SELECT * FROM m2m_order_requests WHERE id=? AND seller_tenant_id=?",
            (request_id, tenant_id),
        ).fetchone()
    if r is None:
        raise sf.StoreNotFoundError("order request")
    if new not in SELLER_MOVES.get(r["status"], ()):
        raise sf.StoreInvalidError(f"cannot move a {r['status']} request to {new}")
    items = json.loads(r["items_json"])
    if new == ACCEPTED:
        _take_stock(items)
        try:
            r = _move(r, new, "seller", body.note)
        except sf.StoreConflictError:
            _return_stock(items)
            raise
    else:
        r = _move(r, new, "seller", body.note)
        if new == CANCELLED:  # only reachable from ACCEPTED, which took the stock
            _return_stock(items)
    return _seller_view(r)


def buyer_cancel(slug: str, request_id: str, token: str) -> dict[str, Any]:
    r, store = _row_for_buyer(slug, request_id, token)
    if CANCELLED not in BUYER_MOVES.get(r["status"], ()):
        raise sf.StoreInvalidError("the seller has already answered this request")
    return _buyer_view(_move(r, CANCELLED, "buyer"), store["slug"])


def webhook_summary(view: dict[str, Any], store_slug: str) -> dict[str, Any]:
    """What the seller's webhook gets: identifiers and amounts, no personal data."""
    return {"order_request_id": view["id"], "store": store_slug, "status": view["status"],
            "currency": view["currency"], "total_minor": view["total_minor"],
            "item_count": sum(i["qty"] for i in view["items"])}
