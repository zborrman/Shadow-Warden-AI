"""
warden/m2m_store/customers.py
──────────────────────────────
Plan stage R8.1: the seller's customers, built from its own shop's order
requests. On the shop the seller owns the buyer relationship (unlike Amazon,
where a persistent buyer record is forbidden - that contour is R8.5).

* A customer is one email address within one store. The address is never
  stored in clear: the card is found by an HMAC of the normalised address
  (``resolve_key(..., purpose="m2m_store_customer_index")``), and the latest
  contact details are Fernet-sealed with the same key as the order requests.
* Cards are derived, not typed: every order request of the store that no card
  holds yet is linked on read (``_sync``), so a card cannot disagree with the
  orders behind it and nothing on the order path had to change.
* Notes are seller-written free text about a person - personal data too, so
  they are sealed as well, length-capped and injection-screened.
* Erasure (GDPR Art. 17) deletes the card, its notes and its links. The order
  requests themselves stay: they are the seller's commercial record, kept on
  that basis, and a later order from the same address starts a new card
  (the erased card's links stay, pointed at a tombstone, so it is not rebuilt).
* No marketing consent is recorded or inferred here; R8.1 has no messaging.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from warden.db.ddl_registry import register

from . import order_requests as orq
from . import storefront as sf
from .inventory import _conn, _db_lock
from .security import PromptInjectionError, validate_content_string

_DDL = """
    CREATE TABLE IF NOT EXISTS m2m_customers (
        id               TEXT PRIMARY KEY,
        store_id         TEXT NOT NULL,
        seller_tenant_id TEXT NOT NULL,
        email_hash       TEXT NOT NULL,
        contact_enc      TEXT NOT NULL,
        notes_enc        TEXT NOT NULL DEFAULT '',
        tags_json        TEXT NOT NULL DEFAULT '[]',
        first_seen_at    TEXT NOT NULL,
        last_seen_at     TEXT NOT NULL,
        UNIQUE (store_id, email_hash)
    );
    CREATE INDEX IF NOT EXISTS idx_m2m_customers_seller
        ON m2m_customers(seller_tenant_id, store_id, last_seen_at);
    CREATE TABLE IF NOT EXISTS m2m_customer_orders (
        request_id  TEXT PRIMARY KEY,
        customer_id TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_m2m_customer_orders_customer
        ON m2m_customer_orders(customer_id);
"""
register("m2m_store", "customers", _DDL)

MAX_NOTES = 2000
MAX_TAGS = 10
MAX_TAG_LEN = 32
MAX_LIST = 500
_ERASED = "erased"
# Statuses in which the seller agreed to sell: what the buyer "spent" with it.
_COUNTED = frozenset({orq.ACCEPTED, orq.PAID, orq.SHIPPED, orq.COMPLETED})


class CustomerPatch(BaseModel):
    notes: str | None = Field(default=None, max_length=MAX_NOTES)
    tags: list[str] | None = Field(default=None, max_length=MAX_TAGS)

    @field_validator("tags")
    @classmethod
    def _clean_tags(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        out: list[str] = []
        for t in v:
            t = t.strip().lower()
            if not t:
                continue
            if len(t) > MAX_TAG_LEN:
                raise ValueError(f"a tag is at most {MAX_TAG_LEN} characters")
            if t not in out:
                out.append(t)
        return out


def _index_key() -> bytes:
    from warden.secret_keys import resolve_key
    try:
        return resolve_key("M2M_STORE_PII_KEY", purpose="m2m_store_customer_index")
    except Exception as exc:
        raise orq.OrderRequestUnavailableError("customers are unavailable") from exc


def _email_hash(email: str) -> str:
    return hmac.new(_index_key(), email.strip().lower().encode(), hashlib.sha256).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _sync(store_id: str, tenant_id: str) -> None:
    """Link every order request of the store that no card holds yet."""
    with _db_lock, _conn() as con:
        rows = con.execute(
            "SELECT r.id, r.contact_enc, r.created_at FROM m2m_order_requests r"
            " LEFT JOIN m2m_customer_orders l ON l.request_id = r.id"
            " WHERE r.store_id=? AND r.seller_tenant_id=? AND l.request_id IS NULL"
            " ORDER BY r.created_at",
            (store_id, tenant_id),
        ).fetchall()
        for r in rows:
            contact = orq._open(r["contact_enc"])
            contact.pop("note", None)
            ehash = _email_hash(contact.get("email", ""))
            sealed = orq._seal(contact)
            cur = con.execute(
                "SELECT id, last_seen_at FROM m2m_customers WHERE store_id=? AND email_hash=?",
                (store_id, ehash),
            ).fetchone()
            if cur is None:
                cid = uuid.uuid4().hex
                con.execute(
                    "INSERT INTO m2m_customers(id, store_id, seller_tenant_id, email_hash,"
                    " contact_enc, first_seen_at, last_seen_at) VALUES(?,?,?,?,?,?,?)",
                    (cid, store_id, tenant_id, ehash, sealed, r["created_at"], r["created_at"]),
                )
            else:
                cid = cur["id"]
                if r["created_at"] >= cur["last_seen_at"]:
                    # The latest order carries the address the seller ships to now.
                    con.execute(
                        "UPDATE m2m_customers SET contact_enc=?, last_seen_at=? WHERE id=?",
                        (sealed, r["created_at"], cid),
                    )
            con.execute(
                "INSERT INTO m2m_customer_orders(request_id, customer_id) VALUES(?,?)",
                (r["id"], cid),
            )


def _orders(con: Any, customer_id: str) -> list[Any]:
    return con.execute(
        "SELECT r.* FROM m2m_order_requests r JOIN m2m_customer_orders l ON l.request_id=r.id"
        " WHERE l.customer_id=? ORDER BY r.created_at DESC",
        (customer_id,),
    ).fetchall()


def _totals(orders: list[Any]) -> dict[str, int]:
    spent: dict[str, int] = {}
    for o in orders:
        if o["status"] in _COUNTED:
            spent[o["currency"]] = spent.get(o["currency"], 0) + int(o["total_minor"])
    return spent


def _summary(c: Any, orders: list[Any]) -> dict[str, Any]:
    contact = orq._open(c["contact_enc"])
    return {
        "id": c["id"], "store_id": c["store_id"],
        "name": contact.get("name", ""), "email": contact.get("email", ""),
        "country": orders[0]["country"] if orders else "",
        "orders": len(orders), "spent_minor": _totals(orders),
        "tags": json.loads(c["tags_json"]),
        "first_seen_at": c["first_seen_at"], "last_seen_at": c["last_seen_at"],
    }


def _card(store_id: str, tenant_id: str, customer_id: str, con: Any) -> Any:
    c = con.execute(
        "SELECT * FROM m2m_customers WHERE id=? AND store_id=? AND seller_tenant_id=?",
        (customer_id, store_id, tenant_id),
    ).fetchone()
    if c is None:
        # Another seller's customer reads exactly like a missing one.
        raise sf.StoreNotFoundError("customer")
    return c


def list_customers(store_id: str, tenant_id: str, q: str = "") -> list[dict[str, Any]]:
    sf.get_store(store_id, tenant_id)
    _sync(store_id, tenant_id)
    with _db_lock, _conn() as con:
        rows = con.execute(
            "SELECT * FROM m2m_customers WHERE store_id=? AND seller_tenant_id=?"
            " ORDER BY last_seen_at DESC LIMIT ?",
            (store_id, tenant_id, MAX_LIST),
        ).fetchall()
        out = [_summary(c, _orders(con, c["id"])) for c in rows]
    needle = q.strip().lower()
    if needle:
        # The address is sealed, so search runs over the opened summaries.
        out = [c for c in out if needle in c["name"].lower() or needle in c["email"].lower()
               or any(needle in t for t in c["tags"])]
    return out


def get_customer(store_id: str, tenant_id: str, customer_id: str) -> dict[str, Any]:
    sf.get_store(store_id, tenant_id)
    _sync(store_id, tenant_id)
    with _db_lock, _conn() as con:
        c = _card(store_id, tenant_id, customer_id, con)
        orders = _orders(con, customer_id)
        view = _summary(c, orders)
        contact = orq._open(c["contact_enc"])
        view["contact"] = contact
        view["notes"] = orq._open(c["notes_enc"]).get("text", "") if c["notes_enc"] else ""
        view["order_requests"] = [
            {"id": o["id"], "status": o["status"], "currency": o["currency"],
             "total_minor": o["total_minor"], "items": json.loads(o["items_json"]),
             "created_at": o["created_at"]}
            for o in orders
        ]
    return view


def update_customer(store_id: str, tenant_id: str, customer_id: str,
                    body: CustomerPatch) -> dict[str, Any]:
    sf.get_store(store_id, tenant_id)
    if body.notes:
        try:
            validate_content_string(body.notes, "notes")
        except PromptInjectionError as exc:
            raise sf.StoreInvalidError("the notes were refused") from exc
    with _db_lock, _conn() as con:
        _card(store_id, tenant_id, customer_id, con)
        if body.notes is not None:
            sealed = orq._seal({"text": body.notes}) if body.notes else ""
            con.execute("UPDATE m2m_customers SET notes_enc=? WHERE id=?", (sealed, customer_id))
        if body.tags is not None:
            con.execute("UPDATE m2m_customers SET tags_json=? WHERE id=?",
                        (json.dumps(body.tags), customer_id))
    return get_customer(store_id, tenant_id, customer_id)


def export_customer(store_id: str, tenant_id: str, customer_id: str) -> dict[str, Any]:
    """Everything held about one person, for an access/portability request."""
    view = get_customer(store_id, tenant_id, customer_id)
    view["exported_at"] = _now()
    view["note"] = ("Order requests are listed in full because they hold this person's "
                    "data; erasing the customer removes the card, not the orders.")
    return view


def erase_customer(store_id: str, tenant_id: str, customer_id: str) -> None:
    sf.get_store(store_id, tenant_id)
    with _db_lock, _conn() as con:
        _card(store_id, tenant_id, customer_id, con)
        # The links stay, pointed at a tombstone: _sync links only orders no
        # row holds, so deleting them would rebuild the card on the next read.
        con.execute("UPDATE m2m_customer_orders SET customer_id=? WHERE customer_id=?",
                    (_ERASED, customer_id))
        con.execute("DELETE FROM m2m_customers WHERE id=?", (customer_id,))
