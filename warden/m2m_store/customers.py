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
* No marketing consent is recorded or inferred here.
* R8.2 journal: the seller's own log about a customer (calls, meetings) and
  message drafts. The platform never sends a message: a draft is written here,
  the seller sends it from its own mail client and marks it sent, which locks
  it. The timeline also shows the status changes of the customer's order
  requests, read from their history, so nothing is copied. Entries are sealed
  like the notes and go with the card on erasure.
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
    CREATE TABLE IF NOT EXISTS m2m_customer_journal (
        id               TEXT PRIMARY KEY,
        customer_id      TEXT NOT NULL,
        store_id         TEXT NOT NULL,
        seller_tenant_id TEXT NOT NULL,
        kind             TEXT NOT NULL,
        status           TEXT NOT NULL,
        body_enc         TEXT NOT NULL,
        created_at       TEXT NOT NULL,
        updated_at       TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_m2m_customer_journal_customer
        ON m2m_customer_journal(customer_id, created_at);
"""
register("m2m_store", "customers", _DDL)

MAX_NOTES = 2000
MAX_TAGS = 10
MAX_TAG_LEN = 32
MAX_LIST = 500
_ERASED = "erased"
MAX_SUBJECT = 200
MAX_BODY = 5000
MAX_ENTRIES = 500
NOTE, MESSAGE = "note", "message"
LOGGED, DRAFT, SENT = "LOGGED", "DRAFT", "SENT"
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


class JournalIn(BaseModel):
    kind: str = Field(pattern="^(note|message)$")
    subject: str = Field(default="", max_length=MAX_SUBJECT)
    body: str = Field(min_length=1, max_length=MAX_BODY)


class JournalPatch(BaseModel):
    subject: str | None = Field(default=None, max_length=MAX_SUBJECT)
    body: str | None = Field(default=None, min_length=1, max_length=MAX_BODY)
    sent: bool = False


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
    view["journal"] = [e for e in journal(store_id, tenant_id, customer_id)
                       if e["type"] != "order"]
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
        con.execute("DELETE FROM m2m_customer_journal WHERE customer_id=?", (customer_id,))
        con.execute("DELETE FROM m2m_customers WHERE id=?", (customer_id,))


# ── Journal (R8.2) ────────────────────────────────────────────────────────────

def _screen(*texts: str) -> None:
    for t in texts:
        if t:
            try:
                validate_content_string(t, "journal")
            except PromptInjectionError as exc:
                raise sf.StoreInvalidError("the entry was refused") from exc


def _entry_view(e: Any) -> dict[str, Any]:
    body = orq._open(e["body_enc"])
    return {"id": e["id"], "type": e["kind"], "status": e["status"],
            "subject": body.get("subject", ""), "body": body.get("body", ""),
            "at": e["created_at"], "updated_at": e["updated_at"]}


def journal(store_id: str, tenant_id: str, customer_id: str) -> list[dict[str, Any]]:
    """Newest first: the seller's entries and the order requests' status changes."""
    sf.get_store(store_id, tenant_id)
    with _db_lock, _conn() as con:
        _card(store_id, tenant_id, customer_id, con)
        out = [_entry_view(e) for e in con.execute(
            "SELECT * FROM m2m_customer_journal WHERE customer_id=? AND seller_tenant_id=?",
            (customer_id, tenant_id),
        ).fetchall()]
        for o in _orders(con, customer_id):
            for h in json.loads(o["history_json"]):
                if "status" in h and "event" not in h:
                    out.append({"id": f"{o['id']}:{h['at']}", "type": "order",
                                "request_id": o["id"], "status": h["status"],
                                "by": h.get("by", ""), "at": h["at"]})
    out.sort(key=lambda e: e["at"], reverse=True)
    return out


def add_entry(store_id: str, tenant_id: str, customer_id: str,
              body: JournalIn) -> dict[str, Any]:
    sf.get_store(store_id, tenant_id)
    _screen(body.subject, body.body)
    now = _now()
    sealed = orq._seal({"subject": body.subject, "body": body.body})
    with _db_lock, _conn() as con:
        _card(store_id, tenant_id, customer_id, con)
        eid = uuid.uuid4().hex
        # One conditional INSERT, so two writers cannot pass the cap together.
        cur = con.execute(
            "INSERT INTO m2m_customer_journal(id, customer_id, store_id, seller_tenant_id,"
            " kind, status, body_enc, created_at, updated_at)"
            " SELECT ?,?,?,?,?,?,?,?,? WHERE (SELECT COUNT(*) FROM m2m_customer_journal"
            " WHERE customer_id=?) < ?",
            (eid, customer_id, store_id, tenant_id, body.kind,
             DRAFT if body.kind == MESSAGE else LOGGED, sealed, now, now,
             customer_id, MAX_ENTRIES),
        )
        if cur.rowcount != 1:
            raise sf.StoreConflictError(f"a customer holds at most {MAX_ENTRIES} entries")
        return _entry_view(con.execute(
            "SELECT * FROM m2m_customer_journal WHERE id=?", (eid,)).fetchone())


def _entry(con: Any, tenant_id: str, customer_id: str, entry_id: str) -> Any:
    e = con.execute(
        "SELECT * FROM m2m_customer_journal WHERE id=? AND customer_id=? AND seller_tenant_id=?",
        (entry_id, customer_id, tenant_id),
    ).fetchone()
    if e is None:
        raise sf.StoreNotFoundError("journal entry")
    return e


def update_entry(store_id: str, tenant_id: str, customer_id: str, entry_id: str,
                 patch: JournalPatch) -> dict[str, Any]:
    """Edit a draft, or mark it sent. A sent message and a logged note stay as written."""
    sf.get_store(store_id, tenant_id)
    _screen(patch.subject or "", patch.body or "")
    with _db_lock, _conn() as con:
        _card(store_id, tenant_id, customer_id, con)
        e = _entry(con, tenant_id, customer_id, entry_id)
        if e["status"] != DRAFT:
            raise sf.StoreConflictError("only a draft message can be changed")
        body = orq._open(e["body_enc"])
        if patch.subject is not None:
            body["subject"] = patch.subject
        if patch.body is not None:
            body["body"] = patch.body
        cur = con.execute(
            "UPDATE m2m_customer_journal SET body_enc=?, status=?, updated_at=?"
            " WHERE id=? AND status=?",
            (orq._seal(body), SENT if patch.sent else DRAFT, _now(), entry_id, DRAFT),
        )
        if cur.rowcount != 1:
            raise sf.StoreConflictError("the entry changed meanwhile; reload it")
        return _entry_view(con.execute(
            "SELECT * FROM m2m_customer_journal WHERE id=?", (entry_id,)).fetchone())


def delete_entry(store_id: str, tenant_id: str, customer_id: str, entry_id: str) -> None:
    sf.get_store(store_id, tenant_id)
    with _db_lock, _conn() as con:
        _card(store_id, tenant_id, customer_id, con)
        _entry(con, tenant_id, customer_id, entry_id)
        con.execute("DELETE FROM m2m_customer_journal WHERE id=?", (entry_id,))
