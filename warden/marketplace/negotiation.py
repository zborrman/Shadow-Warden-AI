"""
warden/marketplace/negotiation.py
───────────────────────────────────
NegotiationEngine — multi-round price negotiation between buyer and seller
agents, with Ed25519-signed offers via the MCP message format.

Message envelope
────────────────
  {
    "type":        "offer" | "accept" | "reject",
    "price":       float,
    "asset_ueciid": str,
    "round":       int,
    "message":     str,
    "agent_id":    str,
    "timestamp":   ISO-8601,
    "signature":   base64(Ed25519(canonical_json))
  }

Tables (shared MARKETPLACE_DB_PATH)
────────────────────────────────────
  marketplace_negotiations  — negotiation sessions
  marketplace_offers        — per-round offer history
"""
from __future__ import annotations

import base64
import json
import logging
import os
import sqlite3
import threading
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

from warden.config import data_path
from warden.db.connect import open_db
from warden.db.ddl_registry import register

log = logging.getLogger("warden.marketplace.negotiation")

_DB_PATH = data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")
_db_lock = threading.RLock()
_MAX_ROUNDS = int(os.getenv("MARKETPLACE_MAX_NEGOTIATION_ROUNDS", "5"))

# ── Prompt-injection guard ─────────────────────────────────────────────────────

_INJECTION_PHRASES = [
    "ignore previous instructions",
    "ignore all previous",
    "system prompt override",
    "do not follow",
    "new instructions:",
    "disregard previous",
    "forget all previous",
    "override previous",
    "you are now",
    "act as if",
    "pretend you are",
    "your new role",
]

_DELIMITER_PATTERNS = [
    "---\n",
    "===\n",
    "```system",
    "<|system|>",
    "<<sys>>",
    "[inst]",
    "<|im_start|>",
    "### instruction",
]


def _scan_injection(text: str) -> bool:
    """Return True if *text* contains known prompt-injection or delimiter-attack patterns."""
    lower = text.lower()
    return (
        any(phrase in lower for phrase in _INJECTION_PHRASES)
        or any(delim in lower for delim in _DELIMITER_PATTERNS)
    )


# ── Schema ────────────────────────────────────────────────────────────────────

_NEGOTIATION_DDL = """
    CREATE TABLE IF NOT EXISTS marketplace_negotiations (
        negotiation_id TEXT PRIMARY KEY,
        listing_id     TEXT NOT NULL,
        buyer_agent    TEXT NOT NULL,
        seller_agent   TEXT NOT NULL,
        asset_ueciid   TEXT NOT NULL DEFAULT '',
        status         TEXT NOT NULL DEFAULT 'open',
        current_price  REAL NOT NULL DEFAULT 0.0,
        round_count    INTEGER NOT NULL DEFAULT 0,
        created_at     TEXT NOT NULL,
        updated_at     TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_mn_listing ON marketplace_negotiations(listing_id);
    CREATE INDEX IF NOT EXISTS idx_mn_buyer   ON marketplace_negotiations(buyer_agent);
    CREATE INDEX IF NOT EXISTS idx_mn_seller  ON marketplace_negotiations(seller_agent);

    CREATE TABLE IF NOT EXISTS marketplace_offers (
        offer_id       TEXT PRIMARY KEY,
        negotiation_id TEXT NOT NULL,
        from_agent     TEXT NOT NULL,
        offer_type     TEXT NOT NULL DEFAULT 'offer',
        price          REAL NOT NULL DEFAULT 0.0,
        message        TEXT NOT NULL DEFAULT '',
        round          INTEGER NOT NULL DEFAULT 1,
        signature      TEXT NOT NULL DEFAULT '',
        created_at     TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_mo_negotiation ON marketplace_offers(negotiation_id);
"""
register("marketplace", "warden.marketplace.negotiation", _NEGOTIATION_DDL)


@contextmanager
def _conn(db_path: str = _DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    with open_db(
        "marketplace", db_path, turso_name="marketplace", module_default_path=_DB_PATH
    ) as con:
        yield con


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class Negotiation:
    negotiation_id: str
    listing_id:     str
    buyer_agent:    str
    seller_agent:   str
    asset_ueciid:   str
    status:         str
    current_price:  float
    round_count:    int
    created_at:     str
    updated_at:     str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Offer:
    offer_id:       str
    negotiation_id: str
    from_agent:     str
    offer_type:     str
    price:          float
    message:        str
    round:          int
    signature:      str
    created_at:     str

    def to_dict(self) -> dict:
        return asdict(self)


def _row_to_negotiation(row: sqlite3.Row) -> Negotiation:
    return Negotiation(
        negotiation_id=row["negotiation_id"],
        listing_id=row["listing_id"],
        buyer_agent=row["buyer_agent"],
        seller_agent=row["seller_agent"],
        asset_ueciid=row["asset_ueciid"],
        status=row["status"],
        current_price=row["current_price"],
        round_count=row["round_count"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _row_to_offer(row: sqlite3.Row) -> Offer:
    return Offer(
        offer_id=row["offer_id"],
        negotiation_id=row["negotiation_id"],
        from_agent=row["from_agent"],
        offer_type=row["offer_type"],
        price=row["price"],
        message=row["message"],
        round=row["round"],
        signature=row["signature"],
        created_at=row["created_at"],
    )


# ── Signing helpers ───────────────────────────────────────────────────────────

def _canonical_offer(
    offer_type: str,
    price: float,
    asset_ueciid: str,
    round_: int,
    agent_id: str,
    timestamp: str,
) -> bytes:
    envelope = {
        "type":         offer_type,
        "price":        price,
        "asset_ueciid": asset_ueciid,
        "round":        round_,
        "agent_id":     agent_id,
        "timestamp":    timestamp,
    }
    return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()


def _sign_offer(canonical: bytes, keypair) -> str:
    """Sign canonical offer bytes with the agent's Ed25519 key. Fail-open → empty string."""
    try:
        sig_bytes = keypair.sign(canonical)
        return base64.b64encode(sig_bytes).decode()
    except Exception as exc:
        log.debug("Offer signing failed (non-critical): %s", exc)
        return ""


def _verify_offer_signature(
    canonical: bytes, signature_b64: str, public_key_b64: str
) -> bool:
    """Verify Ed25519 signature on a canonical offer. Returns False on any error."""
    if not signature_b64 or not public_key_b64:
        return False
    try:
        import base64 as _b64

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pub_bytes = _b64.b64decode(public_key_b64)
        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        sig = _b64.b64decode(signature_b64)
        pub_key.verify(sig, canonical)
        return True
    except Exception:
        return False


# ── NegotiationEngine ─────────────────────────────────────────────────────────

class NegotiationEngine:
    """Multi-round negotiation protocol between two marketplace agents."""

    def start_negotiation(
        self,
        buyer_agent_id: str,
        seller_agent_id: str,
        listing_id: str,
        initial_price: float,
        asset_ueciid: str = "",
        db_path: str = _DB_PATH,
    ) -> Negotiation:
        """Open a new negotiation session. Returns Negotiation."""
        negotiation_id = f"NEG-{uuid.uuid4().hex[:12].upper()}"
        now = datetime.now(UTC).isoformat()
        neg = Negotiation(
            negotiation_id=negotiation_id,
            listing_id=listing_id,
            buyer_agent=buyer_agent_id,
            seller_agent=seller_agent_id,
            asset_ueciid=asset_ueciid,
            status="open",
            current_price=initial_price,
            round_count=0,
            created_at=now,
            updated_at=now,
        )
        with _db_lock, _conn(db_path) as con:
            con.execute(
                """INSERT INTO marketplace_negotiations
                   (negotiation_id, listing_id, buyer_agent, seller_agent,
                    asset_ueciid, status, current_price, round_count,
                    created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    neg.negotiation_id, neg.listing_id, neg.buyer_agent,
                    neg.seller_agent, neg.asset_ueciid, neg.status,
                    neg.current_price, neg.round_count,
                    neg.created_at, neg.updated_at,
                ),
            )
        return neg

    def send_offer(
        self,
        negotiation_id: str,
        from_agent_id: str,
        price: float,
        message: str = "",
        keypair=None,
        db_path: str = _DB_PATH,
    ) -> Offer:
        """Send a counter-offer. Raises ValueError if negotiation closed or max rounds hit."""
        neg = self._get_neg(negotiation_id, db_path)
        if neg is None:
            raise ValueError(f"Negotiation '{negotiation_id}' not found.")
        if neg.status != "open":
            raise ValueError(f"Negotiation '{negotiation_id}' is {neg.status}.")
        if neg.round_count >= _MAX_ROUNDS:
            self._close(negotiation_id, "expired", db_path)
            raise ValueError(
                f"Negotiation '{negotiation_id}' exceeded max rounds ({_MAX_ROUNDS})."
            )
        if message and _scan_injection(message):
            log.warning(
                "Negotiation injection detected neg=%s agent=%s", negotiation_id, from_agent_id
            )
            raise ValueError("Prompt injection detected in negotiation message.")

        now       = datetime.now(UTC).isoformat()
        new_round = neg.round_count + 1
        canonical = _canonical_offer("offer", price, neg.asset_ueciid, new_round, from_agent_id, now)
        sig       = _sign_offer(canonical, keypair) if keypair else ""

        offer = Offer(
            offer_id=f"OFR-{uuid.uuid4().hex[:10].upper()}",
            negotiation_id=negotiation_id,
            from_agent=from_agent_id,
            offer_type="offer",
            price=price,
            message=message,
            round=new_round,
            signature=sig,
            created_at=now,
        )
        with _db_lock, _conn(db_path) as con:
            con.execute(
                """INSERT INTO marketplace_offers
                   (offer_id, negotiation_id, from_agent, offer_type,
                    price, message, round, signature, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    offer.offer_id, offer.negotiation_id, offer.from_agent,
                    offer.offer_type, offer.price, offer.message,
                    offer.round, offer.signature, offer.created_at,
                ),
            )
            con.execute(
                """UPDATE marketplace_negotiations
                   SET current_price=?, round_count=?, updated_at=?
                   WHERE negotiation_id=?""",
                (price, new_round, now, negotiation_id),
            )
        return offer

    def accept_offer(
        self,
        negotiation_id: str,
        from_agent_id: str,
        keypair=None,
        db_path: str = _DB_PATH,
    ) -> Offer:
        """Accept the current offer. Closes the negotiation as 'accepted'."""
        neg = self._get_neg(negotiation_id, db_path)
        if neg is None:
            raise ValueError(f"Negotiation '{negotiation_id}' not found.")
        if neg.status != "open":
            raise ValueError(f"Negotiation '{negotiation_id}' is already {neg.status}.")

        now       = datetime.now(UTC).isoformat()
        new_round = neg.round_count + 1
        canonical = _canonical_offer(
            "accept", neg.current_price, neg.asset_ueciid, new_round, from_agent_id, now
        )
        sig = _sign_offer(canonical, keypair) if keypair else ""

        offer = Offer(
            offer_id=f"OFR-{uuid.uuid4().hex[:10].upper()}",
            negotiation_id=negotiation_id,
            from_agent=from_agent_id,
            offer_type="accept",
            price=neg.current_price,
            message="Offer accepted.",
            round=new_round,
            signature=sig,
            created_at=now,
        )
        with _db_lock, _conn(db_path) as con:
            con.execute(
                """INSERT INTO marketplace_offers
                   (offer_id, negotiation_id, from_agent, offer_type,
                    price, message, round, signature, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    offer.offer_id, offer.negotiation_id, offer.from_agent,
                    offer.offer_type, offer.price, offer.message,
                    offer.round, offer.signature, offer.created_at,
                ),
            )
            con.execute(
                """UPDATE marketplace_negotiations
                   SET status='accepted', round_count=?, updated_at=?
                   WHERE negotiation_id=?""",
                (new_round, now, negotiation_id),
            )
        return offer

    def reject_offer(
        self,
        negotiation_id: str,
        from_agent_id: str,
        reason: str = "",
        db_path: str = _DB_PATH,
    ) -> bool:
        """Reject — closes the negotiation as 'rejected'."""
        neg = self._get_neg(negotiation_id, db_path)
        if neg is None or neg.status != "open":
            return False
        self._close(negotiation_id, "rejected", db_path)
        return True

    def get_negotiation_status(
        self, negotiation_id: str, db_path: str = _DB_PATH
    ) -> dict | None:
        neg = self._get_neg(negotiation_id, db_path)
        if neg is None:
            return None
        offers = self._get_offers(negotiation_id, db_path)
        return {
            **neg.to_dict(),
            "offers": [o.to_dict() for o in offers],
        }

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _get_neg(self, negotiation_id: str, db_path: str) -> Negotiation | None:
        with _conn(db_path) as con:
            row = con.execute(
                "SELECT * FROM marketplace_negotiations WHERE negotiation_id=?",
                (negotiation_id,),
            ).fetchone()
        return _row_to_negotiation(row) if row else None

    def _get_offers(self, negotiation_id: str, db_path: str) -> list[Offer]:
        with _conn(db_path) as con:
            rows = con.execute(
                "SELECT * FROM marketplace_offers WHERE negotiation_id=? ORDER BY round",
                (negotiation_id,),
            ).fetchall()
        return [_row_to_offer(r) for r in rows]

    def _close(self, negotiation_id: str, status: str, db_path: str) -> None:
        now = datetime.now(UTC).isoformat()
        with _db_lock, _conn(db_path) as con:
            con.execute(
                "UPDATE marketplace_negotiations SET status=?, updated_at=? WHERE negotiation_id=?",
                (status, now, negotiation_id),
            )
