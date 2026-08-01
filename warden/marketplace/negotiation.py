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
    negotiation_id: str = "",
) -> bytes:
    """Canonical bytes an agent signs for one offer.

    MP-1b added ``negotiation_id``. Without it the envelope was portable: a
    signature produced for round N of one negotiation verified just as well
    against a different negotiation over the same asset at the same price and
    round, so a captured signature could be replayed sideways. Binding the
    negotiation makes each signature usable in exactly one place.

    Changing the envelope broke no existing signer — until MP-1b nothing signed
    at all, every stored signature was the empty string.
    """
    envelope = {
        "type":           offer_type,
        "price":          price,
        "asset_ueciid":   asset_ueciid,
        "round":          round_,
        "agent_id":       agent_id,
        "timestamp":      timestamp,
        "negotiation_id": negotiation_id,
    }
    return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()


def build_offer_canonical(
    *,
    offer_type: str,
    price: float,
    asset_ueciid: str,
    round_: int,
    agent_id: str,
    timestamp: str,
    negotiation_id: str,
) -> bytes:
    """Public envelope builder — the bytes a client must sign.

    Exported so an agent SDK and the tests derive the envelope from the same
    code the server verifies against. A second, hand-rolled copy of this
    serialization on the client side is how signature schemes quietly stop
    matching.
    """
    return _canonical_offer(
        offer_type, price, asset_ueciid, round_, agent_id, timestamp, negotiation_id
    )


def _sign_offer(canonical: bytes, keypair) -> str:
    """Sign canonical offer bytes with the agent's Ed25519 key. Fail-open → empty string."""
    try:
        sig_bytes = keypair.sign(canonical)
        return base64.b64encode(sig_bytes).decode()
    except Exception as exc:
        log.debug("Offer signing failed (non-critical): %s", exc)
        return ""


def signed_offers_required() -> bool:
    """True when an unsigned/badly-signed offer is rejected rather than merely counted.

    Read per call, never snapshotted at import, so an operator can flip it
    without a redeploy and so tests can toggle it.

    Defaults to **false**: every offer already persisted carries ``signature=''``
    (nothing ever signed), so switching straight to rejection would break every
    live integration at once. Verification and its metric run either way — the
    ``absent`` counter is what tells an operator when it is safe to flip.
    """
    return os.getenv("MARKETPLACE_REQUIRE_SIGNED_OFFERS", "false").strip().lower() == "true"


def _max_skew_seconds() -> int:
    try:
        return int(os.getenv("MARKETPLACE_OFFER_MAX_SKEW_S", "300"))
    except ValueError:
        return 300


def _record_signature_outcome(result: str) -> None:
    """Count a verification outcome. Never raises — telemetry must not break a trade."""
    try:
        from warden.metrics import MARKETPLACE_OFFER_SIGNATURE_TOTAL  # noqa: PLC0415
        MARKETPLACE_OFFER_SIGNATURE_TOTAL.labels(
            result=result, enforced=str(signed_offers_required()).lower()
        ).inc()
    except Exception as exc:  # pragma: no cover - metrics are optional
        log.debug("offer signature metric unavailable: %s", exc)


class OfferSignatureError(ValueError):
    """Raised when an offer's actor proof is missing or invalid and enforcement is on."""


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


def _assert_actor(
    *,
    neg: Negotiation,
    from_agent_id: str,
    offer_type: str,
    price: float,
    round_: int,
    signature: str,
    timestamp: str,
    db_path: str,
) -> None:
    """Prove the caller controls ``from_agent_id`` before its offer moves the price.

    An API key (MP-1a) proves *a tenant*; it says nothing about *which agent* an
    action is attributed to. ``from_agent_id`` arrives as body text, so without
    this check any authenticated caller could send or accept offers as anybody —
    that is how a $1000 listing was settled at $0.01 by impersonating the seller
    on accept.

    The binding is free: ``agent_id`` is *derived from* the public key
    (``did:shadow:{base62(sha256(pubkey))}``, see ``agent.pubkey_to_agent_id``),
    so a signature that verifies against the registered
    ``marketplace_agents.public_key`` is itself proof of the claimed identity.
    No extra binding table, no key-distribution step.

    Fail-CLOSED under enforcement: unknown agent, missing key, absent signature,
    stale timestamp or a verify error all reject. This is signature
    verification, governed by the Phase-7 signing rule (an unresolvable key
    denies) — *not* by the x402 fail-open rule, which is about payment
    availability.

    Party check runs regardless of enforcement: a signature from an agent that
    is not a party to this negotiation is meaningless even when it verifies, and
    rejecting that never breaks a legitimate unsigned client.
    """
    if from_agent_id not in (neg.buyer_agent, neg.seller_agent):
        raise OfferSignatureError(
            f"Agent '{from_agent_id}' is not a party to negotiation '{neg.negotiation_id}'."
        )

    enforced = signed_offers_required()

    if not signature:
        _record_signature_outcome("absent")
        if enforced:
            raise OfferSignatureError(
                "Offer must carry an Ed25519 signature over the canonical envelope "
                "(MARKETPLACE_REQUIRE_SIGNED_OFFERS is on)."
            )
        return

    # Reject a stale or far-future envelope so a captured signature cannot be
    # replayed later. Checked before the crypto so a malformed timestamp cannot
    # be laundered by a valid signature.
    if not _timestamp_within_skew(timestamp):
        _record_signature_outcome("stale")
        if enforced:
            raise OfferSignatureError(
                f"Offer timestamp '{timestamp}' is outside the "
                f"{_max_skew_seconds()}s acceptance window."
            )
        return

    public_key = ""
    try:
        from warden.marketplace.agent import get_agent  # noqa: PLC0415
        agent = get_agent(from_agent_id, db_path=db_path)
        public_key = getattr(agent, "public_key", "") or ""
    except Exception as exc:
        # A lookup failure must not become an accept. Under enforcement it
        # denies; unenforced it is counted so the failure is visible rather
        # than silently scored as "valid".
        log.warning("offer signature: agent lookup failed for %s: %s", from_agent_id, exc)
        _record_signature_outcome("lookup_error")
        if enforced:
            raise OfferSignatureError(
                f"Could not resolve signing key for agent '{from_agent_id}'."
            ) from exc
        return

    if not public_key:
        _record_signature_outcome("no_key")
        if enforced:
            raise OfferSignatureError(
                f"Agent '{from_agent_id}' has no registered public key to verify against."
            )
        return

    canonical = _canonical_offer(
        offer_type, price, neg.asset_ueciid, round_, from_agent_id,
        timestamp, neg.negotiation_id,
    )
    if not _verify_offer_signature(canonical, signature, public_key):
        _record_signature_outcome("invalid")
        if enforced:
            raise OfferSignatureError(
                "Offer signature does not verify against the agent's registered public key."
            )
        return

    _record_signature_outcome("valid")


def _timestamp_within_skew(timestamp: str) -> bool:
    """True when *timestamp* is a parseable ISO-8601 instant inside the skew window."""
    if not timestamp:
        return False
    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return abs((datetime.now(UTC) - parsed).total_seconds()) <= _max_skew_seconds()


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
        signature: str = "",
        timestamp: str = "",
    ) -> Offer:
        """Send a counter-offer. Raises ValueError if negotiation closed or max rounds hit.

        MP-1b: *signature* is the caller's Ed25519 proof over
        ``build_offer_canonical(...)`` and *timestamp* the instant it signed.
        Together they prove the caller controls *from_agent_id*; see
        ``_assert_actor``. *keypair* remains for in-process callers that sign
        server-side.
        """
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

        # Actor proof before any state change: an offer that cannot be attributed
        # must not reach the price or the offer history.
        _assert_actor(
            neg=neg, from_agent_id=from_agent_id, offer_type="offer", price=price,
            round_=new_round, signature=signature, timestamp=timestamp or now,
            db_path=db_path,
        )

        canonical = _canonical_offer(
            "offer", price, neg.asset_ueciid, new_round, from_agent_id, now, negotiation_id
        )
        sig       = signature or (_sign_offer(canonical, keypair) if keypair else "")

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
        signature: str = "",
        timestamp: str = "",
    ) -> Offer:
        """Accept the current offer. Closes the negotiation as 'accepted'.

        MP-1b: this is the step the impersonation exploit targeted — accepting
        as the counterparty locks in whatever price the attacker just offered.
        It carries the same actor proof as ``send_offer``.
        """
        neg = self._get_neg(negotiation_id, db_path)
        if neg is None:
            raise ValueError(f"Negotiation '{negotiation_id}' not found.")
        if neg.status != "open":
            raise ValueError(f"Negotiation '{negotiation_id}' is already {neg.status}.")

        now       = datetime.now(UTC).isoformat()
        new_round = neg.round_count + 1

        _assert_actor(
            neg=neg, from_agent_id=from_agent_id, offer_type="accept",
            price=neg.current_price, round_=new_round, signature=signature,
            timestamp=timestamp or now, db_path=db_path,
        )

        canonical = _canonical_offer(
            "accept", neg.current_price, neg.asset_ueciid, new_round, from_agent_id,
            now, negotiation_id,
        )
        sig = signature or (_sign_offer(canonical, keypair) if keypair else "")

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
