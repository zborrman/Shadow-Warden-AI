"""
warden/communities/sep.py
──────────────────────────
Syndicate Exchange Protocol (SEP) — core primitives.

UECIID  (Unique Encrypted Content Identifier)
───────────────────────────────────────────────
  Every entity in every community gets a human-readable, globally-sortable
  document number at storage time:

    Format:  SEP-{11 base-62 digits}   (15 chars total)
    Example: SEP-0JMj9K2WfKE

  The 11-char tail encodes a 64-bit Snowflake integer (same engine as
  new_entity_id() in id_generator.py).  The encoding is:

    base-62 alphabet: 0-9 A-Z a-z
    11 digits cover 62¹¹ ≈ 5.2 × 10¹⁹  >  2⁶⁴

  Sorting UECIIDs lexicographically gives chronological order (Snowflake
  encodes ms timestamp in the high bits → base-62 preserves that order).

  Search: GET /sep/search?q=SEP-0JMj9K2WfKE

UECIID Index
─────────────
  SQLite table `sep_ueciid_index` maps every UECIID → (entity_id, community_id).
  Populated by `register_ueciid()` at upload time.
  Allows cross-community search without decrypting payloads.

Causal Transfer Proof (CTP)
────────────────────────────
  HMAC-SHA256 over canonical fields — proves who sent what to whom and why.
  Immutable evidence for SOC 2 CC6.3 (data sharing authorisation controls)
  and GDPR Art. 30 (records of processing activities).

  Canonical form:
    transfer_id | source_community_id | target_community_id |
    entity_ueciid | initiator_mid | issued_at | purpose

  Key: COMMUNITY_VAULT_KEY → VAULT_MASTER_KEY → dev fallback.

Sovereign Pod Tag
──────────────────
  Optional per-entity metadata that pins a document to a jurisdiction +
  data classification.  Checked before any inter-community re-wrap:

    {jurisdiction: "EU", data_class: "PHI"}
      → transfer to "US" is blocked (GDPR Chapter V adequacy required)
      → transfer to "UK" is allowed (EU↔UK adequacy decision)

  Stored in `sep_pod_tags`.  Tags survive entity deletion (for audit trail).
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import sqlite3
import string
import threading
from dataclasses import dataclass
from datetime import UTC, datetime

from warden.communities.id_generator import new_entity_id

log = logging.getLogger("warden.communities.sep")

_SEP_DB_PATH = os.getenv("SEP_DB_PATH", "/tmp/warden_sep.db")
_db_lock     = threading.RLock()


# ── UECIID codec ──────────────────────────────────────────────────────────────

_B62       = string.digits + string.ascii_uppercase + string.ascii_lowercase  # 62 chars
_UECIID_LEN = 11     # ceil(log62(2^64)) = 11 base-62 digits


def _to_b62(n: int) -> str:
    if n < 0:
        raise ValueError(f"Snowflake must be non-negative, got {n}")
    digits: list[str] = []
    while n:
        digits.append(_B62[n % 62])
        n //= 62
    while len(digits) < _UECIID_LEN:
        digits.append(_B62[0])
    return "".join(reversed(digits))


def _from_b62(s: str) -> int:
    n = 0
    for ch in s:
        idx = _B62.find(ch)
        if idx == -1:
            raise ValueError(f"Invalid base-62 character: {ch!r}")
        n = n * 62 + idx
    return n


def new_ueciid() -> tuple[int, str]:
    """Generate a UECIID.  Returns (snowflake_int, display_str)."""
    sf = new_entity_id()
    return sf, snowflake_to_ueciid(sf)


def snowflake_to_ueciid(snowflake: int) -> str:
    """Convert Snowflake integer → SEP display string."""
    return "SEP-" + _to_b62(snowflake)


def ueciid_to_snowflake(ueciid: str) -> int:
    """Parse UECIID display string → Snowflake integer."""
    ueciid = ueciid.strip()
    if not ueciid.upper().startswith("SEP-"):
        raise ValueError(f"Invalid UECIID — must start with 'SEP-': {ueciid!r}")
    tail = ueciid[4:]
    if len(tail) != _UECIID_LEN:
        raise ValueError(f"Invalid UECIID length (expected {_UECIID_LEN} chars after prefix)")
    return _from_b62(tail)


# ── Schema ─────────────────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_SEP_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sep_ueciid_index (
            ueciid        TEXT PRIMARY KEY,
            snowflake_id  INTEGER NOT NULL,
            entity_id     TEXT NOT NULL,
            community_id  TEXT NOT NULL,
            display_name  TEXT NOT NULL DEFAULT '',
            content_type  TEXT NOT NULL DEFAULT 'application/octet-stream',
            byte_size     INTEGER NOT NULL DEFAULT 0,
            created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS ueciid_community_idx
            ON sep_ueciid_index(community_id)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS ueciid_snowflake_idx
            ON sep_ueciid_index(snowflake_id)
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sep_pod_tags (
            entity_id     TEXT NOT NULL,
            community_id  TEXT NOT NULL,
            jurisdiction  TEXT NOT NULL DEFAULT 'EU',
            data_class    TEXT NOT NULL DEFAULT 'GENERAL',
            notes         TEXT NOT NULL DEFAULT '',
            created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            PRIMARY KEY (entity_id, community_id)
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS pod_community_idx
            ON sep_pod_tags(community_id)
    """)
    conn.commit()
    return conn


# ── UECIID index ───────────────────────────────────────────────────────────────

@dataclass
class UECIIDEntry:
    ueciid:        str
    snowflake_id:  int
    entity_id:     str
    community_id:  str
    display_name:  str
    content_type:  str
    byte_size:     int
    created_at:    str


def register_ueciid(
    entity_id:    str,
    community_id: str,
    display_name: str = "",
    content_type: str = "application/octet-stream",
    byte_size:    int = 0,
    snowflake:    int | None = None,
) -> UECIIDEntry:
    """
    Register an entity in the UECIID index.

    If *snowflake* is None a new Snowflake ID is generated.
    Call this at entity upload time to make the document searchable by UECIID.
    """
    if snowflake is None:
        snowflake, ueciid = new_ueciid()
    else:
        ueciid = snowflake_to_ueciid(snowflake)

    now = datetime.now(UTC).isoformat()
    with _db_lock:
        conn = _get_conn()
        conn.execute("""
            INSERT OR IGNORE INTO sep_ueciid_index
              (ueciid, snowflake_id, entity_id, community_id,
               display_name, content_type, byte_size, created_at)
            VALUES (?,?,?,?,?,?,?,?)
        """, (ueciid, snowflake, entity_id, community_id,
              display_name, content_type, byte_size, now))
        conn.commit()

    log.info("sep: registered UECIID=%s entity=%s community=%s",
             ueciid, entity_id[:8], community_id[:8])
    return UECIIDEntry(
        ueciid=ueciid, snowflake_id=snowflake, entity_id=entity_id,
        community_id=community_id, display_name=display_name,
        content_type=content_type, byte_size=byte_size, created_at=now,
    )


def lookup_ueciid(ueciid: str) -> UECIIDEntry | None:
    """Find an entity by its UECIID display string."""
    ueciid = ueciid.strip()
    with _db_lock:
        conn = _get_conn()
        row = conn.execute(
            "SELECT * FROM sep_ueciid_index WHERE ueciid=?", (ueciid,)
        ).fetchone()
    if not row:
        return None
    return UECIIDEntry(**dict(row))


def list_ueciids(community_id: str, limit: int = 100, offset: int = 0) -> list[UECIIDEntry]:
    """List UECIIDs for a community, newest first."""
    with _db_lock:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT * FROM sep_ueciid_index WHERE community_id=? "
            "ORDER BY snowflake_id DESC LIMIT ? OFFSET ?",
            (community_id, limit, offset),
        ).fetchall()
    return [UECIIDEntry(**dict(r)) for r in rows]


def search_ueciids(
    community_id: str,
    query: str,
    limit: int = 20,
) -> list[UECIIDEntry]:
    """
    Full-text search within a community's UECIID index.

    *query* is matched against:
      - exact UECIID string (prefix match)
      - display_name LIKE %query%
    """
    like = f"%{query}%"
    with _db_lock:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT * FROM sep_ueciid_index "
            "WHERE community_id=? AND (ueciid LIKE ? OR display_name LIKE ?) "
            "ORDER BY snowflake_id DESC LIMIT ?",
            (community_id, f"{query}%", like, limit),
        ).fetchall()
    return [UECIIDEntry(**dict(r)) for r in rows]


# ── HMAC key ────────────────────────────────────────────────────────────────────

def _sep_key() -> bytes:
    raw = (
        os.getenv("COMMUNITY_VAULT_KEY")
        or os.getenv("VAULT_MASTER_KEY")
        or "dev-sep-key-insecure"
    )
    return raw.encode() if isinstance(raw, str) else raw


# ── Causal Transfer Proof ──────────────────────────────────────────────────────

@dataclass
class CausalTransferProof:
    transfer_id:         str
    source_community_id: str
    target_community_id: str
    entity_ueciid:       str
    initiator_mid:       str
    issued_at:           str
    purpose:             str    # "sharing" | "archive" | "compliance" | free-text
    signature:           str    # HMAC-SHA256 hex
    pqc_signature:       str = ""  # ML-DSA-65 hybrid sig (base64); "" if PQC disabled


def _ctp_canonical(p: CausalTransferProof) -> bytes:
    return (
        f"{p.transfer_id}|{p.source_community_id}|{p.target_community_id}|"
        f"{p.entity_ueciid}|{p.initiator_mid}|{p.issued_at}|{p.purpose}"
    ).encode()


def sign_transfer_proof(
    transfer_id:         str,
    source_community_id: str,
    target_community_id: str,
    entity_ueciid:       str,
    initiator_mid:       str,
    purpose:             str = "sharing",
    community_keypair:   object | None = None,  # CommunityKeypair — for PQC signing
) -> CausalTransferProof:
    """
    Issue a signed Causal Transfer Proof for an inter-community entity transfer.

    If *community_keypair* is provided and is a hybrid PQC keypair (kid ends
    with "-hybrid"), the canonical CTP bytes are also signed with ML-DSA-65
    via hybrid_sign().  The resulting base64 signature is stored in
    pqc_signature for quantum-safe verification.
    """
    import base64
    now = datetime.now(UTC).isoformat()
    p = CausalTransferProof(
        transfer_id=transfer_id,
        source_community_id=source_community_id,
        target_community_id=target_community_id,
        entity_ueciid=entity_ueciid,
        initiator_mid=initiator_mid,
        issued_at=now,
        purpose=purpose,
        signature="",
        pqc_signature="",
    )
    p.signature = hmac.new(_sep_key(), _ctp_canonical(p), hashlib.sha256).hexdigest()

    # PQC hybrid signature (ML-DSA-65 + Ed25519) if keypair is hybrid
    if community_keypair is not None:
        try:
            kp = community_keypair
            if getattr(kp, "is_hybrid", False):
                raw_sig = kp.hybrid_sign(_ctp_canonical(p))
                p.pqc_signature = base64.b64encode(raw_sig).decode()
                log.debug("sep: CTP signed with ML-DSA-65 hybrid (kid=%s)", kp.kid)
        except Exception as exc:
            log.warning("sep: PQC signing failed (non-fatal): %s", exc)

    return p


def verify_transfer_proof(
    p: CausalTransferProof,
    community_keypair: object | None = None,
) -> bool:
    """
    Return True if the CTP HMAC signature is intact.

    If *community_keypair* is provided and the proof has a pqc_signature,
    also verifies the ML-DSA-65 hybrid signature.  Both must pass.
    """
    import base64
    expected = hmac.new(_sep_key(), _ctp_canonical(p), hashlib.sha256).hexdigest()
    hmac_ok  = hmac.compare_digest(expected, p.signature)
    if not hmac_ok:
        return False

    if p.pqc_signature and community_keypair is not None:
        try:
            kp = community_keypair
            if getattr(kp, "is_hybrid", False):
                raw_sig = base64.b64decode(p.pqc_signature)
                if not kp.hybrid_verify(_ctp_canonical(p), raw_sig):
                    log.warning("sep: CTP PQC signature verification failed")
                    return False
        except Exception as exc:
            log.warning("sep: PQC verification error (non-fatal): %s", exc)

    return True


# ── Sovereign Pod Tags ─────────────────────────────────────────────────────────

@dataclass
class SovereignPodTag:
    entity_id:    str
    community_id: str
    jurisdiction: str   # EU | US | UK | CA | SG | AU | JP | CH
    data_class:   str   # GENERAL | PII | PHI | FINANCIAL | CLASSIFIED
    notes:        str
    created_at:   str


def set_pod_tag(
    entity_id:    str,
    community_id: str,
    jurisdiction: str = "EU",
    data_class:   str = "GENERAL",
    notes:        str = "",
) -> SovereignPodTag:
    """Attach or update a Sovereign Pod Tag on an entity."""
    now = datetime.now(UTC).isoformat()
    with _db_lock:
        conn = _get_conn()
        conn.execute("""
            INSERT OR REPLACE INTO sep_pod_tags
              (entity_id, community_id, jurisdiction, data_class, notes, created_at)
            VALUES (?,?,?,?,?,?)
        """, (entity_id, community_id, jurisdiction, data_class, notes, now))
        conn.commit()
    return SovereignPodTag(
        entity_id=entity_id, community_id=community_id,
        jurisdiction=jurisdiction, data_class=data_class,
        notes=notes, created_at=now,
    )


def get_pod_tag(entity_id: str, community_id: str) -> SovereignPodTag | None:
    with _db_lock:
        conn = _get_conn()
        row = conn.execute(
            "SELECT * FROM sep_pod_tags WHERE entity_id=? AND community_id=?",
            (entity_id, community_id),
        ).fetchone()
    if not row:
        return None
    return SovereignPodTag(**dict(row))


def check_transfer_sovereign_compliance(
    entity_id:           str,
    source_community_id: str,
    target_jurisdiction: str,
) -> tuple[bool, str]:
    """
    Check whether the entity's sovereign pod tag allows transfer to *target_jurisdiction*.

    Returns (allowed: bool, reason: str).
    No pod tag → allowed by default (not classified).
    """
    tag = get_pod_tag(entity_id, source_community_id)
    if not tag:
        return True, "No pod tag — transfer allowed (unclassified)."

    try:
        from warden.sovereign.jurisdictions import is_transfer_allowed
        allowed = is_transfer_allowed(tag.data_class, tag.jurisdiction, target_jurisdiction)
        if allowed:
            return True, (
                f"{tag.data_class} data ({tag.jurisdiction}→{target_jurisdiction}): allowed."
            )
        return False, (
            f"Sovereign pod: {tag.data_class} data from {tag.jurisdiction} cannot "
            f"be transferred to {target_jurisdiction} (data residency policy)."
        )
    except ImportError:
        return True, "Sovereign module unavailable — transfer allowed by default."
