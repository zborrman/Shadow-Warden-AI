"""
warden/communities/peering.py
───────────────────────────────
Inter-Community Peering — Syndicate Exchange Protocol (SEP).

Two communities can peer to exchange encrypted entities.  The peering
agreement defines what is allowed across the link:

  MIRROR_ONLY    — target community receives a read-only copy (no re-export)
  REWRAP_ALLOWED — target can re-wrap and forward to its own members
  FULL_SYNC      — bidirectional: either side can initiate transfers

Peering lifecycle
──────────────────
  1. Community A calls initiate_peering() → PeeringRecord (status=PENDING)
     A short HMAC handshake token is returned for out-of-band delivery.
  2. Community B calls accept_peering(peering_id, token) → status=ACTIVE
  3. Either side calls revoke_peering(peering_id) → status=REVOKED

Transfer flow
──────────────
  transfer_entity(peering_id, entity_id, initiator_mid, purpose) →
    1. Validate peering is ACTIVE.
    2. Check Sovereign Pod Tag for cross-jurisdiction compliance.
    3. Sign a Causal Transfer Proof (HMAC-SHA256, immutable evidence).
    4. Register a new UECIID for the copy in the target community.
    5. Insert TransferRecord.

  The caller is responsible for re-encrypting the payload with the
  target community's public key (via existing ClearanceEnvelope mechanism).

Storage
────────
  SQLite `sep_peerings` + `sep_transfers` (shared _SEP_DB_PATH with sep.py).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from warden.communities.sep import (
    check_transfer_sovereign_compliance,
    register_ueciid,
    sign_transfer_proof,
)

log = logging.getLogger("warden.communities.peering")

_SEP_DB_PATH     = os.getenv("SEP_DB_PATH", "/tmp/warden_sep.db")
_db_lock         = threading.RLock()
_VALID_POLICIES  = {"MIRROR_ONLY", "REWRAP_ALLOWED", "FULL_SYNC"}


# ── Schema ─────────────────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_SEP_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sep_peerings (
            peering_id            TEXT PRIMARY KEY,
            initiator_community   TEXT NOT NULL,
            target_community      TEXT NOT NULL,
            policy                TEXT NOT NULL DEFAULT 'REWRAP_ALLOWED',
            status                TEXT NOT NULL DEFAULT 'PENDING',
            handshake_token_hash  TEXT NOT NULL,
            initiator_mid         TEXT NOT NULL,
            accepted_by_mid       TEXT,
            created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            accepted_at           TEXT,
            revoked_at            TEXT,
            notes                 TEXT NOT NULL DEFAULT ''
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS peering_initiator_idx
            ON sep_peerings(initiator_community)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS peering_target_idx
            ON sep_peerings(target_community)
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sep_transfers (
            transfer_id           TEXT PRIMARY KEY,
            peering_id            TEXT NOT NULL,
            source_community_id   TEXT NOT NULL,
            target_community_id   TEXT NOT NULL,
            source_entity_id      TEXT NOT NULL,
            source_ueciid         TEXT NOT NULL,
            target_ueciid         TEXT,
            initiator_mid         TEXT NOT NULL,
            purpose               TEXT NOT NULL DEFAULT 'sharing',
            status                TEXT NOT NULL DEFAULT 'PENDING',
            causal_proof_json     TEXT NOT NULL DEFAULT '{}',
            sovereign_ok          INTEGER NOT NULL DEFAULT 1,
            sovereign_reason      TEXT NOT NULL DEFAULT '',
            transferred_at        TEXT,
            created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS transfer_peering_idx
            ON sep_transfers(peering_id)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS transfer_source_ueciid_idx
            ON sep_transfers(source_ueciid)
    """)
    conn.commit()
    return conn


# ── Data models ────────────────────────────────────────────────────────────────

@dataclass
class PeeringRecord:
    peering_id:          str
    initiator_community: str
    target_community:    str
    policy:              str
    status:              str     # PENDING | ACTIVE | REVOKED
    initiator_mid:       str
    accepted_by_mid:     str | None
    created_at:          str
    accepted_at:         str | None
    revoked_at:          str | None
    notes:               str


@dataclass
class TransferRecord:
    transfer_id:         str
    peering_id:          str
    source_community_id: str
    target_community_id: str
    source_entity_id:    str
    source_ueciid:       str
    target_ueciid:       str | None
    initiator_mid:       str
    purpose:             str
    status:              str     # PENDING | TRANSFERRED | REJECTED
    causal_proof:        dict
    sovereign_ok:        bool
    sovereign_reason:    str
    transferred_at:      str | None
    created_at:          str


def _row_to_peering(row) -> PeeringRecord:
    return PeeringRecord(
        peering_id          = row["peering_id"],
        initiator_community = row["initiator_community"],
        target_community    = row["target_community"],
        policy              = row["policy"],
        status              = row["status"],
        initiator_mid       = row["initiator_mid"],
        accepted_by_mid     = row["accepted_by_mid"],
        created_at          = row["created_at"],
        accepted_at         = row["accepted_at"],
        revoked_at          = row["revoked_at"],
        notes               = row["notes"],
    )


def _row_to_transfer(row) -> TransferRecord:
    try:
        proof = json.loads(row["causal_proof_json"])
    except Exception:
        proof = {}
    return TransferRecord(
        transfer_id         = row["transfer_id"],
        peering_id          = row["peering_id"],
        source_community_id = row["source_community_id"],
        target_community_id = row["target_community_id"],
        source_entity_id    = row["source_entity_id"],
        source_ueciid       = row["source_ueciid"],
        target_ueciid       = row["target_ueciid"],
        initiator_mid       = row["initiator_mid"],
        purpose             = row["purpose"],
        status              = row["status"],
        causal_proof        = proof,
        sovereign_ok        = bool(row["sovereign_ok"]),
        sovereign_reason    = row["sovereign_reason"],
        transferred_at      = row["transferred_at"],
        created_at          = row["created_at"],
    )


# ── HMAC handshake token ────────────────────────────────────────────────────────

def _sep_key() -> bytes:
    raw = (
        os.getenv("COMMUNITY_VAULT_KEY")
        or os.getenv("VAULT_MASTER_KEY")
        or "dev-sep-key-insecure"
    )
    return raw.encode() if isinstance(raw, str) else raw


def _issue_handshake_token(peering_id: str) -> tuple[str, str]:
    """Return (token_plaintext, sha256_hash).  Only the hash is stored in DB."""
    nonce = uuid.uuid4().hex
    token = f"peer-{peering_id[:8]}-{nonce}"
    h     = hmac.new(_sep_key(), token.encode(), hashlib.sha256).hexdigest()
    return token, h


def _verify_handshake_token(token: str, stored_hash: str) -> bool:
    expected = hmac.new(_sep_key(), token.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, stored_hash)


# ── Peering CRUD ───────────────────────────────────────────────────────────────

def initiate_peering(
    initiator_community: str,
    target_community:    str,
    initiator_mid:       str,
    policy:              str = "REWRAP_ALLOWED",
    notes:               str = "",
) -> tuple[PeeringRecord, str]:
    """
    Initiate a peering request.

    Returns (PeeringRecord, handshake_token).
    Deliver the handshake_token out-of-band to the target community admin.
    """
    if policy not in _VALID_POLICIES:
        raise ValueError(f"Invalid policy {policy!r}. Valid: {sorted(_VALID_POLICIES)}")
    if initiator_community == target_community:
        raise ValueError("A community cannot peer with itself.")

    peering_id          = str(uuid.uuid4())
    token, token_hash   = _issue_handshake_token(peering_id)
    now                 = datetime.now(UTC).isoformat()

    with _db_lock:
        conn = _get_conn()
        dup = conn.execute(
            "SELECT peering_id FROM sep_peerings "
            "WHERE initiator_community=? AND target_community=? AND status='ACTIVE'",
            (initiator_community, target_community),
        ).fetchone()
        if dup:
            raise ValueError(
                f"Active peering already exists (id={dup['peering_id'][:8]}…). Revoke it first."
            )
        conn.execute("""
            INSERT INTO sep_peerings
              (peering_id, initiator_community, target_community, policy,
               status, handshake_token_hash, initiator_mid, notes, created_at)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (
            peering_id, initiator_community, target_community, policy,
            "PENDING", token_hash, initiator_mid, notes, now,
        ))
        conn.commit()

    log.info(
        "peering: initiated id=%s %s→%s policy=%s",
        peering_id[:8], initiator_community[:8], target_community[:8], policy,
    )
    return PeeringRecord(
        peering_id=peering_id,
        initiator_community=initiator_community,
        target_community=target_community,
        policy=policy,
        status="PENDING",
        initiator_mid=initiator_mid,
        accepted_by_mid=None,
        created_at=now,
        accepted_at=None,
        revoked_at=None,
        notes=notes,
    ), token


def accept_peering(
    peering_id:      str,
    handshake_token: str,
    accepted_by_mid: str,
) -> PeeringRecord:
    """
    Accept a PENDING peering.  Raises ValueError if token invalid or status != PENDING.
    """
    with _db_lock:
        conn = _get_conn()
        row = conn.execute(
            "SELECT * FROM sep_peerings WHERE peering_id=? AND status='PENDING'",
            (peering_id,),
        ).fetchone()
        if not row:
            raise ValueError(f"Peering {peering_id[:8]}… not found or not PENDING.")
        if not _verify_handshake_token(handshake_token, row["handshake_token_hash"]):
            raise ValueError("Invalid handshake token.")
        now = datetime.now(UTC).isoformat()
        conn.execute(
            "UPDATE sep_peerings SET status='ACTIVE', accepted_by_mid=?, accepted_at=? "
            "WHERE peering_id=?",
            (accepted_by_mid, now, peering_id),
        )
        conn.commit()

    log.info("peering: accepted id=%s by mid=%s", peering_id[:8], accepted_by_mid[:8])
    return PeeringRecord(
        peering_id=peering_id,
        initiator_community=row["initiator_community"],
        target_community=row["target_community"],
        policy=row["policy"],
        status="ACTIVE",
        initiator_mid=row["initiator_mid"],
        accepted_by_mid=accepted_by_mid,
        created_at=row["created_at"],
        accepted_at=now,
        revoked_at=None,
        notes=row["notes"],
    )


def revoke_peering(peering_id: str) -> bool:
    """Revoke a PENDING or ACTIVE peering → REVOKED. Returns True if found."""
    now = datetime.now(UTC).isoformat()
    with _db_lock:
        conn = _get_conn()
        cur = conn.execute(
            "UPDATE sep_peerings SET status='REVOKED', revoked_at=? "
            "WHERE peering_id=? AND status IN ('PENDING','ACTIVE')",
            (now, peering_id),
        )
        conn.commit()
    revoked = cur.rowcount > 0
    if revoked:
        log.info("peering: revoked id=%s", peering_id[:8])
    return revoked


def get_peering(peering_id: str) -> PeeringRecord | None:
    with _db_lock:
        conn = _get_conn()
        row = conn.execute(
            "SELECT * FROM sep_peerings WHERE peering_id=?", (peering_id,)
        ).fetchone()
    return _row_to_peering(row) if row else None


def list_peerings(community_id: str, status_filter: str | None = None) -> list[PeeringRecord]:
    """List peerings where *community_id* is initiator OR target."""
    with _db_lock:
        conn = _get_conn()
        if status_filter:
            rows = conn.execute(
                "SELECT * FROM sep_peerings "
                "WHERE (initiator_community=? OR target_community=?) AND status=? "
                "ORDER BY created_at DESC",
                (community_id, community_id, status_filter),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM sep_peerings "
                "WHERE initiator_community=? OR target_community=? "
                "ORDER BY created_at DESC",
                (community_id, community_id),
            ).fetchall()
    return [_row_to_peering(r) for r in rows]


# ── Entity Transfer ────────────────────────────────────────────────────────────

def transfer_entity(
    peering_id:          str,
    entity_id:           str,
    source_ueciid:       str,
    initiator_mid:       str,
    purpose:             str = "sharing",
    target_jurisdiction: str | None = None,
    display_name:        str = "",
) -> TransferRecord:
    """
    Record an inter-community entity transfer and issue a Causal Transfer Proof.

    Returns TransferRecord.  status="TRANSFERRED" if sovereign check passes,
    "REJECTED" if the pod tag blocks the transfer.

    The caller must separately re-encrypt the payload with the target community's
    public X25519 key via the existing ClearanceEnvelope mechanism.
    """
    peering = get_peering(peering_id)
    if not peering:
        raise ValueError(f"Peering {peering_id[:8]}… not found.")
    if peering.status != "ACTIVE":
        raise ValueError(f"Peering {peering_id[:8]}… is {peering.status}, not ACTIVE.")

    source_id   = peering.initiator_community
    target_id   = peering.target_community
    transfer_id = str(uuid.uuid4())
    now         = datetime.now(UTC).isoformat()

    # Resolve entity data class from sovereign pod tag (for risk assessment)
    data_class = "GENERAL"
    try:
        from warden.communities.sep import get_pod_tag  # noqa: PLC0415
        tag = get_pod_tag(entity_id, source_id)
        if tag:
            data_class = tag.data_class
    except Exception:
        pass

    # ── Causal Transfer Guard (Bayesian DAG — < 20ms) ─────────────────────────
    guard_risk_score  = 0.0
    guard_blocked     = False
    guard_reason      = "transfer_guard unavailable (allowed by default)"
    try:
        from warden.communities.transfer_guard import evaluate_transfer_risk  # noqa: PLC0415
        peering_age_days = 30.0
        if peering.accepted_at:
            try:
                accepted = datetime.fromisoformat(peering.accepted_at.replace("Z", "+00:00"))
                peering_age_days = (datetime.now(UTC) - accepted).total_seconds() / 86400
            except Exception:
                pass
        decision = evaluate_transfer_risk(
            source_community_id = source_id,
            target_community_id = target_id,
            peering_id          = peering_id,
            entity_id           = entity_id,
            data_class          = data_class,
            peering_policy      = peering.policy,
            peering_age_days    = peering_age_days,
        )
        guard_risk_score = decision.score
        guard_blocked    = not decision.allowed
        guard_reason     = decision.reason
        if guard_blocked:
            log.warning(
                "peering: transfer BLOCKED by causal guard id=%s score=%.3f reason=%s",
                transfer_id[:8], decision.score, decision.reason,
            )
    except Exception as _ge:
        log.debug("transfer_guard error (non-fatal, transfer continues): %s", _ge)

    # Sovereign compliance check
    sovereign_ok     = True
    sovereign_reason = "No pod tag — unclassified."
    if target_jurisdiction:
        sovereign_ok, sovereign_reason = check_transfer_sovereign_compliance(
            entity_id, source_id, target_jurisdiction
        )

    status = "TRANSFERRED"
    if guard_blocked:
        status = "REJECTED"
        sovereign_ok = False
        sovereign_reason = guard_reason
    elif not sovereign_ok:
        status = "REJECTED"

    # Sign Causal Transfer Proof (with optional PQC hybrid signature)
    proof = sign_transfer_proof(
        transfer_id         = transfer_id,
        source_community_id = source_id,
        target_community_id = target_id,
        entity_ueciid       = source_ueciid,
        initiator_mid       = initiator_mid,
        purpose             = purpose,
    )
    proof_dict = {
        "transfer_id":         proof.transfer_id,
        "source_community_id": proof.source_community_id,
        "target_community_id": proof.target_community_id,
        "entity_ueciid":       proof.entity_ueciid,
        "initiator_mid":       proof.initiator_mid,
        "issued_at":           proof.issued_at,
        "purpose":             proof.purpose,
        "signature":           proof.signature,
        "pqc_signature":       proof.pqc_signature,
    }

    # Assign new UECIID for the copy in the target community
    target_ueciid: str | None = None
    if status == "TRANSFERRED":
        entry = register_ueciid(
            entity_id    = entity_id,
            community_id = target_id,
            display_name = display_name or f"[via {source_id[:8]}…] {source_ueciid}",
        )
        target_ueciid = entry.ueciid

    transferred_at = now if status == "TRANSFERRED" else None

    with _db_lock:
        conn = _get_conn()
        conn.execute("""
            INSERT INTO sep_transfers
              (transfer_id, peering_id, source_community_id, target_community_id,
               source_entity_id, source_ueciid, target_ueciid, initiator_mid,
               purpose, status, causal_proof_json, sovereign_ok, sovereign_reason,
               transferred_at, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            transfer_id, peering_id, source_id, target_id,
            entity_id, source_ueciid, target_ueciid, initiator_mid,
            purpose, status, json.dumps(proof_dict),
            int(sovereign_ok), sovereign_reason,
            transferred_at, now,
        ))
        conn.commit()

    # ── STIX 2.1 Audit Chain — append regardless of status ────────────────────
    try:
        from warden.communities.stix_audit import append_transfer  # noqa: PLC0415
        append_transfer(
            transfer_id          = transfer_id,
            source_community_id  = source_id,
            target_community_id  = target_id,
            entity_ueciid        = source_ueciid,
            initiator_mid        = initiator_mid,
            purpose              = purpose,
            ctp_hmac_signature   = proof.signature,
            pqc_signature        = proof.pqc_signature,
            risk_score           = guard_risk_score,
            data_class           = data_class,
        )
    except Exception as _sa:
        log.debug("stix_audit append failed (non-fatal): %s", _sa)

    log.info(
        "peering: transfer id=%s %s→%s entity=%s status=%s risk=%.3f",
        transfer_id[:8], source_id[:8], target_id[:8], entity_id[:8],
        status, guard_risk_score,
    )
    return TransferRecord(
        transfer_id         = transfer_id,
        peering_id          = peering_id,
        source_community_id = source_id,
        target_community_id = target_id,
        source_entity_id    = entity_id,
        source_ueciid       = source_ueciid,
        target_ueciid       = target_ueciid,
        initiator_mid       = initiator_mid,
        purpose             = purpose,
        status              = status,
        causal_proof        = proof_dict,
        sovereign_ok        = sovereign_ok,
        sovereign_reason    = sovereign_reason,
        transferred_at      = transferred_at,
        created_at          = now,
    )


def list_transfers(
    peering_id:   str | None = None,
    community_id: str | None = None,
    limit:        int = 100,
) -> list[TransferRecord]:
    """List transfer records by peering or community."""
    with _db_lock:
        conn = _get_conn()
        if peering_id:
            rows = conn.execute(
                "SELECT * FROM sep_transfers WHERE peering_id=? "
                "ORDER BY created_at DESC LIMIT ?",
                (peering_id, limit),
            ).fetchall()
        elif community_id:
            rows = conn.execute(
                "SELECT * FROM sep_transfers "
                "WHERE source_community_id=? OR target_community_id=? "
                "ORDER BY created_at DESC LIMIT ?",
                (community_id, community_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM sep_transfers ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
    return [_row_to_transfer(r) for r in rows]


def get_transfer(transfer_id: str) -> TransferRecord | None:
    with _db_lock:
        conn = _get_conn()
        row = conn.execute(
            "SELECT * FROM sep_transfers WHERE transfer_id=?", (transfer_id,)
        ).fetchone()
    return _row_to_transfer(row) if row else None
