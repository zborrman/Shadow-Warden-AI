"""
warden/communities/stix_audit.py
──────────────────────────────────
STIX 2.1 Tamper-Evident Audit Chain for SEP transfers.

Every inter-community document transfer is recorded as a STIX 2.1 bundle
containing three Structured Threat Information Expression (STIX) objects:

  1. identity (source community)
  2. identity (target community)
  3. relationship "transferred-to" (source → target)
     custom extension x-sep-proof: Causal Transfer Proof fields
  4. note      Canonical CTP proof string for audit reconstruction

Chain integrity
───────────────
  Each bundle carries the SHA-256 hash of the previous bundle's canonical
  JSON in a `x-chain` extension on the bundle.  This creates a blockchain-
  style tamper-evident log: modifying any past transfer invalidates all
  subsequent hashes.

  Genesis block: prev_hash = "0" * 64

Compliance relevance
────────────────────
  STIX 2.1 (OASIS standard) is accepted by many SIEM/SOAR platforms
  and is the de-facto format for CTI sharing.  Exporting the chain as
  STIX bundles satisfies:
    • SOC 2 CC6.3  — data-sharing authorisation audit trail
    • GDPR Art. 30 — records of processing activities (ROPA)
    • ISO 27001 A.8.3 — information transfer

Storage
────────
  SQLite `sep_stix_chain` in SEP_DB_PATH — same file as sep.py / peering.py.
  Bundles stored as JSON text; `bundle_hash` enables integrity check without
  re-serialising.

API endpoints (via sep.py API router)
───────────────────────────────────────
  GET /sep/audit-chain/{community_id}          list chain entries
  GET /sep/audit-chain/{community_id}/verify   verify integrity
  GET /sep/audit-chain/{community_id}/export   export as JSONL (one bundle/line)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

log = logging.getLogger("warden.communities.stix_audit")

_SEP_DB_PATH = os.getenv("SEP_DB_PATH", "/tmp/warden_sep.db")
_db_lock     = threading.RLock()

_STIX_SPEC_VERSION = "2.1"
_CHAIN_GENESIS_HASH = "0" * 64


# ── Schema ─────────────────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_SEP_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sep_stix_chain (
            chain_id      TEXT PRIMARY KEY,
            community_id  TEXT NOT NULL,      -- the source community of the transfer
            transfer_id   TEXT NOT NULL UNIQUE,
            bundle_json   TEXT NOT NULL,
            bundle_hash   TEXT NOT NULL,      -- SHA-256 of canonical bundle_json
            prev_hash     TEXT NOT NULL,      -- hash of preceding bundle (chain link)
            seq           INTEGER NOT NULL,   -- sequence number within community
            created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS stix_community_seq_idx
            ON sep_stix_chain(community_id, seq)
    """)
    conn.commit()
    return conn


# ── STIX 2.1 object builders ──────────────────────────────────────────────────

def _stix_id(stix_type: str) -> str:
    return f"{stix_type}--{uuid.uuid4()}"


def _build_identity(community_id: str, display_name: str = "") -> dict[str, Any]:
    return {
        "type":             "identity",
        "spec_version":     _STIX_SPEC_VERSION,
        "id":               f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, community_id)}",
        "name":             display_name or f"community:{community_id[:8]}",
        "identity_class":   "organization",
        "description":      f"Shadow Warden AI community id={community_id}",
        "created":          datetime.now(UTC).isoformat(),
        "modified":         datetime.now(UTC).isoformat(),
    }


def _build_relationship(
    source_ref:    str,
    target_ref:    str,
    transfer_id:   str,
    entity_ueciid: str,
    purpose:       str,
    ctp_signature: str,
    pqc_signature: str,
    risk_score:    float,
    data_class:    str,
) -> dict[str, Any]:
    ts = datetime.now(UTC).isoformat()
    return {
        "type":               "relationship",
        "spec_version":       _STIX_SPEC_VERSION,
        "id":                 _stix_id("relationship"),
        "relationship_type":  "transferred-to",
        "source_ref":         source_ref,
        "target_ref":         target_ref,
        "description":        f"SEP document transfer: {entity_ueciid} (purpose: {purpose})",
        "created":            ts,
        "modified":           ts,
        "extensions": {
            "x-sep-proof": {
                "transfer_id":     transfer_id,
                "entity_ueciid":   entity_ueciid,
                "purpose":         purpose,
                "ctp_hmac":        ctp_signature,
                "pqc_signature":   pqc_signature,   # ML-DSA-65 hybrid (empty if no PQC)
                "risk_score":      round(risk_score, 4),
                "data_class":      data_class,
            }
        },
    }


def _build_note(
    content:         str,
    object_refs:     list[str],
) -> dict[str, Any]:
    ts = datetime.now(UTC).isoformat()
    return {
        "type":         "note",
        "spec_version": _STIX_SPEC_VERSION,
        "id":           _stix_id("note"),
        "content":      content,
        "object_refs":  object_refs,
        "created":      ts,
        "modified":     ts,
    }


def _build_bundle(
    stix_objects: list[dict],
    prev_hash:    str,
    community_id: str,
    seq:          int,
) -> dict[str, Any]:
    return {
        "type":         "bundle",
        "id":           _stix_id("bundle"),
        "spec_version": _STIX_SPEC_VERSION,
        "objects":      stix_objects,
        "extensions": {
            "x-chain": {
                "community_id": community_id,
                "seq":          seq,
                "prev_hash":    prev_hash,
            }
        },
    }


def _canonical_json(obj: dict) -> str:
    """Deterministic JSON (sorted keys, no whitespace) for hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _hash_bundle(bundle: dict) -> str:
    return hashlib.sha256(_canonical_json(bundle).encode()).hexdigest()


# ── Chain management ───────────────────────────────────────────────────────────

def _last_hash(community_id: str, conn: sqlite3.Connection) -> tuple[str, int]:
    """Return (prev_hash, next_seq) for the chain tip of *community_id*."""
    row = conn.execute(
        "SELECT bundle_hash, seq FROM sep_stix_chain "
        "WHERE community_id=? ORDER BY seq DESC LIMIT 1",
        (community_id,),
    ).fetchone()
    if row:
        return row["bundle_hash"], row["seq"] + 1
    return _CHAIN_GENESIS_HASH, 0


@dataclass
class ChainEntry:
    chain_id:    str
    community_id: str
    transfer_id: str
    bundle:      dict      # parsed STIX bundle
    bundle_hash: str
    prev_hash:   str
    seq:         int
    created_at:  str


def append_transfer(
    transfer_id:          str,
    source_community_id:  str,
    target_community_id:  str,
    entity_ueciid:        str,
    initiator_mid:        str,
    purpose:              str,
    ctp_hmac_signature:   str,
    pqc_signature:        str   = "",
    risk_score:           float = 0.0,
    data_class:           str   = "GENERAL",
    source_display_name:  str   = "",
    target_display_name:  str   = "",
) -> ChainEntry:
    """
    Append a transfer event to the STIX audit chain.

    Builds a STIX 2.1 bundle (identities + relationship + note),
    chains it to the previous entry via SHA-256 prev_hash, and stores
    in sep_stix_chain.

    Parameters
    ----------
    transfer_id         : UUID from the TransferRecord.
    source_community_id : Source community GUID.
    target_community_id : Target community GUID.
    entity_ueciid       : UECIID of the transferred document.
    initiator_mid       : Member ID who initiated the transfer.
    purpose             : Transfer purpose string.
    ctp_hmac_signature  : HMAC-SHA256 hex from CausalTransferProof.signature.
    pqc_signature       : ML-DSA-65 hybrid signature (empty if PQC not enabled).
    risk_score          : P(HIGH_RISK) from TransferGuard (0–1).
    data_class          : Entity data classification.
    """
    # Build STIX objects
    src_identity = _build_identity(source_community_id, source_display_name)
    tgt_identity = _build_identity(target_community_id, target_display_name)
    relationship = _build_relationship(
        source_ref    = src_identity["id"],
        target_ref    = tgt_identity["id"],
        transfer_id   = transfer_id,
        entity_ueciid = entity_ueciid,
        purpose       = purpose,
        ctp_signature = ctp_hmac_signature,
        pqc_signature = pqc_signature,
        risk_score    = risk_score,
        data_class    = data_class,
    )
    # CTP canonical proof as a Note for reconstructability
    canonical = (
        f"{transfer_id}|{source_community_id}|{target_community_id}|"
        f"{entity_ueciid}|{initiator_mid}|{purpose}"
    )
    note = _build_note(
        content     = f"CTP canonical: {canonical}",
        object_refs = [relationship["id"]],
    )

    with _db_lock:
        conn = _get_conn()
        prev_hash, seq = _last_hash(source_community_id, conn)

        bundle    = _build_bundle(
            stix_objects = [src_identity, tgt_identity, relationship, note],
            prev_hash    = prev_hash,
            community_id = source_community_id,
            seq          = seq,
        )
        canonical_bundle = _canonical_json(bundle)
        bundle_hash      = hashlib.sha256(canonical_bundle.encode()).hexdigest()
        chain_id         = str(uuid.uuid4())
        now              = datetime.now(UTC).isoformat()

        conn.execute("""
            INSERT INTO sep_stix_chain
              (chain_id, community_id, transfer_id, bundle_json,
               bundle_hash, prev_hash, seq, created_at)
            VALUES (?,?,?,?,?,?,?,?)
        """, (
            chain_id, source_community_id, transfer_id, canonical_bundle,
            bundle_hash, prev_hash, seq, now,
        ))
        conn.commit()

    log.info(
        "stix_audit: appended chain_id=%s community=%s seq=%d hash=%.8s",
        chain_id[:8], source_community_id[:8], seq, bundle_hash,
    )
    return ChainEntry(
        chain_id    = chain_id,
        community_id = source_community_id,
        transfer_id = transfer_id,
        bundle      = bundle,
        bundle_hash = bundle_hash,
        prev_hash   = prev_hash,
        seq         = seq,
        created_at  = now,
    )


def get_chain(community_id: str, limit: int = 100, offset: int = 0) -> list[ChainEntry]:
    """Return ordered audit chain entries for *community_id* (oldest first)."""
    with _db_lock:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT * FROM sep_stix_chain WHERE community_id=? "
            "ORDER BY seq ASC LIMIT ? OFFSET ?",
            (community_id, limit, offset),
        ).fetchall()
    result = []
    for row in rows:
        d = dict(row)
        d["bundle"] = json.loads(d["bundle_json"])
        del d["bundle_json"]
        result.append(ChainEntry(**d))
    return result


def verify_chain(community_id: str) -> dict[str, Any]:
    """
    Re-hash every bundle in the chain and verify the prev_hash links.

    Returns:
        {
          "valid":   bool,
          "entries": int,
          "broken_at_seq": int | None,   # first seq where chain breaks
          "reason":  str,
        }
    """
    entries = get_chain(community_id, limit=10_000)
    if not entries:
        return {"valid": True, "entries": 0, "broken_at_seq": None, "reason": "empty chain"}

    expected_prev = _CHAIN_GENESIS_HASH
    for entry in entries:
        if entry.prev_hash != expected_prev:
            return {
                "valid":         False,
                "entries":       len(entries),
                "broken_at_seq": entry.seq,
                "reason": (
                    f"Chain broken at seq={entry.seq}: "
                    f"stored prev_hash={entry.prev_hash[:12]}… "
                    f"expected={expected_prev[:12]}…"
                ),
            }
        # Verify stored hash matches re-computed hash of canonical bundle JSON
        recomputed = hashlib.sha256(
            _canonical_json(entry.bundle).encode()
        ).hexdigest()
        if recomputed != entry.bundle_hash:
            return {
                "valid":         False,
                "entries":       len(entries),
                "broken_at_seq": entry.seq,
                "reason": (
                    f"Bundle hash mismatch at seq={entry.seq}: "
                    f"stored={entry.bundle_hash[:12]}… recomputed={recomputed[:12]}…"
                ),
            }
        expected_prev = entry.bundle_hash

    return {
        "valid":         True,
        "entries":       len(entries),
        "broken_at_seq": None,
        "reason":        f"All {len(entries)} entries verified.",
    }


def export_chain_jsonl(community_id: str) -> str:
    """Export the full audit chain as JSONL (one STIX bundle per line)."""
    entries = get_chain(community_id, limit=100_000)
    return "\n".join(
        _canonical_json(e.bundle) for e in entries
    )
