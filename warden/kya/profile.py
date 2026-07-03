"""
warden/kya/profile.py
─────────────────────
Agent profile store in Turso `marketplace` DB.

Tables
──────
  kya_agent_profiles  — one row per DID; trust_score 0.0–1.0
  kya_trust_events    — audit trail of trust adjustments

Turso routing: TURSO_URL_MARKETPLACE + TURSO_TOKEN_MARKETPLACE → remote;
               else local SQLite at MARKETPLACE_DB_PATH.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from collections.abc import Generator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime

log = logging.getLogger("warden.kya.profile")

_DB_PATH = os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")
_db_lock = threading.RLock()

_DDL = """
    CREATE TABLE IF NOT EXISTS kya_agent_profiles (
        did             TEXT PRIMARY KEY,
        owner_tenant_id TEXT NOT NULL DEFAULT '',
        pubkey_b64      TEXT NOT NULL DEFAULT '',
        trust_score     REAL NOT NULL DEFAULT 0.5,
        reputation_json TEXT NOT NULL DEFAULT '{}',
        kya_status      TEXT NOT NULL DEFAULT 'PENDING',
        created_at      TEXT NOT NULL,
        updated_at      TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_kya_owner
        ON kya_agent_profiles(owner_tenant_id);
    CREATE INDEX IF NOT EXISTS idx_kya_status
        ON kya_agent_profiles(kya_status);
    CREATE TABLE IF NOT EXISTS kya_trust_events (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        did         TEXT NOT NULL,
        delta       REAL NOT NULL,
        reason      TEXT NOT NULL DEFAULT '',
        new_score   REAL NOT NULL,
        ts          TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_kte_did ON kya_trust_events(did, ts);
"""


@dataclass
class AgentProfile:
    did:             str
    owner_tenant_id: str
    pubkey_b64:      str
    trust_score:     float
    kya_status:      str
    reputation:      dict = field(default_factory=dict)
    created_at:      str = ""
    updated_at:      str = ""

    def to_dict(self) -> dict:
        return {
            "did":             self.did,
            "owner_tenant_id": self.owner_tenant_id,
            "pubkey_b64":      self.pubkey_b64,
            "trust_score":     self.trust_score,
            "kya_status":      self.kya_status,
            "reputation":      self.reputation,
            "created_at":      self.created_at,
            "updated_at":      self.updated_at,
        }


# ── DB connection ──────────────────────────────────────────────────────────────

@contextmanager
def _conn(db_path: str | None = None) -> Generator[sqlite3.Connection, None, None]:
    effective = db_path or _DB_PATH
    use_local  = effective != _DB_PATH

    if not use_local:
        try:
            from warden.db.turso import get_connection, is_turso_enabled  # noqa: PLC0415
            if is_turso_enabled("marketplace"):
                with get_connection("marketplace", fallback_path=_DB_PATH) as con:  # type: ignore[assignment]
                    with suppress(Exception):
                        con.executescript(_DDL)
                    yield con  # type: ignore[misc]
                return
        except ImportError:
            pass

    con = sqlite3.connect(effective, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(_DDL)
    try:
        yield con
        con.commit()
    finally:
        con.close()


# ── Public API ─────────────────────────────────────────────────────────────────

def register_did(
    did: str,
    pubkey_b64: str,
    owner_tenant_id: str = "",
    db_path: str | None = None,
) -> AgentProfile:
    """Register or upsert a DID in the profile store."""
    now = datetime.now(UTC).isoformat()
    with _db_lock, _conn(db_path) as con:
        con.execute(
            """
            INSERT INTO kya_agent_profiles
              (did, owner_tenant_id, pubkey_b64, trust_score, reputation_json,
               kya_status, created_at, updated_at)
            VALUES (?,?,?,0.5,'{}','PENDING',?,?)
            ON CONFLICT(did) DO UPDATE SET
              owner_tenant_id = excluded.owner_tenant_id,
              pubkey_b64      = excluded.pubkey_b64,
              updated_at      = excluded.updated_at
            """,
            (did, owner_tenant_id, pubkey_b64, now, now),
        )
    return AgentProfile(
        did=did, owner_tenant_id=owner_tenant_id, pubkey_b64=pubkey_b64,
        trust_score=0.5, kya_status="PENDING", created_at=now, updated_at=now,
    )


def get_profile(did: str, db_path: str | None = None) -> AgentProfile | None:
    """Fetch agent profile by DID. Returns None if not found."""
    with _db_lock, _conn(db_path) as con:
        row = con.execute(
            "SELECT * FROM kya_agent_profiles WHERE did = ?", (did,)
        ).fetchone()
    if row is None:
        return None
    return AgentProfile(
        did=row["did"],
        owner_tenant_id=row["owner_tenant_id"],
        pubkey_b64=row["pubkey_b64"],
        trust_score=float(row["trust_score"]),
        kya_status=row["kya_status"],
        reputation=json.loads(row["reputation_json"] or "{}"),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def get_trust_score(did: str, db_path: str | None = None) -> float:
    """Return agent trust score (0.0–1.0). Defaults to 0.5 for unknown agents."""
    profile = get_profile(did, db_path)
    return profile.trust_score if profile else 0.5


def update_trust(
    did: str,
    delta: float,
    reason: str = "",
    db_path: str | None = None,
) -> float:
    """Adjust trust_score by *delta* (clamped to 0.0–1.0). Returns new score."""
    now = datetime.now(UTC).isoformat()
    with _db_lock, _conn(db_path) as con:
        row = con.execute(
            "SELECT trust_score FROM kya_agent_profiles WHERE did = ?", (did,)
        ).fetchone()
        if row is None:
            return 0.5
        new_score = max(0.0, min(1.0, float(row["trust_score"]) + delta))
        con.execute(
            "UPDATE kya_agent_profiles SET trust_score=?, updated_at=? WHERE did=?",
            (new_score, now, did),
        )
        con.execute(
            "INSERT INTO kya_trust_events (did,delta,reason,new_score,ts) VALUES (?,?,?,?,?)",
            (did, delta, reason, new_score, now),
        )
    log.info("kya: trust update did=%s delta=%.2f new=%.2f reason=%s", did, delta, new_score, reason)
    return new_score


def promote_status(did: str, status: str, db_path: str | None = None) -> None:
    """Set KYA status: PENDING → VERIFIED | FLAGGED | REVOKED."""
    now = datetime.now(UTC).isoformat()
    with _db_lock, _conn(db_path) as con:
        con.execute(
            "UPDATE kya_agent_profiles SET kya_status=?, updated_at=? WHERE did=?",
            (status, now, did),
        )


def list_profiles(
    owner_tenant_id: str | None = None,
    min_trust: float = 0.0,
    limit: int = 100,
    db_path: str | None = None,
) -> list[AgentProfile]:
    """List profiles, optionally filtered by owner and minimum trust score."""
    with _db_lock, _conn(db_path) as con:
        if owner_tenant_id:
            rows = con.execute(
                "SELECT * FROM kya_agent_profiles WHERE owner_tenant_id=? AND trust_score>=? LIMIT ?",
                (owner_tenant_id, min_trust, limit),
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT * FROM kya_agent_profiles WHERE trust_score>=? LIMIT ?",
                (min_trust, limit),
            ).fetchall()
    return [
        AgentProfile(
            did=r["did"], owner_tenant_id=r["owner_tenant_id"], pubkey_b64=r["pubkey_b64"],
            trust_score=float(r["trust_score"]), kya_status=r["kya_status"],
            reputation=json.loads(r["reputation_json"] or "{}"),
            created_at=r["created_at"], updated_at=r["updated_at"],
        )
        for r in rows
    ]
