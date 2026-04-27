"""
warden/communities/charter.py
──────────────────────────────
Community Charter — Versioned Governance Framework.

A Charter codifies the operating rules of a community: transparency
requirements, data minimisation commitments, accountability assignments,
and sustainability targets.  It is a living document: each amendment
creates a new version and invalidates the previous acceptance signatures
of all members, requiring re-acceptance.

DB tables (appended to community registry SQLite)
─────────────────────────────────────────────────
  community_charters         — one row per version per community
  community_charter_accepts  — member acceptance signatures

Enforcement hooks
─────────────────
  validate_charter_compliance(community_id, action) is called by the
  transfer pipeline to ensure the action is permitted by the active charter.
  Returns (allowed: bool, reason: str).
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

log = logging.getLogger("warden.communities.charter")

_REGISTRY_DB_PATH = os.getenv(
    "COMMUNITY_REGISTRY_PATH",
    "/tmp/warden_community_registry.db",
)
_db_lock = threading.RLock()


# ── Schema ────────────────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_REGISTRY_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS community_charters (
            charter_id          TEXT PRIMARY KEY,
            community_id        TEXT NOT NULL,
            version             INTEGER NOT NULL DEFAULT 1,
            title               TEXT NOT NULL,
            transparency        TEXT NOT NULL DEFAULT 'REQUIRED',
            data_minimization   TEXT NOT NULL DEFAULT 'STRICT',
            accountability      TEXT NOT NULL,
            sustainability      TEXT NOT NULL DEFAULT 'STANDARD',
            allowed_data_classes TEXT NOT NULL DEFAULT '["GENERAL","PII","FINANCIAL"]',
            prohibited_actions  TEXT NOT NULL DEFAULT '[]',
            auto_block_threshold REAL NOT NULL DEFAULT 0.70,
            content_hash        TEXT NOT NULL,
            status              TEXT NOT NULL DEFAULT 'DRAFT',
            created_by          TEXT NOT NULL,
            created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            published_at        TEXT,
            superseded_at       TEXT,
            UNIQUE(community_id, version)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS community_charter_accepts (
            accept_id       TEXT PRIMARY KEY,
            charter_id      TEXT NOT NULL,
            community_id    TEXT NOT NULL,
            member_id       TEXT NOT NULL,
            accepted_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            ip_fingerprint  TEXT,
            UNIQUE(charter_id, member_id)
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_charters_community
            ON community_charters(community_id, status)
    """)
    conn.commit()
    return conn


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class CharterRecord:
    charter_id: str
    community_id: str
    version: int
    title: str
    transparency: str           # REQUIRED | ENCOURAGED | OPTIONAL
    data_minimization: str      # STRICT | STANDARD | RELAXED
    accountability: str         # member_id of designated DPO / owner
    sustainability: str         # STANDARD | ADVANCED | CERTIFIED
    allowed_data_classes: list[str]
    prohibited_actions: list[str]
    auto_block_threshold: float
    content_hash: str
    status: str                 # DRAFT | ACTIVE | SUPERSEDED | REVOKED
    created_by: str
    created_at: str
    published_at: str | None
    superseded_at: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "charter_id":           self.charter_id,
            "community_id":         self.community_id,
            "version":              self.version,
            "title":                self.title,
            "transparency":         self.transparency,
            "data_minimization":    self.data_minimization,
            "accountability":       self.accountability,
            "sustainability":       self.sustainability,
            "allowed_data_classes": self.allowed_data_classes,
            "prohibited_actions":   self.prohibited_actions,
            "auto_block_threshold": self.auto_block_threshold,
            "status":               self.status,
            "created_by":           self.created_by,
            "created_at":           self.created_at,
            "published_at":         self.published_at,
            "superseded_at":        self.superseded_at,
            "content_hash":         self.content_hash,
        }


def _row_to_charter(row: sqlite3.Row) -> CharterRecord:
    return CharterRecord(
        charter_id=row["charter_id"],
        community_id=row["community_id"],
        version=row["version"],
        title=row["title"],
        transparency=row["transparency"],
        data_minimization=row["data_minimization"],
        accountability=row["accountability"],
        sustainability=row["sustainability"],
        allowed_data_classes=json.loads(row["allowed_data_classes"]),
        prohibited_actions=json.loads(row["prohibited_actions"]),
        auto_block_threshold=row["auto_block_threshold"],
        content_hash=row["content_hash"],
        status=row["status"],
        created_by=row["created_by"],
        created_at=row["created_at"],
        published_at=row["published_at"],
        superseded_at=row["superseded_at"],
    )


def _compute_hash(community_id: str, version: int, title: str, rules: dict) -> str:
    canonical = json.dumps(
        {"community_id": community_id, "version": version, "title": title, **rules},
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


# ── CRUD ──────────────────────────────────────────────────────────────────────

def create_charter(
    community_id: str,
    title: str,
    created_by: str,
    *,
    transparency: str = "REQUIRED",
    data_minimization: str = "STRICT",
    accountability: str = "",
    sustainability: str = "STANDARD",
    allowed_data_classes: list[str] | None = None,
    prohibited_actions: list[str] | None = None,
    auto_block_threshold: float = 0.70,
) -> CharterRecord:
    """Create a new DRAFT charter (version auto-incremented)."""
    valid_trans = {"REQUIRED", "ENCOURAGED", "OPTIONAL"}
    valid_dm    = {"STRICT", "STANDARD", "RELAXED"}
    valid_sus   = {"STANDARD", "ADVANCED", "CERTIFIED"}

    if transparency not in valid_trans:
        raise ValueError(f"transparency must be one of {valid_trans}")
    if data_minimization not in valid_dm:
        raise ValueError(f"data_minimization must be one of {valid_dm}")
    if sustainability not in valid_sus:
        raise ValueError(f"sustainability must be one of {valid_sus}")
    if not 0.0 <= auto_block_threshold <= 1.0:
        raise ValueError("auto_block_threshold must be in [0.0, 1.0]")

    allowed = allowed_data_classes or ["GENERAL", "PII", "FINANCIAL"]
    prohibited = prohibited_actions or []
    charter_id = f"CHR-{uuid.uuid4().hex[:12].upper()}"

    rules = {
        "transparency": transparency,
        "data_minimization": data_minimization,
        "accountability": accountability,
        "sustainability": sustainability,
        "allowed_data_classes": allowed,
        "prohibited_actions": prohibited,
        "auto_block_threshold": auto_block_threshold,
    }

    with _db_lock:
        conn = _get_conn()
        row = conn.execute(
            "SELECT COALESCE(MAX(version),0) as v FROM community_charters WHERE community_id=?",
            (community_id,),
        ).fetchone()
        version = (row["v"] or 0) + 1
        content_hash = _compute_hash(community_id, version, title, rules)
        conn.execute(
            """
            INSERT INTO community_charters
              (charter_id, community_id, version, title, transparency,
               data_minimization, accountability, sustainability,
               allowed_data_classes, prohibited_actions,
               auto_block_threshold, content_hash, status, created_by)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'DRAFT',?)
            """,
            (
                charter_id, community_id, version, title, transparency,
                data_minimization, accountability, sustainability,
                json.dumps(allowed), json.dumps(prohibited),
                auto_block_threshold, content_hash, created_by,
            ),
        )
        conn.commit()

    log.info("charter created community=%s charter_id=%s version=%d", community_id, charter_id, version)
    return get_charter(charter_id)  # type: ignore[return-value]


def publish_charter(charter_id: str) -> CharterRecord:
    """Activate a DRAFT charter; supersede any previously ACTIVE one."""
    with _db_lock:
        conn = _get_conn()
        row = conn.execute(
            "SELECT * FROM community_charters WHERE charter_id=?", (charter_id,)
        ).fetchone()
        if not row:
            raise KeyError(f"Charter {charter_id!r} not found")
        if row["status"] != "DRAFT":
            raise ValueError(f"Charter {charter_id!r} is {row['status']}, not DRAFT")

        community_id = row["community_id"]
        now = datetime.now(UTC).isoformat()

        # Supersede any existing ACTIVE charter
        conn.execute(
            """UPDATE community_charters SET status='SUPERSEDED', superseded_at=?
               WHERE community_id=? AND status='ACTIVE'""",
            (now, community_id),
        )
        conn.execute(
            "UPDATE community_charters SET status='ACTIVE', published_at=? WHERE charter_id=?",
            (now, charter_id),
        )
        conn.commit()

    log.info("charter published charter_id=%s community=%s", charter_id, community_id)
    return get_charter(charter_id)  # type: ignore[return-value]


def get_charter(charter_id: str) -> CharterRecord | None:
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM community_charters WHERE charter_id=?", (charter_id,)
    ).fetchone()
    return _row_to_charter(row) if row else None


def get_active_charter(community_id: str) -> CharterRecord | None:
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM community_charters WHERE community_id=? AND status='ACTIVE' LIMIT 1",
        (community_id,),
    ).fetchone()
    return _row_to_charter(row) if row else None


def list_charters(community_id: str) -> list[CharterRecord]:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM community_charters WHERE community_id=? ORDER BY version DESC",
        (community_id,),
    ).fetchall()
    return [_row_to_charter(r) for r in rows]


# ── Member acceptance ─────────────────────────────────────────────────────────

def accept_charter(
    charter_id: str,
    member_id: str,
    *,
    ip_fingerprint: str = "",
) -> dict[str, str]:
    """Record a member's explicit acceptance of the charter."""
    conn = _get_conn()
    row = conn.execute(
        "SELECT community_id, status FROM community_charters WHERE charter_id=?",
        (charter_id,),
    ).fetchone()
    if not row:
        raise KeyError(f"Charter {charter_id!r} not found")
    if row["status"] != "ACTIVE":
        raise ValueError(f"Cannot accept charter in status {row['status']!r}")

    accept_id = f"ACC-{uuid.uuid4().hex[:12].upper()}"
    with _db_lock:
        conn.execute(
            """INSERT OR REPLACE INTO community_charter_accepts
               (accept_id, charter_id, community_id, member_id, ip_fingerprint)
               VALUES (?,?,?,?,?)""",
            (accept_id, charter_id, row["community_id"], member_id, ip_fingerprint),
        )
        conn.commit()

    log.info("charter accepted charter_id=%s member_id=%s", charter_id, member_id)
    return {"accept_id": accept_id, "charter_id": charter_id, "member_id": member_id}


def get_member_acceptance(charter_id: str, member_id: str) -> dict | None:
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM community_charter_accepts WHERE charter_id=? AND member_id=?",
        (charter_id, member_id),
    ).fetchone()
    return dict(row) if row else None


def list_pending_acceptances(community_id: str) -> list[dict]:
    """Members who have not yet accepted the currently ACTIVE charter."""
    conn = _get_conn()
    charter_row = conn.execute(
        "SELECT charter_id FROM community_charters WHERE community_id=? AND status='ACTIVE' LIMIT 1",
        (community_id,),
    ).fetchone()
    if not charter_row:
        return []
    charter_id = charter_row["charter_id"]

    rows = conn.execute(
        """
        SELECT m.member_id, m.display_name
        FROM community_members m
        WHERE m.community_id=? AND m.status='ACTIVE'
          AND m.member_id NOT IN (
              SELECT member_id FROM community_charter_accepts WHERE charter_id=?
          )
        """,
        (community_id, charter_id),
    ).fetchall()
    return [dict(r) for r in rows]


# ── Compliance validation ─────────────────────────────────────────────────────

def validate_charter_compliance(
    community_id: str,
    action: str,
    data_class: str = "GENERAL",
) -> tuple[bool, str]:
    """
    Returns (allowed, reason).  Called by the transfer pipeline before
    any cross-community document exchange.
    """
    charter = get_active_charter(community_id)
    if not charter:
        return True, "no_charter_active"

    if action in charter.prohibited_actions:
        return False, f"action '{action}' prohibited by charter v{charter.version}"

    if data_class not in charter.allowed_data_classes:
        return False, f"data_class '{data_class}' not in charter allowlist"

    return True, "charter_compliant"
