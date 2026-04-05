"""
warden/communities/registry.py
────────────────────────────────
Community + Member CRUD — SQLite-backed (dev/test) / PostgreSQL (prod).

Responsibilities
────────────────
  • Create a new Community with a fresh keypair (v1).
  • Invite a member → assign Member_ID + clearance level.
  • Query community profile (metadata + active kid).
  • List members with their clearance levels.
  • Downgrade/upgrade member clearance (triggers rotation when CONFIDENTIAL/
    RESTRICTED is lost — Gemini audit recommendation).
  • Remove/deactivate a member.

DB tables (created by create_communities_schema())
───────────────────────────────────────────────────
  warden_communities.communities         — one row per community
  warden_communities.community_members   — one row per membership

Tier enforcement
────────────────
  Communities are gated by tenant tier — see warden/billing/feature_gate.py.
  This module is tier-agnostic; callers must validate tier before invocation.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Optional

from warden.communities.clearance import ClearanceLevel, check_downgrade_requires_rotation
from warden.communities.id_generator import new_community_id, new_entity_id, new_member_id
from warden.communities.key_archive import KeyStatus, store_keypair
from warden.communities.keypair import generate_community_keypair

log = logging.getLogger("warden.communities.registry")

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
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS communities (
            community_id    TEXT PRIMARY KEY,
            tenant_id       TEXT NOT NULL,
            display_name    TEXT NOT NULL DEFAULT '',
            description     TEXT NOT NULL DEFAULT '',
            tier            TEXT NOT NULL DEFAULT 'business',
            active_kid      TEXT NOT NULL DEFAULT 'v1',
            status          TEXT NOT NULL DEFAULT 'ACTIVE',
            created_by      TEXT NOT NULL,
            created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS community_members (
            member_id       TEXT PRIMARY KEY,
            community_id    TEXT NOT NULL REFERENCES communities(community_id),
            tenant_id       TEXT NOT NULL,
            external_id     TEXT NOT NULL,
            display_name    TEXT NOT NULL DEFAULT '',
            clearance       TEXT NOT NULL DEFAULT 'PUBLIC',
            role            TEXT NOT NULL DEFAULT 'MEMBER',
            status          TEXT NOT NULL DEFAULT 'ACTIVE',
            invited_by      TEXT,
            joined_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS cm_community_idx
            ON community_members(community_id)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS cm_external_idx
            ON community_members(community_id, external_id)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS communities_tenant_idx
            ON communities(tenant_id)
    """)
    conn.commit()
    return conn


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class CommunityRecord:
    community_id:  str
    tenant_id:     str
    display_name:  str
    description:   str
    tier:          str
    active_kid:    str
    status:        str
    created_by:    str
    created_at:    str
    updated_at:    str


@dataclass
class MemberRecord:
    member_id:    str
    community_id: str
    tenant_id:    str
    external_id:  str   # caller's own user ID (email, UUID, etc.)
    display_name: str
    clearance:    str   # ClearanceLevel name
    role:         str   # MEMBER | MODERATOR | ADMIN
    status:       str   # ACTIVE | REMOVED
    invited_by:   Optional[str]
    joined_at:    str
    updated_at:   str


def _row_to_community(row) -> CommunityRecord:
    return CommunityRecord(
        community_id = row["community_id"],
        tenant_id    = row["tenant_id"],
        display_name = row["display_name"],
        description  = row["description"],
        tier         = row["tier"],
        active_kid   = row["active_kid"],
        status       = row["status"],
        created_by   = row["created_by"],
        created_at   = row["created_at"],
        updated_at   = row["updated_at"],
    )


def _row_to_member(row) -> MemberRecord:
    return MemberRecord(
        member_id    = row["member_id"],
        community_id = row["community_id"],
        tenant_id    = row["tenant_id"],
        external_id  = row["external_id"],
        display_name = row["display_name"],
        clearance    = row["clearance"],
        role         = row["role"],
        status       = row["status"],
        invited_by   = row["invited_by"],
        joined_at    = row["joined_at"],
        updated_at   = row["updated_at"],
    )


# ── Community CRUD ────────────────────────────────────────────────────────────

def create_community(
    tenant_id:    str,
    display_name: str,
    created_by:   str,
    description:  str = "",
    tier:         str = "business",
) -> CommunityRecord:
    """
    Create a new Community.

    Steps:
      1. Generate a UUIDv7 Community_ID.
      2. Generate an Ed25519 + X25519 keypair (kid=v1).
      3. Store the keypair in key_archive.
      4. Insert the community row.

    Returns the CommunityRecord.
    """
    community_id = new_community_id()
    kp = generate_community_keypair(community_id, kid="v1")
    store_keypair(kp, status=KeyStatus.ACTIVE)

    now = datetime.now(UTC).isoformat()
    with _db_lock:
        conn = _get_conn()
        conn.execute("""
            INSERT INTO communities
              (community_id, tenant_id, display_name, description, tier,
               active_kid, status, created_by, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (
            community_id, tenant_id, display_name, description, tier,
            "v1", "ACTIVE", created_by, now, now,
        ))
        conn.commit()

    log.info(
        "registry: created community=%s tenant=%s tier=%s",
        community_id[:8], tenant_id, tier,
    )
    return CommunityRecord(
        community_id = community_id,
        tenant_id    = tenant_id,
        display_name = display_name,
        description  = description,
        tier         = tier,
        active_kid   = "v1",
        status       = "ACTIVE",
        created_by   = created_by,
        created_at   = now,
        updated_at   = now,
    )


def get_community(community_id: str) -> Optional[CommunityRecord]:
    """Return CommunityRecord or None."""
    with _db_lock:
        conn = _get_conn()
        row = conn.execute(
            "SELECT * FROM communities WHERE community_id=?",
            (community_id,)
        ).fetchone()
    return _row_to_community(row) if row else None


def list_communities(tenant_id: str) -> list[CommunityRecord]:
    """List all communities for a tenant, newest first."""
    with _db_lock:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT * FROM communities WHERE tenant_id=? ORDER BY created_at DESC",
            (tenant_id,)
        ).fetchall()
    return [_row_to_community(r) for r in rows]


def _update_community_kid(community_id: str, new_kid: str) -> None:
    """Internal: update active_kid after successful key rotation."""
    now = datetime.now(UTC).isoformat()
    with _db_lock:
        conn = _get_conn()
        conn.execute(
            "UPDATE communities SET active_kid=?, updated_at=? WHERE community_id=?",
            (new_kid, now, community_id)
        )
        conn.commit()


# ── Member CRUD ───────────────────────────────────────────────────────────────

def invite_member(
    community_id: str,
    tenant_id:    str,
    external_id:  str,
    display_name: str = "",
    clearance:    ClearanceLevel = ClearanceLevel.PUBLIC,
    role:         str = "MEMBER",
    invited_by:   Optional[str] = None,
) -> MemberRecord:
    """
    Invite a member to a community.

    Generates a scoped Member_ID (UUIDv7 namespaced under community_id),
    inserts the membership row, and returns the MemberRecord.

    Raises ValueError if external_id is already a member of this community.
    """
    # Check for existing membership
    with _db_lock:
        conn = _get_conn()
        existing = conn.execute(
            "SELECT member_id FROM community_members "
            "WHERE community_id=? AND external_id=? AND status='ACTIVE'",
            (community_id, external_id)
        ).fetchone()
        if existing:
            raise ValueError(
                f"external_id={external_id!r} is already a member of community {community_id[:8]}…"
            )

        member_id = new_member_id(community_id)
        now = datetime.now(UTC).isoformat()
        conn.execute("""
            INSERT INTO community_members
              (member_id, community_id, tenant_id, external_id, display_name,
               clearance, role, status, invited_by, joined_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (
            member_id, community_id, tenant_id, external_id, display_name,
            clearance.name, role, "ACTIVE", invited_by, now, now,
        ))
        conn.commit()

    log.info(
        "registry: invited member=%s community=%s clearance=%s",
        member_id[:8], community_id[:8], clearance.name,
    )
    return MemberRecord(
        member_id    = member_id,
        community_id = community_id,
        tenant_id    = tenant_id,
        external_id  = external_id,
        display_name = display_name,
        clearance    = clearance.name,
        role         = role,
        status       = "ACTIVE",
        invited_by   = invited_by,
        joined_at    = now,
        updated_at   = now,
    )


def get_member(community_id: str, member_id: str) -> Optional[MemberRecord]:
    """Return MemberRecord or None."""
    with _db_lock:
        conn = _get_conn()
        row = conn.execute(
            "SELECT * FROM community_members WHERE community_id=? AND member_id=?",
            (community_id, member_id)
        ).fetchone()
    return _row_to_member(row) if row else None


def get_member_by_external(community_id: str, external_id: str) -> Optional[MemberRecord]:
    """Look up a membership by the caller's own user ID."""
    with _db_lock:
        conn = _get_conn()
        row = conn.execute(
            "SELECT * FROM community_members "
            "WHERE community_id=? AND external_id=? AND status='ACTIVE'",
            (community_id, external_id)
        ).fetchone()
    return _row_to_member(row) if row else None


def list_members(community_id: str, active_only: bool = True) -> list[MemberRecord]:
    """List all members of a community."""
    with _db_lock:
        conn = _get_conn()
        if active_only:
            rows = conn.execute(
                "SELECT * FROM community_members WHERE community_id=? AND status='ACTIVE' "
                "ORDER BY joined_at DESC",
                (community_id,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM community_members WHERE community_id=? ORDER BY joined_at DESC",
                (community_id,)
            ).fetchall()
    return [_row_to_member(r) for r in rows]


def update_clearance(
    community_id: str,
    member_id:    str,
    new_clearance: ClearanceLevel,
) -> tuple[MemberRecord, bool]:
    """
    Change a member's clearance level.

    Returns (updated_MemberRecord, rotation_required).

    If the member is being DOWNGRADED from CONFIDENTIAL or RESTRICTED,
    rotation_required=True is returned.  The caller must then call
    rotation.initiate_rotation() to prevent the demoted member from
    using cached keys to read future CONFIDENTIAL/RESTRICTED content.
    """
    with _db_lock:
        conn = _get_conn()
        row = conn.execute(
            "SELECT * FROM community_members WHERE community_id=? AND member_id=? AND status='ACTIVE'",
            (community_id, member_id)
        ).fetchone()
        if not row:
            raise ValueError(f"Member {member_id[:8]}… not found in community {community_id[:8]}…")

        old_clearance = ClearanceLevel.from_str(row["clearance"])
        rotation_required = check_downgrade_requires_rotation(old_clearance, new_clearance)

        now = datetime.now(UTC).isoformat()
        conn.execute(
            "UPDATE community_members SET clearance=?, updated_at=? "
            "WHERE community_id=? AND member_id=?",
            (new_clearance.name, now, community_id, member_id)
        )
        conn.commit()

    log.info(
        "registry: clearance update member=%s %s→%s rotation_required=%s",
        member_id[:8], old_clearance.name, new_clearance.name, rotation_required,
    )

    updated = MemberRecord(
        member_id    = row["member_id"],
        community_id = row["community_id"],
        tenant_id    = row["tenant_id"],
        external_id  = row["external_id"],
        display_name = row["display_name"],
        clearance    = new_clearance.name,
        role         = row["role"],
        status       = row["status"],
        invited_by   = row["invited_by"],
        joined_at    = row["joined_at"],
        updated_at   = now,
    )
    return updated, rotation_required


def remove_member(community_id: str, member_id: str) -> bool:
    """
    Deactivate a member (soft delete).

    Returns True if the member was found and deactivated.
    """
    now = datetime.now(UTC).isoformat()
    with _db_lock:
        conn = _get_conn()
        cur = conn.execute(
            "UPDATE community_members SET status='REMOVED', updated_at=? "
            "WHERE community_id=? AND member_id=? AND status='ACTIVE'",
            (now, community_id, member_id)
        )
        conn.commit()

    removed = cur.rowcount > 0
    if removed:
        log.info("registry: removed member=%s community=%s", member_id[:8], community_id[:8])
    return removed
