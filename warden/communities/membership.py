"""
Community Membership — per-community member management.
Member ID: SHA-256(tenant_id + community_id + timestamp)[:32]
Each member gets an Ed25519 public key for action non-repudiation.
"""
from __future__ import annotations

import base64
import hashlib
import os
import threading
import time
from dataclasses import dataclass

COMM_DB_PATH = os.getenv("COMM_DB_PATH", "/tmp/warden_communities.db")
_lock = threading.RLock()

ROLES = ("owner", "admin", "member", "observer")

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )
    _CRYPTO_OK = True
except ImportError:
    _CRYPTO_OK = False


@dataclass
class Member:
    member_id: str
    tenant_id: str
    community_id: str
    role: str
    joined_at: str
    public_key: str     # Ed25519 raw bytes, base64-encoded
    display_name: str
    status: str = "active"


def _db():
    import sqlite3
    c = sqlite3.connect(COMM_DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.executescript("""
        CREATE TABLE IF NOT EXISTS community_members (
            member_id    TEXT PRIMARY KEY,
            tenant_id    TEXT NOT NULL,
            community_id TEXT NOT NULL,
            role         TEXT NOT NULL DEFAULT 'member',
            joined_at    TEXT NOT NULL,
            public_key   TEXT NOT NULL DEFAULT '',
            display_name TEXT NOT NULL DEFAULT '',
            status       TEXT NOT NULL DEFAULT 'active'
        );
        CREATE INDEX IF NOT EXISTS idx_mb_community ON community_members(community_id, status);
        CREATE INDEX IF NOT EXISTS idx_mb_tenant    ON community_members(tenant_id, status);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_mb_unique ON community_members(tenant_id, community_id);
    """)
    c.commit()
    return c


def _generate_keypair() -> tuple[str, str]:
    if _CRYPTO_OK:
        priv = Ed25519PrivateKey.generate()
        priv_b = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pub_b = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(priv_b).decode(), base64.b64encode(pub_b).decode()
    import secrets
    return secrets.token_urlsafe(32), secrets.token_urlsafe(32)


def generate_member_id(tenant_id: str, community_id: str) -> str:
    raw = f"{tenant_id}:{community_id}:{time.time()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def add_member(
    community_id: str,
    tenant_id: str,
    role: str = "member",
    display_name: str = "",
) -> Member:
    _, pub_key = _generate_keypair()
    mid = generate_member_id(tenant_id, community_id)
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    dn = display_name or tenant_id[:16]
    with _lock:
        db = _db()
        db.execute(
            "INSERT OR IGNORE INTO community_members VALUES (?,?,?,?,?,?,?,?)",
            (mid, tenant_id, community_id, role, ts, pub_key, dn, "active"),
        )
        db.commit()
    try:
        from warden.metrics import COMMUNITY_MEMBERS_TOTAL  # noqa: PLC0415
        COMMUNITY_MEMBERS_TOTAL.inc()
    except Exception:
        pass
    return get_member(community_id, tenant_id)  # type: ignore[return-value]


def get_member(community_id: str, tenant_id: str) -> Member | None:
    row = _db().execute(
        "SELECT * FROM community_members WHERE community_id=? AND tenant_id=?",
        (community_id, tenant_id),
    ).fetchone()
    return Member(**dict(row)) if row else None


def get_member_by_id(member_id: str) -> Member | None:
    row = _db().execute(
        "SELECT * FROM community_members WHERE member_id=?", (member_id,)
    ).fetchone()
    return Member(**dict(row)) if row else None


def list_members(community_id: str, status: str = "active") -> list[Member]:
    rows = _db().execute(
        "SELECT * FROM community_members WHERE community_id=? AND status=? ORDER BY joined_at",
        (community_id, status),
    ).fetchall()
    return [Member(**dict(r)) for r in rows]


def remove_member(community_id: str, member_id: str) -> bool:
    with _lock:
        db = _db()
        cur = db.execute(
            "UPDATE community_members SET status='removed' "
            "WHERE community_id=? AND member_id=?",
            (community_id, member_id),
        )
        db.commit()
        return cur.rowcount > 0


def update_member_role(community_id: str, member_id: str, role: str) -> bool:
    if role not in ROLES:
        return False
    with _lock:
        db = _db()
        cur = db.execute(
            "UPDATE community_members SET role=? WHERE community_id=? AND member_id=?",
            (role, community_id, member_id),
        )
        db.commit()
        return cur.rowcount > 0


def get_member_communities(tenant_id: str) -> list[dict]:
    """Return all communities a tenant belongs to (with community metadata)."""
    db = _db()
    try:
        rows = db.execute(
            """SELECT cm.*, c.name, c.description, c.status AS comm_status, c.visibility
               FROM community_members cm
               JOIN communities c ON cm.community_id = c.community_id
               WHERE cm.tenant_id=? AND cm.status='active'
               ORDER BY cm.joined_at DESC""",
            (tenant_id,),
        ).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        # communities table may not exist yet
        rows = db.execute(
            "SELECT * FROM community_members WHERE tenant_id=? AND status='active'",
            (tenant_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_member_count(community_id: str) -> int:
    return _db().execute(
        "SELECT COUNT(*) FROM community_members WHERE community_id=? AND status='active'",
        (community_id,),
    ).fetchone()[0]
