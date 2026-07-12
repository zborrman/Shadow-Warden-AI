"""
Community Factory — create and manage communities.
32-char hex ID: SHA-256(creator_id + timestamp + uuid4)[:32]
Storage: SQLite (COMM_DB_PATH env var).
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from warden.config import data_path

COMM_DB_PATH = data_path("warden_communities.db", "COMM_DB_PATH")
_lock = threading.RLock()


@dataclass
class Community:
    community_id: str
    name: str
    description: str
    creator_tenant_id: str
    created_at: str
    status: str = "active"          # active / suspended
    visibility: str = "private"     # private / public
    join_policy: str = "invite"     # invite / open / approval
    settings: dict = field(default_factory=dict)
    keypair_generated: bool = False
    audit_enabled: bool = False


def _db():
    import sqlite3
    c = sqlite3.connect(COMM_DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.executescript("""
        CREATE TABLE IF NOT EXISTS communities (
            community_id      TEXT PRIMARY KEY,
            name              TEXT NOT NULL,
            description       TEXT NOT NULL DEFAULT '',
            creator_tenant_id TEXT NOT NULL,
            created_at        TEXT NOT NULL,
            status            TEXT NOT NULL DEFAULT 'active',
            visibility        TEXT NOT NULL DEFAULT 'private',
            join_policy       TEXT NOT NULL DEFAULT 'invite',
            settings          TEXT NOT NULL DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS idx_cm_creator ON communities(creator_tenant_id);
        CREATE INDEX IF NOT EXISTS idx_cm_vis    ON communities(visibility, status);
    """)
    c.commit()
    return c


def _row_to_community(row: sqlite3.Row) -> Community:
    d = dict(row)
    settings = json.loads(d["settings"] or "{}")
    d["settings"] = settings
    d["keypair_generated"] = settings.get("keypair_generated", False)
    d["audit_enabled"] = settings.get("audit_enabled", False)
    return Community(**d)


def generate_community_id(creator_tenant_id: str) -> str:
    raw = f"{creator_tenant_id}:{time.time()}:{uuid.uuid4().hex}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def create_community(
    name: str,
    description: str,
    creator_tenant_id: str,
    visibility: str = "private",
    join_policy: str = "invite",
    settings: dict | None = None,
) -> Community:
    cid = generate_community_id(creator_tenant_id)
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    kp_generated = False
    try:
        from warden.communities.keypair import generate_community_keypair
        kp = generate_community_keypair(cid, kid="v1")
        try:
            from warden.communities.key_archive import KeyStatus, store_keypair
            store_keypair(kp, status=KeyStatus.ACTIVE)
        except Exception:
            pass  # PostgreSQL not available; keypair still generated in memory
        kp_generated = True
    except Exception:
        pass

    final_settings: dict = dict(settings or {})
    final_settings["keypair_generated"] = kp_generated
    final_settings["audit_enabled"] = True  # STIX audit chain enabled for all new communities

    c = Community(
        community_id=cid,
        name=name,
        description=description,
        creator_tenant_id=creator_tenant_id,
        created_at=ts,
        status="active",
        visibility=visibility,
        join_policy=join_policy,
        settings=final_settings,
        keypair_generated=kp_generated,
        audit_enabled=True,
    )
    with _lock:
        db = _db()
        db.execute(
            "INSERT INTO communities VALUES (?,?,?,?,?,?,?,?,?)",
            (cid, name, description, creator_tenant_id, ts,
             "active", visibility, join_policy, json.dumps(final_settings)),
        )
        db.commit()

    # Auto-provision a default marketplace agent for the community (fail-open)
    import contextlib
    with contextlib.suppress(Exception):
        _setup_marketplace_defaults(cid, creator_tenant_id)

    return c


def _setup_marketplace_defaults(community_id: str, tenant_id: str) -> None:
    """Register a default marketplace agent with buy+sell capabilities and a $1000 budget."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes_raw()
    pub_b64 = __import__("base64").b64encode(pub_bytes).decode()

    from warden.marketplace.agent import register_agent
    register_agent(
        tenant_id=tenant_id,
        community_id=community_id,
        public_key_b64=pub_b64,
        capabilities=["marketplace_sell", "marketplace_buy"],
    )


def get_community(community_id: str) -> Community | None:
    row = _db().execute(
        "SELECT * FROM communities WHERE community_id=?", (community_id,)
    ).fetchone()
    return _row_to_community(row) if row else None


def list_communities(
    creator_tenant_id: str | None = None,
    visibility: str | None = None,
    status: str = "active",
) -> list[Community]:
    sql = "SELECT * FROM communities WHERE status=?"
    params: list[Any] = [status]
    if creator_tenant_id:
        sql += " AND creator_tenant_id=?"
        params.append(creator_tenant_id)
    if visibility:
        sql += " AND visibility=?"
        params.append(visibility)
    sql += " ORDER BY created_at DESC"
    return [_row_to_community(r) for r in _db().execute(sql, params).fetchall()]


def patch_community(
    community_id: str,
    name: str | None = None,
    description: str | None = None,
) -> bool:
    updates: list[str] = []
    params: list = []
    if name is not None:
        updates.append("name=?")
        params.append(name)
    if description is not None:
        updates.append("description=?")
        params.append(description)
    if not updates:
        return False
    params.append(community_id)
    with _lock:
        db = _db()
        cur = db.execute(
            f"UPDATE communities SET {', '.join(updates)} WHERE community_id=?",
            params,
        )
        db.commit()
        return cur.rowcount > 0


def update_community_settings(community_id: str, settings: dict) -> bool:
    with _lock:
        db = _db()
        cur = db.execute(
            "UPDATE communities SET settings=? WHERE community_id=?",
            (json.dumps(settings), community_id),
        )
        db.commit()
        return cur.rowcount > 0


def update_community_status(community_id: str, status: str) -> bool:
    with _lock:
        db = _db()
        cur = db.execute(
            "UPDATE communities SET status=? WHERE community_id=?",
            (status, community_id),
        )
        db.commit()
        return cur.rowcount > 0


def delete_community(community_id: str, requester_tenant_id: str) -> bool:
    c = get_community(community_id)
    if not c or c.creator_tenant_id != requester_tenant_id:
        return False
    with _lock:
        db = _db()
        db.execute("DELETE FROM communities WHERE community_id=?", (community_id,))
        db.commit()
    return True


def get_community_stats() -> dict:
    db = _db()
    total  = db.execute("SELECT COUNT(*) FROM communities").fetchone()[0]
    active = db.execute("SELECT COUNT(*) FROM communities WHERE status='active'").fetchone()[0]
    public = db.execute(
        "SELECT COUNT(*) FROM communities WHERE visibility='public'"
    ).fetchone()[0]
    return {
        "total": total,
        "active": active,
        "public": public,
        "private": total - public,
        "suspended": total - active,
    }
