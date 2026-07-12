"""
Network Community — meta-community federating multiple communities.
Network ID: SHA-256(creator + timestamp + uuid4)[:32].
"""
from __future__ import annotations

import hashlib
import threading
import time
import uuid
from dataclasses import dataclass

from warden.config import data_path

COMM_DB_PATH = data_path("warden_communities.db", "COMM_DB_PATH")
_lock = threading.RLock()


@dataclass
class NetworkCommunity:
    network_id: str
    name: str
    description: str
    creator_tenant_id: str
    namespace: str          # short label: net-{id[:8]}
    created_at: str
    status: str = "active"


def _db():
    import sqlite3
    c = sqlite3.connect(COMM_DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.executescript("""
        CREATE TABLE IF NOT EXISTS community_networks (
            network_id        TEXT PRIMARY KEY,
            name              TEXT NOT NULL,
            description       TEXT NOT NULL DEFAULT '',
            creator_tenant_id TEXT NOT NULL,
            namespace         TEXT NOT NULL UNIQUE,
            created_at        TEXT NOT NULL,
            status            TEXT NOT NULL DEFAULT 'active'
        );
        CREATE TABLE IF NOT EXISTS network_memberships (
            network_id   TEXT NOT NULL,
            community_id TEXT NOT NULL,
            joined_at    TEXT NOT NULL,
            role         TEXT NOT NULL DEFAULT 'member',
            PRIMARY KEY (network_id, community_id)
        );
        CREATE INDEX IF NOT EXISTS idx_nm_network ON network_memberships(network_id);
        CREATE INDEX IF NOT EXISTS idx_nm_community ON network_memberships(community_id);
    """)
    c.commit()
    return c


def create_network(
    name: str, description: str, creator_tenant_id: str
) -> NetworkCommunity:
    nid = hashlib.sha256(
        f"{creator_tenant_id}:{time.time()}:{uuid.uuid4().hex}".encode()
    ).hexdigest()[:32]
    ns = f"net-{nid[:8]}"
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    n = NetworkCommunity(nid, name, description, creator_tenant_id, ns, ts)
    with _lock:
        db = _db()
        db.execute(
            "INSERT INTO community_networks VALUES (?,?,?,?,?,?,?)",
            (nid, name, description, creator_tenant_id, ns, ts, "active"),
        )
        db.commit()
    return n


def get_network(network_id: str) -> NetworkCommunity | None:
    row = _db().execute(
        "SELECT * FROM community_networks WHERE network_id=?", (network_id,)
    ).fetchone()
    return NetworkCommunity(**dict(row)) if row else None


def list_networks(status: str = "active") -> list[NetworkCommunity]:
    rows = _db().execute(
        "SELECT * FROM community_networks WHERE status=? ORDER BY created_at DESC",
        (status,),
    ).fetchall()
    return [NetworkCommunity(**dict(r)) for r in rows]


def join_network(network_id: str, community_id: str, role: str = "member") -> bool:
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    with _lock:
        db = _db()
        db.execute(
            "INSERT OR IGNORE INTO network_memberships VALUES (?,?,?,?)",
            (network_id, community_id, ts, role),
        )
        db.commit()
    return True


def leave_network(network_id: str, community_id: str) -> bool:
    with _lock:
        db = _db()
        cur = db.execute(
            "DELETE FROM network_memberships WHERE network_id=? AND community_id=?",
            (network_id, community_id),
        )
        db.commit()
        return cur.rowcount > 0


def list_network_communities(network_id: str) -> list[dict]:
    db = _db()
    try:
        rows = db.execute(
            """SELECT nm.*, c.name AS community_name, c.visibility, c.status AS community_status
               FROM network_memberships nm
               JOIN communities c ON nm.community_id = c.community_id
               WHERE nm.network_id=?
               ORDER BY nm.joined_at""",
            (network_id,),
        ).fetchall()
    except Exception:
        rows = db.execute(
            "SELECT * FROM network_memberships WHERE network_id=?", (network_id,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_network_stats(network_id: str) -> dict:
    db = _db()
    count = db.execute(
        "SELECT COUNT(*) FROM network_memberships WHERE network_id=?", (network_id,)
    ).fetchone()[0]
    return {"network_id": network_id, "community_count": count}
