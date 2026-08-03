"""
Community Factory — create and manage communities.
32-char hex ID: SHA-256(creator_id + timestamp + uuid4)[:32]
Storage: SQLite (COMM_DB_PATH env var).
"""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
import time
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from warden.config import data_path
from warden.db.connect import open_db
from warden.db.ddl_registry import register

log = logging.getLogger("warden.communities.community_factory")

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


# Shares warden_communities.db with membership.py / network.py /
# community_data.py / community_evolution.py — same db_key, distinct module.
_FACTORY_DDL = """
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
"""
register("communities", "warden.communities.community_factory", _FACTORY_DDL)


@contextmanager
def _conn() -> Generator[Any, None, None]:
    with open_db("communities", COMM_DB_PATH, module_default_path=COMM_DB_PATH) as con:
        yield con


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
    with _lock, _conn() as db:
        db.execute(
            "INSERT INTO communities VALUES (?,?,?,?,?,?,?,?,?)",
            (cid, name, description, creator_tenant_id, ts,
             "active", visibility, join_policy, json.dumps(final_settings)),
        )

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


# ── Canonical-store bridge (D-6) ─────────────────────────────────────────────
#
# `/communities` is served by two routers over two *different* databases:
#
#   warden/communities/router.py  → warden_community_registry.db
#       POST "" (create), GET/{id}, members, entities, break-glass, rotate, pqc
#   warden/api/communities_v2.py  → warden_communities.db (this module)
#       {id}/join, {id}/settings, {id}/data, {id}/peers, networks, analytics
#
# Their routes do not collide, so both are live — on disjoint halves of the same
# API, backed by disconnected stores. And v2 has **no create endpoint**: nothing
# in the running application ever inserts into this module's table, because the
# only writer, `create_community` below, has no caller outside tests. So every
# v2 endpoint that resolves a community 404s on every community the API can
# actually create. Verified by creating one through the registry path and
# watching `get_community()` return None.
#
# The registry store is therefore canonical: it is what the create endpoint
# writes, and it carries governance/crypto fields (`tier`, `active_kid`,
# clearance-scoped members) that cannot be reconstructed from a default. This
# module keeps its own richer *discovery* model (`visibility`, `join_policy`),
# which the registry expresses inside its existing `settings` JSON — so the
# bridge is a projection, needing no schema change and no ALTER on a live table.
#
# Reads fall back to this module's legacy table so any row already written
# there (tests, older deployments) keeps resolving.

def _registry_visibility(settings: dict) -> tuple[str, str]:
    """Project the create-wizard payload onto (visibility, join_policy).

    `router.py` stores `settings["visibility"]["visibility"]` as
    PUBLIC | PRIVATE | INVITE_ONLY and `settings["security"]
    ["join_approval_required"]` as a bool; this module models the same thing as
    private/public plus invite/approval/open.
    """
    vis_block = settings.get("visibility") or {}
    raw = str(vis_block.get("visibility", "PRIVATE")).upper()
    visibility = "public" if raw == "PUBLIC" else "private"

    if raw == "INVITE_ONLY":
        join_policy = "invite"
    else:
        sec = settings.get("security") or {}
        join_policy = "approval" if sec.get("join_approval_required", True) else "open"
    return visibility, join_policy


def _registry_to_community(rec: Any) -> Community:
    """Map a registry CommunityRecord onto this module's Community."""
    visibility, join_policy = _registry_visibility(rec.settings or {})
    return Community(
        community_id      = rec.community_id,
        name              = rec.display_name,
        description       = rec.description,
        creator_tenant_id = rec.tenant_id,
        created_at        = rec.created_at,
        status            = (rec.status or "ACTIVE").lower(),
        visibility        = visibility,
        join_policy       = join_policy,
        settings          = rec.settings or {},
    )


def _registry_get(community_id: str) -> Community | None:
    try:
        from warden.communities import registry
        rec = registry.get_community(community_id)
        return _registry_to_community(rec) if rec else None
    except Exception as exc:
        log.debug("community_factory: registry lookup unavailable: %s", exc)
        return None


def _registry_write(fn_name: str, community_id: str, *args: Any, **kwargs: Any) -> bool:
    """Apply a mutation to the canonical store; False when it does not own the row.

    Returns False both when the registry has no such community *and* when the
    registry itself is unreachable, so the caller falls through to the legacy
    table rather than reporting a success that never landed.
    """
    try:
        from warden.communities import registry
        return bool(getattr(registry, fn_name)(community_id, *args, **kwargs))
    except Exception as exc:
        log.debug("community_factory: registry %s unavailable: %s", fn_name, exc)
        return False


def get_community(community_id: str) -> Community | None:
    # Canonical store first — see the bridge note above.
    found = _registry_get(community_id)
    if found is not None:
        return found
    with _conn() as db:
        row = db.execute(
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
    with _conn() as db:
        legacy = [_row_to_community(r) for r in db.execute(sql, params).fetchall()]

    # Union with the canonical store, legacy rows losing on community_id so a
    # row present in both is reported once, from the authoritative side.
    merged: dict[str, Community] = {c.community_id: c for c in legacy}
    for c in _registry_list(creator_tenant_id):
        if c.status != status:
            continue
        if visibility and c.visibility != visibility:
            continue
        merged[c.community_id] = c
    return sorted(merged.values(), key=lambda c: c.created_at, reverse=True)


def _registry_list(tenant_id: str | None) -> list[Community]:
    """Communities from the canonical store.

    The registry indexes by tenant, so an un-scoped listing has no equivalent
    query there; returning nothing keeps this a strict *addition* to the legacy
    result rather than a silently partial replacement of it.
    """
    if not tenant_id:
        return []
    try:
        from warden.communities import registry
        return [_registry_to_community(r) for r in registry.list_communities(tenant_id)]
    except Exception as exc:
        log.debug("community_factory: registry listing unavailable: %s", exc)
        return []


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
    # Canonical store first: the community the API actually created lives there,
    # so writing only here would silently no-op (rowcount 0 → endpoint reports
    # failure) for every real community.
    if _registry_write(
        "update_community_fields", community_id,
        display_name=name, description=description,
    ):
        return True

    params.append(community_id)
    with _lock, _conn() as db:
        cur = db.execute(
            f"UPDATE communities SET {', '.join(updates)} WHERE community_id=?",
            params,
        )
        return cur.rowcount > 0


def update_community_settings(community_id: str, settings: dict) -> bool:
    if _registry_write("update_community_settings", community_id, settings):
        return True
    with _lock, _conn() as db:
        cur = db.execute(
            "UPDATE communities SET settings=? WHERE community_id=?",
            (json.dumps(settings), community_id),
        )
        return cur.rowcount > 0


def update_community_status(community_id: str, status: str) -> bool:
    if _registry_write("update_community_status", community_id, status.upper()):
        return True
    with _lock, _conn() as db:
        cur = db.execute(
            "UPDATE communities SET status=? WHERE community_id=?",
            (status, community_id),
        )
        return cur.rowcount > 0


def delete_community(community_id: str, requester_tenant_id: str) -> bool:
    if _registry_write("delete_community", community_id, requester_tenant_id):
        return True

    c = get_community(community_id)
    if not c or c.creator_tenant_id != requester_tenant_id:
        return False
    with _lock, _conn() as db:
        db.execute("DELETE FROM communities WHERE community_id=?", (community_id,))
    return True


def get_community_stats() -> dict:
    with _conn() as db:
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
