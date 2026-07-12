"""
GSAM Hermes JIT credential lease.

Time-boxed, single-use credential leasing for agents ("Hermes Proxy" in the SAC
spec). An agent that needs a scoped downstream credential requests a *lease*;
the lease itself carries **no secret** — only when it is redeemed (once) is a
scope-bound ephemeral capability returned, server-side. This keeps raw
credentials out of the agent's context and chat history.

Design mirrors :mod:`warden.protocols.acp.token_vault`:
  • Turso-or-SQLite ``gsam_leases`` table is the durable store + audit trail;
  • Redis is an optional best-effort cache of lease metadata (SQLite is the
    durable source of truth if it is unavailable);
  • HMAC-SHA256 binds ``lease_id|agent_id|tenant_id|scope|expires_at``.

**Fail-CLOSED:** the signing key is resolved via
:func:`warden.secret_keys.resolve_key`, which raises :class:`InsecureKeyError`
in production when no key/master is configured. The API layer maps that to
HTTP 503 — leasing is a credential path and must never issue a lease when
unconfigured.

**Single-use:** redemption sets ``used_at`` under a lock; a second redeem fails.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import sqlite3
import threading
from collections.abc import Generator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime, timedelta

from warden.config import settings
from warden.secret_keys import resolve_key

log = logging.getLogger("warden.gsam.jit_lease")

_db_lock = threading.RLock()
_REDIS_PREFIX = "gsam:lease:"

# Self-sufficient DDL (matches app_factory._GSAM_DDL so tests need no migration).
_GSAM_LEASES_DDL = """
    CREATE TABLE IF NOT EXISTS gsam_leases (
        lease_id   TEXT PRIMARY KEY,
        agent_id   TEXT NOT NULL,
        tenant_id  TEXT NOT NULL,
        scope      TEXT NOT NULL,
        status     TEXT NOT NULL DEFAULT 'PENDING',
        hmac_sig   TEXT NOT NULL DEFAULT '',
        expires_at TEXT NOT NULL DEFAULT '',
        used_at    TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_gsam_leases_agent ON gsam_leases(agent_id, created_at);
"""


class LeaseError(RuntimeError):
    """Raised when a lease operation fails a hard precondition (fail-CLOSED)."""


def _lease_key() -> bytes:
    """Resolve the HMAC signing key — fail-CLOSED via resolve_key."""
    return resolve_key("GSAM_LEASE_SECRET", purpose="gsam_lease")


@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    """Yield a Turso-or-SQLite connection for the GSAM database."""
    with suppress(ImportError):
        from warden.db.turso import get_connection, is_turso_enabled
        if is_turso_enabled("gsam"):
            with get_connection("gsam", fallback_path=settings.gsam_db_path) as con:
                with suppress(Exception):
                    con.executescript(_GSAM_LEASES_DDL)
                yield con  # type: ignore[misc]
            return

    con = sqlite3.connect(settings.gsam_db_path, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(_GSAM_LEASES_DDL)
    try:
        yield con
        con.commit()
    finally:
        con.close()


def _sign(lease_id: str, agent_id: str, tenant_id: str, scope: str, expires_at: str) -> str:
    canonical = f"{lease_id}|{agent_id}|{tenant_id}|{scope}|{expires_at}"
    return hmac.new(_lease_key(), canonical.encode(), hashlib.sha256).hexdigest()


def _derive_capability(lease_id: str, scope: str) -> str:
    """Scope-bound ephemeral capability revealed only on successful redeem.

    This is a bearer capability the downstream verifies (HMAC-derived, bound to
    this exact lease + scope) — not a stored raw secret. A real secret backend
    (Vault/AWS SM) can be swapped in behind this function later.
    """
    material = hmac.new(_lease_key(), f"cred:{lease_id}:{scope}".encode(), hashlib.sha256)
    return f"gsam_cap_{material.hexdigest()}"


def _redis_cache(lease: dict, redis) -> None:
    if redis is None:
        return
    with suppress(Exception):
        ttl_s = max(
            30,
            int((datetime.fromisoformat(lease["expires_at"]) - datetime.now(UTC)).total_seconds()),
        )
        redis.set(f"{_REDIS_PREFIX}{lease['lease_id']}", json.dumps(lease), ex=ttl_s)


def _redis_invalidate(lease_id: str, redis) -> None:
    if redis is None:
        return
    with suppress(Exception):
        redis.delete(f"{_REDIS_PREFIX}{lease_id}")


def _meta(row: sqlite3.Row) -> dict:
    """Metadata-only view of a lease row — never includes any capability."""
    return {
        "lease_id": row["lease_id"],
        "agent_id": row["agent_id"],
        "tenant_id": row["tenant_id"],
        "scope": row["scope"],
        "status": row["status"],
        "expires_at": row["expires_at"],
        "used_at": row["used_at"],
        "created_at": row["created_at"],
    }


def issue_lease(
    agent_id: str,
    tenant_id: str,
    scope: str,
    ttl_s: int | None = None,
    redis=None,
) -> dict:
    """Issue a single-use JIT credential lease. Returns metadata only — NO secret.

    Raises :class:`LeaseError` if GSAM is disabled and :class:`InsecureKeyError`
    (fail-CLOSED) if no signing key can be resolved.
    """
    if not settings.gsam_enabled:
        raise LeaseError("GSAM disabled — leasing unavailable")
    if not scope:
        raise ValueError("scope is required")

    ttl = int(ttl_s if ttl_s is not None else settings.gsam_lease_ttl_s)
    lease_id = f"gsam_lease_{secrets.token_hex(16)}"
    now = datetime.now(UTC)
    expires_at = (now + timedelta(seconds=ttl)).isoformat()
    created_at = now.isoformat()
    sig = _sign(lease_id, agent_id, tenant_id, scope, expires_at)  # resolve_key runs here

    with _db_lock, _conn() as con:
        con.execute(
            "INSERT INTO gsam_leases (lease_id,agent_id,tenant_id,scope,status,"
            "hmac_sig,expires_at,used_at,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (lease_id, agent_id, tenant_id, scope, "ACTIVE", sig, expires_at, "", created_at),
        )

    lease = {
        "lease_id": lease_id, "agent_id": agent_id, "tenant_id": tenant_id,
        "scope": scope, "status": "ACTIVE", "expires_at": expires_at,
        "used_at": "", "created_at": created_at,
    }
    _redis_cache(lease, redis)
    log.info("GSAM: lease issued id=%s agent=%s scope=%s ttl=%ds", lease_id[:24], agent_id, scope, ttl)
    return lease


def redeem_lease(lease_id: str, agent_id: str, redis=None) -> dict:
    """Redeem a lease exactly once. Returns ``{scope, credential, ...}``.

    Verifies HMAC + agent match + expiry + single-use, all under a lock. The
    scope-bound ephemeral capability is returned only on this one success.
    """
    with _db_lock, _conn() as con:
        row = con.execute("SELECT * FROM gsam_leases WHERE lease_id=?", (lease_id,)).fetchone()
        if not row:
            raise LeaseError("lease not found")

        expected = _sign(
            row["lease_id"], row["agent_id"], row["tenant_id"], row["scope"], row["expires_at"]
        )
        if not hmac.compare_digest(row["hmac_sig"], expected):
            raise LeaseError("signature invalid")
        if row["agent_id"] != agent_id:
            raise LeaseError("agent mismatch")
        if row["status"] != "ACTIVE" or row["used_at"]:
            raise LeaseError("lease already used" if row["used_at"] else f"lease {row['status'].lower()}")
        if datetime.fromisoformat(row["expires_at"]) < datetime.now(UTC):
            con.execute("UPDATE gsam_leases SET status='EXPIRED' WHERE lease_id=?", (lease_id,))
            raise LeaseError("lease expired")

        used_at = datetime.now(UTC).isoformat()
        # Atomic single-use claim: only the caller that flips used_at='' wins.
        cur = con.execute(
            "UPDATE gsam_leases SET status='USED', used_at=? WHERE lease_id=? AND used_at=''",
            (used_at, lease_id),
        )
        if cur.rowcount != 1:
            raise LeaseError("lease already used")

        scope = row["scope"]

    _redis_invalidate(lease_id, redis)
    credential = _derive_capability(lease_id, scope)
    log.info("GSAM: lease redeemed id=%s agent=%s scope=%s", lease_id[:24], agent_id, scope)
    return {"lease_id": lease_id, "scope": scope, "credential": credential, "used_at": used_at}


def revoke_lease(lease_id: str, redis=None) -> bool:
    with _db_lock, _conn() as con:
        cur = con.execute(
            "UPDATE gsam_leases SET status='REVOKED' WHERE lease_id=? AND status='ACTIVE'",
            (lease_id,),
        )
        changed = cur.rowcount > 0
    _redis_invalidate(lease_id, redis)
    return changed


def get_lease(lease_id: str) -> dict | None:
    """Return lease metadata (never a credential), or None if unknown."""
    with _db_lock, _conn() as con:
        row = con.execute("SELECT * FROM gsam_leases WHERE lease_id=?", (lease_id,)).fetchone()
    return _meta(row) if row else None
