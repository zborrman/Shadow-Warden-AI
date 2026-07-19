"""
ACP Shared Payment Token vault.

Issue, verify, consume, and revoke SPTs.
Redis is the primary store (TTL-enforced expiry + atomic DECRBY for use count).
SQLite is the immutable audit trail (every issue/use/revoke recorded).

Token format: acp_spt_{32 hex chars}
HMAC-SHA256 signature over: token_id|merchant_id|agent_id|max_amount|expires_at
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import sqlite3
import threading
from collections.abc import Generator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime, timedelta

from warden.config import data_path
from warden.db.connect import open_db
from warden.db.ddl_registry import register
from warden.protocols.acp.models import SharedPaymentToken
from warden.secret_keys import resolve_key

log = logging.getLogger("warden.acp.token_vault")

_DB_PATH  = data_path("warden_acp.db", "ACP_DB_PATH")
def _hmac_key() -> bytes:
    return resolve_key("ACP_HMAC_KEY", purpose="acp_spt")
_db_lock  = threading.RLock()
_REDIS_PREFIX = "acp:spt:"
_DEFAULT_TTL_MINUTES = int(os.getenv("ACP_SPT_TTL_MINUTES", "30"))


# ── Schema ─────────────────────────────────────────────────────────────────────

_ACP_DDL = """
    CREATE TABLE IF NOT EXISTS acp_tokens (
        token_id    TEXT PRIMARY KEY,
        merchant_id TEXT NOT NULL,
        agent_id    TEXT NOT NULL,
        max_amount  REAL NOT NULL,
        currency    TEXT NOT NULL,
        use_limit   INTEGER NOT NULL,
        expires_at  TEXT NOT NULL,
        status      TEXT NOT NULL DEFAULT 'ACTIVE',
        issued_at   TEXT NOT NULL,
        signature   TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS acp_token_uses (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        token_id   TEXT NOT NULL,
        order_id   TEXT NOT NULL,
        amount     REAL NOT NULL,
        used_at    TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_acp_tok_mid ON acp_tokens(merchant_id);
    CREATE INDEX IF NOT EXISTS idx_acp_tok_aid ON acp_tokens(agent_id);
    CREATE TABLE IF NOT EXISTS acp_refunds (
        refund_id   TEXT PRIMARY KEY,
        order_id    TEXT NOT NULL,
        merchant_id TEXT NOT NULL,
        agent_id    TEXT NOT NULL,
        tenant_id   TEXT NOT NULL,
        amount      REAL NOT NULL,
        currency    TEXT NOT NULL DEFAULT 'USD',
        reason      TEXT NOT NULL DEFAULT '',
        status      TEXT NOT NULL DEFAULT 'PENDING_REVIEW',
        stix_chain_id TEXT NOT NULL DEFAULT '',
        created_at  TEXT NOT NULL,
        resolved_at TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_acp_refunds_tenant ON acp_refunds(tenant_id, status);
"""
register("acp", "warden.protocols.acp.token_vault", _ACP_DDL)


@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    """Yield a Turso-or-SQLite connection for the ACP database."""
    with open_db("acp", _DB_PATH, turso_name="acp", module_default_path=_DB_PATH) as con:
        yield con


# ── HMAC helpers ───────────────────────────────────────────────────────────────

def _sign(token_id: str, merchant_id: str, agent_id: str, max_amount: float, expires_at: str) -> str:
    canonical = f"{token_id}|{merchant_id}|{agent_id}|{max_amount}|{expires_at}"
    return hmac.new(_hmac_key(), canonical.encode(), hashlib.sha256).hexdigest()


def _verify_sig(spt: SharedPaymentToken) -> bool:
    expected = _sign(spt.token_id, spt.merchant_id, spt.agent_id, spt.max_amount, spt.expires_at)
    return hmac.compare_digest(spt.signature, expected)


# ── Redis helpers (fail-open) ──────────────────────────────────────────────────

def _redis_key(token_id: str) -> str:
    return f"{_REDIS_PREFIX}{token_id}"


def _cache_spt(spt: SharedPaymentToken, redis) -> None:
    if redis is None:
        return
    try:
        ttl_s = max(60, int(
            (datetime.fromisoformat(spt.expires_at.replace("Z", "+00:00")) - datetime.now(UTC)).total_seconds()
        ))
        redis.set(_redis_key(spt.token_id), spt.model_dump_json(), ex=ttl_s)
    except Exception as exc:
        log.debug("ACP: Redis cache write failed (fail-open): %s", exc)


def _get_cached(token_id: str, redis) -> SharedPaymentToken | None:
    if redis is None:
        return None
    try:
        raw = redis.get(_redis_key(token_id))
        if raw:
            return SharedPaymentToken.model_validate_json(raw)
    except Exception:
        pass
    return None


def _invalidate_cache(token_id: str, redis) -> None:
    if redis is None:
        return
    with suppress(Exception):
        redis.delete(_redis_key(token_id))


# ── Public API ─────────────────────────────────────────────────────────────────

def issue_spt(
    merchant_id: str,
    agent_id: str,
    max_amount: float,
    currency: str = "USD",
    scope: list[str] | None = None,
    ttl_minutes: int = _DEFAULT_TTL_MINUTES,
    use_limit: int = 1,
    redis=None,
) -> SharedPaymentToken:
    """Issue a new Shared Payment Token. Merchant calls this before handing to agent."""
    if max_amount <= 0:
        raise ValueError("max_amount must be positive")
    token_id   = f"acp_spt_{secrets.token_hex(16)}"
    expires_at = (datetime.now(UTC) + timedelta(minutes=ttl_minutes)).isoformat()
    issued_at  = datetime.now(UTC).isoformat()
    sig        = _sign(token_id, merchant_id, agent_id, max_amount, expires_at)

    spt = SharedPaymentToken(
        token_id=token_id,
        merchant_id=merchant_id,
        agent_id=agent_id,
        max_amount=max_amount,
        currency=currency,
        scope=scope or ["checkout"],
        expires_at=expires_at,
        use_limit=use_limit,
        remaining_uses=use_limit,
        status="ACTIVE",
        issued_at=issued_at,
        signature=sig,
    )

    with _db_lock, _conn() as con:
        con.execute(
            "INSERT INTO acp_tokens (token_id,merchant_id,agent_id,max_amount,currency,"
            "use_limit,expires_at,status,issued_at,signature) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (token_id, merchant_id, agent_id, max_amount, currency,
             use_limit, expires_at, "ACTIVE", issued_at, sig),
        )

    _cache_spt(spt, redis)
    log.info("ACP: SPT issued token=%s merchant=%s agent=%s max=%.2f", token_id[:24], merchant_id, agent_id, max_amount)
    return spt


def verify_spt(
    token_id: str,
    expected_agent_id: str | None = None,
    consume: bool = False,
    order_id: str = "",
    amount: float = 0.0,
    redis=None,
) -> dict:
    """
    Verify an SPT. Returns {"valid": bool, "reason": str, "spt": SPT | None}.

    consume=True: atomically decrement remaining_uses and record the use.
    Call with consume=False for dry-run checks (e.g. cart total validation).
    """
    # Cache-first read
    spt = _get_cached(token_id, redis)

    if spt is None:
        with _db_lock, _conn() as con:
            row = con.execute(
                "SELECT * FROM acp_tokens WHERE token_id=?", (token_id,)
            ).fetchone()
        if not row:
            return {"valid": False, "reason": "not_found", "spt": None}
        # Re-hydrate uses count from audit log
        with _db_lock, _conn() as con:
            uses = con.execute(
                "SELECT COUNT(*) FROM acp_token_uses WHERE token_id=?", (token_id,)
            ).fetchone()[0]
        spt = SharedPaymentToken(
            token_id=row["token_id"],
            merchant_id=row["merchant_id"],
            agent_id=row["agent_id"],
            max_amount=row["max_amount"],
            currency=row["currency"],
            use_limit=row["use_limit"],
            remaining_uses=max(0, row["use_limit"] - uses),
            status=row["status"],
            issued_at=row["issued_at"],
            expires_at=row["expires_at"],
            signature=row["signature"],
        )

    if not _verify_sig(spt):
        return {"valid": False, "reason": "signature_invalid", "spt": None}

    if spt.status != "ACTIVE":
        return {"valid": False, "reason": f"status_{spt.status.lower()}", "spt": spt}

    expires = datetime.fromisoformat(spt.expires_at.replace("Z", "+00:00"))
    if expires < datetime.now(UTC):
        _set_status(token_id, "EXPIRED", redis)
        return {"valid": False, "reason": "expired", "spt": spt}

    if expected_agent_id and spt.agent_id != expected_agent_id:
        return {"valid": False, "reason": "agent_mismatch", "spt": spt}

    if amount > 0 and amount > spt.max_amount:
        return {"valid": False, "reason": "amount_exceeds_token_limit", "spt": spt}

    if spt.remaining_uses <= 0:
        return {"valid": False, "reason": "use_limit_exhausted", "spt": spt}

    if consume:
        _consume(spt, order_id, amount, redis)

    return {"valid": True, "reason": "ok", "spt": spt}


def _consume(spt: SharedPaymentToken, order_id: str, amount: float, redis) -> None:
    """Record a use and decrement remaining_uses atomically."""
    now = datetime.now(UTC).isoformat()
    with _db_lock, _conn() as con:
        con.execute(
            "INSERT INTO acp_token_uses (token_id,order_id,amount,used_at) VALUES(?,?,?,?)",
            (spt.token_id, order_id, amount, now),
        )
        uses_after = con.execute(
            "SELECT COUNT(*) FROM acp_token_uses WHERE token_id=?", (spt.token_id,)
        ).fetchone()[0]
        if uses_after >= spt.use_limit:
            con.execute("UPDATE acp_tokens SET status='USED' WHERE token_id=?", (spt.token_id,))

    spt.remaining_uses = max(0, spt.use_limit - uses_after)
    if spt.remaining_uses <= 0:
        spt.status = "USED"
        _invalidate_cache(spt.token_id, redis)
    else:
        _cache_spt(spt, redis)

    log.info("ACP: SPT consumed token=%s order=%s amount=%.2f remaining_uses=%d",
             spt.token_id[:24], order_id, amount, spt.remaining_uses)


def revoke_spt(token_id: str, redis=None) -> bool:
    with _db_lock, _conn() as con:
        cur = con.execute("UPDATE acp_tokens SET status='REVOKED' WHERE token_id=?", (token_id,))
    _invalidate_cache(token_id, redis)
    return cur.rowcount > 0


def _set_status(token_id: str, status: str, redis) -> None:
    with _db_lock, _conn() as con:
        con.execute("UPDATE acp_tokens SET status=? WHERE token_id=?", (status, token_id))
    _invalidate_cache(token_id, redis)
