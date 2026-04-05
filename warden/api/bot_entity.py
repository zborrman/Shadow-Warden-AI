"""
warden/api/bot_entity.py
─────────────────────────
Bot_ID — Virtual Member_ID for external integrations.

What is a Bot_ID?
──────────────────
  A Bot represents an external system (Shopify webhook, Zapier flow,
  CI/CD pipeline, another AI agent) that needs to interact with a
  Community as a participant.

  Unlike human members, Bots:
    • Are assigned a scoped JWT (not a password) for authentication.
    • Have an explicit allowed_ips whitelist — requests from outside
      the whitelist are rejected at the gateway (Gemini audit recommendation).
    • Have a clearance level that caps what community data they can
      read/write (same ClearanceLevel enum as human members).
    • Are tracked separately in community_bots table for clear auditability.

Security controls (Gemini audit recommendations)
──────────────────────────────────────────────────
  1. allowed_ips whitelist: the JWT claims include an allowed_ips list.
     The gateway verifies the caller's IP is in the list before any
     action is performed — prevents stolen-JWT credential abuse.

  2. Scoped JWT: the token carries community_id, bot_id, clearance, and
     allowed_ips claims.  It is signed with BOT_JWT_SECRET (separate from
     the portal/admin JWT secrets to limit blast radius).

  3. Short TTL: default BOT_TOKEN_TTL_S = 3600 (1 hour).  Bots must
     re-authenticate to renew; long-lived static tokens are not supported.

  4. Revocation: each bot has a jti (JWT ID) stored in Redis with TTL.
     Calling revoke_bot_token() deletes the Redis key, immediately
     invalidating any copies of the token.

  5. Per-bot rate limit: tracked separately from human member rate limits.

JWT claims
──────────
  {
    "sub": "<bot_id>",
    "iss": "warden-bot-v1",
    "jti": "<uuid>",
    "iat": <int>,
    "exp": <int>,
    "community_id": "<community_id>",
    "clearance": "INTERNAL",
    "allowed_ips": ["10.0.1.5", "192.168.0.0/24"],
    "scopes": ["read", "write"],
  }

Usage
─────
  # Register a bot
  bot = create_bot(community_id, "shopify-webhook", ClearanceLevel.INTERNAL,
                   allowed_ips=["185.27.134.0/24"], created_by=admin_mid)

  # Issue JWT
  token = issue_bot_token(bot.bot_id)

  # Verify incoming request
  claims = verify_bot_token(token, caller_ip="185.27.134.15")
  # → raises PermissionError if IP not in whitelist
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Optional

import jwt as pyjwt

from warden.communities.clearance import ClearanceLevel
from warden.communities.id_generator import new_member_id

log = logging.getLogger("warden.api.bot_entity")

BOT_TOKEN_TTL_S:  int = int(os.getenv("BOT_TOKEN_TTL_S", "3600"))
BOT_JWT_SECRET:   str = os.getenv("BOT_JWT_SECRET", "")
_BOT_DB_PATH:     str = os.getenv("BOT_DB_PATH", "/tmp/warden_bot_entities.db")

_db_lock = threading.RLock()


# ── Schema ────────────────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_BOT_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS community_bots (
            bot_id          TEXT PRIMARY KEY,
            community_id    TEXT NOT NULL,
            tenant_id       TEXT NOT NULL,
            display_name    TEXT NOT NULL DEFAULT '',
            clearance       TEXT NOT NULL DEFAULT 'PUBLIC',
            allowed_ips     TEXT NOT NULL DEFAULT '[]',
            scopes          TEXT NOT NULL DEFAULT '["read"]',
            status          TEXT NOT NULL DEFAULT 'ACTIVE',
            created_by      TEXT,
            created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS bots_community_idx ON community_bots(community_id)
    """)
    conn.commit()
    return conn


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class BotEntity:
    bot_id:       str
    community_id: str
    tenant_id:    str
    display_name: str
    clearance:    str          # ClearanceLevel name
    allowed_ips:  list[str]   # CIDR or exact IPs
    scopes:       list[str]   # ["read"] | ["read", "write"] | ["read", "write", "admin"]
    status:       str
    created_by:   Optional[str]
    created_at:   str
    updated_at:   str


def _row_to_bot(row) -> BotEntity:
    return BotEntity(
        bot_id       = row["bot_id"],
        community_id = row["community_id"],
        tenant_id    = row["tenant_id"],
        display_name = row["display_name"],
        clearance    = row["clearance"],
        allowed_ips  = json.loads(row["allowed_ips"]),
        scopes       = json.loads(row["scopes"]),
        status       = row["status"],
        created_by   = row["created_by"],
        created_at   = row["created_at"],
        updated_at   = row["updated_at"],
    )


# ── JWT helpers ───────────────────────────────────────────────────────────────

def _get_secret() -> str:
    secret = BOT_JWT_SECRET or os.getenv("BOT_JWT_SECRET", "")
    if not secret:
        # Ephemeral secret (dev/test) — tokens invalid across restarts
        log.warning("BOT_JWT_SECRET not set — using ephemeral secret. Set in production.")
        secret = os.urandom(32).hex()
        os.environ["BOT_JWT_SECRET"] = secret
    return secret


def _ip_in_whitelist(caller_ip: str, allowed_ips: list[str]) -> bool:
    """Return True if *caller_ip* matches any entry in *allowed_ips*."""
    if not allowed_ips:
        return True   # empty whitelist = allow all (for internal bots)
    try:
        caller = ipaddress.ip_address(caller_ip)
    except ValueError:
        return False
    for entry in allowed_ips:
        try:
            if "/" in entry:
                if caller in ipaddress.ip_network(entry, strict=False):
                    return True
            else:
                if caller == ipaddress.ip_address(entry):
                    return True
        except ValueError:
            continue
    return False


# ── Public API ────────────────────────────────────────────────────────────────

def create_bot(
    community_id: str,
    tenant_id:    str,
    display_name: str,
    clearance:    ClearanceLevel = ClearanceLevel.PUBLIC,
    allowed_ips:  Optional[list[str]] = None,
    scopes:       Optional[list[str]] = None,
    created_by:   Optional[str] = None,
) -> BotEntity:
    """
    Register a new Bot entity in a community.

    The bot_id is a scoped Member_ID (UUIDv7 namespaced under community_id)
    so it is guaranteed unique per community and sortable by creation time.
    """
    if allowed_ips is None:
        allowed_ips = []
    if scopes is None:
        scopes = ["read"]

    bot_id = new_member_id(community_id)
    now = datetime.now(UTC).isoformat()

    with _db_lock:
        conn = _get_conn()
        conn.execute("""
            INSERT INTO community_bots
              (bot_id, community_id, tenant_id, display_name, clearance,
               allowed_ips, scopes, status, created_by, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (
            bot_id, community_id, tenant_id, display_name, clearance.name,
            json.dumps(allowed_ips), json.dumps(scopes),
            "ACTIVE", created_by, now, now,
        ))
        conn.commit()

    log.info(
        "bot_entity: created bot=%s community=%s clearance=%s ips=%s",
        bot_id[:8], community_id[:8], clearance.name, allowed_ips,
    )
    return BotEntity(
        bot_id       = bot_id,
        community_id = community_id,
        tenant_id    = tenant_id,
        display_name = display_name,
        clearance    = clearance.name,
        allowed_ips  = allowed_ips,
        scopes       = scopes,
        status       = "ACTIVE",
        created_by   = created_by,
        created_at   = now,
        updated_at   = now,
    )


def get_bot(bot_id: str) -> Optional[BotEntity]:
    """Return BotEntity or None."""
    with _db_lock:
        conn = _get_conn()
        row = conn.execute(
            "SELECT * FROM community_bots WHERE bot_id=?", (bot_id,)
        ).fetchone()
    return _row_to_bot(row) if row else None


def list_bots(community_id: str, active_only: bool = True) -> list[BotEntity]:
    """List bots registered in a community."""
    with _db_lock:
        conn = _get_conn()
        if active_only:
            rows = conn.execute(
                "SELECT * FROM community_bots WHERE community_id=? AND status='ACTIVE' "
                "ORDER BY created_at DESC",
                (community_id,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM community_bots WHERE community_id=? ORDER BY created_at DESC",
                (community_id,)
            ).fetchall()
    return [_row_to_bot(r) for r in rows]


def issue_bot_token(bot_id: str, ttl_s: int = BOT_TOKEN_TTL_S) -> str:
    """
    Issue a signed JWT for *bot_id*.

    The token embeds allowed_ips so the verifier can enforce the whitelist
    without a DB round-trip on every request.

    Returns the compact JWT string.
    """
    bot = get_bot(bot_id)
    if bot is None:
        raise ValueError(f"Bot {bot_id} not found.")
    if bot.status != "ACTIVE":
        raise PermissionError(f"Bot {bot_id} is {bot.status}.")

    jti = str(uuid.uuid4())
    now = int(time.time())
    payload = {
        "sub":          bot.bot_id,
        "iss":          "warden-bot-v1",
        "jti":          jti,
        "iat":          now,
        "exp":          now + ttl_s,
        "community_id": bot.community_id,
        "clearance":    bot.clearance,
        "allowed_ips":  bot.allowed_ips,
        "scopes":       bot.scopes,
    }
    token = pyjwt.encode(payload, _get_secret(), algorithm="HS256")

    # Store jti in Redis for revocation checks (fail-open)
    try:
        from warden.cache import _get_client
        r = _get_client()
        if r:
            r.setex(f"warden:bot:jti:{jti}", ttl_s + 60, "1")
    except Exception as exc:
        log.debug("bot_entity: Redis jti store error: %s", exc)

    log.info("bot_entity: issued token bot=%s jti=%s ttl=%ds", bot_id[:8], jti[:8], ttl_s)
    return token


def verify_bot_token(
    token:     str,
    caller_ip: str = "",
) -> dict:
    """
    Verify a Bot JWT and enforce the allowed_ips whitelist.

    Returns the decoded claims dict on success.

    Raises
    ──────
    jwt.ExpiredSignatureError   Token TTL exceeded.
    jwt.InvalidTokenError       Signature invalid or claims malformed.
    PermissionError             Caller IP not in allowed_ips whitelist.
    PermissionError             JTI has been revoked.
    """
    claims = pyjwt.decode(
        token,
        _get_secret(),
        algorithms=["HS256"],
        options={"require": ["sub", "jti", "exp", "community_id"]},
    )

    # IP whitelist enforcement
    allowed_ips = claims.get("allowed_ips", [])
    if caller_ip and allowed_ips and not _ip_in_whitelist(caller_ip, allowed_ips):
        raise PermissionError(
            f"Bot token rejected: caller IP {caller_ip!r} not in allowed_ips whitelist."
        )

    # JTI revocation check
    jti = claims.get("jti", "")
    try:
        from warden.cache import _get_client
        r = _get_client()
        if r:
            revoked_key = f"warden:bot:revoked:{jti}"
            if r.exists(revoked_key):
                raise PermissionError(f"Bot token jti={jti[:8]} has been revoked.")
    except PermissionError:
        raise
    except Exception:
        pass   # Redis unavailable — fail-open for token checks

    return claims


def revoke_bot_token(jti: str, ttl_s: int = BOT_TOKEN_TTL_S + 3600) -> None:
    """
    Revoke a specific Bot JWT by JTI.

    Stores a revocation marker in Redis for *ttl_s* seconds (should cover
    the maximum remaining lifetime of any token issued with this JTI).
    """
    try:
        from warden.cache import _get_client
        r = _get_client()
        if r:
            r.delete(f"warden:bot:jti:{jti}")
            r.setex(f"warden:bot:revoked:{jti}", ttl_s, "1")
    except Exception as exc:
        log.warning("bot_entity: revoke error jti=%s: %s", jti[:8], exc)


def deactivate_bot(bot_id: str) -> bool:
    """Soft-deactivate a bot (prevents new token issuance)."""
    now = datetime.now(UTC).isoformat()
    with _db_lock:
        conn = _get_conn()
        cur = conn.execute(
            "UPDATE community_bots SET status='DEACTIVATED', updated_at=? WHERE bot_id=?",
            (now, bot_id)
        )
        conn.commit()
    return cur.rowcount > 0
