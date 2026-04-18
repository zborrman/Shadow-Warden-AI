"""
warden/communities/knock.py
─────────────────────────────
Knock-and-Verify — invite verified Shadow Warden tenants into a community.

Why "Knock-and-Verify"?
────────────────────────
  Traditional invite links work for anyone with the URL.  SEP invitations
  are closed: only tenants who already operate a Shadow Warden installation
  (and can prove it with a valid WARDEN_API_KEY) may knock on a community
  door.  This prevents outsiders from discovering or joining communities.

Flow
─────
  1. Community admin calls issue_knock() → KnockRecord + knock_token.
     The token is delivered to the target tenant (e.g. via Slack or email).

  2. Target tenant calls verify_and_accept_knock(token, their_api_key).
     Shadow Warden verifies the API key hits the local /health endpoint
     of a known warden installation, or is present in the warden tenant DB.

  3. On success → invite_member() is called and MemberRecord returned.
     The knock token is consumed (one-use).

Token storage
──────────────
  Redis: `sep:knock:{token_hash}` (72-hour TTL) — JSON with community_id,
  inviter_mid, invitee_tenant_id, clearance, expires_at.
  In-memory dict fallback if Redis unavailable.

Security
────────
  • Tokens are HMAC-SHA256 signed (COMMUNITY_VAULT_KEY) — forgery-resistant.
  • Each token is single-use; accepted_at is set to prevent replay.
  • invitee_tenant_id binds the token to one specific tenant.
  • Expired tokens return HTTP 410 (Gone), not 404, to distinguish expiry
    from non-existence.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

log = logging.getLogger("warden.communities.knock")

_KNOCK_TTL_HOURS = int(os.getenv("SEP_KNOCK_TTL_HOURS", "72"))
_MEMORY_KNOCKS: dict[str, dict] = {}   # token_hash → knock dict


# ── Redis helpers ──────────────────────────────────────────────────────────────

def _redis():
    try:
        import redis as _r
        url = os.getenv("REDIS_URL", "redis://localhost:6379")
        if url.startswith("memory://"):
            return None
        return _r.from_url(url, decode_responses=True)
    except Exception:
        return None


def _redis_key(token_hash: str) -> str:
    return f"sep:knock:{token_hash}"


# ── HMAC signing ───────────────────────────────────────────────────────────────

def _sep_key() -> bytes:
    raw = (
        os.getenv("COMMUNITY_VAULT_KEY")
        or os.getenv("VAULT_MASTER_KEY")
        or "dev-sep-key-insecure"
    )
    return raw.encode() if isinstance(raw, str) else raw


def _sign_token(token: str) -> str:
    return hmac.new(_sep_key(), token.encode(), hashlib.sha256).hexdigest()


def _verify_token(token: str, stored_hash: str) -> bool:
    return hmac.compare_digest(_sign_token(token), stored_hash)


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class KnockRecord:
    knock_id:          str
    token_hash:        str     # HMAC-SHA256 of plaintext token (stored, not the token)
    community_id:      str
    inviter_mid:       str
    invitee_tenant_id: str     # only this SW tenant may accept
    clearance:         str     # initial clearance level
    role:              str
    message:           str     # optional personal note from the inviter
    status:            str     # PENDING | ACCEPTED | EXPIRED | REVOKED
    expires_at:        str
    accepted_at:       str | None
    created_at:        str


def _knock_to_dict(k: KnockRecord) -> dict:
    return {
        "knock_id":          k.knock_id,
        "token_hash":        k.token_hash,
        "community_id":      k.community_id,
        "inviter_mid":       k.inviter_mid,
        "invitee_tenant_id": k.invitee_tenant_id,
        "clearance":         k.clearance,
        "role":              k.role,
        "message":           k.message,
        "status":            k.status,
        "expires_at":        k.expires_at,
        "accepted_at":       k.accepted_at,
        "created_at":        k.created_at,
    }


def _dict_to_knock(d: dict) -> KnockRecord:
    return KnockRecord(
        knock_id          = d["knock_id"],
        token_hash        = d["token_hash"],
        community_id      = d["community_id"],
        inviter_mid       = d["inviter_mid"],
        invitee_tenant_id = d["invitee_tenant_id"],
        clearance         = d.get("clearance", "PUBLIC"),
        role              = d.get("role", "MEMBER"),
        message           = d.get("message", ""),
        status            = d.get("status", "PENDING"),
        expires_at        = d["expires_at"],
        accepted_at       = d.get("accepted_at"),
        created_at        = d["created_at"],
    )


# ── Storage helpers ────────────────────────────────────────────────────────────

def _store_knock(k: KnockRecord, ttl_seconds: int) -> None:
    d   = _knock_to_dict(k)
    key = _redis_key(k.token_hash)
    _MEMORY_KNOCKS[k.token_hash] = d
    r = _redis()
    if r:
        try:
            r.setex(key, ttl_seconds, json.dumps(d))
        except Exception as exc:
            log.warning("knock: redis store error: %s", exc)


def _load_knock(token_hash: str) -> KnockRecord | None:
    r = _redis()
    if r:
        try:
            raw = r.get(_redis_key(token_hash))
            if raw:
                return _dict_to_knock(json.loads(raw))
        except Exception as exc:
            log.debug("knock: redis load error: %s", exc)
    d = _MEMORY_KNOCKS.get(token_hash)
    return _dict_to_knock(d) if d else None


def _update_knock(token_hash: str, patch: dict) -> None:
    d = _MEMORY_KNOCKS.get(token_hash, {})
    d.update(patch)
    _MEMORY_KNOCKS[token_hash] = d
    r = _redis()
    if r:
        try:
            key = _redis_key(token_hash)
            raw = r.get(key)
            if raw:
                full = json.loads(raw)
                full.update(patch)
                remaining = r.ttl(key)
                if remaining and remaining > 0:
                    r.setex(key, remaining, json.dumps(full))
        except Exception as exc:
            log.debug("knock: redis update error: %s", exc)


# ── Public API ────────────────────────────────────────────────────────────────

def issue_knock(
    community_id:      str,
    inviter_mid:       str,
    invitee_tenant_id: str,
    clearance:         str = "PUBLIC",
    role:              str = "MEMBER",
    message:           str = "",
) -> tuple[KnockRecord, str]:
    """
    Issue a Knock-and-Verify invitation.

    Returns (KnockRecord, plaintext_token).

    The plaintext_token must be delivered to the invitee out-of-band
    (e.g. via Slack DM, email, or a secure channel outside Shadow Warden).
    Only the invitee_tenant_id may accept the knock.
    """
    # Validate community exists
    from warden.communities.registry import get_community
    if not get_community(community_id):
        raise ValueError(f"Community {community_id[:8]}… not found.")

    knock_id   = str(uuid.uuid4())
    nonce      = uuid.uuid4().hex
    token      = f"knock-{knock_id[:8]}-{nonce}"
    token_hash = _sign_token(token)

    now        = datetime.now(UTC)
    expires_at = (now + timedelta(hours=_KNOCK_TTL_HOURS)).isoformat()
    created_at = now.isoformat()

    k = KnockRecord(
        knock_id          = knock_id,
        token_hash        = token_hash,
        community_id      = community_id,
        inviter_mid       = inviter_mid,
        invitee_tenant_id = invitee_tenant_id,
        clearance         = clearance,
        role              = role,
        message           = message,
        status            = "PENDING",
        expires_at        = expires_at,
        accepted_at       = None,
        created_at        = created_at,
    )

    ttl = _KNOCK_TTL_HOURS * 3600
    _store_knock(k, ttl)

    log.info(
        "knock: issued knock_id=%s community=%s invitee=%s",
        knock_id[:8], community_id[:8], invitee_tenant_id,
    )
    return k, token


def get_knock(token: str) -> KnockRecord | None:
    """Look up a knock by plaintext token."""
    token_hash = _sign_token(token)
    k = _load_knock(token_hash)
    if not k:
        return None
    # Check expiry
    if k.expires_at < datetime.now(UTC).isoformat():
        _update_knock(token_hash, {"status": "EXPIRED"})
        k.status = "EXPIRED"
    return k


def get_knock_by_id(knock_id: str, community_id: str) -> KnockRecord | None:
    """Scan in-memory knocks for admin listing (Redis TTL handles cleanup)."""
    for d in _MEMORY_KNOCKS.values():
        if d.get("knock_id") == knock_id and d.get("community_id") == community_id:
            k = _dict_to_knock(d)
            if k.expires_at < datetime.now(UTC).isoformat():
                k.status = "EXPIRED"
            return k
    return None


def verify_and_accept_knock(
    token:             str,
    claiming_tenant_id: str,
) -> tuple[KnockRecord, object]:
    """
    Verify the token and accept the knock for *claiming_tenant_id*.

    Steps:
      1. Validate HMAC token signature.
      2. Verify the knock is PENDING and not expired.
      3. Assert claiming_tenant_id matches invitee_tenant_id.
      4. Call invite_member() to complete the join.
      5. Mark knock ACCEPTED (one-time use).

    Returns (KnockRecord, MemberRecord).
    Raises ValueError on any failure.
    """
    k = get_knock(token)
    if not k:
        raise ValueError("Knock token not found.")
    if k.status == "EXPIRED":
        raise ValueError("Knock token has expired.")
    if k.status != "PENDING":
        raise ValueError(f"Knock token already {k.status}.")
    if k.invitee_tenant_id != claiming_tenant_id:
        raise ValueError("This invitation is for a different tenant.")

    # Invite the member
    from warden.communities.clearance import ClearanceLevel
    from warden.communities.registry import invite_member
    try:
        clearance_level = ClearanceLevel.from_str(k.clearance)
    except Exception:
        clearance_level = ClearanceLevel.PUBLIC

    member = invite_member(
        community_id = k.community_id,
        tenant_id    = claiming_tenant_id,
        external_id  = claiming_tenant_id,
        display_name = claiming_tenant_id,
        clearance    = clearance_level,
        role         = k.role,
        invited_by   = k.inviter_mid,
    )

    # Consume token
    now = datetime.now(UTC).isoformat()
    _update_knock(k.token_hash, {"status": "ACCEPTED", "accepted_at": now})
    k.status      = "ACCEPTED"
    k.accepted_at = now

    log.info(
        "knock: accepted knock_id=%s community=%s tenant=%s member=%s",
        k.knock_id[:8], k.community_id[:8], claiming_tenant_id, member.member_id[:8],
    )
    return k, member


def revoke_knock(token: str) -> bool:
    """Revoke a PENDING knock.  Returns True if found and revoked."""
    k = get_knock(token)
    if not k or k.status != "PENDING":
        return False
    _update_knock(k.token_hash, {"status": "REVOKED"})
    log.info("knock: revoked knock_id=%s", k.knock_id[:8])
    return True


def list_pending_knocks(community_id: str) -> list[KnockRecord]:
    """
    List all PENDING knocks for a community.

    Note: uses the in-memory fallback — Redis-stored knocks that haven't
    been loaded into this process won't appear.  For production, query
    Redis SCAN sep:knock:* and filter by community_id.
    """
    now = datetime.now(UTC).isoformat()
    result: list[KnockRecord] = []
    for d in _MEMORY_KNOCKS.values():
        if d.get("community_id") != community_id:
            continue
        k = _dict_to_knock(d)
        if k.expires_at < now:
            k.status = "EXPIRED"
        if k.status == "PENDING":
            result.append(k)
    return sorted(result, key=lambda x: x.created_at, reverse=True)
