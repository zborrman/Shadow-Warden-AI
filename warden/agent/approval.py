"""
warden/agent/approval.py
─────────────────────────
Human-in-the-loop approval gate for state-changing agent tools.

Enforcement lives in the tool layer: a gated handler called without a
*resolved* token returns {"status": "approval_required", "token": ...}
instead of executing. The action runs only after a human resolves the
token via POST /agent/execute/{token}.

Fail-closed: if the approval store (Redis) is unavailable, `issue()` raises
`ApprovalStoreUnavailableError` and the caller surfaces a 503 — a mutation is
never performed just because approvals could not be recorded.

Redis keys
──────────
  sova:approval:{token}          pending JSON  (TTL 1h)
  sova:approval:result:{token}   resolved JSON (TTL 1h)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time

log = logging.getLogger("warden.agent.approval")

_TTL = 3600


def _secret() -> bytes:
    """Signing key for approval tokens.

    Resolved through :func:`warden.secret_keys.resolve_key` so it fails CLOSED
    when unset in production. A module-level ``os.getenv(..., "<literal>")``
    would make every approval token forgeable by anyone who can read the repo.
    Same key material and purpose as master.py's task tokens.
    """
    from warden.secret_keys import resolve_key
    return resolve_key("MASTER_AGENT_SECRET", purpose="master_agent")

# Tool names that must not execute without a resolved approval token.
GATED_ACTIONS: frozenset[str] = frozenset({
    "update_config",
    "rotate_community_key",
    "revoke_agent",
    "block_ip_range",
    "dismiss_threat",
    "moderate_community_post",
    "publish_to_community",
    "post_community_announcement",
    "smb_provision_suite",
    "share_obsidian_note",
    "sync_misp_feed",
    "apply_community_recommendation",
    "revoke_mandate",
    "approve_purchase_intent",
    # AG-23 — both erase data irreversibly
    "run_gdpr_purge",
    "run_retention_enforce",
})


class ApprovalStoreUnavailableError(RuntimeError):
    """Raised when the approval store cannot be reached — caller must fail closed."""


def _redis_error_types() -> tuple[type[BaseException], ...]:
    """``redis.RedisError`` when the client is installed, nothing otherwise.

    Resolved once at import rather than appended to a module global on first
    use: a tuple that only becomes complete after some other function has run
    is a tuple whose contents depend on call order, and neither a reader nor
    mypy can confirm what a given ``except`` clause actually catches.
    """
    try:
        import redis  # noqa: PLC0415
    except ImportError:                                   # pragma: no cover
        return ()
    return (redis.RedisError,)


#: Everything a redis round-trip can realistically fail with. Named explicitly
#: rather than caught as a blanket ``Exception`` so a genuine bug in this module
#: (a typo, a bad json payload) still surfaces instead of reading as "store down".
_STORE_ERRORS: tuple[type[BaseException], ...] = (
    *_redis_error_types(), OSError, ValueError, TypeError,
)

#: The same set plus our own unavailability signal, for callers that fail soft.
#: Bound to a name because mypy cannot check a starred unpack in an `except`.
_STORE_OR_UNAVAILABLE: tuple[type[BaseException], ...] = (
    ApprovalStoreUnavailableError, *_STORE_ERRORS,
)


def _redis():
    import redis  # noqa: PLC0415
    url = os.getenv("REDIS_URL", "redis://localhost:6379")
    if not url or url == "memory://":
        raise ApprovalStoreUnavailableError("REDIS_URL not configured for approvals")
    try:
        r = redis.from_url(url, decode_responses=True)
        r.ping()
        return r
    except _STORE_ERRORS as exc:
        raise ApprovalStoreUnavailableError(str(exc)) from exc


def issue(action: str, context: str, tenant_id: str, params: dict | None = None) -> str:
    """Create a pending approval and return its token. Raises if the store is down."""
    ts = int(time.time())
    payload = f"{action}:{hashlib.sha256(context.encode()).hexdigest()[:16]}:{ts}"
    sig = hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest()[:24]
    token = f"appr-{sig}"
    r = _redis()
    r.setex(
        f"sova:approval:{token}",
        _TTL,
        json.dumps({
            "action":    action,
            "context":   context[:500],
            "params":    params or {},
            "tenant_id": tenant_id,
            "issued_at": ts,
            "status":    "pending",
        }),
    )
    log.info("approval: issued token=%s action=%s tenant=%s", token, action, tenant_id)
    return token


def get_pending(token: str) -> dict | None:
    try:
        raw = _redis().get(f"sova:approval:{token}")
    except ApprovalStoreUnavailableError:
        return None
    return json.loads(raw) if raw else None


def resolve(token: str, approved: bool) -> bool:
    """Consume a pending token, store the decision. Returns False if unknown/expired."""
    try:
        r = _redis()
    except ApprovalStoreUnavailableError:
        return False
    key = f"sova:approval:{token}"
    raw = r.get(key)
    if not raw:
        return False
    data = json.loads(raw)
    data["status"]      = "approved" if approved else "rejected"
    data["resolved_at"] = int(time.time())
    r.setex(f"sova:approval:result:{token}", _TTL, json.dumps(data))
    r.delete(key)
    log.info("approval: token=%s -> %s", token, data["status"])
    return True


def resolution(token: str) -> dict | None:
    """Return the resolved record ({status: approved|rejected, ...}) or None."""
    try:
        raw = _redis().get(f"sova:approval:result:{token}")
    except ApprovalStoreUnavailableError:
        return None
    return json.loads(raw) if raw else None


def is_approved(token: str) -> bool:
    rec = resolution(token)
    return bool(rec and rec.get("status") == "approved" and not rec.get("consumed"))


def mark_consumed(token: str) -> None:
    """Mark a resolved approval as spent so it cannot be replayed."""
    try:
        r = _redis()
        raw = r.get(f"sova:approval:result:{token}")
        if raw:
            data = json.loads(raw)
            data["consumed"] = True
            r.setex(f"sova:approval:result:{token}", _TTL, json.dumps(data))
    except _STORE_OR_UNAVAILABLE as exc:
        # Best-effort bookkeeping; try_consume() is the authoritative single-use
        # claim, so a failure here cannot let a token execute twice.
        log.warning("approval: mark_consumed failed for %s: %s", token, exc)


def try_consume(token: str) -> bool:
    """
    Atomically claim a resolved+approved token for a single execution.

    Returns True for exactly one caller; every subsequent call (concurrent or
    later) returns False. Fails closed if the store is unavailable.
    """
    try:
        rec = resolution(token)
        if not rec or rec.get("status") != "approved":
            return False
        r = _redis()
        # SET NX is atomic — only the first caller wins the claim.
        if not r.set(f"sova:approval:claimed:{token}", "1", nx=True, ex=_TTL):
            return False
        rec["consumed"] = True
        r.setex(f"sova:approval:result:{token}", _TTL, json.dumps(rec))
        return True
    except _STORE_OR_UNAVAILABLE:
        return False          # fail closed: an unclaimable token does not run
