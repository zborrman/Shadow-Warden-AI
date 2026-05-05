"""
warden/site/approval.py
───────────────────────
HMAC-SHA256 approval token store for Tier-1 configuration changes.

Tier-1 keys: ANTHROPIC_API_KEY, WARDEN_API_KEY, VAULT_MASTER_KEY,
             NVIDIA_API_KEY, ADMIN_KEY

Flow:
  1. POST /api/config with a Tier-1 key → returns 202 + approval_token
  2. Slack webhook receives "Approve? /api/config/approve/<token>"
  3. Admin calls POST /api/config/approve/<token>?action=approve|reject
  4. On approve: change applied, evidence written to MinIO (fail-open)
  5. Token consumed (one-time use, 1h TTL)

Storage: Redis `config:approval:{token}` (1h TTL).
Fallback: in-process dict when Redis unavailable (single-instance only).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime

log = logging.getLogger("warden.site.approval")

_TTL = 3600          # 1 hour
_PREFIX = "config:approval:"

# Keys that require human approval before being applied
TIER1_KEYS: frozenset[str] = frozenset({
    "anthropic_api_key",
    "warden_api_key",
    "vault_master_key",
    "nvidia_api_key",
    "admin_key",
    "super_admin_key",
})

_local_store: dict[str, dict] = {}   # fallback when Redis unavailable


@dataclass
class PendingChange:
    token:        str
    key:          str
    new_value:    str           # redacted in responses
    requested_by: str           # tenant_id or IP
    issued_at:    float = field(default_factory=time.time)
    status:       str   = "pending"   # pending | approved | rejected

    def is_expired(self) -> bool:
        return time.time() - self.issued_at > _TTL

    def redacted(self) -> dict:
        return {
            "token":        self.token,
            "key":          self.key,
            "new_value":    "***",
            "requested_by": self.requested_by,
            "issued_at":    datetime.fromtimestamp(self.issued_at, UTC).isoformat(),
            "status":       self.status,
        }


def _redis():
    url = os.getenv("REDIS_URL", "")
    if not url or url.startswith("memory://"):
        return None
    try:
        import redis as _redis_lib  # noqa: PLC0415
        return _redis_lib.from_url(url, decode_responses=True)
    except Exception:
        return None


def _sign(token: str) -> str:
    key = os.getenv("ADMIN_KEY", os.getenv("VAULT_MASTER_KEY", "fallback-insecure"))
    return hmac.new(key.encode(), token.encode(), hashlib.sha256).hexdigest()


def issue_token(key: str, new_value: str, requested_by: str = "unknown") -> PendingChange:
    """Create and store a new approval token. Returns the PendingChange."""
    raw = secrets.token_urlsafe(32)
    sig = _sign(raw)
    token = f"{raw}.{sig[:16]}"

    change = PendingChange(
        token=token,
        key=key,
        new_value=new_value,
        requested_by=requested_by,
    )
    _save(change)
    return change


def resolve_token(token: str, action: str) -> PendingChange | None:
    """
    Mark token as approved or rejected. Returns None if not found / expired.
    One-time use — deletes token after resolution.
    """
    change = _load(token)
    if change is None:
        return None
    if change.is_expired() or change.status != "pending":
        _delete(token)
        return None
    change.status = action   # "approved" | "rejected"
    _delete(token)
    return change


def get_pending(token: str) -> PendingChange | None:
    change = _load(token)
    if change and change.is_expired():
        _delete(token)
        return None
    return change


def list_pending() -> list[dict]:
    r = _redis()
    if r:
        try:
            keys = r.keys(f"{_PREFIX}*")
            items = []
            for k in keys:
                raw = r.get(k)
                if raw:
                    items.append(json.loads(raw))
            return [PendingChange(**d).redacted() for d in items]
        except Exception as exc:
            log.warning("approval list_pending redis error: %s", exc)
    return [PendingChange(**d).redacted() for d in _local_store.values()]


# ── Private helpers ───────────────────────────────────────────────────────────

def _save(change: PendingChange) -> None:
    r = _redis()
    payload = json.dumps(asdict(change))
    if r:
        try:
            r.setex(f"{_PREFIX}{change.token}", _TTL, payload)
            return
        except Exception as exc:
            log.warning("approval save redis error: %s", exc)
    _local_store[change.token] = asdict(change)


def _load(token: str) -> PendingChange | None:
    r = _redis()
    if r:
        try:
            raw = r.get(f"{_PREFIX}{token}")
            if raw:
                return PendingChange(**json.loads(raw))
        except Exception as exc:
            log.warning("approval load redis error: %s", exc)
    data = _local_store.get(token)
    return PendingChange(**data) if data else None


def _delete(token: str) -> None:
    r = _redis()
    if r:
        try:
            r.delete(f"{_PREFIX}{token}")
        except Exception as exc:
            log.warning("approval delete redis error: %s", exc)
    _local_store.pop(token, None)
