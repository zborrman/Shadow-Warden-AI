"""
warden/billing/trial.py
────────────────────────
14-day Pro trial management.

Rules
─────
  - One trial per tenant (Redis key `billing:trial:{tenant_id}`)
  - Trial gives Pro-equivalent features capped at 10 000 requests / 14 days
  - MasterAgent disabled during trial (Pro add-on restriction, not full Pro)
  - Trial auto-expires via Redis TTL; no cron needed
  - On expiry the tenant reverts to their previous tier (Starter by default)
  - `start_trial()` is idempotent — calling twice returns the existing trial

Storage
───────
  Redis hash  billing:trial:{tenant_id}
    started_at   ISO-8601 UTC
    expires_at   ISO-8601 UTC
    req_limit    10000
    previous_tier  original tier before trial

  Falls back to in-process dict when Redis unavailable.
"""
from __future__ import annotations

import logging
import os
from datetime import UTC, datetime, timedelta
from typing import Any

log = logging.getLogger("warden.billing.trial")

_TRIAL_DAYS        = int(os.getenv("TRIAL_DAYS", "14"))
_TRIAL_REQ_LIMIT   = int(os.getenv("TRIAL_REQ_LIMIT", "10000"))
_MEMORY_TRIALS: dict[str, dict[str, Any]] = {}


def _redis():
    try:
        import redis as _r
        url = os.getenv("REDIS_URL", "redis://localhost:6379")
        if url.startswith("memory://"):
            return None
        return _r.from_url(url, decode_responses=True)
    except Exception:
        return None


def _trial_key(tenant_id: str) -> str:
    return f"billing:trial:{tenant_id}"


# ── Public API ────────────────────────────────────────────────────────────────

def start_trial(tenant_id: str, current_tier: str = "starter") -> dict[str, Any]:
    """
    Activate a 14-day Pro trial for *tenant_id*.

    Returns trial metadata dict. Idempotent — returns existing trial if already active.
    Raises ValueError if tenant already consumed their one-time trial.
    """
    existing = get_trial(tenant_id)
    if existing:
        if existing["status"] == "active":
            return existing
        if existing["status"] == "expired":
            raise ValueError(
                f"Tenant {tenant_id!r} already used their trial. "
                "Upgrade to Pro at /billing/upgrade?plan=pro"
            )

    now = datetime.now(UTC)
    expires = now + timedelta(days=_TRIAL_DAYS)
    record: dict[str, Any] = {
        "tenant_id":     tenant_id,
        "started_at":    now.isoformat(),
        "expires_at":    expires.isoformat(),
        "req_limit":     _TRIAL_REQ_LIMIT,
        "previous_tier": current_tier,
        "status":        "active",
        "master_agent":  False,    # MasterAgent excluded from trial
        "days_remaining": _TRIAL_DAYS,
    }

    _MEMORY_TRIALS[tenant_id] = record
    r = _redis()
    if r:
        try:
            key = _trial_key(tenant_id)
            r.hset(key, mapping={
                "started_at":    record["started_at"],
                "expires_at":    record["expires_at"],
                "req_limit":     str(_TRIAL_REQ_LIMIT),
                "previous_tier": current_tier,
            })
            ttl = int((_TRIAL_DAYS + 1) * 86400)   # +1 day buffer for expiry check
            r.expire(key, ttl)
        except Exception as exc:
            log.warning("start_trial redis error tenant=%s: %s", tenant_id, exc)

    log.info("Trial started tenant=%s expires=%s", tenant_id, expires.isoformat())
    return record


def get_trial(tenant_id: str) -> dict[str, Any] | None:
    """
    Return current trial record for *tenant_id*, or None if no trial exists.

    Enriches with live `status` and `days_remaining`.
    """
    raw: dict[str, Any] | None = None

    r = _redis()
    if r:
        try:
            data = r.hgetall(_trial_key(tenant_id))
            if data:
                raw = data
        except Exception as exc:
            log.debug("get_trial redis error: %s", exc)

    if raw is None:
        raw = _MEMORY_TRIALS.get(tenant_id)

    if not raw:
        return None

    now = datetime.now(UTC)
    try:
        expires_at = datetime.fromisoformat(raw["expires_at"])
    except (KeyError, ValueError):
        return None

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)

    days_remaining = max(0, (expires_at - now).days)
    status = "active" if now < expires_at else "expired"

    return {
        "tenant_id":     tenant_id,
        "started_at":    raw.get("started_at"),
        "expires_at":    raw["expires_at"],
        "req_limit":     int(raw.get("req_limit", _TRIAL_REQ_LIMIT)),
        "previous_tier": raw.get("previous_tier", "starter"),
        "status":        status,
        "days_remaining": days_remaining,
        "master_agent":  False,
        "upgrade_url":   "/billing/upgrade?plan=pro",
    }


def is_trial_active(tenant_id: str) -> bool:
    """Return True if tenant has an active (non-expired) trial."""
    trial = get_trial(tenant_id)
    return trial is not None and trial["status"] == "active"


def get_trial_tier_limits() -> dict[str, Any]:
    """
    Return the TIER_LIMITS-compatible dict for an active trial.
    Pro features minus MasterAgent, capped at TRIAL_REQ_LIMIT requests.
    """
    from warden.billing.feature_gate import TIER_LIMITS
    limits = dict(TIER_LIMITS["pro"])
    limits["req_per_month"]      = _TRIAL_REQ_LIMIT
    limits["master_agent_enabled"] = False   # not included in trial
    limits["overage_enabled"]    = False     # no overages during trial
    limits["_is_trial"]          = True
    return limits
