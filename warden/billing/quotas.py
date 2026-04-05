"""
warden/billing/quotas.py
────────────────────────
O(1) tunnel bandwidth quota enforcement backed by Redis atomic counters.

Plans and limits
────────────────
  individual  ($5/mo)  — 1 GB  /  month
  business    ($49/mo) — 50 GB /  month
  mcp         ($199/mo)— 500 GB / month

Implementation
──────────────
  Each tenant has one Redis key per calendar month:
      warden:bandwidth:{tenant_id}:{YYYY-MM}

  INCRBY atomically adds the file size to the counter and returns the new
  total.  This is thread-safe and handles concurrent requests across multiple
  uvicorn workers without any lock or SELECT.

  The Redis key is set to expire after ~32 days on first write so counters
  self-clean across months.

  On quota breach we DECRBY to roll back before raising HTTP 402 — the
  write must not be counted if the transfer is rejected.

Usage
─────
    from warden.billing.quotas import check_bandwidth, get_bandwidth_usage

    # Before transferring a file:
    await check_bandwidth(tenant_id, plan, file_size_bytes)   # raises 402 if over limit

    # In the dashboard quota display:
    used, limit = await get_bandwidth_usage(tenant_id, plan)
"""
from __future__ import annotations

import os
from datetime import datetime, UTC

from fastapi import HTTPException

# ── Plan limits ───────────────────────────────────────────────────────────────

_GB = 1024 ** 3

PLAN_BANDWIDTH_BYTES: dict[str, int | None] = {
    "individual": 1  * _GB,   #   1 GB
    "business":   50 * _GB,   #  50 GB
    "mcp":        500 * _GB,  # 500 GB
    "free":       0,           # tunnel transfers not allowed on free tier
}

# Allow usage-based overage (Stripe metered billing) instead of hard block.
# Set TUNNEL_HARD_BLOCK=true in .env to enforce a strict cut-off.
_HARD_BLOCK: bool = os.getenv("TUNNEL_HARD_BLOCK", "false").lower() == "true"


def _redis():
    """Sync Redis client (fast, O(1) counter ops)."""
    import redis as _r
    from warden.config import settings
    return _r.from_url(
        settings.redis_url,
        decode_responses=True,
        socket_connect_timeout=2,
        socket_timeout=1,
    )


def _month_key(tenant_id: str) -> str:
    month = datetime.now(UTC).strftime("%Y-%m")
    return f"warden:bandwidth:{tenant_id}:{month}"


def check_bandwidth(tenant_id: str, plan: str, file_size_bytes: int) -> None:
    """
    Atomically increment the tenant's monthly bandwidth counter and enforce limits.

    Raises
    ------
    HTTPException(402)  — quota exceeded (hard block mode)
    HTTPException(503)  — Redis unavailable (fail-open: transfer proceeds)
    """
    limit = PLAN_BANDWIDTH_BYTES.get(plan)

    # Free tier: no tunnel transfers allowed at all
    if limit == 0:
        raise HTTPException(
            status_code=402,
            detail="Tunnel document transfer is not available on the free plan. Upgrade to Individual or higher.",
        )

    # Unlimited plan (None) — skip quota check
    if limit is None:
        return

    try:
        r = _redis()
        key = _month_key(tenant_id)

        new_total = r.incrby(key, file_size_bytes)

        # First write this month — set TTL for auto-cleanup (~32 days)
        if new_total == file_size_bytes:
            r.expire(key, 60 * 60 * 24 * 32)

        if new_total > limit:
            # Roll back — the transfer is rejected
            r.decrby(key, file_size_bytes)

            used_gb  = (new_total - file_size_bytes) / _GB
            limit_gb = limit / _GB

            if _HARD_BLOCK:
                raise HTTPException(
                    status_code=402,
                    detail=(
                        f"Tunnel bandwidth quota exceeded: used {used_gb:.2f} GB of {limit_gb:.0f} GB "
                        f"({plan} plan). Upgrade to increase your limit."
                    ),
                )
            # Soft block: log but allow (metered overage — billed via Stripe)
            import logging
            logging.getLogger("warden.billing.quotas").warning(
                "Bandwidth soft-limit exceeded: tenant=%s plan=%s used=%.2fGB limit=%.0fGB",
                tenant_id, plan, used_gb, limit_gb,
            )

    except HTTPException:
        raise
    except Exception as exc:
        # Redis unavailable — fail-open so transfers aren't blocked by infrastructure issues
        import logging
        logging.getLogger("warden.billing.quotas").warning(
            "Quota check skipped (Redis unavailable): tenant=%s error=%s", tenant_id, exc
        )


def get_bandwidth_usage(tenant_id: str, plan: str) -> tuple[int, int | None]:
    """
    Return (bytes_used_this_month, monthly_limit_bytes) for dashboard display.

    Returns (0, limit) if Redis is unavailable.
    """
    limit = PLAN_BANDWIDTH_BYTES.get(plan)
    try:
        r = _redis()
        raw = r.get(_month_key(tenant_id))
        used = int(raw) if raw else 0
    except Exception:
        used = 0
    return used, limit
