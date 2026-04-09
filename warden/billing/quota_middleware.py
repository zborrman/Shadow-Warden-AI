"""
warden/billing/quota_middleware.py
────────────────────────────────────
Per-request monthly quota enforcement for Shadow Warden AI.

How it works
────────────
  1. Each POST /filter (or /filter/batch) increments a Redis counter:
         warden:quota:req:{tenant_id}:{YYYY-MM}
     The first INCRBY in a month sets a 35-day TTL so old keys self-clean.

  2. The effective limit = plan.req_per_month + referral_bonus_requests.
     - None (Enterprise unlimited) → always passes.
     - Individual / Starter: hard stop at limit (HTTP 429, upgrade link).
     - Pro / Enterprise with overage_enabled=True: soft stop — logs the
       overage event and lets the request through for metered billing.

  3. Middleware is injected at ASGI level so it applies to every worker
     without duplicating logic in each route handler.

Tested paths (quota-counted)
─────────────────────────────
  POST /filter
  POST /filter/batch

All other paths (health, billing, subscription, …) are NOT counted.

ENV
───
  QUOTA_HARD_BLOCK  — default "true". Set to "false" to disable hard-stops
                      globally (e.g. in load-testing environments).
"""
from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime

log = logging.getLogger("warden.billing.quota_middleware")

_COUNTED_PATHS = frozenset({"/filter", "/filter/batch"})
_HARD_BLOCK    = os.getenv("QUOTA_HARD_BLOCK", "true").lower() != "false"
_KEY_TTL       = 35 * 86400  # ~35 days


def _redis():
    """Return a sync Redis client (None on failure)."""
    try:
        import redis as _r

        from warden.config import settings
        return _r.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=1,
        )
    except Exception:
        return None


def _quota_key(tenant_id: str) -> str:
    month = datetime.now(UTC).strftime("%Y-%m")
    return f"warden:quota:req:{tenant_id}:{month}"


def _get_tenant_id_from_scope(scope: dict) -> str:
    """
    Extract tenant_id from the request state set by auth middleware,
    or fall back to the X-Tenant-ID header.
    """
    state  = scope.get("state", {})
    tenant = getattr(state, "tenant", None) or (state if isinstance(state, dict) else {})
    if isinstance(tenant, dict) and tenant.get("tenant_id"):
        return str(tenant["tenant_id"])
    # Header fallback (b"x-tenant-id")
    headers = dict(scope.get("headers", []))
    raw = headers.get(b"x-tenant-id", b"").decode("utf-8", errors="ignore")
    return raw or "anonymous"


def _get_plan_from_scope(scope: dict, tenant_id: str) -> str:
    """
    Resolve the tenant's active plan.
    Tries request state first, then LemonBilling DB as fallback.
    """
    state  = scope.get("state", {})
    tenant = getattr(state, "tenant", None) or (state if isinstance(state, dict) else {})
    if isinstance(tenant, dict) and tenant.get("plan"):
        return str(tenant["plan"])
    if isinstance(tenant, dict) and tenant.get("tier"):
        return str(tenant["tier"])
    try:
        from warden.lemon_billing import get_lemon_billing
        return get_lemon_billing().get_plan(tenant_id)
    except Exception:
        return "starter"


async def _send_429(send, detail: str, upgrade_url: str) -> None:
    body = json.dumps({
        "detail":      detail,
        "error":       "quota_exceeded",
        "upgrade_url": upgrade_url,
    }).encode()
    await send({
        "type":    "http.response.start",
        "status":  429,
        "headers": [
            (b"content-type",   b"application/json"),
            (b"content-length", str(len(body)).encode()),
            (b"retry-after",    b"86400"),
        ],
    })
    await send({"type": "http.response.body", "body": body})


class QuotaMiddleware:
    """
    ASGI middleware that enforces monthly request quotas.

    Mount AFTER auth middleware so request.state.tenant is populated.

    app.add_middleware(QuotaMiddleware)
    """

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path   = scope.get("path", "")
        method = scope.get("method", "GET")

        # Only count POST requests to gated paths
        if method != "POST" or path not in _COUNTED_PATHS:
            await self.app(scope, receive, send)
            return

        tenant_id = _get_tenant_id_from_scope(scope)
        plan      = _get_plan_from_scope(scope, tenant_id)

        from warden.billing.feature_gate import TIER_LIMITS, _normalize_tier
        tier   = _normalize_tier(plan)
        limits = TIER_LIMITS.get(tier, TIER_LIMITS["starter"])
        limit  = limits.get("req_per_month")

        # Enterprise / unlimited plan — skip quota check entirely
        if limit is None:
            await self.app(scope, receive, send)
            return

        # Extend limit with any referral bonuses earned this month
        try:
            from warden.billing.referral import get_bonus_requests
            limit += get_bonus_requests(tenant_id)
        except Exception:
            pass

        # Increment Redis counter
        r = _redis()
        if r is None:
            # Redis unavailable — fail-open
            log.warning("quota_middleware: Redis unavailable, skipping quota check for tenant=%s", tenant_id)
            await self.app(scope, receive, send)
            return

        try:
            key       = _quota_key(tenant_id)
            new_total = r.incr(key)
            if new_total == 1:
                r.expire(key, _KEY_TTL)
        except Exception as exc:
            log.warning("quota_middleware: Redis INCR error tenant=%s: %s", tenant_id, exc)
            await self.app(scope, receive, send)
            return

        if new_total > limit:
            overage_enabled = limits.get("overage_enabled", False)
            upgrade_url     = _build_upgrade_url(tier)

            if overage_enabled:
                # Soft stop: pass through but emit overage log
                log.warning(
                    "quota_middleware: OVERAGE tenant=%s plan=%s requests=%d limit=%d",
                    tenant_id, tier, new_total, limit,
                )
                await self.app(scope, receive, send)
                return

            if not _HARD_BLOCK:
                log.warning(
                    "quota_middleware: SOFT-BLOCK (QUOTA_HARD_BLOCK=false) tenant=%s plan=%s requests=%d limit=%d",
                    tenant_id, tier, new_total, limit,
                )
                await self.app(scope, receive, send)
                return

            # Hard stop — roll back the counter (request was not served)
            import contextlib
            with contextlib.suppress(Exception):
                r.decr(key)

            await _send_429(
                send,
                detail=(
                    f"Monthly request quota exceeded: {new_total - 1}/{limit} "
                    f"on {tier.upper()} plan. Upgrade to continue."
                ),
                upgrade_url=upgrade_url,
            )
            return

        await self.app(scope, receive, send)


def get_quota_usage(tenant_id: str) -> dict:
    """
    Return current monthly request usage for *tenant_id*.

    {
      "tenant_id":   str,
      "plan":        str,
      "used":        int,
      "limit":       int | None,   # None = unlimited
      "bonus_req":   int,
      "effective_limit": int | None,
      "pct_used":    float | None, # 0.0–100.0
    }
    """
    try:
        from warden.lemon_billing import get_lemon_billing
        plan = get_lemon_billing().get_plan(tenant_id)
    except Exception:
        plan = "starter"

    from warden.billing.feature_gate import TIER_LIMITS, _normalize_tier
    tier   = _normalize_tier(plan)
    limits = TIER_LIMITS.get(tier, TIER_LIMITS["starter"])
    limit  = limits.get("req_per_month")

    bonus = 0
    try:
        from warden.billing.referral import get_bonus_requests
        bonus = get_bonus_requests(tenant_id)
    except Exception:
        pass

    effective_limit = (limit + bonus) if limit is not None else None

    used = 0
    r    = _redis()
    if r is not None:
        try:
            raw = r.get(_quota_key(tenant_id))
            used = int(raw) if raw else 0
        except Exception:
            pass

    pct = None
    if effective_limit and effective_limit > 0:
        pct = round(min(used / effective_limit * 100.0, 100.0), 2)

    return {
        "tenant_id":       tenant_id,
        "plan":            tier,
        "used":            used,
        "limit":           limit,
        "bonus_req":       bonus,
        "effective_limit": effective_limit,
        "pct_used":        pct,
    }


def _build_upgrade_url(current_tier: str) -> str:
    base = os.getenv("PORTAL_BASE_URL", "https://app.shadowwarden.ai")
    next_tier_map = {
        "starter":    "individual",
        "individual": "pro",
        "pro":        "enterprise",
    }
    next_tier = next_tier_map.get(current_tier, "pro")
    return f"{base}/billing/upgrade?from={current_tier}&to={next_tier}&reason=quota"
