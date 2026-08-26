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

import asyncio
import json
import logging
import os
from datetime import UTC, datetime

log = logging.getLogger("warden.billing.quota_middleware")

_COUNTED_PATHS = frozenset({"/filter", "/filter/batch"})
_HARD_BLOCK    = os.getenv("QUOTA_HARD_BLOCK", "true").lower() != "false"
_KEY_TTL       = 35 * 86400  # ~35 days


_CLIENT: object | None = None


def _reset_client() -> None:
    """Drop the cached client. For tests, and for anything that must re-resolve."""
    global _CLIENT
    _CLIENT = None


def _redis():
    """Return a sync Redis client, built once per process (None on failure).

    This used to call ``from_url`` on every request. ``from_url`` builds a new
    ConnectionPool each time, so every request opened its own TCP connection to
    Redis and threw it away — the pool existed but was never reused. Most of the
    time that is invisible against a local Redis; occasionally the connect
    stalls, and the client then spends its whole retry budget
    (``socket_connect_timeout`` 2s plus ``socket_timeout`` 1s, retried) before
    giving up.

    Measured on production: a stall of 5028-5168 ms, attributed to this
    middleware by per-layer spans —

        mw.QuotaMiddleware      own = 5067.9ms
        mw.RegionMiddleware     own =      0.5ms   (the next layer down)
        every layer above it    own =  0.0-0.5ms

    The client is cheap to hold and thread-safe, so it is cached. The retry
    budget is unchanged: the point is to stop paying connection setup per
    request, not to hide a Redis outage.
    """
    # Only a *successful* client is cached.
    #
    # The first version of this cached the function, lru_cache and all, which
    # also cached the None returned on failure. The caller treats None as
    # "Redis unavailable — fail open", so a single construction failure would
    # have disabled quota enforcement for every request until the process
    # restarted. A cost control that switches itself off permanently on one
    # transient error is worse than one that is slow.
    global _CLIENT
    if _CLIENT is not None:
        return _CLIENT
    try:
        import redis as _r

        from warden.config import settings
        _CLIENT = _r.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=1,
        )
        return _CLIENT
    except Exception:
        return None


def _quota_key(tenant_id: str) -> str:
    month = datetime.now(UTC).strftime("%Y-%m")
    return f"warden:quota:req:{tenant_id}:{month}"


def _get_tenant_id_from_scope(scope: dict) -> str:
    """
    Resolve the caller's tenant_id.

    NOTE ON ORDERING: this middleware runs at the ASGI layer, i.e. BEFORE the
    route's ``Depends(require_api_key)`` executes, and there is no auth
    *middleware* that populates ``request.state.tenant``. So the state branch is
    effectively never populated in production, and a bare fallback to
    ``"anonymous"`` collapses EVERY authenticated caller — who sends
    ``X-API-Key`` but not ``X-Tenant-ID`` — into one shared bucket. That let the
    entire ``/filter`` endpoint hit the starter 1000/month cap in aggregate and
    hard-block all traffic. So we resolve the API key ourselves here, the same
    way ``require_api_key`` will, before conceding "anonymous".

    IDENTITY IS TRUST-ANCHORED TO THE API KEY, never to a client-supplied
    ``X-Tenant-ID`` header. Charging quota against a header value the caller
    controls would let an unauthenticated request pick whose bucket it drains —
    burn a victim tenant's allowance, or name an unlimited-plan tenant to evade
    its own quota entirely. The only tenant selectors are populated auth state
    (trusted) and ``resolve_tenant_id`` over the presented key.
    """
    state  = scope.get("state", {})
    tenant = getattr(state, "tenant", None) or (state if isinstance(state, dict) else {})
    if isinstance(tenant, dict) and tenant.get("tenant_id"):
        return str(tenant["tenant_id"])

    headers = dict(scope.get("headers", []))

    # Resolve the API key → tenant, mirroring require_api_key. A single-key
    # deployment maps every key to "default"; a multi-key store maps each key to
    # its own tenant, giving each customer their own quota bucket.
    api_key = headers.get(b"x-api-key", b"").decode("utf-8", errors="ignore")
    if api_key:
        try:
            from warden.auth_guard import resolve_tenant_id
            resolved = resolve_tenant_id(api_key)
            if resolved:
                return resolved
        except Exception as _exc:  # noqa: BLE001
            log.debug("quota_middleware: tenant resolve failed (%s)", type(_exc).__name__)

    return "anonymous"


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
        except Exception as _exc:  # noqa: BLE001
            log.debug("suppressed exception: %r", _exc)

        # Increment Redis counter
        r = _redis()
        if r is None:
            # Redis unavailable — fail-open
            log.warning("quota_middleware: Redis unavailable, skipping quota check for tenant=%s", tenant_id)
            await self.app(scope, receive, send)
            return

        try:
            key = _quota_key(tenant_id)

            # ── Off the event loop ────────────────────────────────────────────
            # redis-py's client is synchronous. These calls sat directly in an
            # async ASGI __call__, so a slow Redis operation did not just delay
            # this request — it pinned the whole event loop, and every other
            # request in flight stalled for the same duration. That is why the
            # 5s stalls appeared on unrelated, otherwise-clean requests, before
            # their bodies had even been read.
            def _bump() -> int:
                total = r.incr(key)
                if total == 1:
                    r.expire(key, _KEY_TTL)
                return int(total)

            new_total = await asyncio.to_thread(_bump)
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
    except Exception as _exc:  # noqa: BLE001
        log.debug("suppressed exception: %r", _exc)

    effective_limit = (limit + bonus) if limit is not None else None

    used = 0
    r    = _redis()
    if r is not None:
        try:
            raw = r.get(_quota_key(tenant_id))
            used = int(raw) if raw else 0
        except Exception as _exc:  # noqa: BLE001
            log.debug("suppressed exception: %r", _exc)

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
