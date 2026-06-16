"""
warden/marketplace/rate_limit.py
────────────────────────────────
FastAPI dependency for marketplace rate limiting.

100 req/min per tenant (default); reuses the Redis sliding-window logic
from warden.m2m_store.security but keyed on tenant_id instead of agent_id.

Usage:
    from warden.marketplace.rate_limit import marketplace_rate_limit
    router = APIRouter(dependencies=[Depends(marketplace_rate_limit)])
"""
from __future__ import annotations

import os
import time

from fastapi import HTTPException, Request, Response

_RATE_LIMIT = int(os.getenv("MARKETPLACE_RATE_LIMIT_PER_MINUTE", "100"))
_RATE_WINDOW = 60

_mem_counters: dict[str, list[float]] = {}


def _redis():
    try:
        import redis as _r
        url = os.getenv("REDIS_URL", "redis://localhost:6379")
        if "memory://" in url:
            return None
        return _r.from_url(url, decode_responses=True, socket_connect_timeout=1)
    except Exception:
        return None


def _check_and_count(tenant_id: str) -> tuple[bool, int]:
    """Return (allowed, remaining). Remaining is approximate."""
    key = f"mkt:rl:{tenant_id}"
    now = time.time()
    window_start = now - _RATE_WINDOW

    r = _redis()
    if r is not None:
        try:
            pipe = r.pipeline()
            pipe.zremrangebyscore(key, 0, window_start)
            pipe.zadd(key, {str(now): now})
            pipe.zcard(key)
            pipe.expire(key, _RATE_WINDOW * 2)
            results = pipe.execute()
            count = int(results[2])
            allowed = count <= _RATE_LIMIT
            remaining = max(0, _RATE_LIMIT - count)
            return allowed, remaining
        except Exception:
            pass

    hits = _mem_counters.setdefault(tenant_id, [])
    _mem_counters[tenant_id] = [t for t in hits if t > window_start]
    _mem_counters[tenant_id].append(now)
    count = len(_mem_counters[tenant_id])
    allowed = count <= _RATE_LIMIT
    remaining = max(0, _RATE_LIMIT - count)
    return allowed, remaining


async def marketplace_rate_limit(request: Request, response: Response) -> None:
    tenant_id = (
        request.headers.get("X-Tenant-ID")
        or request.headers.get("X-API-Key", "")[:16]
        or request.client.host  # type: ignore[union-attr]
        or "anonymous"
    )

    allowed, remaining = _check_and_count(tenant_id)
    response.headers["X-RateLimit-Limit"] = str(_RATE_LIMIT)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    response.headers["X-RateLimit-Reset"] = str(int(time.time()) + _RATE_WINDOW)

    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Marketplace rate limit exceeded",
            headers={
                "Retry-After": str(_RATE_WINDOW),
                "X-RateLimit-Limit": str(_RATE_LIMIT),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(time.time()) + _RATE_WINDOW),
            },
        )
