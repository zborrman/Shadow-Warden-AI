"""
warden/sovereign/preflight.py
──────────────────────────────
Preflight checks for MASQUE tunnel creation.

Before a tunnel is registered for a jurisdiction, this module verifies
that the supporting services (MinIO, Redis, main API) are reachable and
within acceptable latency bounds.

Each check:
  - Runs with a 5-second timeout.
  - Returns {service, status, latency_ms, error}.

Aggregate result:
  {all_ok: bool, jurisdiction: str, checks: list[dict]}
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any

log = logging.getLogger("warden.sovereign.preflight")

_PREFLIGHT_TIMEOUT = float(os.getenv("PREFLIGHT_TIMEOUT_S", "5.0"))
_MINIO_URL = os.getenv("MINIO_ENDPOINT", "http://minio:9000")
_WARDEN_API = os.getenv("WARDEN_INTERNAL_URL", "http://localhost:8001")
_REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")


# ── Single check result ───────────────────────────────────────────────────────

def _check_result(service: str, ok: bool, latency_ms: float, error: str | None = None) -> dict:
    return {
        "service":    service,
        "status":     "ok" if ok else "fail",
        "latency_ms": round(latency_ms, 1),
        "error":      error,
    }


# ── Individual checks ─────────────────────────────────────────────────────────

async def _check_minio(client: Any) -> dict:
    url = f"{_MINIO_URL.rstrip('/')}/minio/health/live"
    t0 = time.perf_counter()
    try:
        r = await client.get(url, timeout=_PREFLIGHT_TIMEOUT)
        latency = (time.perf_counter() - t0) * 1000
        return _check_result("minio", r.status_code < 400, latency)
    except Exception as exc:
        latency = (time.perf_counter() - t0) * 1000
        return _check_result("minio", False, latency, str(exc))


async def _check_warden_api(client: Any) -> dict:
    url = f"{_WARDEN_API.rstrip('/')}/health"
    t0 = time.perf_counter()
    try:
        r = await client.get(url, timeout=_PREFLIGHT_TIMEOUT)
        latency = (time.perf_counter() - t0) * 1000
        return _check_result("warden_api", r.status_code < 400, latency)
    except Exception as exc:
        latency = (time.perf_counter() - t0) * 1000
        return _check_result("warden_api", False, latency, str(exc))


def _check_redis_sync() -> dict:
    t0 = time.perf_counter()
    try:
        import redis as _redis
        url = _REDIS_URL
        if url.startswith("memory://"):
            latency = (time.perf_counter() - t0) * 1000
            return _check_result("redis", True, latency)
        r = _redis.from_url(url, socket_connect_timeout=_PREFLIGHT_TIMEOUT)
        r.ping()
        latency = (time.perf_counter() - t0) * 1000
        return _check_result("redis", True, latency)
    except Exception as exc:
        latency = (time.perf_counter() - t0) * 1000
        return _check_result("redis", False, latency, str(exc))


# ── Preflight orchestrator ────────────────────────────────────────────────────

async def preflight_check(jurisdiction: str) -> dict:
    """
    Run all preflight checks for the target jurisdiction.

    Returns:
        {
            "all_ok":       bool,
            "jurisdiction": str,
            "checks":       list[{service, status, latency_ms, error}]
        }

    Side effects:
        - Increments warden_tunnel_preflight_total{region, status} Prometheus counter.
    """
    import asyncio

    try:
        import httpx
        async_http_available = True
    except ImportError:
        async_http_available = False

    checks: list[dict] = []

    if async_http_available:
        import httpx as _httpx
        async with _httpx.AsyncClient() as client:
            minio_task  = asyncio.create_task(_check_minio(client))
            api_task    = asyncio.create_task(_check_warden_api(client))
            minio_res, api_res = await asyncio.gather(minio_task, api_task)
        checks.extend([minio_res, api_res])
    else:
        checks.append(_check_result("minio", False, 0.0, "httpx not installed"))
        checks.append(_check_result("warden_api", False, 0.0, "httpx not installed"))

    redis_res = _check_redis_sync()
    checks.append(redis_res)

    all_ok = all(c["status"] == "ok" for c in checks)

    result = {
        "all_ok":       all_ok,
        "jurisdiction": jurisdiction.upper(),
        "checks":       checks,
    }

    # Prometheus metric
    status_label = "ok" if all_ok else "fail"
    try:
        from warden.metrics import TUNNEL_PREFLIGHT_TOTAL
        TUNNEL_PREFLIGHT_TOTAL.labels(region=jurisdiction.upper(), status=status_label).inc()
    except Exception:
        pass

    log.info(
        "preflight_check %s → %s  (%d/%d checks ok)",
        jurisdiction.upper(),
        status_label,
        sum(1 for c in checks if c["status"] == "ok"),
        len(checks),
    )
    return result
