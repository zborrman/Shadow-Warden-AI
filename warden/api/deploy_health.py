"""
warden/api/deploy_health.py
───────────────────────────
GET /deploy/status — aggregate health for all 11 Docker services.

Probed internally (from the warden container):
  warden     — self, always OK
  redis      — ping via warden.cache
  postgres   — asyncpg SELECT 1 via DATABASE_URL
  minio      — GET /minio/health/live
  prometheus — GET /-/healthy
  grafana    — GET /api/health
  app        — GET /health  (app:8000)
  analytics  — GET /      (analytics:8002)
  arq_worker — Redis sentinel key sova:heartbeat

Reported without active probe:
  proxy      — Caddy :80/443, assumed up if request reached warden
  dashboard  — Next.js :3002, client-side
"""
from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter

from warden.config import settings

router = APIRouter(prefix="/deploy", tags=["ops"])

_MINIO_URL    = settings.minio_url
_PROM_URL     = settings.prometheus_url
_GRAFANA_URL  = settings.grafana_url
_APP_URL      = settings.app_url
_ANALYTICS_URL= settings.analytics_int_url
_DATABASE_URL = settings.database_url
_TIMEOUT      = 2.0


def _ok(name: str, display: str, latency: float, detail: str = "OK") -> dict:
    return {"name": name, "display": display, "status": "ok",
            "latency_ms": round(latency, 2), "detail": detail}


def _fail(name: str, display: str, detail: str) -> dict:
    return {"name": name, "display": display, "status": "down",
            "latency_ms": None, "detail": detail}


def _unknown(name: str, display: str, detail: str = "not probed") -> dict:
    return {"name": name, "display": display, "status": "unknown",
            "latency_ms": None, "detail": detail}


def _check_redis() -> dict:
    try:
        from warden.cache import _get_client
        client = _get_client()
        if client is None:
            return _unknown("redis", "Redis")
        t0 = time.perf_counter()
        client.ping()
        lat = (time.perf_counter() - t0) * 1000
        # also check ARQ heartbeat key
        arq_ok = bool(client.exists("sova:heartbeat") or client.keys("arq:*"))
        return {**_ok("redis", "Redis", lat), "arq_worker_seen": arq_ok}
    except Exception as exc:
        return _fail("redis", "Redis", str(exc))


async def _http_check(name: str, display: str, url: str, ok_text: str = "") -> dict:
    try:
        import httpx
        t0 = time.perf_counter()
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            r = await client.get(url)
        lat = (time.perf_counter() - t0) * 1000
        if r.status_code < 400:
            detail = ok_text or r.text[:80].strip() or f"HTTP {r.status_code}"
            return _ok(name, display, lat, detail)
        return {"name": name, "display": display, "status": "degraded",
                "latency_ms": round(lat, 2), "detail": f"HTTP {r.status_code}"}
    except Exception as exc:
        return _fail(name, display, str(exc)[:120])


async def _postgres_check() -> dict:
    if not _DATABASE_URL:
        return _unknown("postgres", "PostgreSQL", "DATABASE_URL not set")
    try:
        import asyncpg
        t0 = time.perf_counter()
        conn = await asyncio.wait_for(asyncpg.connect(_DATABASE_URL), timeout=_TIMEOUT)
        await conn.fetchval("SELECT 1")
        await conn.close()
        lat = (time.perf_counter() - t0) * 1000
        return _ok("postgres", "PostgreSQL", lat)
    except ImportError:
        return _unknown("postgres", "PostgreSQL", "asyncpg not installed")
    except Exception as exc:
        return _fail("postgres", "PostgreSQL", str(exc)[:120])


async def _arq_check(redis_result: dict) -> dict:
    seen = redis_result.get("arq_worker_seen", False)
    return {
        "name": "arq_worker",
        "display": "ARQ Worker",
        "status": "ok" if seen else "unknown",
        "latency_ms": None,
        "detail": "heartbeat key found" if seen else "no Redis heartbeat key (may still be running)",
    }


@router.get("/status", summary="Aggregate service health")
async def deploy_status() -> dict[str, Any]:
    redis_result = _check_redis()

    results = await asyncio.gather(
        _http_check("minio",      "MinIO",       f"{_MINIO_URL}/minio/health/live"),
        _http_check("prometheus", "Prometheus",  f"{_PROM_URL}/-/healthy", "Prometheus is Healthy."),
        _http_check("grafana",    "Grafana",     f"{_GRAFANA_URL}/api/health"),
        _http_check("app",        "App Service", f"{_APP_URL}/health"),
        _http_check("analytics",  "Analytics",   f"{_ANALYTICS_URL}/api/v1/stats"),
        _postgres_check(),
        _arq_check(redis_result),
    )

    minio, prom, grafana, app, analytics, postgres, arq = results

    services: list[dict] = [
        {   "name": "warden", "display": "Filter Gateway",
            "status": "ok", "latency_ms": 0.1,
            "detail": "serving this request"},
        {k: v for k, v in redis_result.items() if k != "arq_worker_seen"},
        postgres, minio, prom, grafana, app, analytics, arq,
        _unknown("proxy",     "Caddy Proxy",     "assumed up (request reached warden)"),
        _unknown("dashboard", "SOC Dashboard",   "Next.js :3002, not probed from here"),
    ]

    statuses = [s["status"] for s in services]
    if "down" in statuses:
        overall = "down"
    elif "degraded" in statuses:
        overall = "degraded"
    elif "unknown" in statuses:
        overall = "partial"
    else:
        overall = "ok"

    ok_count = sum(1 for s in statuses if s == "ok")

    return {
        "checked_at": datetime.now(UTC).isoformat(),
        "overall":    overall,
        "ok_count":   ok_count,
        "total":      len(services),
        "services":   services,
    }
