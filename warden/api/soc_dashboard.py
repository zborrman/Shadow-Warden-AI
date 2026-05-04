"""
Internal SOC Dashboard REST API — /soc/*

Requires X-Admin-Key header on all write endpoints.
Read endpoints are open (deployed behind VPN in production).

Endpoints:
  GET  /soc/health       — circuit breaker state, bypass ratio, ERS bans, heap
  GET  /soc/healer       — last WardenHealer report
  GET  /soc/metrics      — Prometheus snapshot (key counters)
  GET  /soc/posture      — security posture badge (thin wrapper, for SOC sidebar)
  POST /soc/heal         — trigger WardenHealer run manually (admin)
"""
from __future__ import annotations

import hmac
import logging
import os
import time
from typing import Annotated

import httpx
from fastapi import APIRouter, Header, HTTPException

log = logging.getLogger("warden.api.soc_dashboard")

router = APIRouter(prefix="/soc", tags=["soc"])

_WARDEN_BASE = os.getenv("WARDEN_INTERNAL_URL", "http://localhost:8001")
_TIMEOUT     = 5.0


def _require_admin(key: str | None) -> None:
    admin = os.getenv("ADMIN_KEY", "")
    if not admin or not key or not hmac.compare_digest(key, admin):
        raise HTTPException(status_code=403, detail="Admin key required")


async def _get_health() -> dict:
    """Fetch /health from warden core. Fail-open with error dict."""
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.get(f"{_WARDEN_BASE}/health")
            r.raise_for_status()
            return r.json()
    except Exception as exc:
        log.warning("soc: health fetch failed: %s", exc)
        return {"error": str(exc), "status": "unreachable"}


async def _get_stats() -> dict:
    """Fetch /stats from warden core."""
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.get(f"{_WARDEN_BASE}/stats")
            r.raise_for_status()
            return r.json()
    except Exception as exc:
        log.warning("soc: stats fetch failed: %s", exc)
        return {"error": str(exc)}


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/health")
async def soc_health():
    """
    Core warden health snapshot for the SOC sidebar.
    Returns circuit_breaker state, bypass_rate_1m, ERS ban count, uptime.
    Refresh every ≤30s.
    """
    health = await _get_health()
    stats  = await _get_stats()

    return {
        "circuit_breaker": health.get("circuit_breaker", {}),
        "bypass_rate_1m":  health.get("bypass_rate_1m",  0.0),
        "ers_bans_active": stats.get("ers_bans_active",  0),
        "requests_1m":     stats.get("requests_1m",      0),
        "block_rate_1m":   stats.get("block_rate_1m",    0.0),
        "uptime_seconds":  health.get("uptime_seconds",  0),
        "warden_version":  health.get("version",         "unknown"),
        "snapshot_ts":     time.time(),
    }


@router.get("/healer")
async def soc_healer():
    """Last WardenHealer diagnostic report — issues, actions, trend prediction."""
    try:
        from warden.agent.healer import WardenHealer
        healer = WardenHealer()
        report = await healer.run()
        return {
            "issues":                  report.issues,
            "actions":                 report.actions,
            "alerted":                 report.alerted,
            "incident_classification": report.incident_classification,
            "ts":                      report.ts,
        }
    except Exception as exc:
        log.warning("soc/healer: failed: %s", exc)
        return {"error": str(exc)}


@router.get("/metrics")
async def soc_metrics():
    """Key Prometheus counters in JSON form (avoids Grafana dependency for SOC quick-view)."""
    stats = await _get_stats()
    health = await _get_health()
    return {
        "filter_requests_total": stats.get("requests_total", 0),
        "block_total":           stats.get("block_total",    0),
        "shadow_ban_total":      stats.get("shadow_ban_total", 0),
        "evolution_runs":        stats.get("evolution_runs",  0),
        "cache_hits":            stats.get("cache_hits",      0),
        "circuit_breaker_trips": health.get("circuit_breaker", {}).get("trips", 0),
        "snapshot_ts":           time.time(),
    }


@router.get("/posture")
async def soc_posture():
    """Security posture badge — thin proxy to /security/posture for SOC sidebar."""
    from warden.api.security_hub import _compute_posture
    return _compute_posture()


@router.post("/heal", status_code=202)
async def trigger_heal(
    x_admin_key: Annotated[str | None, Header()] = None,
):
    """Trigger a WardenHealer diagnostic run now (admin only)."""
    _require_admin(x_admin_key)
    try:
        from warden.agent.healer import WardenHealer
        report = await WardenHealer().run()
        return {
            "triggered": True,
            "issues":    report.issues,
            "actions":   report.actions,
        }
    except Exception as exc:
        log.warning("soc/heal trigger failed: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc))
