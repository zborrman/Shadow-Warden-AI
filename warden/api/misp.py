"""
warden/api/misp.py
──────────────────
REST API for the MISP ZMQ / syslog bridge (IN-22).

Endpoints
─────────
  GET  /misp/status   — bridge config + live stats
  GET  /misp/stats    — counters only (for Prometheus scraping / dashboards)
  POST /misp/sync     — trigger one-shot HTTP pull (requires MISP_API_URL+KEY)

Tier gate: Pro+  (require_feature("misp_bridge_enabled"))
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from warden.billing.feature_gate import require_feature
from warden.integrations.misp_bridge import (
    _MISP_API_KEY,
    _MISP_API_URL,
    _MISP_ZMQ_URL,
    _SYSLOG_ENABLED,
    _SYSLOG_TARGET_HOST,
    _SYSLOG_TARGET_PORT,
    get_bridge_stats,
)

router = APIRouter(
    prefix="/misp",
    tags=["MISP"],
    dependencies=[require_feature("misp_bridge_enabled")],
)


@router.get("/status", summary="MISP bridge config and live stats")
async def misp_status() -> dict:
    return {
        "zmq_mode":            bool(_MISP_ZMQ_URL),
        "http_mode":           bool(_MISP_API_URL and _MISP_API_KEY),
        "zmq_url":             _MISP_ZMQ_URL or None,
        "api_url":             _MISP_API_URL or None,
        "syslog_forwarding":   _SYSLOG_ENABLED,
        "syslog_target":       f"{_SYSLOG_TARGET_HOST}:{_SYSLOG_TARGET_PORT}",
        **get_bridge_stats(),
    }


@router.get("/stats", summary="MISP bridge ingestion counters")
async def misp_stats() -> dict:
    return get_bridge_stats()


@router.post("/sync", summary="Trigger one-shot MISP HTTP pull")
async def misp_sync() -> dict:
    """
    Fetch recent MISP events via REST API and ingest into the threat pipeline.
    Requires MISP_API_URL and MISP_API_KEY to be configured.
    """
    if not (_MISP_API_URL and _MISP_API_KEY):
        raise HTTPException(
            status_code=422,
            detail="MISP_API_URL and MISP_API_KEY must be set for HTTP sync",
        )
    try:
        from warden.integrations.misp import MISPConnector  # noqa: PLC0415
        result = await MISPConnector().sync()
        return result.to_dict()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
