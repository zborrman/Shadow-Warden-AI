"""
warden/api/monitor.py
━━━━━━━━━━━━━━━━━━━━
Uptime monitoring REST API.

Endpoints:
  POST   /monitors/                      — create monitor
  GET    /monitors/                      — list tenant monitors
  GET    /monitors/{id}                  — get monitor
  PATCH  /monitors/{id}                  — update (name, interval, active)
  DELETE /monitors/{id}                  — delete
  GET    /monitors/{id}/status           — latest probe result
  GET    /monitors/{id}/uptime?hours=24  — uptime % + avg latency
  GET    /monitors/{id}/history?limit=50 — recent probe results
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy import text

from warden.auth_guard import AuthResult, require_api_key
from warden.db.connection import get_async_engine

log = logging.getLogger("warden.api.monitor")

router = APIRouter(prefix="/monitors", tags=["uptime"])


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class MonitorCreate(BaseModel):
    name:       str     = Field(default="", max_length=120)
    url:        HttpUrl
    interval_s: int     = Field(default=60, ge=10, le=3600)
    check_type: str     = Field(default="http", pattern=r"^(http|ssl|dns|tcp)$")


class MonitorPatch(BaseModel):
    name:       str  | None = Field(None, max_length=120)
    interval_s: int  | None = Field(None, ge=10, le=3600)
    is_active:  bool | None = None


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _get_monitor(monitor_id: str, tenant_id: str) -> dict:
    async with get_async_engine().connect() as conn:
        row = await conn.execute(
            text("SELECT * FROM warden_core.monitors WHERE id=:id AND tenant_id=:tid"),
            {"id": monitor_id, "tid": tenant_id},
        )
        m = row.fetchone()
    if not m:
        raise HTTPException(status_code=404, detail="Monitor not found.")
    return dict(m._mapping)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_monitor(
    body: MonitorCreate,
    auth: AuthResult = Depends(require_api_key),
) -> dict[str, Any]:
    async with get_async_engine().begin() as conn:
        row = await conn.execute(
            text("""
                INSERT INTO warden_core.monitors (tenant_id, name, url, interval_s, check_type)
                VALUES (:tid, :name, :url, :interval_s, :check_type)
                RETURNING id, name, url, interval_s, check_type, is_active, created_at
            """),
            {
                "tid":        auth.tenant_id,
                "name":       body.name,
                "url":        str(body.url),
                "interval_s": body.interval_s,
                "check_type": body.check_type,
            },
        )
    return dict(row.fetchone()._mapping)


@router.get("/")
async def list_monitors(
    auth: AuthResult = Depends(require_api_key),
) -> list[dict[str, Any]]:
    async with get_async_engine().connect() as conn:
        rows = await conn.execute(
            text("""
                SELECT id, name, url, interval_s, check_type, is_active, created_at
                FROM warden_core.monitors
                WHERE tenant_id = :tid
                ORDER BY created_at DESC
            """),
            {"tid": auth.tenant_id},
        )
    return [dict(r._mapping) for r in rows]


@router.get("/{monitor_id}")
async def get_monitor(
    monitor_id: str,
    auth: AuthResult = Depends(require_api_key),
) -> dict[str, Any]:
    return await _get_monitor(monitor_id, auth.tenant_id)


@router.patch("/{monitor_id}")
async def patch_monitor(
    monitor_id: str,
    body: MonitorPatch,
    auth: AuthResult = Depends(require_api_key),
) -> dict[str, Any]:
    await _get_monitor(monitor_id, auth.tenant_id)  # 404 guard

    updates: dict[str, Any] = {}
    if body.name       is not None:
        updates["name"]       = body.name
    if body.interval_s is not None:
        updates["interval_s"] = body.interval_s
    if body.is_active  is not None:
        updates["is_active"]  = body.is_active
    if not updates:
        raise HTTPException(status_code=422, detail="No fields to update.")

    set_clause = ", ".join(f"{k}=:{k}" for k in updates)
    updates.update({"id": monitor_id, "tid": auth.tenant_id,
                    "updated_at": "NOW()"})
    async with get_async_engine().begin() as conn:
        await conn.execute(
            text(f"UPDATE warden_core.monitors SET {set_clause}, updated_at=NOW() "  # noqa: S608
                 "WHERE id=:id AND tenant_id=:tid"),
            updates,
        )
    return await _get_monitor(monitor_id, auth.tenant_id)


@router.delete("/{monitor_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_monitor(
    monitor_id: str,
    auth: AuthResult = Depends(require_api_key),
) -> None:
    await _get_monitor(monitor_id, auth.tenant_id)  # 404 guard
    async with get_async_engine().begin() as conn:
        await conn.execute(
            text("DELETE FROM warden_core.monitors WHERE id=:id AND tenant_id=:tid"),
            {"id": monitor_id, "tid": auth.tenant_id},
        )


@router.get("/{monitor_id}/status")
async def monitor_status(
    monitor_id: str,
    auth: AuthResult = Depends(require_api_key),
) -> dict[str, Any]:
    """Latest probe result."""
    await _get_monitor(monitor_id, auth.tenant_id)
    async with get_async_engine().connect() as conn:
        row = await conn.execute(
            text("""
                SELECT is_up, status_code, latency_ms, error, time
                FROM warden_core.probe_results
                WHERE monitor_id=:id AND tenant_id=:tid
                ORDER BY time DESC
                LIMIT 1
            """),
            {"id": monitor_id, "tid": auth.tenant_id},
        )
    r = row.fetchone()
    if not r:
        return {"is_up": None, "message": "No probe results yet."}
    return dict(r._mapping)


@router.get("/{monitor_id}/uptime")
async def monitor_uptime(
    monitor_id: str,
    hours: int = 24,
    auth: AuthResult = Depends(require_api_key),
) -> dict[str, Any]:
    """Uptime % and average latency from continuous aggregate."""
    await _get_monitor(monitor_id, auth.tenant_id)
    async with get_async_engine().connect() as conn:
        row = await conn.execute(
            text("""
                SELECT
                    ROUND(AVG(uptime_pct)::numeric, 2)     AS uptime_pct,
                    ROUND(AVG(avg_latency_ms)::numeric, 2) AS avg_latency_ms,
                    SUM(checks)                            AS total_checks
                FROM warden_core.probe_hourly
                WHERE monitor_id=:id
                  AND tenant_id=:tid
                  AND bucket >= NOW() - :hours * INTERVAL '1 hour'
            """),
            {"id": monitor_id, "tid": auth.tenant_id, "hours": hours},
        )
    r = row.fetchone()
    return {
        "monitor_id":     monitor_id,
        "window_hours":   hours,
        "uptime_pct":     float(r.uptime_pct or 0),
        "avg_latency_ms": float(r.avg_latency_ms or 0),
        "total_checks":   int(r.total_checks or 0),
    }


@router.get("/{monitor_id}/history")
async def monitor_history(
    monitor_id: str,
    limit: int = 50,
    auth: AuthResult = Depends(require_api_key),
) -> list[dict[str, Any]]:
    """Recent probe results (raw, newest first)."""
    await _get_monitor(monitor_id, auth.tenant_id)
    limit = min(limit, 1000)
    async with get_async_engine().connect() as conn:
        rows = await conn.execute(
            text("""
                SELECT time, is_up, status_code, latency_ms, error
                FROM warden_core.probe_results
                WHERE monitor_id=:id AND tenant_id=:tid
                ORDER BY time DESC
                LIMIT :lim
            """),
            {"id": monitor_id, "tid": auth.tenant_id, "lim": limit},
        )
    return [dict(r._mapping) for r in rows]
