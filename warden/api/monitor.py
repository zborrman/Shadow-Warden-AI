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
  GET    /monitors/error-budget          — SLA error-budget report (FM-5)
"""
from __future__ import annotations

import logging
import math
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy import text

from warden.auth_guard import AuthResult, require_api_key
from warden.db.connection import DATABASE_URL, get_async_engine, get_engine
from warden.db.sql_safety import safe_set_clause

log = logging.getLogger("warden.api.monitor")

#: Columns PATCH /monitors/{id} may touch. The f-string SET clause can only ever
#: interpolate names from this list (warden/db/sql_safety.py).
_MONITOR_UPDATE_COLS = frozenset({"name", "interval_s", "is_active"})

router = APIRouter(prefix="/monitors", tags=["uptime"])


# ── Cross-module read contract (F8) ───────────────────────────────────────────

def availability_window(
    since_ts: float,
    until_ts: float,
    *,
    tenant_id: str | None = None,
) -> dict[str, Any] | None:
    """Availability over a window, for callers outside the uptime subsystem.

    Exists because `compliance/soc2_collector.py` used to open a
    `warden_uptime.db` SQLite file and query an `uptime_checks` table — neither
    of which any module has ever written. Uptime has lived in
    `warden_core.probe_results` (Timescale) since D-1/migration 0010, so the
    SOC 2 A1.1/A1.2 controls reported `0 checks / availability None` against
    548 k rows sitting one engine away. That is the F8 failure exactly: the
    reader hard-coded the writer's *storage* instead of asking it a question.

    Returns ``None`` — never a zeroed dict — when Postgres is not configured or
    not reachable, so a caller can label the difference between "measured, and
    it was empty" and "could not measure". Synchronous on purpose: the callers
    are collectors and report builders, not request handlers.
    """
    if not DATABASE_URL:
        return None

    since = datetime.fromtimestamp(since_ts, UTC)
    until = datetime.fromtimestamp(until_ts, UTC)
    params: dict[str, Any] = {"since": since, "until": until}

    # Two whole literal statements rather than one with an interpolated WHERE
    # fragment. The fragment was a fixed string and safe, but neither a reader
    # nor `avoid-sqlalchemy-text` can tell that at a glance, and the repo's two
    # existing exceptions are for genuinely dynamic SET clauses guarded by
    # `sql_safety.safe_set_clause`. A duplicated line of SQL is cheaper than a
    # suppression.
    try:
        with get_engine().connect() as conn:
            if tenant_id:
                params["tid"] = tenant_id
                row = conn.execute(
                    text("""
                        SELECT COUNT(*)                      AS checks,
                               COUNT(*) FILTER (WHERE is_up) AS up_count,
                               AVG(latency_ms)               AS avg_latency_ms
                        FROM warden_core.probe_results
                        WHERE time >= :since AND time < :until
                          AND tenant_id = :tid
                    """),
                    params,
                ).fetchone()
            else:
                row = conn.execute(
                    text("""
                        SELECT COUNT(*)                      AS checks,
                               COUNT(*) FILTER (WHERE is_up) AS up_count,
                               AVG(latency_ms)               AS avg_latency_ms
                        FROM warden_core.probe_results
                        WHERE time >= :since AND time < :until
                    """),
                    params,
                ).fetchone()
    except Exception as exc:
        log.debug("availability_window unavailable (fail-open): %s", exc)
        return None

    if row is None:
        return None
    checks = int(row.checks or 0)
    up_count = int(row.up_count or 0)
    return {
        "source": "warden_core.probe_results",
        "checks": checks,
        "up_count": up_count,
        "availability_pct": round(100.0 * up_count / checks, 4) if checks else None,
        "avg_response_ms": round(float(row.avg_latency_ms), 2)
        if row.avg_latency_ms is not None
        else None,
        "by_monitor": _availability_by_monitor(since, until, tenant_id),
    }


def _availability_by_monitor(
    since: datetime, until: datetime, tenant_id: str | None
) -> list[dict[str, Any]]:
    """Per-target rows behind the blended figure.

    The blended number alone is not usable evidence. Measured on 2026-08-11 the
    platform reported **76.25%** over 24 151 checks — which reads as a serious
    availability failure and is not one. Five of six monitors were at
    99.86–100%; a sixth, `Portal`, was at **0.00% over 5 724 checks** because
    its hostname has no DNS record at all, so every probe failed in 4 ms
    without ever reaching the service.

    One misconfigured target dragging the platform figure 24 points is the same
    error shape as the zeros this collector used to report, pointing the other
    way: a number that is arithmetically correct and tells the reader something
    false. An auditor needs to see which target, not an average.
    """
    params: dict[str, Any] = {"since": since, "until": until}
    try:
        with get_engine().connect() as conn:
            if tenant_id:
                params["tid"] = tenant_id
                rows = conn.execute(
                    text("""
                        SELECT COALESCE(m.name, pr.monitor_id::text) AS target,
                               COUNT(*)                              AS checks,
                               COUNT(*) FILTER (WHERE pr.is_up)      AS up_count,
                               AVG(pr.latency_ms)                    AS avg_latency_ms
                        FROM warden_core.probe_results pr
                        LEFT JOIN warden_core.monitors m ON m.id = pr.monitor_id
                        WHERE pr.time >= :since AND pr.time < :until
                          AND pr.tenant_id = :tid
                        GROUP BY 1
                        ORDER BY 2 DESC
                    """),
                    params,
                ).fetchall()
            else:
                rows = conn.execute(
                    text("""
                        SELECT COALESCE(m.name, pr.monitor_id::text) AS target,
                               COUNT(*)                              AS checks,
                               COUNT(*) FILTER (WHERE pr.is_up)      AS up_count,
                               AVG(pr.latency_ms)                    AS avg_latency_ms
                        FROM warden_core.probe_results pr
                        LEFT JOIN warden_core.monitors m ON m.id = pr.monitor_id
                        WHERE pr.time >= :since AND pr.time < :until
                        GROUP BY 1
                        ORDER BY 2 DESC
                    """),
                    params,
                ).fetchall()
    except Exception as exc:
        log.debug("availability_by_monitor unavailable (fail-open): %s", exc)
        return []

    out: list[dict[str, Any]] = []
    for r in rows:
        n = int(r.checks or 0)
        up = int(r.up_count or 0)
        out.append({
            "target": r.target,
            "checks": n,
            "up_count": up,
            "availability_pct": round(100.0 * up / n, 4) if n else None,
            "avg_response_ms": round(float(r.avg_latency_ms), 2)
            if r.avg_latency_ms is not None
            else None,
        })
    return out


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


@router.get("/error-budget")
async def error_budget_report(
    window_days: int = 30,
    tier: str = "pro",
    auth: AuthResult = Depends(require_api_key),
) -> dict[str, Any]:
    """SLA error-budget report across all of the tenant's monitors (FM-5).

    Uptime comes from the ``probe_hourly`` continuous aggregate over
    ``window_days``; each monitor's budget is scored against the ``tier`` SLA
    target (docs/sla.md §2). ``burn_1h`` is the instantaneous burn rate over the
    last hour — >1 means the budget is draining faster than sustainable. All
    scoring is delegated to the pure ``warden.reliability`` math.

    Registered before ``/{monitor_id}`` so the literal path isn't captured as an id.
    """
    from warden.reliability import budget as _b

    window_days = max(1, min(window_days, 90))
    sla = _b.sla_for_tier(tier)

    async with get_async_engine().connect() as conn:
        rows = await conn.execute(
            text("""
                SELECT m.id, m.name, m.url,
                       ROUND(AVG(ph.uptime_pct) FILTER (
                           WHERE ph.bucket >= NOW() - :wd * INTERVAL '1 day'
                       )::numeric, 4) AS uptime_window,
                       ROUND(AVG(ph.uptime_pct) FILTER (
                           WHERE ph.bucket >= NOW() - INTERVAL '1 hour'
                       )::numeric, 4) AS uptime_1h
                FROM warden_core.monitors m
                LEFT JOIN warden_core.probe_hourly ph
                       ON ph.monitor_id = m.id AND ph.tenant_id = m.tenant_id
                WHERE m.tenant_id = :tid
                GROUP BY m.id, m.name, m.url
            """),
            {"tid": auth.tenant_id, "wd": window_days},
        )
        monitors = [dict(r._mapping) for r in rows]

    report: list[dict[str, Any]] = []
    worst_consumed = 0.0
    for m in monitors:
        # No probe history yet → treat as perfect (100%) rather than a false breach.
        up = float(m["uptime_window"]) if m["uptime_window"] is not None else 100.0
        up_1h = float(m["uptime_1h"]) if m["uptime_1h"] is not None else 100.0
        b = _b.error_budget(up, sla_target=sla, window_days=window_days)
        burn_1h = _b.burn_rate(up_1h, sla)
        report.append({
            "monitor_id":        str(m["id"]),
            "name":              m["name"],
            "url":               m["url"],
            "uptime_pct":        up,
            "consumed_fraction": b.consumed_fraction,
            "remaining_minutes": b.remaining_minutes,
            "exhausted":         b.exhausted,
            "burn_1h":           round(burn_1h, 3) if math.isfinite(burn_1h) else None,
        })
        if math.isfinite(b.consumed_fraction):
            worst_consumed = max(worst_consumed, b.consumed_fraction)

    return {
        "tier":                    tier.strip().lower(),
        "sla_target":              sla,
        "window_days":             window_days,
        "monitors":                report,
        "worst_consumed_fraction": round(worst_consumed, 6),
        "any_exhausted":           any(r["exhausted"] for r in report),
    }


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

    set_clause = safe_set_clause(updates, _MONITOR_UPDATE_COLS, assign="{col}=:{col}")
    updates.update({"id": monitor_id, "tid": auth.tenant_id,
                    "updated_at": "NOW()"})
    async with get_async_engine().begin() as conn:
        await conn.execute(
            text(f"UPDATE warden_core.monitors SET {set_clause}, updated_at=NOW() "  # noqa: S608  # nosemgrep: avoid-sqlalchemy-text -- set_clause is allowlisted, values bound
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
