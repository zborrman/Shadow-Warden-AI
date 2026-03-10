"""
analytics/main.py
━━━━━━━━━━━━━━━━━
Shadow Warden AI — Analytics Service (port 8002)

Provides a structured HTTP API over the NDJSON event log written by the
warden gateway.  Designed to be consumed by Grafana, SIEM tools, or
external dashboards.

Endpoints
─────────
GET  /health                    — liveness probe
GET  /api/v1/events             — recent filter events (paginated)
GET  /api/v1/stats              — aggregated statistics
GET  /api/v1/threats            — threat-type breakdown
GET  /api/v1/events/{request_id} — single event by request_id

GDPR notes:
  • No prompt content is stored in the log — only metadata.
  • The /api/v1/stats endpoint returns only aggregated counts.
  • Entries older than GDPR_LOG_RETENTION_DAYS are never returned.
"""
from __future__ import annotations

import json
import logging
import os
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "info").upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("analytics.api")

# ── Config ────────────────────────────────────────────────────────────────────

LOGS_PATH          = Path(os.getenv("ANALYTICS_DATA_PATH", "/analytics/data")) / "logs.json"
LOG_RETENTION_DAYS = int(os.getenv("GDPR_LOG_RETENTION_DAYS", "30"))

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Shadow Warden AI — Analytics API",
    description=(
        "Structured HTTP API over the NDJSON event log written by the "
        "warden gateway.  All fields are metadata only — no prompt content "
        "is stored (GDPR-compliant)."
    ),
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_methods=["GET"],
    allow_headers=["*"],
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load(days: int | None = None) -> list[dict]:
    """Load entries from the NDJSON log, applying the retention window."""
    if not LOGS_PATH.exists():
        return []

    cutoff = datetime.now(UTC) - timedelta(days=days or LOG_RETENTION_DAYS)
    entries: list[dict] = []

    try:
        with LOGS_PATH.open("r", encoding="utf-8") as f:
            for raw in f:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    entry = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                ts_str = entry.get("ts", "1970-01-01T00:00:00+00:00")
                try:
                    ts = datetime.fromisoformat(ts_str)
                    if ts < cutoff:
                        continue
                except ValueError:
                    pass
                entries.append(entry)
    except OSError as exc:
        log.warning("Could not read log file: %s", exc)

    return entries


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["ops"])
def health() -> dict[str, str]:
    return {"status": "ok", "service": "warden-analytics"}


@app.get("/api/v1/events", tags=["analytics"])
def list_events(
    limit: int = Query(default=100, ge=1, le=1000,
                       description="Maximum number of events to return."),
    days:  int = Query(default=7, ge=1, le=LOG_RETENTION_DAYS,
                       description="Number of past days to include."),
    allowed: bool | None = Query(default=None,
                                  description="Filter by allowed=true/false."),
) -> dict[str, Any]:
    """
    Return the most-recent filter events.

    Events are sorted newest-first.  Use *limit* and *days* to control
    the result size.
    """
    entries = _load(days=days)
    if allowed is not None:
        entries = [e for e in entries if e.get("allowed") == allowed]
    entries.sort(key=lambda e: e.get("ts", ""), reverse=True)
    return {"total": len(entries), "events": entries[:limit]}


@app.get("/api/v1/events/{request_id}", tags=["analytics"])
def get_event(request_id: str) -> dict[str, Any]:
    """Return a single event by its request_id."""
    for entry in _load():
        if entry.get("request_id") == request_id:
            return entry
    raise HTTPException(status_code=404, detail=f"No event found for request_id={request_id!r}.")


@app.get("/api/v1/stats", tags=["analytics"])
def stats(
    days: int = Query(default=7, ge=1, le=LOG_RETENTION_DAYS,
                      description="Number of past days to aggregate."),
) -> dict[str, Any]:
    """
    Return aggregated statistics for the requested window.

    Includes total/allowed/blocked counts, average latency, and
    per-day breakdown.
    """
    entries = _load(days=days)
    if not entries:
        return {"days": days, "total": 0, "allowed": 0, "blocked": 0,
                "avg_latency_ms": 0.0, "by_day": {}}

    total   = len(entries)
    allowed = sum(1 for e in entries if e.get("allowed"))
    blocked = total - allowed

    latencies = [e["elapsed_ms"] for e in entries if "elapsed_ms" in e]
    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else 0.0

    # Per-day counts
    by_day: dict[str, dict[str, int]] = {}
    for e in entries:
        day = e.get("ts", "")[:10]
        if day not in by_day:
            by_day[day] = {"total": 0, "blocked": 0}
        by_day[day]["total"] += 1
        if not e.get("allowed"):
            by_day[day]["blocked"] += 1

    return {
        "days":           days,
        "total":          total,
        "allowed":        allowed,
        "blocked":        blocked,
        "block_rate_pct": round(blocked / total * 100, 2) if total else 0.0,
        "avg_latency_ms": avg_latency,
        "by_day":         dict(sorted(by_day.items())),
    }


@app.get("/api/v1/attack-cost", tags=["analytics"])
def attack_cost(
    days: int = Query(default=7, ge=1, le=LOG_RETENTION_DAYS,
                      description="Number of past days to aggregate."),
) -> dict[str, Any]:
    """
    Cost-to-Attack metrics — aggregate USD cost of all blocked payloads.

    Reports:
      total_attack_cost_usd  — cumulative cost of all blocked requests
      avg_cost_per_attack    — mean cost per blocked request
      total_tokens_blocked   — total tokens in blocked payloads
      costliest_attack_usd   — single most expensive blocked payload
      by_risk_level          — cost breakdown by risk level (high/block)
      by_day                 — daily cost time-series (blocked only)
    """
    entries = _load(days=days)
    blocked = [e for e in entries if not e.get("allowed")]

    if not blocked:
        return {
            "days": days,
            "total_requests": len(entries),
            "total_blocked": 0,
            "total_attack_cost_usd": 0.0,
            "avg_cost_per_attack": 0.0,
            "total_tokens_blocked": 0,
            "costliest_attack_usd": 0.0,
            "by_risk_level": {},
            "by_day": {},
        }

    costs  = [e.get("attack_cost_usd", 0.0) for e in blocked]
    tokens = [e.get("payload_tokens", 0) for e in blocked]

    total_cost   = round(sum(costs), 8)
    avg_cost     = round(total_cost / len(blocked), 8)
    total_tokens = sum(tokens)
    costliest    = round(max(costs), 8)

    # Per-risk-level breakdown
    by_risk: dict[str, dict[str, float | int]] = {}
    for e in blocked:
        rl = e.get("risk_level", "unknown")
        if rl not in by_risk:
            by_risk[rl] = {"count": 0, "total_cost_usd": 0.0, "total_tokens": 0}
        by_risk[rl]["count"] = int(by_risk[rl]["count"]) + 1
        by_risk[rl]["total_cost_usd"] = round(
            float(by_risk[rl]["total_cost_usd"]) + e.get("attack_cost_usd", 0.0), 8
        )
        by_risk[rl]["total_tokens"] = (
            int(by_risk[rl]["total_tokens"]) + e.get("payload_tokens", 0)
        )

    # Daily time-series
    by_day: dict[str, dict[str, float | int]] = {}
    for e in blocked:
        day = e.get("ts", "")[:10]
        if day not in by_day:
            by_day[day] = {"count": 0, "total_cost_usd": 0.0}
        by_day[day]["count"] = int(by_day[day]["count"]) + 1
        by_day[day]["total_cost_usd"] = round(
            float(by_day[day]["total_cost_usd"]) + e.get("attack_cost_usd", 0.0), 8
        )

    return {
        "days":                  days,
        "total_requests":        len(entries),
        "total_blocked":         len(blocked),
        "total_attack_cost_usd": total_cost,
        "avg_cost_per_attack":   avg_cost,
        "total_tokens_blocked":  total_tokens,
        "costliest_attack_usd":  costliest,
        "by_risk_level":         by_risk,
        "by_day":                dict(sorted(by_day.items())),
    }


@app.get("/api/v1/threats", tags=["analytics"])
def threats(
    days: int = Query(default=7, ge=1, le=LOG_RETENTION_DAYS,
                      description="Number of past days to aggregate."),
    limit: int = Query(default=10, ge=1, le=50,
                       description="Top-N threat types to return."),
) -> dict[str, Any]:
    """
    Return a frequency breakdown of detected threat flag types.

    Useful for feeding Grafana bar charts or Pie panels.
    """
    entries = _load(days=days)
    counter: Counter[str] = Counter()
    for entry in entries:
        for flag in entry.get("flags", []):
            counter[flag] += 1

    top = counter.most_common(limit)
    return {
        "days":   days,
        "total_flags": sum(counter.values()),
        "threats": [{"flag": flag, "count": count} for flag, count in top],
    }


# ── Error handler ─────────────────────────────────────────────────────────────

@app.exception_handler(Exception)
async def unhandled(request, exc: Exception):  # type: ignore[override]
    log.exception("Unhandled error: %s", exc)
    return JSONResponse(status_code=500, content={"detail": "Internal analytics error."})
