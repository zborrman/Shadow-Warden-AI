"""
warden/api/system.py
────────────────────
Operational / dashboard system endpoints.

  GET /api/stats        — aggregated filter stats for the dashboard
  GET /health/pipeline   — per-stage pipeline / model / Turso / PQC / journal health

Extracted from ``warden/main.py`` (P-2). Both endpoints only read the event
journal (``warden.analytics.logger``) and probe optional subsystems lazily, so
the module is imported directly rather than resolved through ``warden.runtime``.
``_check_redis_health`` lives here too and is re-imported by main.py's remaining
``/health`` liveness route. The inline ``/health`` and ``/api/config`` routes
land here in later increments — those touch the resilience sliding windows and
live-tunable knobs and need the runtime seam first.
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter

from warden.analytics import logger as event_logger

router = APIRouter(tags=["ops"])
log = logging.getLogger("warden.gateway")


def _check_redis_health() -> dict:
    """Probe Redis and return degradation info.

    ``cache._get_client()`` returns None both when Redis is intentionally
    disabled (REDIS_URL unset or memory://) and when it's configured but
    unreachable — a real outage. Those two cases must not collapse into the
    same "unavailable" status, or a genuine outage gets reported "ok" by
    /health (Redis is optional-by-design for the content-hash cache, so only
    the disabled case should count as healthy).
    """
    from warden.cache import _REDIS_URL, _get_client
    if not _REDIS_URL or _REDIS_URL == "memory://":
        return {"status": "unavailable", "latency_ms": None}
    try:
        client = _get_client()
        if client is None:
            return {"status": "degraded: redis configured but unreachable", "latency_ms": None}
        t0 = time.perf_counter()
        client.ping()
        lat = round((time.perf_counter() - t0) * 1000, 2)
        return {"status": "ok", "latency_ms": lat}
    except Exception as exc:
        return {"status": f"degraded: {exc}", "latency_ms": None}


@router.get("/api/stats", summary="Aggregated filter stats for dashboard")
async def api_stats(hours: float = 24.0):
    # load_entries() reads and JSON-parses the whole NDJSON log file; keep that
    # blocking I/O off the event loop so concurrent requests aren't stalled.
    entries = await asyncio.to_thread(event_logger.load_entries, days=hours / 24)

    total   = len(entries)
    blocked = sum(1 for e in entries if not e.get("allowed"))
    allowed = total - blocked

    by_risk: Counter = Counter(e.get("risk_level", "LOW") for e in entries)

    all_flags: list[str] = []
    for e in entries:
        all_flags.extend(e.get("flags", []))
    top_flags = Counter(all_flags).most_common(10)

    secrets_counter: Counter = Counter()
    for e in entries:
        secrets_counter.update(e.get("secrets_found", []))

    latencies = [e["elapsed_ms"] for e in entries if "elapsed_ms" in e]
    avg_lat = round(sum(latencies) / len(latencies), 2) if latencies else 0.0
    sorted_lat = sorted(latencies)
    p99_lat = round(sorted_lat[int(len(sorted_lat) * 0.99)], 2) if sorted_lat else 0.0

    # 1-minute buckets for last 60 minutes
    now = datetime.now(UTC)
    buckets: dict[int, dict] = defaultdict(lambda: {"total": 0, "blocked": 0})
    for e in entries:
        try:
            ts = datetime.fromisoformat(e["ts"])
            age_min = int((now - ts).total_seconds() / 60)
            if 0 <= age_min < 60:
                buckets[age_min]["total"] += 1
                if not e.get("allowed"):
                    buckets[age_min]["blocked"] += 1
        except Exception as _exc:  # noqa: BLE001
            log.debug("suppressed exception: %r", _exc)

    time_series = [
        {
            "minute_ago": m,
            "ts": (now - timedelta(minutes=m)).strftime("%H:%M"),
            "total": buckets[m]["total"],
            "blocked": buckets[m]["blocked"],
        }
        for m in range(59, -1, -1)
    ]

    recent = [
        {
            "ts":         e.get("ts"),
            "request_id": e.get("request_id"),
            "allowed":    e.get("allowed"),
            "risk_level": e.get("risk_level"),
            "flags":      e.get("flags", []),
            "elapsed_ms": e.get("elapsed_ms"),
            "payload_len": e.get("payload_len"),
        }
        for e in reversed(entries[-50:])
    ]

    return {
        "period_hours":   hours,
        "total":          total,
        "allowed":        allowed,
        "blocked":        blocked,
        "by_risk":        dict(by_risk),
        "top_flags":      top_flags,
        "secrets_found":  dict(secrets_counter.most_common(10)),
        "avg_latency_ms": avg_lat,
        "p99_latency_ms": p99_lat,
        "time_series":    time_series,
        "recent":         recent,
        "generated_at":   now.isoformat(),
    }


@router.get("/health/pipeline", summary="Per-stage pipeline health")
async def health_pipeline(deep: bool = False) -> dict:
    """Reports availability of each filter stage, the ML model, and Turso connections.

    With ``?deep=true`` it additionally fires the live canary corpus through the
    real pipeline (sub-second) and folds a missed jailbreak / false-positive into
    the ``degraded`` verdict — a load-balancer probe should use the cheap default.
    """
    stages: dict[str, dict] = {}

    def _try_import(label: str, module: str, cls: str) -> None:
        try:
            mod = __import__(module, fromlist=[cls])
            getattr(mod, cls)
            stages[label] = {"status": "ok"}
        except Exception as exc:
            stages[label] = {"status": "unavailable", "error": str(exc)[:80]}

    _try_import("topology",       "warden.topology_guard",  "TopologicalGatekeeper")
    _try_import("obfuscation",    "warden.obfuscation",     "decode")
    _try_import("secrets",        "warden.secret_redactor", "SecretRedactor")
    _try_import("semantic_rules", "warden.semantic_guard",  "SemanticGuard")

    # Brain stage — check whether MiniLM model is already loaded (no trigger)
    try:
        from warden.brain import semantic as _brain_mod  # noqa: PLC0415
        loaded = _brain_mod._load_model.cache_info().currsize > 0
        stages["brain"] = {"status": "ok" if loaded else "loading", "model_loaded": loaded}
    except Exception as exc:
        stages["brain"] = {"status": "unavailable", "error": str(exc)[:80]}

    _try_import("causal", "warden.causal_arbiter",  "arbitrate")
    _try_import("phish",  "warden.phishing_guard",  "analyse")

    # ERS stage — backed by Redis
    _redis_h = _check_redis_health()
    stages["ers"] = {
        "status": "ok" if _redis_h["status"] == "ok" else _redis_h["status"],
        "redis_latency_ms": _redis_h.get("latency_ms"),
    }

    stages["decision"] = {"status": "ok"}

    # Turso connection summary
    turso: dict[str, bool] = {}
    try:
        from warden.db.turso import is_turso_enabled  # noqa: PLC0415
        for _db in ("billing_audit", "acp", "marketplace", "sep", "staff"):
            turso[_db] = is_turso_enabled(_db)
    except Exception as _exc:  # noqa: BLE001
        log.debug("suppressed exception: %r", _exc)

    degraded = [k for k, v in stages.items() if v["status"] not in ("ok", "loading")]

    # Deep mode: live canary self-test through the real pipeline.
    canary: dict | None = None
    if deep:
        try:
            from warden.observability import run_pipeline_canary  # noqa: PLC0415
            canary = await run_pipeline_canary()
            if canary.get("available") and not canary["healthy"]:
                degraded.append("canary")
        except Exception as _cn_err:  # noqa: BLE001
            log.debug("health canary errored: %r", _cn_err)

    # P-3a: PQC reported as its own key, deliberately NOT folded into
    # `degraded_stages`. PQC is an optional Enterprise crypto backend, and
    # air-gapped / lower-tier deployments run without liboqs by design — making
    # it flip the load-balancer verdict would take healthy gateways out of
    # rotation. It is surfaced here so that a deployment which is *supposed* to
    # have PQC can alert on `pqc.ok == false`, which is exactly what nobody
    # could do while it was silently broken from v4.7 to 2026-07-27.
    pqc: dict = {"ok": False, "detail": "self-check unavailable"}
    try:
        from warden.crypto.pqc import pqc_selfcheck
        _ok, _detail = pqc_selfcheck()
        pqc = {"ok": _ok, "detail": _detail}
    except Exception as _pqc_err:
        log.debug("pqc self-check unavailable in health: %r", _pqc_err)

    # The NDJSON journal's only bound is the daily `run_gdpr_retention` cron.
    # A cron that stops has no symptom: the file grows, every analytics reader
    # scans more of it, and personal data outlives its retention period —
    # silently, because a purge that removed nothing looks like a quiet day.
    # Reported as its own key, and deliberately not folded into
    # `degraded_stages`: an over-long journal is a compliance and cost problem,
    # not a reason to pull a healthy gateway out of the load balancer.
    journal: dict = {"bounded": True, "detail": "stats unavailable"}
    try:
        journal = await asyncio.to_thread(event_logger.journal_stats)
    except Exception as _j_err:
        log.debug("journal stats unavailable in health: %r", _j_err)

    result = {
        "status":          "degraded" if degraded else "ok",
        "stages":          stages,
        "turso":           turso,
        "pqc":             pqc,
        "journal":         journal,
        "degraded_stages": degraded,
    }
    if canary is not None:
        result["canary"] = canary
    return result
