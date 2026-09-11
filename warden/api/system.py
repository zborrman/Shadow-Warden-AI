"""
warden/api/system.py
────────────────────
Operational / dashboard system endpoints.

  GET  /health            — liveness probe
  GET  /api/stats        — aggregated filter stats for the dashboard
  GET  /health/pipeline   — per-stage pipeline / model / Turso / PQC / journal health
  GET  /api/config        — current live configuration (auth)
  POST /api/config        — update live-tunable settings (auth)

Extracted from ``warden/main.py`` (P-2). The journal reads go through
``warden.analytics.logger``; the Redis probe lives in ``warden.cache`` (the leaf
it probes); the live-tunable knobs + resilience windows + multi-tenant guard
registry live in ``warden.gateway_state`` — all leaves, so this router's import
can't defeat ``register_router_safe``'s isolation. The shared singletons
(``evolve`` / ``brain_guard`` / ``guard``) are read from ``warden.runtime``,
``None`` until main.py's lifespan publishes them.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends
from pydantic import BaseModel

import warden.circuit_breaker as circuit_breaker
from warden.analytics import logger as event_logger
from warden.api.ws_events import subscriber_count as ws_subscriber_count
from warden.auth_guard import AuthResult, require_api_key, set_default_rate_limit
from warden.cache import _get_client as get_redis_client
from warden.cache import check_redis_health
from warden.config import settings
from warden.gateway_state import gateway_state
from warden.offline import is_offline
from warden.runtime import runtime

router = APIRouter(tags=["ops"])
log = logging.getLogger("warden.gateway")


@router.get("/health", summary="Liveness probe")
async def health():
    redis_health = await asyncio.to_thread(check_redis_health)
    overall = "ok" if redis_health["status"] in ("ok", "unavailable") else "degraded"

    # Compute bypass_rate_1m from sliding windows (prune entries older than 60 s)
    now = time.perf_counter()
    cutoff = now - 60.0
    while gateway_state.bypass_window and gateway_state.bypass_window[0] < cutoff:
        gateway_state.bypass_window.popleft()
    while gateway_state.filter_window and gateway_state.filter_window[0] < cutoff:
        gateway_state.filter_window.popleft()
    bypasses_1m  = len(gateway_state.bypass_window)
    filter_1m    = len(gateway_state.filter_window)
    bypass_rate  = round(bypasses_1m / filter_1m, 4) if filter_1m else 0.0

    # Synchronous Redis read, same reasoning as check_redis_health — off the loop.
    cb_state = await asyncio.to_thread(circuit_breaker.get_state, get_redis_client())
    if cb_state.get("status") == "open":
        overall = "degraded"

    return {
        "status":           overall,
        "service":          "warden-gateway",
        "evolution":        runtime.evolve is not None,
        # The backend actually serving calls. Differs from the configured
        # choice after an auto-mode demotion, which is the only place an
        # operator can see that the selected engine stopped answering.
        "evolution_engine": runtime.evolve.active_engine if runtime.evolve is not None else None,
        "tenants":          list(gateway_state.tenant_guards.keys()),
        "strict":           os.getenv("STRICT_MODE", "false").lower() == "true",
        "fail_strategy":    gateway_state.fail_strategy,
        "cache":            redis_health,
        "ws_clients":       ws_subscriber_count(),
        "bypass_rate_1m":   bypass_rate,
        "bypasses_1m":      bypasses_1m,
        "filter_rps_1m":    round(filter_1m / 60, 2),
        "circuit_breaker":  cb_state,
        "offline_mode":     is_offline(),
    }


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

    # ERS stage — backed by Redis. The probe is synchronous and network-bound
    # (up to an 8 s stall on a configured-but-unreachable Redis), so keep it off
    # the event loop — the journal reads in this handler already are.
    _redis_h = await asyncio.to_thread(check_redis_health)
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


# ── Live configuration ───────────────────────────────────────────────────────


class _ConfigUpdate(BaseModel):
    semantic_threshold: float | None = None
    strict_mode: bool | None = None
    rate_limit_per_minute: int | None = None
    uncertainty_lower_threshold: float | None = None


# Live-tunable settings are ADMIN surface: this endpoint writes SEMANTIC_THRESHOLD,
# STRICT_MODE, the default rate limit and the uncertainty band straight into the
# running gateway. It had NO authentication, and `POST /api/config {}` returned
# {"ok":true} to an anonymous caller in production on 2026-07-29 — a remote kill
# switch on the product's own protection. `require_api_key` closed it (PR #244);
# keep the dependency on both verbs.
@router.get("/api/config", summary="Current live configuration",
            dependencies=[Depends(require_api_key)])
async def api_config(auth: AuthResult = Depends(require_api_key)):
    return {
        "semantic_threshold":   settings.semantic_threshold,
        "strict_mode":          os.getenv("STRICT_MODE", "false").lower() == "true",
        "rate_limit_per_minute": int(os.getenv("RATE_LIMIT_PER_MINUTE", "60")),  # live value via set_default_rate_limit()
        "evolution_enabled":    runtime.evolve is not None,
        "log_retention_days":   int(os.getenv("GDPR_LOG_RETENTION_DAYS", "30")),
        "browser_enabled":      os.getenv("BROWSER_ENABLED", "false").lower() == "true",
        "mtls_enabled":         os.getenv("MTLS_ENABLED", "false").lower() == "true",
        "otel_enabled":         os.getenv("OTEL_ENABLED", "false").lower() == "true",
        "model_cache_dir":          settings.model_cache_dir,
        # Enterprise resilience
        "fail_strategy":            gateway_state.fail_strategy,
        "pipeline_timeout_ms":      gateway_state.pipeline_timeout_ms,
        "uncertainty_lower_threshold": gateway_state.uncertainty_lower,
        "nvidia_api_key_set":       bool(os.getenv("NVIDIA_API_KEY")),
        "prompt_shield_enabled":    settings.prompt_shield_enabled,
        "audit_trail_enabled":      os.getenv("AUDIT_TRAIL_ENABLED", "false").lower() == "true",
    }


@router.post("/api/config", summary="Update live-tunable settings",
             dependencies=[Depends(require_api_key)])
async def update_config(update: _ConfigUpdate,
                        auth: AuthResult = Depends(require_api_key)):
    if update.semantic_threshold is not None:
        val = max(0.1, min(1.0, update.semantic_threshold))
        os.environ["SEMANTIC_THRESHOLD"] = str(val)
        if runtime.brain_guard is not None:
            runtime.brain_guard.threshold = val
    if update.strict_mode is not None:
        os.environ["STRICT_MODE"] = str(update.strict_mode).lower()
        if runtime.guard is not None:
            runtime.guard.strict = update.strict_mode
    if update.rate_limit_per_minute is not None:
        set_default_rate_limit(update.rate_limit_per_minute)
    if update.uncertainty_lower_threshold is not None:
        gateway_state.set_uncertainty_lower(update.uncertainty_lower_threshold)
    return {"ok": True}
