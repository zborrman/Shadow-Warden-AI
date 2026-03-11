"""
Shadow Warden AI — Warden Gateway
FastAPI application that acts as the mandatory filter proxy.

Every request from app/ must hit POST /filter before the payload
is forwarded to any model or downstream service.

Pipeline
────────
    raw content
        → SecretRedactor  (strip credentials / PII)
        → SemanticGuard   (rule-based injection / harmful-intent detection)
        → BrainSemanticGuard  (ML — all-MiniLM-L6-v2, catches paraphrases)
        → Decision        (allowed | blocked)
        → [if blocked] EvolutionEngine  (BackgroundTask — calls Claude Opus,
                                         writes new rule, hot-reloads corpus)
        → [if blocked] AlertEngine      (BackgroundTask — Slack / PagerDuty)
        → FilterResponse  (allowed | blocked, with reasons + per-stage timing)

New in v0.4
───────────
  • Per-tenant API keys     (JSON file multi-key auth with SHA-256 hash lookup)
  • Per-stage timing        (processing_ms in FilterResponse)
  • Health degradation      (/health reports cache + Redis status)
  • Batch filtering         (POST /filter/batch — up to 50 items)
  • Obfuscation decoding    (base64, hex, unicode homoglyphs, ROT13 pre-filter)
"""
from __future__ import annotations

import asyncio
import json
import logging
import logging.handlers
import os
import re
import time
import uuid
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    HTTPException,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from warden.analytics import logger as event_logger
from warden.auth_guard import AuthResult, require_api_key
from warden.billing import BILLING_AGG_INTERVAL, BillingStore
from warden.brain.evolve import EvolutionEngine
from warden.brain.semantic import SemanticGuard as BrainSemanticGuard
from warden.cache import check_tenant_rate_limit, get_cached, set_cached
from warden.data_policy import DataPolicyEngine
from warden.mtls import MTLSMiddleware
from warden.obfuscation import decode as decode_obfuscation
from warden.onboarding import OnboardingEngine, PLANS
from warden.review_queue import ReviewQueue
from warden.rule_ledger import RuleLedger
from warden.schemas import FilterRequest, FilterResponse, FlagType, RiskLevel, SemanticFlag
from warden.secret_redactor import SecretRedactor
from warden.semantic_guard import SemanticGuard
from warden.telegram_alert import send_block_alert as _tg_block_alert
from warden.threat_store import ThreatStore

# ── Structured JSON logging ───────────────────────────────────────────────────

class _JsonFormatter(logging.Formatter):
    """Emit each log record as a single JSON line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict = {
            "ts":      datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level":   record.levelname,
            "logger":  record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def _configure_json_logging() -> None:
    log_level = getattr(logging, os.getenv("LOG_LEVEL", "info").upper(), logging.INFO)
    fmt = _JsonFormatter()
    handler = logging.StreamHandler()
    handler.setFormatter(fmt)
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(log_level)


_configure_json_logging()
log = logging.getLogger("warden.gateway")

# ── Prometheus metrics ────────────────────────────────────────────────────────

try:
    from prometheus_fastapi_instrumentator import Instrumentator as _Instrumentator
    _PROMETHEUS_ENABLED = True
except ImportError:
    _PROMETHEUS_ENABLED = False
    log.warning("prometheus-fastapi-instrumentator not installed — /metrics disabled.")

# ── Rate limiter ──────────────────────────────────────────────────────────────

_RATE_LIMIT = os.getenv("RATE_LIMIT_PER_MINUTE", "60")
_limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=os.getenv("REDIS_URL", "redis://redis:6379/0"),
)

# Per-key rate limit is now carried by AuthResult.rate_limit (set in auth_guard.py).
# TENANT_RATE_LIMIT env var sets the default for single-key / dev-mode requests.

# ── Dynamic rules path ────────────────────────────────────────────────────────

_DYNAMIC_RULES_PATH = Path(
    os.getenv("DYNAMIC_RULES_PATH", "/warden/data/dynamic_rules.json")
)

# ── WebSocket / LLM streaming env vars ───────────────────────────────────────

_LLM_BASE_URL   = os.getenv("LLM_BASE_URL", "").rstrip("/")  # e.g. https://api.openai.com/v1
_LLM_API_KEY    = os.getenv("LLM_API_KEY", "")
_WS_MAX_PAYLOAD = int(os.getenv("WS_MAX_PAYLOAD_BYTES", "65536"))  # 64 KiB


# ── Risk helpers ──────────────────────────────────────────────────────────────

_RISK_ORDER = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.BLOCK]


def _max_risk(a: RiskLevel, b: RiskLevel) -> RiskLevel:
    return a if _RISK_ORDER.index(a) >= _RISK_ORDER.index(b) else b


# ── Dynamic evolution rule registry ───────────────────────────────────────────

@dataclass
class _DynamicRegexRule:
    rule_id: str
    pattern: re.Pattern  # type: ignore[type-arg]
    snippet: str         # first 60 chars of the pattern for logging


# Hot-loadable list of evolution-generated regex rules (populated at startup
# and whenever the EvolutionEngine generates a new regex_pattern rule).
_dynamic_regex_rules: list[_DynamicRegexRule] = []


# ── Multi-tenant SemanticGuard registry ──────────────────────────────────────

_tenant_guards: dict[str, BrainSemanticGuard] = {}


def _get_tenant_guard(tenant_id: str) -> BrainSemanticGuard:
    """Return (or create) the BrainSemanticGuard for *tenant_id*."""
    if tenant_id not in _tenant_guards:
        log.info("Creating new ML brain corpus for tenant=%r", tenant_id)
        _tenant_guards[tenant_id] = BrainSemanticGuard()
    return _tenant_guards[tenant_id]


# ── Singletons (one per process) ─────────────────────────────────────────────

_redactor:       SecretRedactor    | None = None
_guard:          SemanticGuard     | None = None
_brain_guard:    BrainSemanticGuard| None = None   # "default" tenant
_evolve:         EvolutionEngine   | None = None
_agent_monitor:  AgentMonitor | None   = None
_ledger:         RuleLedger        | None = None
_review_queue:   ReviewQueue       | None = None
_threat_store:   ThreatStore       | None = None
_billing:        BillingStore      | None = None
_onboarding:     OnboardingEngine  | None = None
_policy:         DataPolicyEngine  | None = None

try:
    from warden.agent_monitor import AgentMonitor
    _AGENT_MONITOR_AVAILABLE = True
except ImportError:
    _AGENT_MONITOR_AVAILABLE = False


def _add_dynamic_regex_rule(rule_id: str, pattern_str: str) -> None:
    """Hot-load a new evolution-generated regex rule into the running filter."""
    try:
        compiled = re.compile(pattern_str, re.IGNORECASE)
        _dynamic_regex_rules.append(
            _DynamicRegexRule(
                rule_id = rule_id,
                pattern = compiled,
                snippet = pattern_str[:60],
            )
        )
        log.info(
            json.dumps({
                "event":   "dynamic_regex_hot_loaded",
                "rule_id": rule_id,
                "snippet": pattern_str[:60],
            })
        )
    except re.error as exc:
        log.warning(
            json.dumps({
                "event":   "dynamic_regex_compile_error",
                "rule_id": rule_id,
                "error":   str(exc),
            })
        )


async def _nightly_rule_retirement() -> None:
    """Background task: run retire_stale() once every 24 hours."""
    while True:
        await asyncio.sleep(86_400)
        if _ledger is not None:
            _ledger.retire_stale()


async def _billing_aggregation_loop() -> None:
    """Background task: aggregate new log entries into billing totals every N seconds."""
    while True:
        await asyncio.sleep(BILLING_AGG_INTERVAL)
        if _billing is not None:
            with suppress(Exception):
                _billing.aggregate_from_logs()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _redactor, _guard, _brain_guard, _evolve, _agent_monitor, _ledger, _review_queue, _threat_store, _billing, _onboarding, _policy

    strict = os.getenv("STRICT_MODE", "false").lower() == "true"

    log.info("Warden gateway starting — initialising filter pipeline…")
    _redactor = SecretRedactor(strict=strict)
    _guard    = SemanticGuard(strict=strict)

    # ── ML Brain Guard ────────────────────────────────────────────────
    log.info("Loading ML semantic brain (all-MiniLM-L6-v2) …")
    _brain_guard = BrainSemanticGuard()
    _tenant_guards["default"] = _brain_guard
    log.info("ML brain corpus ready.")

    # ── Restore evolved corpus ────────────────────────────────────────
    if _DYNAMIC_RULES_PATH.exists():
        try:
            data = json.loads(_DYNAMIC_RULES_PATH.read_text())
            examples = [
                r["new_rule"]["value"]
                for r in data.get("rules", [])
                if r["new_rule"]["rule_type"] == "semantic_example"
            ]
            if examples:
                _brain_guard.add_examples(examples)
                log.info(
                    "Restored %d evolved semantic rule(s) from dynamic_rules.json.",
                    len(examples),
                )
        except Exception:
            log.warning("Could not load dynamic_rules.json — starting with base corpus.")

    # ── Pre-warm inference path ───────────────────────────────────────
    _brain_guard.check("system warm-up ping")
    log.info("ML brain warm-up complete.")

    # ── Rule Ledger ────────────────────────────────────────────────────
    _ledger = RuleLedger()
    stale = _ledger.retire_stale()
    if stale:
        log.info("RuleLedger: retired %d stale rule(s) at startup.", stale)

    # Load evolution-generated regex rules into the in-memory dynamic list
    for dyn in _ledger.get_active_regex_rules():
        with suppress(re.error):
            _dynamic_regex_rules.append(
                _DynamicRegexRule(
                    rule_id = dyn["rule_id"],
                    pattern = re.compile(dyn["pattern"], re.IGNORECASE),
                    snippet = dyn["pattern"][:60],
                )
            )
    if _dynamic_regex_rules:
        log.info(
            "RuleLedger: loaded %d active dynamic regex rule(s).",
            len(_dynamic_regex_rules),
        )

    # ── Threat Store ──────────────────────────────────────────────────
    _threat_store = ThreatStore()
    log.info("ThreatStore online.")

    # ── Billing Store ─────────────────────────────────────────────────
    _billing = BillingStore()
    _billing.aggregate_from_logs()   # catch up on any logs from last run
    log.info("BillingStore online.")

    # ── Onboarding Engine ─────────────────────────────────────────────
    _onboarding = OnboardingEngine(
        gateway_url=os.getenv("GATEWAY_URL", "http://localhost:8001")
    )
    log.info("OnboardingEngine online.")

    # ── Data Policy Engine ────────────────────────────────────────────
    _policy = DataPolicyEngine()
    log.info("DataPolicyEngine online.")

    # ── Review Queue ──────────────────────────────────────────────────
    _review_queue = ReviewQueue(on_activate_regex=_add_dynamic_regex_rule)

    # ── Evolution Engine ──────────────────────────────────────────────
    if os.getenv("ANTHROPIC_API_KEY"):
        _evolve = EvolutionEngine(
            semantic_guard = _brain_guard,
            ledger         = _ledger,
            review_queue   = _review_queue,
        )
        log.info("EvolutionEngine online.")
    else:
        log.warning(
            "ANTHROPIC_API_KEY not set — EvolutionEngine disabled. "
            "Set the key to enable automated rule generation."
        )

    # ── Agent Monitor ─────────────────────────────────────────────────
    if _AGENT_MONITOR_AVAILABLE:
        _agent_monitor = AgentMonitor()
        log.info("AgentMonitor online.")
        # Share singleton with openai_proxy so it records tool events
        try:
            import warden.openai_proxy as _proxy_mod
            _proxy_mod._agent_monitor = _agent_monitor
        except Exception:
            pass

    log.info("Filter pipeline ready.")

    # ── Background tasks ──────────────────────────────────────────────
    _retirement_task = asyncio.create_task(_nightly_rule_retirement())
    _billing_task    = asyncio.create_task(_billing_aggregation_loop())

    yield

    _retirement_task.cancel()
    _billing_task.cancel()
    with suppress(asyncio.CancelledError):
        await _retirement_task
    with suppress(asyncio.CancelledError):
        await _billing_task

    if _ledger is not None:
        _ledger.close()
    if _threat_store is not None:
        _threat_store.close()
    if _billing is not None:
        _billing.close()
    if _policy is not None:
        _policy.close()

    log.info("Warden gateway shutting down.")


# ── App factory ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="Shadow Warden AI — Gateway",
    description=(
        "Mandatory filter proxy. All payloads must pass through /filter "
        "before reaching any model or downstream service.\n\n"
        "Blocked HIGH/BLOCK attacks trigger the Evolution Loop: Claude Opus "
        "analyses the attack and auto-generates a new detection rule."
    ),
    version="0.4.0",
    lifespan=lifespan,
)

# Rate limiter state must be on app.state for slowapi to find it
app.state.limiter = _limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

_DEFAULT_CORS = ",".join([
    "http://localhost:3000",
    # Browser extension origins — required for Shadow Warden browser extension
    "https://chatgpt.com",
    "https://chat.openai.com",
    "https://claude.ai",
    "https://gemini.google.com",
    "https://copilot.microsoft.com",
])
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", _DEFAULT_CORS).split(","),
    allow_credentials=False,   # extensions don't send cookies
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key", "X-Request-ID"],
)

# mTLS enforcement — validates client-certificate CN on every non-exempt request.
# Disabled by default (MTLS_ENABLED=false); enable in production after running
# scripts/gen_certs.sh and mounting certs/ into each container.
app.add_middleware(MTLSMiddleware)

# ── Prometheus instrumentation ────────────────────────────────────────────────
if _PROMETHEUS_ENABLED:
    _Instrumentator().instrument(app).expose(app, endpoint="/metrics")

# ── Include sub-routers ───────────────────────────────────────────────────────
try:
    from warden.openai_proxy import router as _openai_router
    app.include_router(_openai_router)
    log.info("OpenAI-compatible proxy mounted at /v1")
except ImportError:
    log.warning("openai_proxy not available — /v1 routes skipped.")


# ── HTTP middleware (request-ID + security headers) ───────────────────────────

@app.middleware("http")
async def attach_request_id(request: Request, call_next):
    rid = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request.state.request_id = rid
    response = await call_next(request)
    response.headers["X-Request-ID"] = rid
    return response


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ── Health ────────────────────────────────────────────────────────────────────

def _check_redis_health() -> dict:
    """Probe Redis and return degradation info."""
    try:
        from warden.cache import _get_client
        client = _get_client()
        if client is None:
            return {"status": "unavailable", "latency_ms": None}
        t0 = time.perf_counter()
        client.ping()
        lat = round((time.perf_counter() - t0) * 1000, 2)
        return {"status": "ok", "latency_ms": lat}
    except Exception as exc:
        return {"status": f"degraded: {exc}", "latency_ms": None}


@app.get("/health", tags=["ops"], summary="Liveness probe")
async def health():
    redis_health = _check_redis_health()
    overall = "ok" if redis_health["status"] == "ok" or redis_health["status"] == "unavailable" else "degraded"
    return {
        "status":    overall,
        "service":   "warden-gateway",
        "evolution": _evolve is not None,
        "tenants":   list(_tenant_guards.keys()),
        "strict":    os.getenv("STRICT_MODE", "false").lower() == "true",
        "cache":     redis_health,
    }


# ── Core filter logic (shared by /filter and /filter/batch) ──────────────────

async def _run_filter_pipeline(
    payload:          FilterRequest,
    rid:              str,
    auth:             AuthResult,
    background_tasks: BackgroundTasks | None = None,
    client_ip:        str                    = "",
) -> FilterResponse:
    """Execute the full filter pipeline and return a FilterResponse."""
    start = time.perf_counter()
    timings: dict[str, float] = {}

    # ── IP block check (pre-auth, earliest possible gate) ──────────────
    if client_ip and _threat_store is not None and _threat_store.is_blocked(
        client_ip, auth.tenant_id if auth.tenant_id != "default" else payload.tenant_id
    ):
        log.info(
            json.dumps({"event": "ip_blocked", "ip": client_ip, "request_id": rid})
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied.",
        )

    # Use tenant_id from auth if available, else from payload
    tenant_id = auth.tenant_id if auth.tenant_id != "default" else payload.tenant_id
    strict = payload.strict or (_guard.strict if _guard else False)

    # ── Monthly quota gate ────────────────────────────────────────────
    if _billing is not None and _billing.is_quota_exceeded(tenant_id):
        log.info(
            json.dumps({"event": "quota_exceeded", "tenant_id": tenant_id, "request_id": rid})
        )
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=f"Monthly cost quota exceeded for tenant {tenant_id!r}. "
                   "Contact your administrator to increase the limit.",
        )

    # ── Data policy check (traffic light) ────────────────────────────
    if _policy is not None:
        _dp_provider = (payload.context or {}).get("provider", "openai")
        _dp_decision = _policy.classify(payload.content, _dp_provider, tenant_id)
        if not _dp_decision.allowed:
            log.warning(
                json.dumps({
                    "event":      "data_policy_block",
                    "request_id": rid,
                    "tenant_id":  tenant_id,
                    "class":      _dp_decision.data_class,
                    "rule":       _dp_decision.triggered_rule,
                })
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "reason":     _dp_decision.reason,
                    "suggestion": _dp_decision.suggestion,
                    "data_class": _dp_decision.data_class,
                },
            )

    # Extract optional session_id for agentic monitoring
    session_id: str | None = (payload.context or {}).get("session_id")

    log.info(
        json.dumps({
            "event": "filter_request",
            "request_id": rid,
            "payload_len": len(payload.content),
            "strict": strict,
            "tenant_id": tenant_id,
        })
    )

    # ── Stage 0: Redis cache check ─────────────────────────────────────
    t0 = time.perf_counter()
    cached_json = get_cached(payload.content)
    timings["cache_check"] = round((time.perf_counter() - t0) * 1000, 2)
    if cached_json:
        try:
            cached = json.loads(cached_json)
            log.info(json.dumps({"event": "cache_hit", "request_id": rid}))
            return FilterResponse(**cached)
        except Exception:
            pass

    # ── Stage 0b: Obfuscation decoding ────────────────────────────────
    t0 = time.perf_counter()
    obfuscation_result = decode_obfuscation(payload.content)
    timings["obfuscation"] = round((time.perf_counter() - t0) * 1000, 2)

    # Use decoded+original combined text for downstream analysis
    analysis_text = obfuscation_result.combined
    if obfuscation_result.has_obfuscation:
        log.warning(
            json.dumps({
                "event":      "obfuscation_detected",
                "request_id": rid,
                "layers":     obfuscation_result.layers_found,
            })
        )

    # ── Stage 1: Secret Redaction ──────────────────────────────────────
    t0 = time.perf_counter()
    redact_result = _redactor.redact(analysis_text, payload.redaction_policy)   # type: ignore[union-attr]
    timings["redaction"] = round((time.perf_counter() - t0) * 1000, 2)

    if redact_result.findings:
        kinds = [f.kind for f in redact_result.findings]
        log.warning(
            json.dumps({"event": "secrets_redacted", "request_id": rid, "kinds": kinds})
        )

    # ── Stage 2: Rule-based Semantic Analysis ─────────────────────────
    t0 = time.perf_counter()
    guard_result = _guard.analyse(redact_result.text)   # type: ignore[union-attr]
    timings["rules"] = round((time.perf_counter() - t0) * 1000, 2)

    if guard_result.flags:
        log.warning(
            json.dumps({
                "event":      "rule_flags",
                "request_id": rid,
                "flags":      [f.flag for f in guard_result.flags],
                "risk":       guard_result.risk_level,
            })
        )

    # ── Stage 2.5: Dynamic evolution regex rules ──────────────────────
    if _dynamic_regex_rules:
        for dyn_rule in list(_dynamic_regex_rules):   # snapshot avoids mutation
            if dyn_rule.pattern.search(redact_result.text):
                guard_result.flags.append(SemanticFlag(
                    flag   = FlagType.PROMPT_INJECTION,
                    score  = 0.80,
                    detail = f"Dynamic evolution rule matched: {dyn_rule.snippet}",
                ))
                guard_result.risk_level = _max_risk(
                    guard_result.risk_level, RiskLevel.HIGH
                )
                if _ledger is not None:
                    _ledger.increment(dyn_rule.rule_id)
                log.warning(
                    json.dumps({
                        "event":      "dynamic_rule_fired",
                        "request_id": rid,
                        "rule_id":    dyn_rule.rule_id,
                        "snippet":    dyn_rule.snippet,
                    })
                )

    # ── Stage 1b: PII flag ─────────────────────────────────────────────
    if redact_result.has_pii:
        guard_result.flags.append(SemanticFlag(
            flag=FlagType.PII_DETECTED,
            score=1.0,
            detail=f"PII detected: {[f.kind for f in redact_result.findings]}",
        ))

    # ── Stage 2b: ML Semantic Brain (async, per-tenant) ───────────────
    t0 = time.perf_counter()
    brain_guard = _get_tenant_guard(tenant_id)
    brain_result = await brain_guard.check_async(redact_result.text)
    timings["ml"] = round((time.perf_counter() - t0) * 1000, 2)

    if brain_result.is_jailbreak:
        ml_risk = (
            RiskLevel.HIGH
            if brain_result.score >= 0.85
            else RiskLevel.MEDIUM
        )
        guard_result.flags.append(SemanticFlag(
            flag=FlagType.PROMPT_INJECTION,
            score=round(brain_result.score, 4),
            detail=(
                f"ML jailbreak detected (similarity={brain_result.score:.3f}) — "
                f"closest corpus entry: {brain_result.closest_example!r}"
            ),
        ))
        guard_result.risk_level = _max_risk(guard_result.risk_level, ml_risk)
        log.warning(
            json.dumps({
                "event":      "ml_flag",
                "request_id": rid,
                "score":      brain_result.score,
                "risk":       guard_result.risk_level.value,
                "tenant_id":  tenant_id,
            })
        )

    # ── Stage 3: Decision ─────────────────────────────────────────────
    allowed = guard_result.safe_for(strict)

    reason = ""
    if not allowed:
        top = guard_result.top_flag
        reason = top.detail if top else f"Risk level: {guard_result.risk_level}"

    # ── Stage 4: Evolution Loop ───────────────────────────────────────
    if (
        not allowed
        and _evolve is not None
        and background_tasks is not None
        and _RISK_ORDER.index(guard_result.risk_level) >= _RISK_ORDER.index(RiskLevel.HIGH)
    ):
        background_tasks.add_task(
            _evolve.process_blocked,
            content    = payload.content,
            flags      = guard_result.flags,
            risk_level = guard_result.risk_level,
        )
        log.info(json.dumps({"event": "evolution_queued", "request_id": rid}))

    # ── Stage 4c: Threat intelligence recording ───────────────────────
    if not allowed and client_ip and _threat_store is not None:
        with suppress(Exception):
            _threat_store.record_block_event(
                ip         = client_ip,
                tenant_id  = tenant_id,
                risk_level = guard_result.risk_level.value,
                flags      = [f.flag.value for f in guard_result.flags],
            )

    # ── Stage 4b: Real-time alerting (Slack / PagerDuty + Telegram) ───
    if not allowed and background_tasks is not None:
        top_flag = guard_result.top_flag
        try:
            from warden.alerting import alert_block_event
            background_tasks.add_task(
                alert_block_event,
                attack_type  = top_flag.flag.value if top_flag else "unknown",
                risk_level   = guard_result.risk_level.value,
                rule_summary = reason,
                request_id   = rid,
            )
        except ImportError:
            pass
        # Telegram channel (per-tenant chat_id from onboarding)
        tg_chat = _onboarding.get_telegram_chat_id(tenant_id) if _onboarding else None
        background_tasks.add_task(
            _tg_block_alert,
            tenant_id      = tenant_id,
            risk_level     = guard_result.risk_level.value,
            attack_type    = top_flag.flag.value if top_flag else "unknown",
            detail         = reason,
            request_id     = rid,
            tenant_chat_id = tg_chat,
        )

    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    timings["total"] = elapsed_ms
    log.info(
        json.dumps({
            "event":      "filter_done",
            "request_id": rid,
            "allowed":    allowed,
            "risk":       guard_result.risk_level.value,
            "elapsed_ms": elapsed_ms,
        })
    )

    # ── Analytics logging ─────────────────────────────────────────────
    try:
        _tokens = event_logger.estimate_tokens(payload.content)
        entry = event_logger.build_entry(
            request_id      = rid,
            allowed         = allowed,
            risk_level      = guard_result.risk_level.value,
            flags           = [f.flag.value for f in guard_result.flags],
            secrets_found   = [f.kind for f in redact_result.findings],
            payload_len     = len(payload.content),
            payload_tokens  = _tokens,
            attack_cost_usd = event_logger.token_cost_usd(_tokens),
            elapsed_ms      = elapsed_ms,
            strict          = strict,
            session_id      = session_id,
        )
        entry["tenant_id"] = tenant_id   # needed for billing aggregation
        event_logger.append(entry)
    except Exception:
        log.exception(json.dumps({"event": "analytics_error", "request_id": rid}))

    # ── SIEM integration ──────────────────────────────────────────────
    if background_tasks is not None:
        try:
            from warden.analytics.siem import ship_event
            background_tasks.add_task(ship_event, entry)  # type: ignore[possibly-undefined]
        except ImportError:
            pass

    # ── Agentic session monitoring ────────────────────────────────────
    if session_id and _agent_monitor is not None and background_tasks is not None:
        with suppress(Exception):
            session_threat = _agent_monitor.record_request(
                session_id,
                rid,
                allowed,
                guard_result.risk_level.value,
                [f.flag.value for f in guard_result.flags],
                tenant_id,
            )
            # Persist session anomalies to threat store for cross-session correlation
            if session_threat is not None and client_ip and _threat_store is not None:
                with suppress(Exception):
                    _threat_store.record_session_threat(
                        ip         = client_ip,
                        tenant_id  = tenant_id,
                        session_id = session_id,
                        pattern    = session_threat.pattern,
                        severity   = session_threat.severity,
                    )

    response = FilterResponse(
        allowed                  = allowed,
        risk_level               = guard_result.risk_level,
        filtered_content         = redact_result.text,
        secrets_found            = redact_result.findings,
        semantic_flags           = guard_result.flags,
        reason                   = reason,
        redaction_policy_applied = payload.redaction_policy,
        processing_ms            = timings,
    )

    # ── Cache write ───────────────────────────────────────────────────
    if allowed:
        set_cached(payload.content, response.model_dump_json())

    return response


# ── Rate-limit helper ─────────────────────────────────────────────────────────

def _enforce_tenant_rate_limit(auth: AuthResult, rid: str) -> None:
    """Raise HTTP 429 if this tenant has exceeded their per-minute quota."""
    if check_tenant_rate_limit(auth.tenant_id, auth.rate_limit):
        log.warning(json.dumps({
            "event": "tenant_rate_limit_exceeded",
            "request_id": rid,
            "tenant_id": auth.tenant_id,
            "limit_per_minute": auth.rate_limit,
        }))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Tenant '{auth.tenant_id}' rate limit exceeded "
                f"({auth.rate_limit} req/min)."
            ),
            headers={"Retry-After": "60"},
        )


# ── /filter ───────────────────────────────────────────────────────────────────

@app.post(
    "/filter",
    response_model=FilterResponse,
    tags=["filter"],
    summary="Filter raw content through the Warden pipeline",
    status_code=status.HTTP_200_OK,
)
@_limiter.limit(f"{_RATE_LIMIT}/minute")
async def filter_content(
    payload:          FilterRequest,
    request:          Request,
    background_tasks: BackgroundTasks,
    auth:             AuthResult = Depends(require_api_key),
) -> FilterResponse:
    rid = getattr(request.state, "request_id", "-")
    _enforce_tenant_rate_limit(auth, rid)
    client_ip = request.client.host if request.client else ""
    return await _run_filter_pipeline(payload, rid, auth, background_tasks, client_ip)


# ── /filter/batch ─────────────────────────────────────────────────────────────

_MAX_BATCH_SIZE = int(os.getenv("MAX_BATCH_SIZE", "50"))


class _BatchRequest(BaseModel):
    items: list[FilterRequest] = Field(..., min_length=1, max_length=_MAX_BATCH_SIZE)


class _BatchResponse(BaseModel):
    results: list[FilterResponse]


@app.post(
    "/filter/batch",
    response_model=_BatchResponse,
    tags=["filter"],
    summary="Filter multiple items in a single request (up to 50)",
    status_code=status.HTTP_200_OK,
)
@_limiter.limit(f"{_RATE_LIMIT}/minute")
async def filter_batch(
    payload:          _BatchRequest,
    request:          Request,
    background_tasks: BackgroundTasks,
    auth:             AuthResult = Depends(require_api_key),
) -> _BatchResponse:
    rid_base = getattr(request.state, "request_id", str(uuid.uuid4()))
    _enforce_tenant_rate_limit(auth, rid_base)
    client_ip = request.client.host if request.client else ""
    results = []
    for i, item in enumerate(payload.items):
        rid = f"{rid_base}:batch-{i}"
        resp = await _run_filter_pipeline(item, rid, auth, background_tasks, client_ip)
        results.append(resp)
    return _BatchResponse(results=results)


# ── GDPR endpoints ────────────────────────────────────────────────────────────

class _GdprExportRequest(BaseModel):
    request_id: str


class _GdprPurgeRequest(BaseModel):
    before: str   # ISO-8601 datetime string, e.g. "2024-01-01T00:00:00Z"


@app.post(
    "/gdpr/export",
    tags=["gdpr"],
    summary="Export log metadata for a specific request ID (GDPR Art. 15)",
    dependencies=[Depends(require_api_key)],
)
async def gdpr_export(body: _GdprExportRequest):
    entry = event_logger.read_by_request_id(body.request_id)
    if entry is None:
        raise JSONResponse(
            status_code=404,
            content={"detail": f"No log entry found for request_id={body.request_id!r}."},
        )
    return {"request_id": body.request_id, "entry": entry}


@app.post(
    "/gdpr/purge",
    tags=["gdpr"],
    summary="Delete log entries before a given date (GDPR Art. 17)",
    dependencies=[Depends(require_api_key)],
)
async def gdpr_purge(body: _GdprPurgeRequest):
    try:
        before_dt = datetime.fromisoformat(body.before)
    except ValueError:
        return JSONResponse(
            status_code=422,
            content={"detail": f"Invalid datetime format: {body.before!r}. Use ISO-8601."},
        )
    removed = event_logger.purge_before(before_dt)
    log.info(
        json.dumps({"event": "gdpr_purge", "removed": removed, "before": body.before})
    )
    return {"removed": removed, "before": body.before}


# ── Rule ledger endpoints ─────────────────────────────────────────────────────

class _FpReportRequest(BaseModel):
    reason: str | None = None


@app.post(
    "/rules/{rule_id}/report-fp",
    tags=["rules"],
    summary="Report a false-positive for an evolution-generated rule (increments fp_reports)",
    dependencies=[Depends(require_api_key)],
)
async def report_false_positive(rule_id: str, body: _FpReportRequest):
    if _ledger is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rule ledger not available.",
        )
    found = _ledger.report_fp(rule_id)
    if not found:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule {rule_id!r} not found in ledger.",
        )
    rule = _ledger.get_rule(rule_id)
    log.info(
        json.dumps({
            "event":        "fp_reported",
            "rule_id":      rule_id,
            "fp_reports":   rule["fp_reports"],  # type: ignore[index]
            "rule_status":  rule["status"],       # type: ignore[index]
            "reason":       body.reason,
        })
    )
    return {
        "rule_id":    rule_id,
        "fp_reports": rule["fp_reports"],    # type: ignore[index]
        "status":     rule["status"],        # type: ignore[index]
    }


@app.get(
    "/rules",
    tags=["rules"],
    summary="List evolution-generated rules from the ledger",
    dependencies=[Depends(require_api_key)],
)
async def list_rules(rule_status: str | None = None, limit: int = 100):
    if _ledger is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rule ledger not available.",
        )
    return {"rules": _ledger.list_rules(status=rule_status, limit=limit)}


# ── Admin rule lifecycle endpoints ────────────────────────────────────────────


@app.post(
    "/admin/rules/{rule_id}/approve",
    tags=["admin"],
    summary="Approve a pending_review rule and activate it (RULE_REVIEW_MODE=manual)",
    dependencies=[Depends(require_api_key)],
)
async def admin_approve_rule(rule_id: str):
    """
    Promote a rule from *pending_review* to *active* and hot-load it into the
    running filter pipeline.

    Only meaningful when ``RULE_REVIEW_MODE=manual``.  Safe to call in auto mode
    (the rule is already active; the ledger update is idempotent).
    """
    if _ledger is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rule ledger not available.",
        )
    rule = _ledger.get_rule(rule_id)
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule {rule_id!r} not found in ledger.",
        )
    if rule["status"] == "retired":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Rule {rule_id!r} is already retired and cannot be approved.",
        )

    # Activate in the running pipeline
    if _review_queue is not None:
        _review_queue.activate(
            rule_id    = rule_id,
            rule_type  = rule["rule_type"],
            value      = rule["pattern_snippet"],
            brain_guard= _brain_guard,
        )

    # Promote in the ledger (approve_rule only changes pending_review → active;
    # already-active rules are unaffected).
    _ledger.approve_rule(rule_id)

    log.info(
        json.dumps({
            "event":     "admin_rule_approved",
            "rule_id":   rule_id,
            "rule_type": rule["rule_type"],
        })
    )
    updated = _ledger.get_rule(rule_id)
    return {
        "rule_id": rule_id,
        "status":  updated["status"],  # type: ignore[index]
        "message": f"Rule {rule_id!r} activated.",
    }


@app.delete(
    "/admin/rules/{rule_id}",
    tags=["admin"],
    summary="Retire an evolution-generated rule immediately",
    dependencies=[Depends(require_api_key)],
)
async def admin_retire_rule(rule_id: str):
    """
    Immediately retire a rule: removes it from the in-memory regex list and sets
    ``status='retired'`` in the ledger so it is not reloaded on restart.
    """
    if _ledger is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rule ledger not available.",
        )
    found = _ledger.retire_rule(rule_id)
    if not found:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule {rule_id!r} not found in ledger.",
        )

    # Remove from the in-memory dynamic regex list (takes effect immediately)
    _dynamic_regex_rules[:] = [r for r in _dynamic_regex_rules if r.rule_id != rule_id]

    log.info(
        json.dumps({
            "event":   "admin_rule_retired",
            "rule_id": rule_id,
        })
    )
    return {
        "rule_id": rule_id,
        "status":  "retired",
        "message": f"Rule {rule_id!r} retired and removed from live filter.",
    }


# ── Threat intelligence endpoints ─────────────────────────────────────────────


class _BlockIpRequest(BaseModel):
    ip:         str
    tenant_id:  str         = "default"
    reason:     str         = ""
    expires_at: str | None  = None   # ISO-8601; None = permanent


@app.get(
    "/threats/profiles",
    tags=["threats"],
    summary="Cross-session attacker profiles aggregated by IP + tenant",
    dependencies=[Depends(require_api_key)],
)
async def get_threat_profiles(tenant_id: str | None = None, limit: int = 50):
    """Return attacker profiles sorted by most recent block activity."""
    if _threat_store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat store not available.",
        )
    return {"profiles": _threat_store.get_profiles(tenant_id=tenant_id, limit=limit)}


@app.get(
    "/threats/blocked-ips",
    tags=["threats"],
    summary="List all currently-blocked IPs",
    dependencies=[Depends(require_api_key)],
)
async def get_blocked_ips(tenant_id: str | None = None):
    if _threat_store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat store not available.",
        )
    return {"blocked_ips": _threat_store.get_blocked_ips(tenant_id=tenant_id)}


@app.post(
    "/threats/block-ip",
    tags=["threats"],
    summary="Manually block an IP address across the filter pipeline",
    dependencies=[Depends(require_api_key)],
)
async def block_ip(body: _BlockIpRequest):
    """
    Add an IP to the blocklist.  All future requests from this IP will receive
    HTTP 403 before any other processing occurs.  Optionally provide an
    ISO-8601 ``expires_at`` for temporary blocks; omit for permanent.
    """
    if _threat_store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat store not available.",
        )
    _threat_store.block_ip(
        ip         = body.ip,
        tenant_id  = body.tenant_id,
        reason     = body.reason,
        blocked_by = "manual",
        expires_at = body.expires_at,
    )
    log.info(
        json.dumps({
            "event":     "ip_manually_blocked",
            "ip":        body.ip,
            "tenant_id": body.tenant_id,
            "reason":    body.reason,
        })
    )
    return {
        "ip":         body.ip,
        "tenant_id":  body.tenant_id,
        "blocked_by": "manual",
        "expires_at": body.expires_at,
        "message":    f"IP {body.ip!r} blocked.",
    }


@app.delete(
    "/threats/blocked-ips/{ip}",
    tags=["threats"],
    summary="Remove an IP from the blocklist",
    dependencies=[Depends(require_api_key)],
)
async def unblock_ip(ip: str, tenant_id: str = "default"):
    if _threat_store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat store not available.",
        )
    found = _threat_store.unblock_ip(ip, tenant_id)
    if not found:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IP {ip!r} is not in the blocklist for tenant {tenant_id!r}.",
        )
    log.info(json.dumps({"event": "ip_unblocked", "ip": ip, "tenant_id": tenant_id}))
    return {"ip": ip, "tenant_id": tenant_id, "message": f"IP {ip!r} unblocked."}


# ── Billing endpoints ─────────────────────────────────────────────────────────


def _require_billing() -> None:
    if _billing is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Billing store not available.",
        )


class _QuotaRequest(BaseModel):
    quota_usd: float   # monthly USD cap; set to 0 to remove cap


@app.get(
    "/billing/{tenant_id}",
    tags=["billing"],
    summary="Aggregated usage and cost for a tenant",
    dependencies=[Depends(require_api_key)],
)
async def get_billing(
    tenant_id: str,
    from_date: str | None = None,
    to_date:   str | None = None,
):
    """
    Return aggregated request counts and USD cost for *tenant_id* over the
    given date range (``from_date`` / ``to_date`` inclusive, format YYYY-MM-DD).
    Includes current-month cost and quota_remaining when a quota is set.
    """
    _require_billing()
    return _billing.get_usage(tenant_id, from_date=from_date, to_date=to_date)  # type: ignore[union-attr]


@app.get(
    "/billing/{tenant_id}/daily",
    tags=["billing"],
    summary="Day-by-day billing breakdown for a tenant",
    dependencies=[Depends(require_api_key)],
)
async def get_billing_daily(
    tenant_id: str,
    from_date: str | None = None,
    to_date:   str | None = None,
    limit:     int        = 90,
):
    _require_billing()
    return {
        "tenant_id": tenant_id,
        "rows": _billing.get_daily_breakdown(tenant_id, from_date, to_date, limit),  # type: ignore[union-attr]
    }


@app.post(
    "/billing/{tenant_id}/quota",
    tags=["billing"],
    summary="Set or update the monthly USD cost cap for a tenant",
    dependencies=[Depends(require_api_key)],
)
async def set_billing_quota(tenant_id: str, body: _QuotaRequest):
    """
    Set the monthly cost cap for *tenant_id*.  All subsequent filter requests
    from this tenant will receive HTTP 402 once the cap is reached.

    Set ``quota_usd=0`` to remove the cap (unlimited).
    """
    _require_billing()
    if body.quota_usd <= 0:
        # Treat 0 / negative as "remove quota" — just set a very high value
        # or use a sentinel.  Here we delete the row to restore unlimited.
        with suppress(Exception):
            _billing._conn.execute(  # type: ignore[union-attr]
                "DELETE FROM tenant_quotas WHERE tenant_id=?", (tenant_id,)
            )
            _billing._conn.commit()  # type: ignore[union-attr]
        log.info(json.dumps({"event": "quota_removed", "tenant_id": tenant_id}))
        return {"tenant_id": tenant_id, "quota_usd": None, "message": "Quota removed (unlimited)."}

    _billing.set_quota(tenant_id, body.quota_usd)  # type: ignore[union-attr]
    log.info(
        json.dumps({
            "event":     "quota_set",
            "tenant_id": tenant_id,
            "quota_usd": body.quota_usd,
        })
    )
    return {
        "tenant_id": tenant_id,
        "quota_usd": body.quota_usd,
        "message":   f"Monthly quota set to ${body.quota_usd:.4f} for tenant {tenant_id!r}.",
    }


# ── WebSocket /ws/stream ─────────────────────────────────────────────────────

async def _ws_send(ws: WebSocket, data: dict) -> None:
    """Send a JSON event over the WebSocket."""
    await ws.send_text(json.dumps(data, ensure_ascii=False))


@app.websocket("/ws/stream")
async def ws_stream(websocket: WebSocket):
    """
    WebSocket streaming endpoint — filter + LLM token stream.

    Connect:  ws://host/ws/stream?key=<api_key>

    Client sends once (JSON):
        {"messages": [...], "model": "gpt-4o-mini", "max_tokens": 512,
         "tenant_id": "default"}

    Server sends (JSON events):
        {"type": "filter_result", "allowed": bool, "risk": str,
         "reason": str, "request_id": str}
        {"type": "token",  "content": str}   <- one per LLM streamed token
        {"type": "done",   "request_id": str}
        {"type": "error",  "code": int, "detail": str}

    WebSocket close codes:
        1008 — Policy Violation (content blocked by Warden filter)
        1009 — Message Too Big
        1011 — Internal server error / upstream error
    """
    await websocket.accept()
    rid = str(uuid.uuid4())

    # ── 1. Authenticate via ?key= query param ─────────────────────────────────
    api_key = websocket.query_params.get("key", "") or None
    try:
        auth = require_api_key(api_key)
    except HTTPException as exc:
        await _ws_send(websocket, {"type": "error", "code": exc.status_code, "detail": exc.detail})
        await websocket.close(code=1008)
        return

    # ── 2. Receive initial message ────────────────────────────────────────────
    try:
        raw = await websocket.receive_text()
    except WebSocketDisconnect:
        return

    if len(raw.encode()) > _WS_MAX_PAYLOAD:
        await _ws_send(websocket, {"type": "error", "code": 413, "detail": "Payload too large."})
        await websocket.close(code=1009)
        return

    try:
        body = json.loads(raw)
    except json.JSONDecodeError:
        await _ws_send(websocket, {"type": "error", "code": 400, "detail": "Invalid JSON."})
        await websocket.close(code=1003)
        return

    messages = body.get("messages")
    if not isinstance(messages, list) or not messages:
        await _ws_send(websocket, {
            "type": "error", "code": 400,
            "detail": "messages must be a non-empty list.",
        })
        await websocket.close(code=1003)
        return

    model      = str(body.get("model", "gpt-4o-mini"))
    max_tokens = int(body.get("max_tokens", 512))
    tenant_id  = str(body.get("tenant_id", auth.tenant_id))

    # Flatten message content to plain text for the filter pipeline
    content_parts: list[str] = []
    for msg in messages:
        c = msg.get("content", "")
        if isinstance(c, str):
            content_parts.append(c)
        elif isinstance(c, list):
            for part in c:
                if isinstance(part, dict) and part.get("type") == "text":
                    content_parts.append(part.get("text", ""))
    content = " ".join(content_parts).strip()

    if not content:
        await _ws_send(websocket, {
            "type": "error", "code": 400,
            "detail": "No text content found in messages.",
        })
        await websocket.close(code=1003)
        return

    # ── 3. Run filter pipeline ────────────────────────────────────────────────
    filter_payload = FilterRequest(content=content, tenant_id=tenant_id)
    bg_tasks       = BackgroundTasks()
    try:
        filter_resp = await _run_filter_pipeline(filter_payload, rid, auth, bg_tasks)
    except Exception as exc:
        log.exception(json.dumps({"event": "ws_filter_error", "request_id": rid, "error": str(exc)}))
        await _ws_send(websocket, {"type": "error", "code": 500, "detail": "Filter pipeline error."})
        await websocket.close(code=1011)
        return

    await _ws_send(websocket, {
        "type":       "filter_result",
        "allowed":    filter_resp.allowed,
        "risk":       filter_resp.risk_level.value,
        "reason":     filter_resp.reason,
        "request_id": rid,
    })

    if not filter_resp.allowed:
        await websocket.close(code=1008)  # Policy Violation
        return

    # ── 4. Stream from LLM backend ────────────────────────────────────────────
    if not _LLM_BASE_URL or not _LLM_API_KEY:
        await _ws_send(websocket, {
            "type": "error", "code": 503,
            "detail": "LLM backend not configured. Set LLM_BASE_URL and LLM_API_KEY.",
        })
        await websocket.close(code=1011)
        return

    try:
        import httpx  # optional dep; only needed for WebSocket LLM streaming

        llm_headers = {
            "Authorization": f"Bearer {_LLM_API_KEY}",
            "Content-Type":  "application/json",
        }
        llm_body = {
            "model":      model,
            "max_tokens": max_tokens,
            "messages":   messages,
            "stream":     True,
        }
        async with httpx.AsyncClient(timeout=120.0) as client, client.stream(
            "POST",
            f"{_LLM_BASE_URL}/chat/completions",
            headers=llm_headers,
            json=llm_body,
        ) as resp:
            if resp.status_code != 200:
                err_body = await resp.aread()
                await _ws_send(websocket, {
                    "type":   "error",
                    "code":   resp.status_code,
                    "detail": f"LLM error: {err_body.decode()[:200]}",
                })
                await websocket.close(code=1011)
                return

            async for line in resp.aiter_lines():
                if not line.startswith("data: "):
                    continue
                chunk = line[6:].strip()
                if chunk == "[DONE]":
                    break
                try:
                    delta      = json.loads(chunk)
                    token_text = (
                        delta.get("choices", [{}])[0]
                        .get("delta", {})
                        .get("content", "")
                    )
                    if token_text:
                        await _ws_send(websocket, {"type": "token", "content": token_text})
                except (json.JSONDecodeError, IndexError, KeyError):
                    continue

    except WebSocketDisconnect:
        log.info(json.dumps({"event": "ws_client_disconnect", "request_id": rid}))
        return
    except Exception as exc:
        log.exception(json.dumps({"event": "ws_llm_error", "request_id": rid, "error": str(exc)}))
        try:
            await _ws_send(websocket, {"type": "error", "code": 502, "detail": "LLM upstream error."})
            await websocket.close(code=1011)
        except Exception:
            pass
        return

    await _ws_send(websocket, {"type": "done", "request_id": rid})
    await websocket.close()


# ── Onboarding API ───────────────────────────────────────────────────────────

class _OnboardRequest(BaseModel):
    company_name:     str   = Field(..., min_length=2, max_length=120)
    contact_email:    str   = Field(..., min_length=5)
    plan:             str   = Field("pro", pattern="^(free|pro|msp)$")
    telegram_chat_id: str | None = None
    custom_quota_usd: float | None = None


class _RotateKeyResponse(BaseModel):
    tenant_id: str
    api_key:   str
    message:   str


class _TelegramSetRequest(BaseModel):
    chat_id: str | None = None


class _TelegramTestRequest(BaseModel):
    chat_id: str


def _require_onboarding() -> None:
    if _onboarding is None:
        raise HTTPException(503, detail="OnboardingEngine not initialized.")


@app.post(
    "/onboard",
    tags=["onboarding"],
    summary="Create a new SMB tenant (MSP admin only)",
    status_code=201,
)
async def create_tenant(
    body: _OnboardRequest,
    auth: AuthResult = Depends(require_api_key),
) -> dict:
    """
    Provision a new SMB client tenant.

    Returns a one-time setup kit including the raw API key (not stored in plaintext),
    OPENAI_BASE_URL for the client, and a .env template.
    """
    _require_onboarding()
    try:
        kit = _onboarding.create_tenant(  # type: ignore[union-attr]
            company_name     = body.company_name,
            contact_email    = body.contact_email,
            plan             = body.plan,
            telegram_chat_id = body.telegram_chat_id,
            custom_quota_usd = body.custom_quota_usd,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Apply billing quota if billing is configured
    if _billing is not None and kit.quota_usd > 0:
        _billing.set_quota(kit.tenant_id, kit.quota_usd)

    log.info(
        json.dumps({
            "event":     "tenant_created",
            "tenant_id": kit.tenant_id,
            "plan":      kit.plan,
            "by":        auth.tenant_id,
        })
    )
    return kit.as_dict()


@app.get(
    "/onboard/{tenant_id}",
    tags=["onboarding"],
    summary="Get tenant status",
)
async def get_tenant_status(
    tenant_id: str,
    auth: AuthResult = Depends(require_api_key),
) -> dict:
    """Return tenant metadata (no key hash exposed)."""
    _require_onboarding()
    tenant = _onboarding.get_tenant(tenant_id)  # type: ignore[union-attr]
    if not tenant:
        raise HTTPException(404, detail=f"Tenant {tenant_id!r} not found.")
    return tenant


@app.get(
    "/tenants",
    tags=["onboarding"],
    summary="List all tenants (MSP dashboard)",
)
async def list_tenants(
    auth: AuthResult = Depends(require_api_key),
) -> dict:
    """Return all provisioned tenants with metadata (no key hashes)."""
    _require_onboarding()
    tenants = _onboarding.list_tenants()  # type: ignore[union-attr]
    return {"count": len(tenants), "tenants": tenants}


@app.post(
    "/onboard/{tenant_id}/rotate-key",
    tags=["onboarding"],
    summary="Issue a new API key for a tenant (invalidates old key immediately)",
)
async def rotate_tenant_key(
    tenant_id: str,
    auth: AuthResult = Depends(require_api_key),
) -> dict:
    """Rotate the API key for a tenant. Old key is immediately revoked."""
    _require_onboarding()
    new_key = _onboarding.rotate_key(tenant_id)  # type: ignore[union-attr]
    if new_key is None:
        raise HTTPException(404, detail=f"Tenant {tenant_id!r} not found.")
    log.info(
        json.dumps({"event": "key_rotated", "tenant_id": tenant_id, "by": auth.tenant_id})
    )
    return {
        "tenant_id": tenant_id,
        "api_key":   new_key,
        "message":   "New API key issued. Update your client's OPENAI_API_KEY immediately.",
    }


@app.put(
    "/onboard/{tenant_id}/status",
    tags=["onboarding"],
    summary="Activate or deactivate a tenant",
)
async def set_tenant_status(
    tenant_id: str,
    active: bool,
    auth: AuthResult = Depends(require_api_key),
) -> dict:
    """Enable or suspend a tenant's API key."""
    _require_onboarding()
    if active:
        found = _onboarding.reactivate_tenant(tenant_id)  # type: ignore[union-attr]
    else:
        found = _onboarding.deactivate_tenant(tenant_id)  # type: ignore[union-attr]
    if not found:
        raise HTTPException(404, detail=f"Tenant {tenant_id!r} not found.")
    return {"tenant_id": tenant_id, "active": active}


@app.put(
    "/onboard/{tenant_id}/telegram",
    tags=["onboarding"],
    summary="Set or clear a tenant's Telegram chat_id",
)
async def set_tenant_telegram(
    tenant_id: str,
    body: _TelegramSetRequest,
    auth: AuthResult = Depends(require_api_key),
) -> dict:
    """Store a Telegram chat_id for per-tenant block event notifications."""
    _require_onboarding()
    found = _onboarding.update_telegram(tenant_id, body.chat_id)  # type: ignore[union-attr]
    if not found:
        raise HTTPException(404, detail=f"Tenant {tenant_id!r} not found.")
    return {"tenant_id": tenant_id, "telegram_chat_id": body.chat_id}


@app.post(
    "/onboard/{tenant_id}/verify-telegram",
    tags=["onboarding"],
    summary="Send a test Telegram message to verify bot and chat_id",
)
async def verify_tenant_telegram(
    tenant_id: str,
    body: _TelegramTestRequest,
    auth: AuthResult = Depends(require_api_key),
) -> dict:
    """Send a test Telegram message. Returns ok=true if message was delivered."""
    from warden.telegram_alert import send_test_message
    ok = await send_test_message(body.chat_id)
    return {"ok": ok, "chat_id": body.chat_id}


# ── Data Policy API ───────────────────────────────────────────────────────────

class _PolicySettingsRequest(BaseModel):
    default_class:      str  = Field("green", pattern="^(green|yellow|red)$")
    block_cloud_yellow: bool = True


class _AddRuleRequest(BaseModel):
    data_class:   str = Field(..., pattern="^(green|yellow|red)$")
    trigger_type: str = Field(..., pattern="^(pattern|keyword)$")
    value:        str = Field(..., min_length=1)
    description:  str = ""


class _ClassifyRequest(BaseModel):
    text:     str = Field(..., min_length=1)
    provider: str = "openai"


def _require_policy() -> None:
    if _policy is None:
        raise HTTPException(503, detail="DataPolicyEngine not initialized.")


@app.get(
    "/policy/{tenant_id}",
    tags=["data-policy"],
    summary="Get full data classification policy for a tenant",
)
async def get_policy(
    tenant_id: str,
    auth: AuthResult = Depends(require_api_key),
) -> dict:
    """
    Returns: settings (block_cloud_yellow), custom rules (RED/YELLOW/GREEN),
    and built-in category descriptions.
    """
    _require_policy()
    return _policy.get_full_policy(tenant_id)  # type: ignore[union-attr]


@app.put(
    "/policy/{tenant_id}/settings",
    tags=["data-policy"],
    summary="Update tenant policy settings",
)
async def update_policy_settings(
    tenant_id: str,
    body: _PolicySettingsRequest,
    auth: AuthResult = Depends(require_api_key),
) -> dict:
    """
    Set block_cloud_yellow=true to restrict YELLOW data to local AI only.
    Set block_cloud_yellow=false to allow YELLOW data to cloud AI (with advisory).
    """
    _require_policy()
    _policy.update_settings(  # type: ignore[union-attr]
        tenant_id          = tenant_id,
        default_class      = body.default_class,
        block_cloud_yellow = body.block_cloud_yellow,
    )
    return {"tenant_id": tenant_id, "settings": body.model_dump()}


@app.post(
    "/policy/{tenant_id}/rules",
    tags=["data-policy"],
    summary="Add a custom classification rule",
    status_code=201,
)
async def add_policy_rule(
    tenant_id: str,
    body: _AddRuleRequest,
    auth: AuthResult = Depends(require_api_key),
) -> dict:
    """
    Add a RED/YELLOW/GREEN rule for this tenant.

    trigger_type='keyword' accepts comma-separated keywords and converts them to
    a regex pattern automatically (e.g. 'client list, crm, contact database').
    trigger_type='pattern' accepts a raw Python regex string.
    """
    _require_policy()
    try:
        rule_id = _policy.add_rule(  # type: ignore[union-attr]
            tenant_id    = tenant_id,
            data_class   = body.data_class,
            trigger_type = body.trigger_type,
            value        = body.value,
            description  = body.description,
        )
    except (ValueError, Exception) as exc:
        raise HTTPException(400, detail=str(exc))
    return {"rule_id": rule_id, "tenant_id": tenant_id, "data_class": body.data_class}


@app.delete(
    "/policy/{tenant_id}/rules/{rule_id}",
    tags=["data-policy"],
    summary="Delete a custom classification rule",
)
async def delete_policy_rule(
    tenant_id: str,
    rule_id:   str,
    auth: AuthResult = Depends(require_api_key),
) -> dict:
    """Delete a custom rule by ID. Built-in category patterns cannot be deleted."""
    _require_policy()
    found = _policy.delete_rule(rule_id, tenant_id)  # type: ignore[union-attr]
    if not found:
        raise HTTPException(404, detail=f"Rule {rule_id!r} not found for tenant {tenant_id!r}.")
    return {"deleted": rule_id}


@app.get(
    "/msp/overview",
    tags=["msp"],
    summary="Cross-tenant MSP overview — aggregate stats for all tenants",
)
async def msp_overview(
    auth: AuthResult = Depends(require_api_key),
) -> dict:
    """
    Returns per-tenant stats (requests, blocks, cost, block rate, quota usage)
    for the current calendar month, plus fleet-wide totals.

    Designed for the MSP sales dashboard — shows all client activity in one view.
    Requires a valid API key (any key; MSP keys have plan=msp in the key file).
    """
    _require_onboarding()
    tenants = _onboarding.list_tenants()  # type: ignore[union-attr]
    year_month = datetime.now(UTC).strftime("%Y-%m")

    tenant_rows: list[dict] = []
    fleet_requests = 0
    fleet_blocked  = 0
    fleet_cost     = 0.0

    for t in tenants:
        tid = t["tenant_id"]
        if _billing is not None:
            usage = _billing.get_usage(tid, from_date=f"{year_month}-01")
        else:
            usage = {"requests": 0, "blocked": 0, "cost_usd": 0.0, "quota_usd": None, "quota_remaining": None}

        reqs    = usage.get("requests", 0)
        blocked = usage.get("blocked",  0)
        cost    = usage.get("cost_usd", 0.0)
        quota   = usage.get("quota_usd")

        fleet_requests += reqs
        fleet_blocked  += blocked
        fleet_cost     += cost

        tenant_rows.append({
            "tenant_id":    tid,
            "label":        t.get("label", tid),
            "plan":         t.get("plan", "unknown"),
            "active":       t.get("active", True),
            "requests":     reqs,
            "blocked":      blocked,
            "block_rate":   round(blocked / reqs, 4) if reqs else 0.0,
            "cost_usd":     round(cost, 6),
            "quota_usd":    quota,
            "quota_pct":    round(cost / quota * 100, 1) if quota else None,
            "created_at":   t.get("created_at", ""),
        })

    # Sort by most blocked first for the demo table
    tenant_rows.sort(key=lambda r: r["blocked"], reverse=True)

    return {
        "month":          year_month,
        "fleet": {
            "tenants":    len(tenant_rows),
            "requests":   fleet_requests,
            "blocked":    fleet_blocked,
            "block_rate": round(fleet_blocked / fleet_requests, 4) if fleet_requests else 0.0,
            "cost_usd":   round(fleet_cost, 6),
        },
        "tenants": tenant_rows,
    }


@app.post(
    "/policy/{tenant_id}/classify",
    tags=["data-policy"],
    summary="Test-classify a piece of text against the tenant's data policy",
)
async def classify_text(
    tenant_id: str,
    body: _ClassifyRequest,
    auth: AuthResult = Depends(require_api_key),
) -> dict:
    """
    Dry-run the data policy against arbitrary text.
    Does NOT block the request — used by MSP admins to test rules before applying them.
    """
    _require_policy()
    decision = _policy.classify(body.text, body.provider, tenant_id)  # type: ignore[union-attr]
    return decision.as_dict()


# ── Global error handler ──────────────────────────────────────────────────────

@app.exception_handler(Exception)
async def unhandled_exception(request: Request, exc: Exception):
    rid = getattr(request.state, "request_id", "-")
    log.exception(json.dumps({"event": "unhandled_error", "request_id": rid, "error": str(exc)}))
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal warden error.", "request_id": rid},
    )
