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
        → FilterResponse  (allowed | blocked, with reasons)

New in v0.3
───────────
  • API-key authentication      (X-API-Key header, via auth_guard.py)
  • Rate limiting                (slowapi, Redis-backed)
  • Redis content-hash cache     (replay protection + latency reduction)
  • Multi-tenant SemanticGuard   (per-tenant isolated corpus, tenant_id field)
  • Structured JSON logging      (machine-parseable, replaces plain-text)
  • Prometheus metrics           (prometheus-fastapi-instrumentator)
  • GDPR endpoints               (POST /gdpr/export, POST /gdpr/purge)
  • OpenAI-compatible proxy      (/v1/chat/completions forwarded after /filter)
  • Real-time alerting           (Slack + PagerDuty on high-severity blocks)
  • Async ML inference           (BrainSemanticGuard.check_async — non-blocking)
"""
from __future__ import annotations

import json
import logging
import logging.handlers
import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

from fastapi import BackgroundTasks, Depends, FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from warden.analytics import logger as event_logger
from warden.auth_guard import require_api_key
from warden.brain.evolve import EvolutionEngine
from warden.brain.semantic import SemanticGuard as BrainSemanticGuard
from warden.cache import get_cached, set_cached
from warden.schemas import FilterRequest, FilterResponse, FlagType, RiskLevel, SemanticFlag
from warden.secret_redactor import SecretRedactor
from warden.semantic_guard import SemanticGuard

# ── Structured JSON logging ───────────────────────────────────────────────────
# Replace the default human-readable formatter with one that emits
# machine-parseable JSON so log aggregators (Loki, Splunk, Datadog) can
# ingest fields directly without a custom parsing rule.

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
# prometheus-fastapi-instrumentator adds /metrics automatically.
# Import is optional — the gateway works without it.

try:
    from prometheus_fastapi_instrumentator import Instrumentator as _Instrumentator
    _PROMETHEUS_ENABLED = True
except ImportError:
    _PROMETHEUS_ENABLED = False
    log.warning("prometheus-fastapi-instrumentator not installed — /metrics disabled.")

# ── Rate limiter ──────────────────────────────────────────────────────────────
# Default: 60 requests / minute per IP.  Override with RATE_LIMIT_PER_MINUTE.
# Uses Redis as the shared store so limits are enforced across all workers.

_RATE_LIMIT = os.getenv("RATE_LIMIT_PER_MINUTE", "60")
_limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=os.getenv("REDIS_URL", "redis://redis:6379/0"),
)

# ── Dynamic rules path ────────────────────────────────────────────────────────

_DYNAMIC_RULES_PATH = Path(
    os.getenv("DYNAMIC_RULES_PATH", "/warden/data/dynamic_rules.json")
)

# ── Risk helpers ──────────────────────────────────────────────────────────────

_RISK_ORDER = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.BLOCK]


def _max_risk(a: RiskLevel, b: RiskLevel) -> RiskLevel:
    return a if _RISK_ORDER.index(a) >= _RISK_ORDER.index(b) else b


# ── Multi-tenant SemanticGuard registry ──────────────────────────────────────
# One SemanticGuard (BrainSemanticGuard) per tenant_id.  Tenants start with
# the base corpus; their evolved rules are isolated from one another.

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


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _redactor, _guard, _brain_guard, _evolve

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

    # ── Evolution Engine ──────────────────────────────────────────────
    if os.getenv("ANTHROPIC_API_KEY"):
        _evolve = EvolutionEngine(semantic_guard=_brain_guard)
        log.info("EvolutionEngine online.")
    else:
        log.warning(
            "ANTHROPIC_API_KEY not set — EvolutionEngine disabled. "
            "Set the key to enable automated rule generation."
        )

    log.info("Filter pipeline ready.")
    yield
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
    version="0.3.0",
    lifespan=lifespan,
)

# Rate limiter state must be on app.state for slowapi to find it
app.state.limiter = _limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

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

@app.get("/health", tags=["ops"], summary="Liveness probe")
async def health():
    return {
        "status":    "ok",
        "service":   "warden-gateway",
        "evolution": _evolve is not None,
        "tenants":   list(_tenant_guards.keys()),
        "strict":    os.getenv("STRICT_MODE", "false").lower() == "true",
    }


# ── /filter ───────────────────────────────────────────────────────────────────

@app.post(
    "/filter",
    response_model=FilterResponse,
    tags=["filter"],
    summary="Filter raw content through the Warden pipeline",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_api_key)],
)
@_limiter.limit(f"{_RATE_LIMIT}/minute")
async def filter_content(
    payload:          FilterRequest,
    request:          Request,
    background_tasks: BackgroundTasks,
) -> FilterResponse:
    """
    **Pipeline** (in order):

    1. **Cache check** — SHA-256 hash of content looked up in Redis.  If hit,
       return the cached FilterResponse immediately (< 1 ms).

    2. **SecretRedactor** — regex scan for API keys, credentials, PII, credit
       cards, SSNs, IBANs, email addresses.  All found values are replaced
       with `[REDACTED:<kind>]` tokens *before* any semantic analysis.

    3. **SemanticGuard (rule-based)** — rule + keyword scan of the redacted
       text for prompt injection, jailbreak attempts, harmful content, and
       policy violations.

    4. **BrainSemanticGuard (ML)** — all-MiniLM-L6-v2 catches paraphrased
       jailbreaks that regex misses.  Runs asynchronously (non-blocking).
       Each tenant_id gets its own isolated corpus.

    5. **Decision** — `allowed=True` if `risk_level` is LOW (or MEDIUM when
       not in strict mode).

    6. **Evolution Loop** *(background)* — if blocked at HIGH/BLOCK and
       `ANTHROPIC_API_KEY` is set, Claude Opus analyses the attack and appends
       a new rule to `dynamic_rules.json`.

    7. **Alerting** *(background)* — Slack / PagerDuty notifications for
       HIGH/BLOCK attacks.

    8. **Cache write** — successful responses are stored in Redis for 5 min.

    GDPR note: original secrets are never logged; only their *type* and
    character offsets are recorded.
    """
    rid   = getattr(request.state, "request_id", "-")
    start = time.perf_counter()

    strict    = payload.strict or (_guard.strict if _guard else False)
    tenant_id = payload.tenant_id

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
    cached_json = get_cached(payload.content)
    if cached_json:
        try:
            cached = json.loads(cached_json)
            log.info(
                json.dumps({"event": "cache_hit", "request_id": rid})
            )
            return FilterResponse(**cached)
        except Exception:
            pass  # corrupted cache entry — proceed normally

    # ── Stage 1: Secret Redaction ──────────────────────────────────────
    redact_result = _redactor.redact(payload.content)   # type: ignore[union-attr]

    if redact_result.findings:
        kinds = [f.kind for f in redact_result.findings]
        log.warning(
            json.dumps({"event": "secrets_redacted", "request_id": rid, "kinds": kinds})
        )

    # ── Stage 2: Rule-based Semantic Analysis ─────────────────────────
    guard_result = _guard.analyse(redact_result.text)   # type: ignore[union-attr]

    if guard_result.flags:
        log.warning(
            json.dumps({
                "event":      "rule_flags",
                "request_id": rid,
                "flags":      [f.flag for f in guard_result.flags],
                "risk":       guard_result.risk_level,
            })
        )

    # ── Stage 2b: ML Semantic Brain (async, per-tenant) ───────────────
    brain_guard = _get_tenant_guard(tenant_id)
    brain_result = await brain_guard.check_async(redact_result.text)

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
        and _RISK_ORDER.index(guard_result.risk_level) >= _RISK_ORDER.index(RiskLevel.HIGH)
    ):
        background_tasks.add_task(
            _evolve.process_blocked,
            content    = payload.content,
            flags      = guard_result.flags,
            risk_level = guard_result.risk_level,
        )
        log.info(
            json.dumps({"event": "evolution_queued", "request_id": rid})
        )

    # ── Stage 4b: Real-time alerting ──────────────────────────────────
    if not allowed:
        try:
            from warden.alerting import alert_block_event
            top_flag = guard_result.top_flag
            background_tasks.add_task(
                alert_block_event,
                attack_type  = top_flag.flag.value if top_flag else "unknown",
                risk_level   = guard_result.risk_level.value,
                rule_summary = reason,
                request_id   = rid,
            )
        except ImportError:
            pass

    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    log.info(
        json.dumps({
            "event":      "filter_done",
            "request_id": rid,
            "allowed":    allowed,
            "risk":       guard_result.risk_level.value,
            "elapsed_ms": elapsed_ms,
        })
    )

    # ── Stage 5: Analytics logging ────────────────────────────────────
    try:
        entry = event_logger.build_entry(
            request_id    = rid,
            allowed       = allowed,
            risk_level    = guard_result.risk_level.value,
            flags         = [f.flag.value for f in guard_result.flags],
            secrets_found = [f.kind for f in redact_result.findings],
            payload_len   = len(payload.content),
            elapsed_ms    = elapsed_ms,
            strict        = strict,
        )
        event_logger.append(entry)
    except Exception:
        log.exception(json.dumps({"event": "analytics_error", "request_id": rid}))

    # ── Stage 6: SIEM integration ─────────────────────────────────────
    try:
        from warden.analytics.siem import ship_event
        background_tasks.add_task(ship_event, entry)  # type: ignore[possibly-undefined]
    except ImportError:
        pass

    response = FilterResponse(
        allowed          = allowed,
        risk_level       = guard_result.risk_level,
        filtered_content = redact_result.text,
        secrets_found    = redact_result.findings,
        semantic_flags   = guard_result.flags,
        reason           = reason,
    )

    # ── Stage 7: Cache write ──────────────────────────────────────────
    if allowed:
        set_cached(payload.content, response.model_dump_json())

    return response


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
    """
    Return the log metadata recorded for a specific *request_id*.

    No prompt content is ever stored — only metadata (flags, timing, lengths).
    """
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
    """
    Remove all log entries whose timestamp is strictly before *before*.

    Use this to honour GDPR right-to-erasure requests.  Returns the
    count of entries removed.
    """
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


# ── Global error handler ──────────────────────────────────────────────────────

@app.exception_handler(Exception)
async def unhandled_exception(request: Request, exc: Exception):
    rid = getattr(request.state, "request_id", "-")
    log.exception(json.dumps({"event": "unhandled_error", "request_id": rid, "error": str(exc)}))
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal warden error.", "request_id": rid},
    )
