"""
Shadow Warden AI — Warden Gateway
FastAPI application that acts as the mandatory filter proxy.

Every request from app/ must hit POST /filter before the payload
is forwarded to any model or downstream service.

Pipeline:
    raw content
        → SecretRedactor  (strip credentials / PII)
        → SemanticGuard   (detect injections / harmful intent)
        → [if blocked] EvolutionEngine  (BackgroundTask — calls Claude Opus,
                                         writes new rule, hot-reloads corpus)
        → FilterResponse  (allowed | blocked, with reasons)
"""
from __future__ import annotations

import json
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from warden.analytics import logger as event_logger
from warden.brain.evolve import EvolutionEngine
from warden.brain.semantic import SemanticGuard as BrainSemanticGuard
from warden.schemas import FilterRequest, FilterResponse, FlagType, RiskLevel, SemanticFlag
from warden.secret_redactor import SecretRedactor
from warden.semantic_guard import SemanticGuard

# ── Logging ───────────────────────────────────────────────────────────────────

LOG_LEVEL = os.getenv("LOG_LEVEL", "info").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("warden.gateway")

# ── Dynamic rules path ────────────────────────────────────────────────────────

_DYNAMIC_RULES_PATH = Path(
    os.getenv("DYNAMIC_RULES_PATH", "/warden/data/dynamic_rules.json")
)

# ── Risk helpers ──────────────────────────────────────────────────────────────

_RISK_ORDER = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.BLOCK]


def _max_risk(a: RiskLevel, b: RiskLevel) -> RiskLevel:
    return a if _RISK_ORDER.index(a) >= _RISK_ORDER.index(b) else b


# ── Singletons (one instance per process, shared across all requests) ─────────

_redactor:    SecretRedactor     | None = None
_guard:       SemanticGuard      | None = None
_brain_guard: BrainSemanticGuard | None = None
_evolve:      EvolutionEngine    | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _redactor, _guard, _brain_guard, _evolve
    strict = os.getenv("STRICT_MODE", "false").lower() == "true"

    log.info("Warden gateway starting — initialising filter pipeline…")
    _redactor = SecretRedactor(strict=strict)
    _guard    = SemanticGuard(strict=strict)

    # ── ML Brain Guard ────────────────────────────────────────────────────
    # Loads all-MiniLM-L6-v2 (~80 MB) on first run, then serves from the
    # MODEL_CACHE_DIR volume.  __post_init__ pre-computes corpus embeddings,
    # so the model is fully ready before the first real request arrives.
    log.info("Loading ML semantic brain (all-MiniLM-L6-v2) …")
    _brain_guard = BrainSemanticGuard()
    log.info("ML brain corpus ready.")

    # ── Restore evolved corpus from previous sessions (Step 5) ───────────
    # dynamic_rules.json is written atomically by EvolutionEngine each time
    # Claude Opus analyses a blocked attack.  On restart we replay those
    # semantic examples so the corpus is never reset to the base 25 entries.
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
            log.warning(
                "Could not load dynamic_rules.json — starting with base corpus."
            )

    # ── Pre-warm inference path (Step 6) ─────────────────────────────────
    # One dummy query forces the model to JIT-compile its forward pass so
    # the first real /filter request has p50 latency, not p99 cold-start.
    _brain_guard.check("system warm-up ping")
    log.info("ML brain warm-up complete.")

    # ── Evolution Engine ──────────────────────────────────────────────────
    # IMPORTANT: pass _brain_guard (which has add_examples) so that evolved
    # semantic rules are hot-reloaded into the same object queried at
    # /filter time.  Previously _guard (rule-based, no add_examples) was
    # passed here — that was a bug preventing corpus hot-reload from working.
    if os.getenv("ANTHROPIC_API_KEY"):
        _evolve = EvolutionEngine(semantic_guard=_brain_guard)
        log.info("EvolutionEngine online — high-severity blocks will trigger Claude Opus analysis.")
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
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


# ── Request-ID middleware ──────────────────────────────────────────────────────

@app.middleware("http")
async def attach_request_id(request: Request, call_next):
    rid = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request.state.request_id = rid
    response = await call_next(request)
    response.headers["X-Request-ID"] = rid
    return response


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["ops"], summary="Liveness probe")
async def health():
    return {
        "status":   "ok",
        "service":  "warden-gateway",
        "evolution": _evolve is not None,
    }


# ── /filter ───────────────────────────────────────────────────────────────────

@app.post(
    "/filter",
    response_model=FilterResponse,
    tags=["filter"],
    summary="Filter raw content through the Warden pipeline",
    status_code=status.HTTP_200_OK,
)
async def filter_content(
    payload:          FilterRequest,
    request:          Request,
    background_tasks: BackgroundTasks,
) -> FilterResponse:
    """
    **Pipeline** (in order):

    1. **SecretRedactor** — regex scan for API keys, credentials, PII, credit
       cards, SSNs, IBANs, email addresses.  All found values are replaced
       with `[REDACTED:<kind>]` tokens *before* any semantic analysis.

    2. **SemanticGuard** — ML + rule-based scan of the *redacted* text for
       prompt injection, jailbreak attempts, harmful content, and policy
       violations.

    3. **Decision** — `allowed=True` if `risk_level` is LOW (or MEDIUM when
       not in strict mode).  The *filtered* (redacted) content is returned
       so the caller can safely forward it downstream.

    4. **Evolution Loop** *(background, non-blocking)* — if the request was
       blocked at HIGH or BLOCK risk and `ANTHROPIC_API_KEY` is set, Claude
       Opus analyses the attack and appends a new rule to `dynamic_rules.json`.
       The SemanticGuard corpus is hot-reloaded immediately — no restart needed.

    GDPR note: original secrets are never logged; only their *type* and
    character offsets are recorded.
    """
    rid   = getattr(request.state, "request_id", "-")
    start = time.perf_counter()

    strict = payload.strict or (_guard.strict if _guard else False)

    log.info("[%s] /filter called — content_len=%d strict=%s",
             rid, len(payload.content), strict)

    # ── Stage 1: Secret Redaction ──────────────────────────────────────────
    redact_result = _redactor.redact(payload.content)   # type: ignore[union-attr]

    if redact_result.findings:
        kinds = [f.kind for f in redact_result.findings]
        log.warning("[%s] Secrets/PII redacted: %s", rid, kinds)

    # ── Stage 2: Rule-based Semantic Analysis (on redacted text only) ─────
    guard_result = _guard.analyse(redact_result.text)   # type: ignore[union-attr]

    if guard_result.flags:
        log.warning("[%s] Rule-based flags: %s risk=%s",
                    rid,
                    [f.flag for f in guard_result.flags],
                    guard_result.risk_level)

    # ── Stage 2b: ML Semantic Brain Check ─────────────────────────────────
    # all-MiniLM-L6-v2 catches paraphrased jailbreaks that regex misses.
    # We merge its output into guard_result so downstream stages (decision,
    # evolution loop, analytics) see a single unified result.
    if _brain_guard is not None:
        brain_result = _brain_guard.check(redact_result.text)
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
                "[%s] ML brain flagged — score=%.3f → risk escalated to %s",
                rid, brain_result.score, guard_result.risk_level.value,
            )

    # ── Stage 3: Decision ─────────────────────────────────────────────────
    allowed = guard_result.safe_for(strict)

    reason = ""
    if not allowed:
        top = guard_result.top_flag
        reason = top.detail if top else f"Risk level: {guard_result.risk_level}"

    # ── Stage 4: Evolution Loop (background — never blocks the response) ──
    if (
        not allowed
        and _evolve is not None
        and _RISK_ORDER.index(guard_result.risk_level) >= _RISK_ORDER.index(RiskLevel.HIGH)
    ):
        background_tasks.add_task(
            _evolve.process_blocked,
            content    = payload.content,   # original (pre-redaction) for hash dedup
            flags      = guard_result.flags,
            risk_level = guard_result.risk_level,
        )
        log.info("[%s] EvolutionEngine queued as background task.", rid)

    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    log.info("[%s] /filter done — allowed=%s risk=%s elapsed_ms=%s",
             rid, allowed, guard_result.risk_level, elapsed_ms)

    # ── Stage 5: Analytics logging (non-blocking, fire-and-forget) ────────
    # Content is NEVER written — only metadata (length, flags, timing, PII types).
    try:
        entry = event_logger.build_entry(
            request_id    = rid,
            allowed       = allowed,
            risk_level    = guard_result.risk_level.value,
            flags         = [f.flag.value for f in guard_result.flags],
            secrets_found = [f.kind for f in redact_result.findings],
            content_len   = len(payload.content),
            elapsed_ms    = elapsed_ms,
            strict        = strict,
        )
        event_logger.append(entry)
    except Exception:
        log.exception("[%s] Analytics logger failed — continuing.", rid)

    return FilterResponse(
        allowed          = allowed,
        risk_level       = guard_result.risk_level,
        filtered_content = redact_result.text,
        secrets_found    = redact_result.findings,
        semantic_flags   = guard_result.flags,
        reason           = reason,
    )


# ── Global error handler ──────────────────────────────────────────────────────

@app.exception_handler(Exception)
async def unhandled_exception(request: Request, exc: Exception):
    rid = getattr(request.state, "request_id", "-")
    log.exception("[%s] Unhandled error: %s", rid, exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal warden error.", "request_id": rid},
    )
