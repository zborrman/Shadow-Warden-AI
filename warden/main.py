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
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from warden.brain.poison import DataPoisoningGuard
    from warden.honey import HoneyEngine
    from warden.session_guard import SessionGuard
    from warden.threat_intel.scheduler import ThreatIntelScheduler as _TISchedulerT
    from warden.threat_intel.store import ThreatIntelStore as _TIStoreT
import json
import logging
import logging.handlers
import os
import re
import uuid
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from fastapi import (
    FastAPI,
    Request,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

from warden import __version__ as _warden_version
from warden import runtime as _runtime_module
from warden.api.docs_router import router as _docs_router
from warden.api.masking import router as _masking_router
from warden.api_versioning import APIVersionMiddleware
from warden.auth.saml_provider import SAMLProvider
from warden.auth.saml_provider import get_provider as _get_saml_provider
from warden.billing import BILLING_AGG_INTERVAL, BillingStore
from warden.brain.evolve import EvolutionEngine, build_evolution_engine
from warden.brain.semantic import SemanticGuard as BrainSemanticGuard
from warden.config import settings
from warden.data_policy import DataPolicyEngine
from warden.gateway_state import gateway_state
from warden.mtls import MTLSMiddleware
from warden.offline import is_offline as _is_offline
from warden.onboarding import OnboardingEngine
from warden.review_queue import ReviewQueue
from warden.rule_ledger import RuleLedger
from warden.secret_redactor import SecretRedactor
from warden.semantic_guard import SemanticGuard
from warden.services.filter_orchestrator import run_filter_pipeline
from warden.threat_feed import ThreatFeedClient
from warden.threat_neutralizer_router import router as _neutralizer_router
from warden.threat_store import ThreatStore
from warden.threat_vault import ThreatVault
from warden.webhook_dispatch import WebhookStore

# ── Structured JSON logging ───────────────────────────────────────────────────

#: Correlation fields lifted off the LogRecord when a caller supplied them via
#: `logging.info(..., extra={"request_id": rid})`. Metadata only — never content.
#: `risk_level` and `request_id` are here because grafana/promtail.yml has been
#: parsing for them since it was written, against a formatter that emitted
#: neither (OB-F11): the Loki `risk_level` label an operator would filter on was
#: always empty, and the extraction was a no-op.
_LOG_EXTRA_FIELDS = ("request_id", "tenant_id", "risk_level", "session_id", "outcome")


def _active_trace_ids() -> tuple[str | None, str | None]:
    """(trace_id, span_id) of the active OTel span as hex, or (None, None).

    Self-populating: no caller has to thread anything through, so every log line
    emitted inside a traced request carries the join key to its trace. This is
    what makes a Loki derived field able to link a log line to Jaeger — before
    OB-9 nothing in a log record and nothing in a span shared a value, so logs
    and traces could not be joined at all.

    Never raises, in any direction: OTel is opt-in (OTEL_ENABLED=false by
    default) and telemetry must never be able to break logging. This is log
    enrichment, not a security guard — nothing is bypassed when it returns
    empty, the line simply carries no trace link. The isinstance guards matter
    because a mocked span sets these to non-ints (see Rule.md / _span_meta).
    """
    try:
        from opentelemetry import trace as _otel_trace

        ctx = _otel_trace.get_current_span().get_span_context()
        tid = getattr(ctx, "trace_id", None)
        sid = getattr(ctx, "span_id", None)
        if isinstance(tid, int) and tid:
            return (
                format(tid, "032x"),
                format(sid, "016x") if isinstance(sid, int) and sid else None,
            )
    except Exception:  # noqa: BLE001 - logging must survive any telemetry fault
        pass
    return None, None


class _JsonFormatter(logging.Formatter):
    """Emit each log record as a single JSON line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict = {
            "ts":      datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level":   record.levelname,
            "logger":  record.name,
            "message": record.getMessage(),
        }

        # ── OB-9 correlation keys ────────────────────────────────────────────
        # Emitted only when present, so a line never gains a null field. GDPR:
        # these are identifiers and metadata, never prompt content, decoded
        # text or PII — the content-is-never-logged rule is unchanged.
        trace_id, span_id = _active_trace_ids()
        if trace_id:
            payload["trace_id"] = trace_id
            if span_id:
                payload["span_id"] = span_id
        for field in _LOG_EXTRA_FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value

        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        # `default=str` so one non-serializable value in `extra` degrades that
        # field to its repr instead of raising and losing the entire log line —
        # losing the line is how an error disappears at exactly the moment
        # somebody is trying to read it.
        return json.dumps(payload, ensure_ascii=False, default=str)


def _configure_json_logging() -> None:
    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)
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
    from prometheus_fastapi_instrumentator import metrics as _pfi_metrics
    _PROMETHEUS_ENABLED = os.getenv("PROMETHEUS_METRICS_ENABLED", "true").lower() != "false"
except ImportError:
    _PROMETHEUS_ENABLED = False
    log.warning("prometheus-fastapi-instrumentator not installed — /metrics disabled.")

# ── OB-5: latency buckets that can express the SLO we sell ───────────────────
# The library ships latency_lowr_buckets=(0.1, 0.5, 1) for the per-handler
# histogram http_request_duration_seconds. docs/sla.md commits to **P99 < 50 ms**
# on /filter — so every observation landed in the first bucket and
# histogram_quantile could only interpolate inside [0, 0.1]. The P95/P99 panels
# and the 500 ms latency alert were reporting a number the histogram had no
# resolution to produce. (The library's fine-grained companion,
# http_request_duration_highr_seconds, carries no `handler` label, so it cannot
# answer "how fast is /filter" either.)
#
# These edges bracket the SLO — five of them below 100 ms — and keep the coarse
# tail so a genuinely slow request is still visible.
#
# Changing bucket edges starts a NEW time series: historical
# http_request_duration_seconds_bucket data is not comparable across this
# change, and the burn-rate alerts should be re-checked against real numbers
# once a full window has elapsed.
# Upper edges added 2026-08-24. With 2.5 as the last finite bucket, production
# measured P99 = exactly 2500 ms for hours — not a latency, but the top edge,
# with histogram_quantile unable to say whether the real value was 3 s or 30 s.
# 2.6% of /filter requests (6 of 230 in 25 min) land above 2.5 s while P50 is
# 19 ms, so the SLO breach is entirely a tail the histogram could not resolve.
# You cannot fix a latency you cannot measure.
#
# 5 / 10 / 30 s bracket the plausible causes: a 5 s client timeout (three exist
# in warden/alerting.py), a 10 s httpx default, and anything beyond that.
_LATENCY_BUCKETS = (
    0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
    float("inf"),
)

# Anchored on purpose. `excluded_handlers` entries are regexes matched with
# re.search, so a bare "/health" would also exclude /gsam/health, /soc/health,
# /business-intelligence/health and 15 other real operator endpoints.
# Only the gateway's own liveness route and the scrape endpoint are dropped:
# the compose healthcheck polls /health every 30s and Prometheus polls /metrics
# every 15s, and counting that synthetic traffic inflates the denominator that
# the availability and burn-rate alerts divide by — on a quiet gateway it is
# most of the "traffic", which makes the measured error ratio look far better
# than it is.
_METRICS_EXCLUDED_HANDLERS = [r"^/metrics$", r"^/health(/.*)?$"]

# API docs auth (_docs_auth, DOCS_USERNAME/DOCS_PASSWORD) moved to
# warden/api/docs_router.py (P-2) with the four routes that used it.

# ── Rate limiter ──────────────────────────────────────────────────────────────
# Hoisted to warden/limiter.py (Phase 3b) so extracted routers can share the same
# Limiter instance without importing warden.main. Aliases keep every existing
# @_limiter.limit(...) decorator and the app.state.limiter binding unchanged.
from warden.limiter import limiter as _limiter  # noqa: E402
from warden.limiter import tenant_key as _tenant_key  # noqa: E402,F401  (re-export for compat)

# ── Dynamic rules path ────────────────────────────────────────────────────────

_DYNAMIC_RULES_PATH = Path(
    settings.dynamic_rules_path
)

# ── Risk helpers ──────────────────────────────────────────────────────────────
#
# `max_risk` and its RISK_ORDER moved to warden/schemas.py, beside the enum whose
# ordering they encode; the WebSocket/LLM env vars moved to warden/api/ws_stream.py
# with their only readers (P-2).


# `_content_entropy` moved to warden/services/filter_orchestrator.py (P-2) —
# the pipeline body was its only caller.


# ── Dynamic evolution rule registry ───────────────────────────────────────────

@dataclass
class _DynamicRegexRule:
    rule_id: str
    pattern: re.Pattern
    snippet: str         # first 60 chars of the pattern for logging


# Hot-loadable list of evolution-generated regex rules (populated at startup
# and whenever the EvolutionEngine generates a new regex_pattern rule).
_dynamic_regex_rules: list[_DynamicRegexRule] = []


# ── Multi-tenant SemanticGuard registry ──────────────────────────────────────
# The dict itself lives in warden.gateway_state (P-2) — a leaf both this module
# and warden/api/system.py's /health route can read; construction (importing
# the heavy BrainSemanticGuard class) stays here.


def _get_tenant_guard(tenant_id: str) -> BrainSemanticGuard:
    """Return (or create) the BrainSemanticGuard for *tenant_id*."""
    if tenant_id not in gateway_state.tenant_guards:
        log.info("Creating new ML brain corpus for tenant=%r", tenant_id)
        gateway_state.tenant_guards[tenant_id] = BrainSemanticGuard()
    return gateway_state.tenant_guards[tenant_id]


# ── Singletons (one per process) ─────────────────────────────────────────────

_redactor:       SecretRedactor    | None = None
_guard:          SemanticGuard     | None = None
_brain_guard:    BrainSemanticGuard| None = None   # "default" tenant
_session_guard:  SessionGuard | None       = None
_honey_engine:   HoneyEngine | None       = None
_evolve:         EvolutionEngine   | None = None
_agent_monitor:  AgentMonitor | None   = None
_ledger:         RuleLedger        | None = None
_review_queue:   ReviewQueue       | None = None
_threat_store:   ThreatStore       | None = None
_threat_vault:   ThreatVault       | None = None
_threat_intel_store: _TIStoreT | None = None
_ti_scheduler:       _TISchedulerT | None = None
_billing:        BillingStore      | None = None
_onboarding:     OnboardingEngine  | None = None
_policy:         DataPolicyEngine  | None = None
_feed:           ThreatFeedClient  | None = None
_saml:           SAMLProvider      | None = None
_webhook_store:  WebhookStore      | None = None
_poison_guard:   DataPoisoningGuard | None = None
_audit_trail = None  # AuditTrail | None — imported lazily in lifespan
_threat_sync    = None  # ThreatSyncClient | None — cross-region sync
_corpus_watcher = None  # CorpusSyncWatcher | None — corpus invalidation consumer
_bl_watcher     = None  # GlobalBlocklistWatcher | None — cross-region IP blocklist

# Guard prevents multiple TestClient instances (module-scoped fixtures in tests)
# from re-running lifespan teardown on the same app singleton, which closes
# SQLite connections that other in-flight tests still need.
_lifespan_active: bool = False


# `_global_blocklist_is_blocked` moved to warden/services/filter_orchestrator.py
# (P-2) with the pipeline body, its only caller.

try:
    from warden.agent_monitor import AgentMonitor
    _AGENT_MONITOR_AVAILABLE = True
except ImportError:
    _AGENT_MONITOR_AVAILABLE = False

from warden.agent_sandbox import get_registry as _get_sandbox_registry  # noqa: E402


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


_FEED_SYNC_SECS = float(os.getenv("THREAT_FEED_SYNC_HRS", "6")) * 3600


async def _threat_feed_sync_loop() -> None:
    """Background task: sync threat intelligence feed every THREAT_FEED_SYNC_HRS hours."""
    # First sync shortly after startup to populate corpus early
    await asyncio.sleep(60)
    while True:
        if _feed is not None and _feed.is_enabled():
            with suppress(Exception):
                n = await asyncio.get_running_loop().run_in_executor(None, _feed.sync)
                if n:
                    log.info("ThreatFeed: synced %d new rule(s) into corpus.", n)
        await asyncio.sleep(_FEED_SYNC_SECS)


def _print_motd(
    evolution:      bool,
    multimodal:     bool,
    audit_ok:       bool,
    agent_monitor:  bool,
    vault_sigs:     int,
    fail_strategy:  str,
) -> None:
    """Print the Shadow Warden MOTD to stdout on startup."""
    import sys  # noqa: PLC0415
    tty = sys.stdout.isatty()
    C = "[1;36m" if tty else ""  # noqa: N806
    G = "[1;32m" if tty else ""  # noqa: N806
    Y = "[1;33m" if tty else ""  # noqa: N806
    R = "[1;31m" if tty else ""  # noqa: N806
    D = "[2m"    if tty else ""  # noqa: N806
    N = "[0m"    if tty else ""  # noqa: N806
    def _flag(ok: bool, on: str, off: str) -> str:
        return f"{G}[{on}]{N}" if ok else f"{R}[{off}]{N}"
    ev = _flag(evolution,     'ACTIVE',       'AIR-GAPPED' )
    mm = _flag(multimodal,    'CLIP+WHISPER', 'UNAVAILABLE')
    au = _flag(audit_ok,      'VERIFIED',     'DEGRADED'   )
    ag = _flag(agent_monitor, 'ENFORCED',     'DISABLED'   )
    fs = f"{Y}[{fail_strategy.upper()}]{N}"
    vs = f"{G}[{vault_sigs:,} sigs]{N}"
    p = print
    p(f"{C}")
    p("###########################################################################")
    p("#                                                                         #")
    p("#              SHADOW WARDEN AI  |  AI SECURITY GATEWAY                  #")
    p("#                           VERSION 2.9                                  #")
    p("#                                                                         #")
    p(f"###########################################################################{N}")
    p(f"  {D}[SYSTEM STATUS]{N}")
    p(f"  Integrity Chain  {au}   Threat Vault    {vs}")
    p(f"  Multi-Modal      {mm}   Zero-Trust      {ag}")
    p(f"  Evolution Engine {ev}   Fail Strategy   {fs}")
    p("")
    p(f"  {D}\"The best firewall is the one the attacker thinks they've already bypassed.\"  {N}")
    p(f"  {D}                                       -- Shadow Warden v2.9{N}")
    p("###########################################################################")
    p("")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _redactor, _guard, _brain_guard, _evolve, _agent_monitor, _ledger, _review_queue, _threat_store, _billing, _onboarding, _policy, _feed, _saml, _session_guard, _honey_engine, _lifespan_active

    # Reentrancy guard: if a module-scoped TestClient triggers a second lifespan
    # entry on the same app singleton, just yield — don't re-init or tear down
    # globals that the session-scoped client is still using.
    if _lifespan_active:
        yield
        return

    _lifespan_active = True

    # ── Config validation + auditable snapshot (Deep-Eng P1) ────────────────
    # Log every config problem at startup (drift visibility — the dev-override
    # incident would have surfaced here) and record the effective, secret-masked
    # configuration once per boot for audit. Soft by default; opt into fail-closed
    # via CONFIG_FAILCLOSED=true so a mis-configured deploy crash-loops instead of
    # serving with e.g. an out-of-range detection threshold.
    try:
        from warden.config import settings as _cfg  # noqa: PLC0415
        _cfg_problems = _cfg.validate()
        for _p in _cfg_problems:
            log.warning("config: %s", _p)
        log.info("effective config: %s", _cfg.redacted_dump())
        if _cfg_problems and os.getenv("CONFIG_FAILCLOSED", "false").lower() == "true":
            from warden.config import ConfigValidationError  # noqa: PLC0415
            raise ConfigValidationError("; ".join(_cfg_problems))
    except ImportError as _cfg_err:
        log.warning("config validation skipped: %r", _cfg_err)

    # ── P-3a: PQC self-check — a paid feature must not be silently absent ───
    # PQC (ML-DSA-65 / ML-KEM-768) is an Enterprise-tier feature. It was
    # non-functional in every deployed image from v4.7 until 2026-07-27: the
    # Dockerfile installed the liboqs *bindings* and never built the native C
    # library, and the failure was swallowed by a `|| echo` in the build and a
    # log.warning at import. Nothing ever asserted it, so nothing ever noticed.
    #
    # Advisory by design: this logs ERROR, it does not refuse to boot. Air-gapped
    # and non-Enterprise deployments legitimately run without liboqs, and taking
    # the whole security gateway down over an optional crypto backend would trade
    # a silent degradation for a loud outage. `GET /health/pipeline` reports the
    # same state, so it is alertable.
    try:
        from warden.crypto.pqc import pqc_selfcheck
        _pqc_ok, _pqc_detail = pqc_selfcheck()
        if _pqc_ok:
            log.info("pqc: self-check passed — %s", _pqc_detail)
        else:
            log.error(
                "pqc: SELF-CHECK FAILED — %s. Post-quantum signing/KEM is NOT "
                "active; hybrid operations degrade to classical Ed25519/X25519. "
                "Enterprise tenants with pqc_enabled are not getting PQC.",
                _pqc_detail,
            )
    except Exception as _pqc_err:  # never let the check itself break boot
        log.error("pqc: self-check could not run: %r", _pqc_err)

    strict = os.getenv("STRICT_MODE", "false").lower() == "true"

    # ── #11: Fail-closed auth check ───────────────────────────────────────
    _api_key   = settings.warden_api_key
    _keys_path = settings.warden_api_keys_path
    if not _api_key and not _keys_path:
        if os.getenv("ALLOW_UNAUTHENTICATED", "false").lower() != "true":
            raise RuntimeError(
                "FATAL: Neither WARDEN_API_KEY nor WARDEN_API_KEYS_PATH is set. "
                "All requests would pass unauthenticated. "
                "Set ALLOW_UNAUTHENTICATED=true to explicitly allow this (dev only)."
            )
        log.warning("AUTH DISABLED — ALLOW_UNAUTHENTICATED=true. Never use in production.")

    # ── #1: VAULT_MASTER_KEY validation ──────────────────────────────────
    _vault_raw = os.getenv("VAULT_MASTER_KEY") or os.getenv("COMMUNITY_VAULT_KEY")
    if _vault_raw:
        try:
            from cryptography.fernet import Fernet as _Fernet  # noqa: PLC0415
            _Fernet(_vault_raw.encode() if isinstance(_vault_raw, str) else _vault_raw)
        except Exception as _vk_err:
            raise RuntimeError(
                f"FATAL: VAULT_MASTER_KEY is not a valid Fernet key: {_vk_err}. "
                "Generate a valid key with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            ) from _vk_err
    else:
        log.warning(
            "VAULT_MASTER_KEY not set — community keypairs and data pod secret keys "
            "will use insecure dev fallbacks. Set in production."
        )

    log.info("Warden gateway starting — initialising filter pipeline…")

    # ── DB schema — Alembic is the authority (D-1) ────────────────────
    # Until D-1 the tree under warden/db/migrations was never executed to
    # completion, so the tables that live only there — warden_core.monitors,
    # probe_results, marketplace_embeddings — existed in no deployment while
    # /monitors stayed mounted. entrypoint.sh did call it on every boot, with an
    # unresolvable -c path behind a `|| echo ... continuing anyway`; that block
    # is gone and this is the only invocation. Every revision is IF NOT EXISTS,
    # so this adopts the live schema rather than recreating it.
    #
    # The `create_schema()` fallback that shipped alongside this is gone.
    # Production reached revision 0013 cleanly on 2026-08-06 — monitors,
    # probe_results and marketplace_embeddings all present, `/monitors` serving
    # 200 — so the safety net now only obscures the thing it was there to cover:
    # with two schema paths, a failed migration still looks like a healthy boot.
    #
    # A failure here is logged and the gateway continues. Not an oversight: the
    # filter pipeline — the part that must not go down — has no Postgres
    # dependency at all, so refusing to boot over a migration error would trade
    # a reporting outage for a security one. The features that do need these
    # tables fail loudly on their own, which is now the only signal, and the
    # correct one.
    try:
        from warden.db.connection import DATABASE_URL  # noqa: PLC0415
        if DATABASE_URL:
            from warden.db.migrate import upgrade_to_head  # noqa: PLC0415
            _mig = await asyncio.to_thread(upgrade_to_head)
            log.info("DB schema: alembic %s", _mig.get("status"))
    except Exception as _db_err:
        log.error(
            "Alembic upgrade failed: %s — tables that exist only in the "
            "migration tree will be missing (/monitors, pgvector search, "
            "filter_events). The gateway continues; the filter pipeline does "
            "not depend on Postgres.",
            _db_err,
        )

    _redactor = SecretRedactor(strict=strict)
    _guard    = SemanticGuard(strict=strict)

    # ── ML Brain Guard ────────────────────────────────────────────────
    log.info("Loading ML semantic brain (all-MiniLM-L6-v2) …")
    _brain_guard = BrainSemanticGuard()
    gateway_state.tenant_guards["default"] = _brain_guard
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

    # ── Data Poisoning Guard ──────────────────────────────────────────
    global _poison_guard
    try:
        from warden.brain.poison import CorpusHealthMonitor, DataPoisoningGuard
        _poison_guard = DataPoisoningGuard(_brain_guard)
        await _poison_guard.initialise_async()
        _monitor = CorpusHealthMonitor(_poison_guard)
        _spawn_task(_monitor.run())
        log.info("DataPoisoningGuard active — corpus health monitor started.")
    except Exception as _pe:
        log.warning("DataPoisoningGuard unavailable (non-fatal): %s", _pe)

    # ── Community peering gauge ────────────────────────────────────────
    # Counted from the peering table at boot, not just on change, so a restart
    # cannot leave warden_community_peering_connections reading 0 while ACTIVE
    # peerings exist — which the "All community peerings lost" rule would then
    # report as a critical outage.
    try:
        from warden.communities.peering import (
            PEERING_COUNT_UNAVAILABLE,
            refresh_peering_gauge,
        )
        _peerings = await asyncio.to_thread(refresh_peering_gauge)
        if _peerings == PEERING_COUNT_UNAVAILABLE:
            log.warning(
                "Community peering gauge UNAVAILABLE at startup — the peering count "
                "could not be taken; see the peering log line above for the cause."
            )
        else:
            log.info("Community peering gauge published: %d active peering(s).", _peerings)
    except Exception as _pg_err:
        log.warning("Community peering gauge skipped (non-fatal): %s", _pg_err)

    # ── Causal Arbiter CPT calibration (MLE from prod logs) ─────────────
    try:
        from warden.causal_arbiter import calibrate_from_logs as _calibrate_cpt
        calibrated = await asyncio.to_thread(_calibrate_cpt)
        if calibrated:
            log.info("CausalArbiter: CPT calibrated from production logs.")
        else:
            log.debug("CausalArbiter: using prior CPT (insufficient log samples).")
    except Exception as _cpt_err:
        log.debug("CausalArbiter: CPT calibration skipped: %s", _cpt_err)

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

    # ── ThreatVault (adversarial prompt signatures) ───────────────────
    global _threat_vault
    _threat_vault = ThreatVault()
    log.info("ThreatVault online: %d signatures loaded.", _threat_vault.stats()["total"])

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

    # ── Threat Intelligence Feed client ──────────────────────────────
    # Initialised here (before EvolutionEngine) so we can pass it in.
    _feed = ThreatFeedClient(guard=_brain_guard)
    if _feed.is_enabled():
        log.info("ThreatFeed: enabled — feed_url=%s", os.getenv("THREAT_FEED_URL", ""))
    else:
        log.info("ThreatFeed: disabled (set THREAT_FEED_ENABLED=true to opt in).")

    # ── Evolution Engine ──────────────────────────────────────────────
    # build_evolution_engine() selects the backend automatically:
    #   EVOLUTION_ENGINE=auto (default) → Nemotron if NVIDIA_API_KEY set,
    #                                      else Claude if ANTHROPIC_API_KEY set
    #   EVOLUTION_ENGINE=nemotron       → always Nemotron Super (NIM)
    #   EVOLUTION_ENGINE=claude         → always Claude Opus (legacy)
    if not _is_offline():
        _evolve = build_evolution_engine(
            semantic_guard = _brain_guard,
            ledger         = _ledger,
            review_queue   = _review_queue,
            feed_client    = _feed,
        )
    if _evolve is not None:
        engine_name = type(_evolve).__name__
        log.info("EvolutionEngine online (%s).", engine_name)
    else:
        log.warning(
            "EvolutionEngine disabled — set NVIDIA_API_KEY (Nemotron) "
            "or ANTHROPIC_API_KEY (Claude) to enable automated rule generation."
        )

    # ── Publish shared singletons to the runtime container (Phase 1) ──────
    # Domain modules read these from warden.runtime instead of importing main,
    # which breaks the historic import cycle. See docs/architecture.md.
    from warden import runtime as _runtime  # noqa: PLC0415
    _runtime.publish(
        brain_guard=_brain_guard,
        evolve=_evolve,
        redactor=_redactor,
        guard=_guard,
        filter_orchestrator=run_filter_pipeline,
        # Read by the websocket handlers in warden/api/ws_stream.py (P-2); the
        # per-tenant corpus registry it closes over stays in main.
        tenant_guard=_get_tenant_guard,
        # Shared with the /filter routes in warden/api/filter.py (P-2).
        spawn_task=_spawn_task,
        ship_bypass=_ship_bypass,
        honey_engine=_honey_engine,
        session_guard=_session_guard,
        threat_vault=_threat_vault,
        threat_store=_threat_store,
        poison_guard=_poison_guard,
        # Phase 3 extracted routers (onboarding/policy/feed/msp)
        billing=_billing,
        onboarding=_onboarding,
        policy=_policy,
        feed=_feed,
        # Phase 3 extracted routers (rules/admin)
        ledger=_ledger,
        review_queue=_review_queue,
        dynamic_regex_rules=_dynamic_regex_rules,
    )

    # ── Agent Monitor ─────────────────────────────────────────────────
    if _AGENT_MONITOR_AVAILABLE:
        _agent_monitor = AgentMonitor()
        log.info("AgentMonitor online.")
        # Share singleton with openai_proxy so it records tool events
        try:
            import warden.openai_proxy as _proxy_mod
            _proxy_mod._agent_monitor = _agent_monitor
        except Exception as _exc:  # noqa: BLE001
            log.debug("suppressed exception: %r", _exc)
        # Publish for extracted routers (api/compliance_report.py, Phase 3)
        _runtime.publish(agent_monitor=_agent_monitor)

    log.info("Filter pipeline ready.")

    # ── Agent Sandbox manifest registry ──────────────────────────────
    _sandbox_count = _get_sandbox_registry().load_from_file()
    if _sandbox_count:
        log.info("AgentSandbox: loaded %d manifest(s).", _sandbox_count)
    else:
        log.info("AgentSandbox: no manifest file configured (set AGENT_SANDBOX_PATH).")
    # Share sandbox registry with openai_proxy so ToolCallGuard picks it up
    try:
        import warden.openai_proxy as _proxy_mod  # noqa: PLC0415
        _proxy_mod._sandbox_registry = _get_sandbox_registry()
    except Exception as _exc:  # noqa: BLE001
        log.debug("suppressed exception: %r", _exc)

    # ── Threat Intelligence Engine (opt-in) ───────────────────────────
    _ti_task = None
    if os.getenv("THREAT_INTEL_ENABLED", "false").lower() == "true":
        try:
            from warden.threat_intel import (  # noqa: PLC0415
                RuleFactory,
                ThreatIntelAnalyzer,
                ThreatIntelCollector,
                ThreatIntelScheduler,
                ThreatIntelStore,
            )
            global _threat_intel_store, _ti_scheduler
            _threat_intel_store = ThreatIntelStore()
            _ti_analyzer   = ThreatIntelAnalyzer(store=_threat_intel_store)
            _ti_collector  = ThreatIntelCollector(store=_threat_intel_store)
            _ti_factory    = RuleFactory(
                store=_threat_intel_store,
                review_queue=_review_queue,
                ledger=_ledger,
                brain_guard=_brain_guard,
            )
            _ti_scheduler  = ThreatIntelScheduler(_ti_collector, _ti_analyzer, _ti_factory)
            _ti_task = asyncio.create_task(_ti_scheduler.loop())
            _runtime.publish(
                threat_intel_store=_threat_intel_store,
                ti_scheduler=_ti_scheduler,
            )
            log.info("ThreatIntelScheduler online (sync every %sh).",
                     os.getenv("THREAT_INTEL_SYNC_HRS", "6"))
        except Exception as _ti_err:
            log.warning("ThreatIntelEngine failed to start: %s", _ti_err)
    else:
        log.info("ThreatIntelEngine disabled (set THREAT_INTEL_ENABLED=true to opt in).")

    # ── Intel Ops Bridge (opt-in) ─────────────────────────────────────
    _intel_bridge_task = None
    if os.getenv("INTEL_OPS_ENABLED", "false").lower() == "true":
        try:
            from warden.intel_bridge import WardenIntelBridge  # noqa: PLC0415
            _intel_bridge = WardenIntelBridge(
                evolve_engine  = _evolve,
                semantic_guard = _brain_guard,
            )
            _intel_bridge_task = asyncio.create_task(_intel_bridge.run_loop())
            _runtime.publish(intel_bridge=_intel_bridge)
            log.info(
                "IntelBridge online (interval=%.0fh).",
                float(os.getenv("INTEL_BRIDGE_INTERVAL_HRS", "6")),
            )
        except Exception as _ib_err:
            log.warning("IntelBridge failed to start (non-fatal): %s", _ib_err)
    else:
        log.info("IntelBridge disabled (set INTEL_OPS_ENABLED=true to opt in).")

    # ── Background tasks ──────────────────────────────────────────────
    _retirement_task  = asyncio.create_task(_nightly_rule_retirement())
    _billing_task     = asyncio.create_task(_billing_aggregation_loop())
    _feed_sync_task   = asyncio.create_task(_threat_feed_sync_loop())

    # ── Uptime probe scheduler (PostgreSQL only) ──────────────────────
    # Skipped when DATABASE_URL is SQLite (tests / air-gapped mode) because
    # TimescaleDB hypertables don't exist on SQLite and the background task
    # would hit a closed DB connection on test teardown.
    from warden.db.connection import is_postgres as _is_postgres  # noqa: PLC0415
    if _is_postgres():
        try:
            from warden.workers.probe_worker import (
                probe_scheduler as _probe_scheduler,
            )
            _spawn_task(_probe_scheduler())
            log.info("Uptime probe scheduler started.")
        except Exception as _probe_err:
            log.warning("probe_scheduler failed to start: %s", _probe_err)
    else:
        log.info("Uptime probe scheduler skipped (no PostgreSQL).")

    # ── Webhook store ─────────────────────────────────────────────────
    _webhook_store = WebhookStore()
    # Publish for extracted router (api/webhook_config.py, Phase 3b)
    _runtime.publish(webhook_store=_webhook_store)
    log.info("WebhookStore ready.")

    # ── Global Threat Sync (cross-region Redis Streams) ───────────────
    global _threat_sync, _corpus_watcher
    try:
        from warden.threat_sync import ThreatSyncClient  # noqa: PLC0415
        _threat_sync = ThreatSyncClient(semantic_guard=_brain_guard)
        _threat_sync.start()
    except Exception as _ts_err:
        log.warning("ThreatSync init failed (non-fatal): %s", _ts_err)

    # ── Corpus Sync (S3 upload + invalidation watcher) ────────────────
    try:
        from warden.corpus_sync import CorpusSyncWatcher  # noqa: PLC0415
        _corpus_watcher = CorpusSyncWatcher(poison_guard=_poison_guard)
        _corpus_watcher.start()
    except Exception as _cw_err:
        log.warning("CorpusSyncWatcher init failed (non-fatal): %s", _cw_err)

    # ── Global Blocklist Watcher (cross-region IP ban sync) ───────────
    global _bl_watcher
    try:
        from warden.global_blocklist import GlobalBlocklistWatcher  # noqa: PLC0415
        _bl_watcher = GlobalBlocklistWatcher(threat_store=_threat_store)
        _bl_watcher.start()
    except Exception as _blw_err:
        log.warning("GlobalBlocklistWatcher init failed (non-fatal): %s", _blw_err)

    # ── SAML 2.0 SSO (optional — only if env vars are set) ───────────
    _saml = _get_saml_provider()
    if _saml is not None:
        from warden.cache import _get_client as _redis_client_fn  # noqa: PLC0415
        try:
            _saml.attach_redis(_redis_client_fn())
            app.state.saml = _saml
            log.info("SAML 2.0 SSO provider ready.")
        except Exception as _saml_err:
            log.warning("SAML provider initialised but Redis attach failed: %s", _saml_err)
    else:
        app.state.saml = None

    # ── Session Guard (incremental injection detection) ───────────────
    try:
        from warden.cache import _get_client as _redis_client_for_sg  # noqa: PLC0415
        from warden.session_guard import SessionGuard  # noqa: PLC0415
        _sg_redis = _redis_client_for_sg()
        if _sg_redis is not None:
            _session_guard = SessionGuard(_sg_redis)
            log.info("SessionGuard online (incremental injection detection).")
        else:
            log.info("SessionGuard: Redis unavailable — disabled.")
    except Exception as _sg_err:
        log.warning("SessionGuard failed to initialise: %s", _sg_err)

    # ── Honey Engine (deception technology) ──────────────────────────
    try:
        from warden.cache import _get_client as _redis_client_for_honey  # noqa: PLC0415
        from warden.honey import HoneyEngine  # noqa: PLC0415
        _honey_engine = HoneyEngine(_redis_client_for_honey())
        log.info("HoneyEngine online (HONEY_MODE=%s).", os.getenv("HONEY_MODE", "false"))
    except Exception as _honey_err:
        log.warning("HoneyEngine failed to initialise: %s", _honey_err)

    # ── Multi-Modal Guard pre-warm (CLIP + Whisper + Haar cascade) ───
    _mm_ready = False
    try:
        from warden import audio_guard as _ag
        from warden import image_guard as _ig  # noqa: PLC0415
        from warden import image_redactor as _ir  # noqa: PLC0415
        _mm_ready = bool(_ig.prewarm())
        _ag.prewarm()
        _ir.prewarm()
    except Exception as _mm_err:
        _mm_ready = False
        log.warning("MultiModal guard pre-warm failed (non-fatal): %s", _mm_err)

    # ── GSAM rollup sink (SAC observations → gsam_agent_stats + drift) ─
    try:
        if settings.gsam_enabled:
            from warden.gsam import collector as _gsam_collector  # noqa: PLC0415
            from warden.gsam.rollup import rollup_sink as _gsam_rollup  # noqa: PLC0415
            _gsam_collector.register_sink(_gsam_rollup)
            log.info("GSAM rollup sink registered (observations → gsam_agent_stats)")
    except Exception as _gsam_err:
        log.warning("GSAM rollup sink registration failed (non-fatal): %s", _gsam_err)

    # ── OpenTelemetry distributed tracing ─────────────────────────────
    try:
        from warden.telemetry import setup_telemetry  # noqa: PLC0415
        setup_telemetry(app)
    except Exception as _otel_err:
        log.warning("OpenTelemetry init failed: %s", _otel_err)

    # ── Cryptographic audit trail (SOC 2) ──────────────────────────────
    global _audit_trail
    try:
        from warden.audit_trail import AuditTrail  # noqa: PLC0415
        _audit_trail = AuditTrail()
        # Publish for extracted routers (api/compliance_report.py, Phase 3)
        _runtime.publish(audit_trail=_audit_trail)
        log.info("AuditTrail online (SOC 2 tamper-evident chain).")
    except Exception as _audit_err:
        log.warning("AuditTrail init failed (non-fatal): %s", _audit_err)

    _print_motd(
        evolution     = _evolve is not None,
        multimodal    = _mm_ready,  # True only if the CLIP model actually loaded
        audit_ok      = _audit_trail is not None,
        agent_monitor = _agent_monitor is not None,
        vault_sigs    = _threat_vault.stats()["total"] if _threat_vault else 0,
        fail_strategy = os.getenv("WARDEN_FAIL_STRATEGY", "open"),
    )

    # ── Production-mode security warnings ────────────────────────────────────
    _env = os.getenv("ENV", "development").lower()
    if _env != "production":
        log.warning(
            "SECURITY: ENV=%s — set ENV=production in .env before public deployment",
            _env,
        )
    if not os.getenv("WARDEN_API_KEY") and not os.getenv("WARDEN_API_KEYS_PATH"):
        log.warning(
            "SECURITY: WARDEN_API_KEY is not set — POST /filter is open to unauthenticated requests"
        )
    if not os.getenv("DOCS_PASSWORD"):
        log.warning(
            "SECURITY: DOCS_PASSWORD is not set — /docs and /redoc are publicly accessible"
        )

    # ── Shadow AI syslog sink (passive DNS telemetry, opt-in) ────────────────
    _syslog_transport = None
    try:
        from warden.shadow_ai.syslog_sink import start_syslog_sink  # noqa: PLC0415
        _syslog_transport = await start_syslog_sink()
    except Exception as _sl_err:
        log.warning("syslog_sink failed to start (non-fatal): %s", _sl_err)

    # ── MISP ZMQ → syslog bridge (opt-in) ───────────────────────────────────
    _misp_task = None
    try:
        import os as _os  # noqa: PLC0415

        from warden.integrations.misp_bridge import start_misp_bridge  # noqa: PLC0415
        if _os.getenv("MISP_ZMQ_URL") or (_os.getenv("MISP_API_URL") and _os.getenv("MISP_API_KEY")):
            _misp_task = asyncio.create_task(start_misp_bridge())
            log.info(
                "misp_bridge started (syslog_forward=%s)",
                _os.getenv("MISP_SYSLOG_ENABLED", "true"),
            )
    except Exception as _misp_err:
        log.warning("misp_bridge failed to start (non-fatal): %s", _misp_err)

    # ── Live pipeline canary gate (Deep-Eng P0.3) ────────────────────────────
    # The orchestrator is published and the model pre-warmed by this point. Fire
    # the canary corpus through the REAL pipeline: proves the detector still
    # detects, not merely that stages import. Default = loud DEGRADED; prod sets
    # PIPELINE_FAILCLOSED_ON_CANARY=true to fail the boot on a broken detector.
    try:
        from warden.observability import (  # noqa: PLC0415
            SecurityDegradedError,
            enforce_canary_gate,
            run_pipeline_canary,
        )

        _canary = await run_pipeline_canary()
        # enforce_canary_gate raises SecurityDegradedError when degraded + fail-closed.
        _degraded = enforce_canary_gate(_canary, settings.pipeline_failclosed_on_canary)
        if _degraded:
            log.critical("PIPELINE CANARY FAILED at startup: %s — serving DEGRADED", _canary)
        elif _canary.get("available"):
            log.info("pipeline canary healthy: %s", _canary)
    except SecurityDegradedError:
        raise  # fail-closed: propagate so the container crash-loops and blocks the deploy
    except Exception as _canary_err:  # noqa: BLE001 — self-test must never crash boot
        log.warning("pipeline canary self-test errored (non-fatal): %r", _canary_err)

    yield

    if _syslog_transport is not None:
        _syslog_transport.close()

    if _misp_task is not None:
        _misp_task.cancel()

    _retirement_task.cancel()
    _billing_task.cancel()
    _feed_sync_task.cancel()
    if _ti_task is not None:
        _ti_task.cancel()
    if _intel_bridge_task is not None:
        _intel_bridge_task.cancel()
    with suppress(asyncio.CancelledError):
        await _retirement_task
    with suppress(asyncio.CancelledError):
        await _billing_task
    with suppress(asyncio.CancelledError):
        await _feed_sync_task
    if _ti_task is not None:
        with suppress(asyncio.CancelledError):
            await _ti_task
    if _intel_bridge_task is not None:
        with suppress(asyncio.CancelledError):
            await _intel_bridge_task

    if _ledger is not None:
        _ledger.close()
    if _threat_store is not None:
        _threat_store.close()
    if _billing is not None:
        _billing.close()
    if _policy is not None:
        _policy.close()
    if _threat_sync is not None:
        _threat_sync.stop()
    if _corpus_watcher is not None:
        _corpus_watcher.stop()
    if _bl_watcher is not None:
        _bl_watcher.stop()

    _lifespan_active = False
    log.info("Warden gateway shutting down.")


# ── Background task tracking ──────────────────────────────────────────────────
# asyncio.create_task() does not keep the returned Task alive on its own — if
# nothing holds a reference, the event loop is free to garbage-collect it
# mid-execution and any exception it raised is silently dropped. Fire-and-
# forget dispatches (bypass shipping, webhook delivery, WS broadcast) route
# through this helper so a strong reference is held until completion.
_live_background_tasks: set[asyncio.Task] = set()


def _spawn_task(coro) -> asyncio.Task:
    task = asyncio.create_task(coro)
    _live_background_tasks.add(task)

    def _on_done(t: asyncio.Task) -> None:
        _live_background_tasks.discard(t)
        if not t.cancelled() and (exc := t.exception()) is not None:
            log.warning("background task failed: %r", exc)

    task.add_done_callback(_on_done)
    return task


# ── App factory ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="Shadow Warden AI — Gateway",
    description=(
        "9-layer AI security gateway. All payloads must pass through **POST /filter** "
        "before reaching any model or downstream service.\n\n"
        "**Pipeline:** TopologicalGatekeeper → ObfuscationDecoder → SecretRedactor "
        "→ SemanticGuard → HyperbolicBrain → CausalArbiter → PhishGuard → ERS → Decision\n\n"
        "Blocked HIGH/BLOCK attacks trigger the **Evolution Loop**: Claude Opus "
        "analyses the attack and auto-generates a new detection rule (hot-reload, no restart).\n\n"
        "**Auth:** `X-API-Key` header required (except dev mode). "
        "Enterprise supports OIDC Bearer tokens on `/ext/*` routes.\n\n"
        "**Rate limiting:** Per-tenant sliding window (default 60 req/min) plus a "
        "monthly request quota set by the plan. Shadow-ban at ERS score ≥ 0.75.\n\n"
        "Every response advertises the throttling contract, so a client can pace itself "
        "instead of discovering a limit by being refused:\n\n"
        "- `RateLimit-Policy` / `RateLimit` — structured fields from "
        "draft-ietf-httpapi-ratelimit-headers-09, e.g. "
        "`RateLimit-Policy: \"requests-per-minute\";q=60;w=60` and "
        "`RateLimit: \"requests-per-minute\";r=59;t=41` — `q` quota, `w` window "
        "seconds, `r` remaining, `t` seconds to reset.\n"
        "- `RateLimit-Limit` / `RateLimit-Remaining` / `RateLimit-Reset` — the earlier "
        "draft spelling, mirrored as `X-RateLimit-*`.\n"
        "- `Retry-After` — delta-seconds, on 429 only, naming the same instant as the "
        "reset parameter.\n\n"
        "Live counters accompany the policy on routes that consume the window; a route "
        "that consumes nothing publishes the policy alone. Full conventions: "
        "https://shadow-warden-ai.com/doc/rate-limits\n\n"
        "**Versioning:** the version is in the URL path — use `/v1/...`. Unversioned "
        "paths still work but answer with `Deprecation: @<unix-time>` (RFC 9745), "
        "`Sunset` (RFC 8594) and `Link: <...>; rel=\"successor-version\"` / "
        "`rel=\"deprecation\"` (RFC 8288), and are served until 2027-08-23. A versioned "
        "resource gets at least 180 days' notice before sunset. "
        "Policy: https://shadow-warden-ai.com/doc/versioning"
    ),
    version=_warden_version,
    # Without this a generated client resolves every path against whatever host
    # it downloaded the spec from. The site publishes a copy of this document at
    # https://shadow-warden-ai.com/openapi.json, where no API lives, so an agent
    # reading it there had no way to learn the base URL — the readiness audit
    # recorded exactly that as "no machine-verifiable API surface confirmed".
    # WARDEN_GATEWAY_URL overrides for self-hosted and sovereign deployments.
    servers=[
        {"url": os.getenv("WARDEN_GATEWAY_URL", "https://api.shadow-warden-ai.com"),
         "description": "Production"},
        {"url": "http://localhost:8001", "description": "Local development"},
    ],
    contact={"name": "Shadow Warden AI", "url": "https://shadow-warden-ai.com", "email": "security@shadow-warden-ai.com"},
    license_info={"name": "Proprietary", "url": "https://shadow-warden-ai.com/terms"},
    openapi_tags=[
        {"name": "filter",    "description": "Core AI security filter pipeline"},
        {"name": "agent",     "description": "Agentic SOC — MasterAgent and SOVA patrols"},
        {"name": "xai",       "description": "Explainable AI — causal chains and PDF reports"},
        {"name": "shadow-ai", "description": "Shadow AI discovery and governance"},
        {"name": "sovereign", "description": "Sovereign AI cloud — jurisdictions and MASQUE tunnels"},
        {"name": "sep",       "description": "Syndicate Exchange Protocol — business community document exchange"},
        {"name": "secrets",   "description": "Secrets Governance — vault connectors and lifecycle"},
        {"name": "gdpr",      "description": "GDPR Art. 17 data scrubbing and retention"},
        {"name": "billing",   "description": "Billing, tiers, and add-on management"},
        {"name": "admin",     "description": "Admin operations — rule management and config"},
    ],
    lifespan=lifespan,
    # Disable FastAPI's built-in docs routes — we serve protected versions below.
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# Rate limiter state must be on app.state for slowapi to find it
app.state.limiter = _limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

# Published immediately (not in lifespan, unlike the singletons below) — the
# app object itself exists as soon as this line runs, and warden.api.docs_router
# needs it to call app.openapi(). The no-upward-import layer rule forbids that
# module from doing `from warden import main`, so it reads runtime.app instead.
_runtime_module.publish(app=app)

_DEFAULT_CORS = ",".join([
    "http://localhost:3000",
    "http://localhost:3001",
    # Portal (customer-facing SPA)
    "https://app.shadow-warden-ai.com",
    "https://shadow-warden-ai.com",
    "https://www.shadow-warden-ai.com",
    # Public API docs (Redoc at docs.shadow-warden-ai.com fetches /openapi-public.json)
    "https://docs.shadow-warden-ai.com",
    # Browser extension origins — required for Shadow Warden browser extension
    "https://chatgpt.com",
    "https://chat.openai.com",
    "https://claude.ai",
    "https://gemini.google.com",
    "https://copilot.microsoft.com",
])
def _cors_origins() -> list[str]:
    """
    Parse CORS_ORIGINS, refusing the wildcard while credentials are enabled (SR-2.4).

    Starlette does not reject `allow_origins=["*"] + allow_credentials=True`: it
    reflects the request Origin *and* sends Allow-Credentials, which is full
    credentialed cross-origin access from any site. An operator setting
    CORS_ORIGINS=* should not silently get that, so we fall back to the explicit
    allowlist and say so loudly.
    """
    raw = [o.strip() for o in os.getenv("CORS_ORIGINS", _DEFAULT_CORS).split(",") if o.strip()]
    if "*" in raw:
        log.error(
            "CORS_ORIGINS=* is refused while allow_credentials=True (it would grant "
            "credentialed cross-origin access to any site). Falling back to the default "
            "allowlist. Set an explicit origin list instead."
        )
        raw = [o for o in raw if o != "*"] or _DEFAULT_CORS.split(",")
    return raw


app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=True,
    allow_methods=["POST", "GET", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key", "X-Request-ID", "Authorization"],
)

# mTLS enforcement — validates client-certificate CN on every non-exempt request.
# Disabled by default (MTLS_ENABLED=false); enable in production after running
# scripts/gen_certs.sh and mounting certs/ into each container.
app.add_middleware(MTLSMiddleware)


#: Origin schemes the browser extension can legitimately present. The extension ID
#: is unknown at build time, so we cannot pin a full origin — but we can pin the
#: *scheme*, which no ordinary web page can forge (SR-2.4).
_EXT_ORIGIN_SCHEMES = ("chrome-extension://", "moz-extension://", "safari-web-extension://")


def _ext_allowed_origin(origin: str) -> str | None:
    """Return the origin to echo for /ext/*, or None when it is not allowed."""
    if not origin:
        return None
    if origin.startswith(_EXT_ORIGIN_SCHEMES):
        return origin
    extra = [o.strip() for o in os.getenv("EXT_CORS_ORIGINS", "").split(",") if o.strip()]
    return origin if origin in extra else None


class _ExtensionCORSMiddleware(BaseHTTPMiddleware):
    """
    Scheme-restricted CORS for /ext/* routes used by the Shadow Warden browser extension.

    Previously this returned `Access-Control-Allow-Origin: *` to *every* origin, so any
    web page could invoke /ext/* from a browser context. The extension ID is unknown at
    build time, so a full origin cannot be pinned — but the *scheme* can: only
    chrome-extension:// / moz-extension:// / safari-web-extension:// origins (plus an
    optional EXT_CORS_ORIGINS allowlist) are echoed now. Anything else gets no CORS
    headers and is blocked by the browser.

    Credentials are never allowed here — auth on /ext/* is the X-API-Key header, which a
    hostile page cannot obtain, so there is no reason to let cookies ride along.

    Registered last (outermost), so it:
      • Short-circuits OPTIONS preflight for /ext/* — bypasses CORSMiddleware
      • Overwrites any CORS headers on the final response for /ext/* routes
    """
    _BASE_HEADERS: dict[str, str] = {
        "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, X-API-Key, X-Request-ID, Authorization",
        "Access-Control-Max-Age":       "600",
        "Vary":                         "Origin",
    }

    async def dispatch(self, request: Request, call_next):
        if not request.url.path.startswith("/ext/"):
            return await call_next(request)

        allowed = _ext_allowed_origin(request.headers.get("origin", ""))

        if request.method == "OPTIONS":
            if allowed is None:
                # Preflight from a non-extension origin: answer without CORS headers,
                # so the browser refuses the actual request.
                return Response(status_code=204, headers={"Vary": "Origin"})
            return Response(
                status_code=204,
                headers={**self._BASE_HEADERS, "Access-Control-Allow-Origin": allowed},
            )

        response = await call_next(request)
        if allowed is None:
            response.headers["Vary"] = "Origin"
            return response
        for key, val in self._BASE_HEADERS.items():
            response.headers[key] = val
        response.headers["Access-Control-Allow-Origin"] = allowed
        return response


app.add_middleware(_ExtensionCORSMiddleware)

# ── Multi-region X-Region header (SC-03) ─────────────────────────────────────
try:
    from warden.middleware.region import RegionMiddleware
    app.add_middleware(RegionMiddleware)
    log.info("RegionMiddleware registered — X-Region headers active.")
except ImportError:
    pass

# ── Per-request quota enforcement (counts POST /filter requests per tenant) ───
try:
    from warden.billing.quota_middleware import QuotaMiddleware
    app.add_middleware(QuotaMiddleware)
    log.info("QuotaMiddleware registered — monthly request limits enforced.")
except ImportError:
    log.warning("QuotaMiddleware not available — quota enforcement skipped.")

# ── Prometheus instrumentation ────────────────────────────────────────────────
# There used to be a monkeypatch here, and it is worth saying what it did.
#
# prometheus_fastapi_instrumentator 8.0.x could not resolve the `_IncludedRouter`
# objects FastAPI >= 0.116 puts in `app.routes` for every `include_router` call —
# they carry no `.path` — so the patch filtered them out before the library saw
# them:
#
#     safe_routes = [r for r in routes if hasattr(r, "path") and hasattr(r, "matches")]
#
# 8.1.0 learned to expand those objects itself, via `effective_route_contexts()`.
# The filter then became the defect: it removed exactly the routes the library
# had just learned to resolve, so every endpoint registered through a router —
# which is all of them but the handful declared on `app` directly — was recorded
# as `handler="none"`. Measured on production 2026-09-20: of the handler labels
# across `http_requests_total` and both latency histograms, **one** was a real
# path (`/filter`, declared inline here) and everything else was `none`. Two
# successful requests to a live `/billing/tiers` produced no new label at all.
#
# So the dashboards, the error-rate alert, the availability SLO and all four
# burn-rate rules have been reading one route and a bucket marked "unknown".
#
# Nothing replaces the patch: the library is correct now, and
# `warden/tests/test_metrics_route_attribution.py` asserts that by making a
# request through a nested router and reading the label back, rather than by
# trusting a version number.

if _PROMETHEUS_ENABLED:
    # .add(metrics.default(...)) rather than a bare .add(metrics.latency(...)):
    # default() is what produces http_requests_total, the request/response size
    # histograms and both latency metrics. Adding only a latency instrumentation
    # would replace that whole set and silently delete http_requests_total —
    # which every dashboard panel, the error-rate alert, the availability SLO and
    # all four burn-rate rules are built on.
    _Instrumentator(
        excluded_handlers=_METRICS_EXCLUDED_HANDLERS,
    ).add(
        _pfi_metrics.default(latency_lowr_buckets=_LATENCY_BUCKETS)
    ).instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)

# /openapi.json, /openapi-public.json, /docs, /redoc extracted to
# warden/api/docs_router.py (P-2). _docs_auth and its DOCS_USERNAME/
# DOCS_PASSWORD constants moved with them — nothing else here used them.
app.include_router(_docs_router)


# ── Include sub-routers ───────────────────────────────────────────────────────
# Application Factory helpers — imported early so the simple single-router
# blocks below can use register_router_safe() one-liners. The staff subsystem +
# Turso migrations are wired via the fuller import near the end of the file.
from warden.app_factory import RouterSpec as _RouterSpec  # noqa: E402
from warden.app_factory import (  # noqa: E402
    register_required_router,
    register_router_safe,
)

register_router_safe(app, _RouterSpec("warden.auth.router", label="HttpOnly session auth mounted at /auth"))

register_router_safe(app, _RouterSpec("warden.openai_proxy", label="OpenAI-compatible proxy mounted at /v1"))

register_router_safe(app, _RouterSpec("warden.portal_router", kwargs={"prefix": "/portal"}, label="Customer portal API mounted at /portal"))

register_router_safe(app, _RouterSpec("warden.agentic.router", label="Agentic Payment Protocol (AP2) mounted at /agents and /mcp"))

app.include_router(_neutralizer_router)
log.info("Business Threat Neutralizer mounted at /threat/neutralizer")

register_router_safe(app, _RouterSpec("warden.api.financial", label="Dollar Impact Calculator mounted at /financial"))

register_router_safe(app, _RouterSpec("warden.api.tenant_impact", label="Tenant Impact Calculator mounted at /tenant/impact"))

try:
    from warden.syndicates.router import router as _syndicates_router
    from warden.syndicates.router import tunnels_router as _tunnels_router
    app.include_router(_syndicates_router)
    app.include_router(_tunnels_router)
    log.info("Warden Syndicates mounted at /syndicates and /tunnels")
except ImportError:
    log.warning("syndicates router not available — /syndicates and /tunnels skipped.")

register_router_safe(app, _RouterSpec("warden.syndicates.invites_router", attr="invites_router", label="Warden Gatekeeper (invites) mounted at /invites"))

register_router_safe(app, _RouterSpec("warden.communities.router", label="Business Communities mounted at /communities"))

register_router_safe(app, _RouterSpec("warden.billing.router", label="Billing API mounted at /billing"))

register_router_safe(app, _RouterSpec("warden.api.monitor", label="Uptime Monitor API mounted at /monitors"))

register_router_safe(app, _RouterSpec("warden.api.agent", label="SOVA Agent mounted at /agent/sova"))

register_router_safe(app, _RouterSpec("warden.api.shadow_ai", label="Shadow AI Governance mounted at /shadow-ai"))

register_router_safe(app, _RouterSpec("warden.gsam.api", label="GSAM Hermes JIT lease mounted at /gsam (SAC)"))

register_router_safe(app, _RouterSpec("warden.api.wallet", label="SAC preflight wallet mounted at /wallet"))

register_router_safe(app, _RouterSpec("warden.api.misp", label="MISP ZMQ bridge mounted at /misp"))

register_router_safe(app, _RouterSpec("warden.api.sdk", label="OTel SDK mounted at /sdk"))

register_router_safe(app, _RouterSpec("warden.api.xai", label="Explainable AI 2.0 mounted at /xai"))

register_router_safe(app, _RouterSpec("warden.api.sovereign", label="Sovereign AI Cloud mounted at /sovereign"))

# Semantic Layer mounted below at /semantic-layer (FE-42) — single mount point

# Settings Hub: commerce + semantic endpoints merged into warden/api/settings.py (single mount below)

register_router_safe(app, _RouterSpec("warden.api.file_scan", label="File Scanner mounted at /filter/file (Community Business SMB)"))

register_router_safe(app, _RouterSpec("warden.api.email_guard", label="Email Guard mounted at /scan/email (C5 email-vector protection)"))

register_router_safe(app, _RouterSpec("warden.api.extension_risk", label="Extension Risk Scanner mounted at /scan/extensions (Q2.4)"))

register_router_safe(app, _RouterSpec("warden.api.rotation", label="Rotation Alerts mounted at /admin/rotation (Q1.3)"))

try:
    from warden.api.compliance_report import (
        router as _compliance_router,
    )
    from warden.api.compliance_report import (
        router_api as _compliance_api_router,
    )
    app.include_router(_compliance_router)
    app.include_router(_compliance_api_router)
    log.info("Compliance Report mounted at /compliance (Q3.7)")
except ImportError:
    log.warning("compliance_report router not available — /compliance skipped.")

register_router_safe(app, _RouterSpec("warden.api.retention", label="Retention Policy mounted at /retention (CP-26)"))

register_router_safe(app, _RouterSpec("warden.api.public_stats", label="Public community stats mounted at /public/community"))

register_router_safe(app, _RouterSpec("warden.api.sep", label="Syndicate Exchange Protocol mounted at /sep"))

register_router_safe(app, _RouterSpec("warden.api.community_intel", label="Community Intelligence mounted at /community-intel"))

register_router_safe(app, _RouterSpec("warden.api.community_notifications", label="Community Notifications mounted at /communities/{id}/notifications"))

register_router_safe(app, _RouterSpec("warden.api.communities_v2", label="Community Hub mounted at /communities"))

register_router_safe(app, _RouterSpec("warden.api.secrets", kwargs={"prefix": "/secrets"}, label="Secrets Governance mounted at /secrets"))

register_router_safe(app, _RouterSpec("warden.api.obsidian", kwargs={"prefix": "/obsidian"}, label="Obsidian Business Community integration mounted at /obsidian"))

register_router_safe(app, _RouterSpec("warden.api.slack_commands", label="Slack slash command handler mounted at /slack/command"))

register_router_safe(app, _RouterSpec("warden.api.gdpr", label="GDPR scrubbing API mounted at /gdpr"))

register_router_safe(app, _RouterSpec("warden.api.community", label="Business Community mounted at /community (NIM moderation + Obsidian bridge)"))

try:
    from warden.api.security_hub import router as _security_router
    from warden.api.soc_dashboard import router as _soc_router
    app.include_router(_security_router)
    app.include_router(_soc_router)
    log.info("Cyber Security Hub mounted at /security + /soc")
except ImportError:
    log.warning("security_hub/soc_dashboard not available — /security /soc routes skipped.")

register_router_safe(app, _RouterSpec("warden.api.config_api", label="Settings API mounted at /api/settings (Tier-1 approval gate)"))

register_router_safe(app, _RouterSpec("warden.api.webhook", label="Lemon Squeezy webhook receiver mounted at POST /billing/webhook"))

register_router_safe(app, _RouterSpec("warden.api.integrations", label="Integrations router mounted at /integrations (IN-16/17/18/20)"))

register_router_safe(app, _RouterSpec("warden.api.ws_events", label="WebSocket anomaly stream mounted at /ws/events (OB-26)"))

register_router_safe(app, _RouterSpec("warden.api.ws_stream", label="WebSocket filter/LLM streams mounted at /ws/stream, /ws/filter, /ws/monitor (P-2)"))

# REQUIRED, not optional: these seven routes are the product. Before P-2 they
# were inline @app routes and could not fail separately from the app; a
# swallowed import error here would boot a gateway that 404s /filter while
# /health still reports "ok". Boot fails instead.
register_required_router(app, _RouterSpec("warden.api.filter", label="Filter group mounted at /filter, /demo/filter, /ext/*, /filter/batch, /filter/multimodal (P-2)"))

register_router_safe(app, _RouterSpec("warden.api.red_team", label="Red-team autopilot mounted at /agent/red-team (AR-11)"))

register_router_safe(app, _RouterSpec("warden.api.vendor_gov", label="Vendor Governance mounted at /vendor-gov (BL-22)"))

register_router_safe(app, _RouterSpec("warden.api.cost_allocation", label="Cost Allocation mounted at /financial/allocation (BL-23)"))

register_router_safe(app, _RouterSpec("warden.api.budget", label="Budget Dashboard mounted at /financial/budget (BL-24)"))

register_router_safe(app, _RouterSpec("warden.api.incident_register", label="Incident Register mounted at /incidents (CM-35)"))

register_router_safe(app, _RouterSpec("warden.api.supplier_risk", label="Supplier Risk Assessment mounted at /supplier-risk (CM-36)"))

register_router_safe(app, _RouterSpec("warden.api.prompt_library", label="Shared Prompt Library mounted at /prompt-library (CM-37)"))

register_router_safe(app, _RouterSpec("warden.api.doc_converter", label="Document Converter (MarkItDown) mounted at /doc-converter"))

register_router_safe(app, _RouterSpec("warden.api.push", label="Mobile SOC push notification API mounted at /push (MO-01)"))

register_router_safe(app, _RouterSpec("warden.document_intel.api", label="Document Intelligence (MarkItDown) mounted at /document-intel (FE-50)"))

register_router_safe(app, _RouterSpec("warden.api.training_records", label="Employee AI Training Records mounted at /training (CM-38)"))

register_router_safe(app, _RouterSpec("warden.api.smb_suite", label="SMB AI Governance Suite mounted at /smb-suite (IN-25)"))

register_router_safe(app, _RouterSpec("warden.api.webhooks", label="Webhook Event System mounted at /webhooks (DEV-05)"))

register_router_safe(app, _RouterSpec("warden.api.saml", label="SSO/SAML 2.0 mounted at /auth/saml (ENT-01)"))

register_router_safe(app, _RouterSpec("warden.api.whitelabel", label="White-Label config mounted at /whitelabel (ENT-02)"))

register_router_safe(app, _RouterSpec("warden.api.framework_builder", label="Compliance Framework Builder mounted at /compliance/frameworks (ENT-03)"))

register_router_safe(app, _RouterSpec("warden.api.usage_budgets", label="AI Usage Budgets mounted at /billing/usage-budgets (ENT-04)"))

register_router_safe(app, _RouterSpec("warden.business_intelligence.router", label="Business Intelligence mounted at /business-intelligence (CM-39)"))

register_router_safe(app, _RouterSpec("warden.communities.federation", label="Community threat federation mounted at /sep/federation (CM-26)"))

register_router_safe(app, _RouterSpec("warden.communities.model_share", label="Community model sharing mounted at /sep/model-bundles (CM-27)"))

register_router_safe(app, _RouterSpec("warden.api.settings", label="Settings API mounted at /settings (FE-41)"))

register_router_safe(app, _RouterSpec("warden.business_community.agentic_commerce.api", label="Agentic Commerce mounted at /business-community/commerce (CM-40)"))

register_router_safe(app, _RouterSpec("warden.semantic_layer.api", label="Semantic Layer mounted at /semantic-layer (FE-42)"))

register_router_safe(app, _RouterSpec("warden.blockchain.api", label="Web3 on-chain mandates mounted at /web3/mandates (Phase 1)"))

register_router_safe(app, _RouterSpec("warden.m2m_store.api", label="M2M Commerce Store mounted at /m2m-store (Enterprise)"))

register_router_safe(app, _RouterSpec("warden.tax.api", label="Tax & Compliance mounted at /tax (Phase 3)"))

register_router_safe(app, _RouterSpec("warden.api.fido_auth", label="FIDO2 Passkey auth mounted at /auth/fido (Phase 4)"))

try:
    from warden.marketplace.api import agent_discovery_alias
    from warden.marketplace.api import router as _marketplace_router
    from warden.marketplace.api_agents import router as _mkt_agents_router
    from warden.marketplace.api_assets import router as _mkt_assets_router
    from warden.marketplace.api_escrow import router as _mkt_escrow_router
    from warden.marketplace.api_listings import router as _mkt_listings_router
    from warden.marketplace.api_negotiations import router as _mkt_negotiations_router
    app.include_router(_marketplace_router, prefix="/marketplace")
    app.add_api_route("/.well-known/agent.json", agent_discovery_alias, methods=["GET"], include_in_schema=False)

    async def _acp_manifest_alias():
        import os
        base = os.getenv("ACP_BASE_URL", "https://api.shadow-warden-ai.com")
        mid  = os.getenv("ACP_MERCHANT_ID", "shadow-warden-ai")
        from warden.protocols.acp.models import ACPMerchantManifest
        return ACPMerchantManifest(
            merchant_id=mid,
            token_endpoint=f"{base}/acp/token",
            checkout_endpoint=f"{base}/acp/cart/{{cart_id}}/checkout",
            refund_endpoint=f"{base}/acp/refund",
            receipt_endpoint=f"{base}/acp/receipt/{{order_id}}",
        ).model_dump()
    app.add_api_route("/.well-known/acp.json", _acp_manifest_alias, methods=["GET"], include_in_schema=False)
    app.include_router(_mkt_agents_router, prefix="/marketplace")
    app.include_router(_mkt_assets_router, prefix="/marketplace")
    app.include_router(_mkt_listings_router, prefix="/marketplace")
    app.include_router(_mkt_negotiations_router, prefix="/marketplace")
    app.include_router(_mkt_escrow_router, prefix="/marketplace")
    log.info("Community M2M Agentic Marketplace mounted at /marketplace (Phase 1)")
except ImportError as exc:
    log.warning("marketplace router not available — /marketplace skipped: %r", exc)

register_router_safe(app, _RouterSpec("warden.marketplace.api_governance", label="DAO Governance router mounted at /marketplace/proposals"))

register_router_safe(app, _RouterSpec("warden.marketplace.api_maestro", label="MAESTRO Threat Detection mounted at /marketplace/maestro"))

register_router_safe(app, _RouterSpec("warden.streams.api", label="Event Streaming mounted at /streams"))

register_router_safe(app, _RouterSpec("warden.tokenomics.api", label="Agent Tokenomics (WAT) mounted at /tokenomics"))

register_router_safe(app, _RouterSpec("warden.payments.api", label="USDC Payments mounted at /payments"))

register_router_safe(app, _RouterSpec("warden.security.api", label="ANS Certificate Authority mounted at /marketplace/agents/{id}/certificate"))

register_router_safe(app, _RouterSpec("warden.agents.packs.api", label="ARC Edge Agent Packs mounted at /agents/packs"))

register_router_safe(app, _RouterSpec("warden.protocols.a2a.api", label="A2A v1.0 task gateway mounted at /a2a (Agent Card: /.well-known/agent.json)"))

register_router_safe(app, _RouterSpec("warden.api.deploy_health", label="Deploy health endpoint mounted at /deploy/status"))

register_router_safe(app, _RouterSpec("warden.api.system", label="System/dashboard ops endpoints mounted at /health, /api/stats, /api/config (P-2)"))

register_router_safe(app, _RouterSpec("warden.api.action_whitelist", label="Agent Action Whitelist mounted at /admin/agents"))

register_router_safe(app, _RouterSpec("warden.marketplace.agent_key_rotation", label="Agent key rotation mounted at /marketplace/agents/{id}/rotate-key"))

register_router_safe(app, _RouterSpec("warden.marketplace.data_lifecycle", label="Data Lifecycle manager mounted at /admin/data-lifecycle"))

try:
    from warden.voice.api import router as _voice_router
    app.include_router(_voice_router)
    log.info("Voice-Commerce router mounted at /voice (VC-01)")
except Exception as _exc:
    log.warning("Voice-Commerce router not available: %s", _exc)

# Federation router already mounted above at /sep/federation (CM-26)


# ── Admin: manual weekly report trigger ──────────────────────────────────────
# POST /admin/weekly-report   — fire off weekly reports immediately (testing /
# ad-hoc re-sends).  Runs synchronously in a thread executor so it doesn't
# block the event loop.  Requires super-admin key.

# ── Admin reporting endpoints ─────────────────────────────────────────────────
# /admin/weekly-report extracted to warden/api/admin_reports.py (Phase 3).
# Self-contained (SUPER_ADMIN_KEY-gated). Included via app.include_router below.


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


# ── Rate-limit headers ────────────────────────────────────────────────────────
#
# The gateway enforces a per-tenant window and a monthly quota and used to
# advertise neither, so a caller could only discover a limit by being refused.
# Registered inside APIVersionMiddleware (which must stay outermost to strip
# `/v1` before any path-based decision) and outside QuotaMiddleware, so it can
# read the quota reading that middleware records and can decorate the 429 the
# quota check itself emits.
try:
    from warden.middleware.rate_limit_headers import RateLimitHeadersMiddleware
    app.add_middleware(RateLimitHeadersMiddleware)
    log.info("RateLimitHeadersMiddleware registered — RateLimit headers active.")
except ImportError:  # pragma: no cover - the module ships with the package
    log.warning("RateLimitHeadersMiddleware not available — rate-limit headers skipped.")


# ── API versioning (P2) ───────────────────────────────────────────────────────
#
# Added LAST so it sits OUTERMOST: Starlette runs the most recently added
# middleware first, and `/v1` has to be stripped before anything that makes a
# decision from the path — auth exemptions, mTLS exemptions, quota, region — or
# `/v1/health` would be treated as an authenticated API call and every one of
# those path lists would need a second, versioned copy.
app.add_middleware(APIVersionMiddleware)


# ── Health ────────────────────────────────────────────────────────────────────
# GET /health, GET /health/pipeline extracted to warden/api/system.py (P-2).


# ── Ops endpoints extracted to warden/api/system.py (P-2) ─────────────────────
# GET /api/stats · GET /health/pipeline · GET+POST /api/config


# ── SIEM bypass helper ────────────────────────────────────────────────────────

async def _ship_bypass(background_tasks, entry: dict) -> None:
    """Fire-and-forget SIEM ship for bypass events that exit the pipeline early."""
    try:
        from warden.analytics.siem import ship_bypass_alert  # noqa: PLC0415
        if background_tasks is not None:
            background_tasks.add_task(ship_bypass_alert, entry)
        else:
            await ship_bypass_alert(entry)
    except Exception:  # noqa: BLE001
        pass   # SIEM is best-effort; never block response delivery


# ── Core filter logic (shared by /filter and /filter/batch) ──────────────────

# `_log_verdict` moved to warden/services/filter_orchestrator.py (P-2).


# ── The /filter pipeline body ─────────────────────────────────────────────────
#
# `run_filter_pipeline` — all nine stages — moved to
# warden/services/filter_orchestrator.py (P-2). It is imported below and
# published into the `filter_orchestrator` runtime slot by lifespan, exactly as
# before, so warden.services.pipeline.FilterPipeline resolves it the same way
# and keeps failing closed when the app has not booted.
#
# It was safe to relocate because the body is read-only with respect to module
# state: no `global`, no rebinding, no in-place mutation of any singleton it
# touches. Checked by AST, not assumed.


# ── Rate-limit + ERS helpers ──────────────────────────────────────────────────
#
# `_enforce_tenant_rate_limit`, `_ers_dominant_flag` and `_ers_enrich` moved to
# warden/api/filter.py with the routes that were their only callers (P-2).
# `_ers_record` stays: the pipeline body below is its only caller.


# `_ers_record` moved to warden/services/filter_orchestrator.py (P-2).


# ── The /filter group ─────────────────────────────────────────────────────────
#
# POST /filter, /demo/filter, /ext/filter, /ext/unmask, GET /ext/health,
# POST /filter/batch and POST /filter/multimodal moved to warden/api/filter.py
# (P-2, final route increment). With these gone **no route is defined inline in
# this file** — all 15 the programme started with are in routers.
#
# They reach the pipeline through warden.services.pipeline.FilterPipeline, the
# Phase-2 facade, which resolves `filter_orchestrator` from warden.runtime. The
# orchestrator itself (`_run_filter_pipeline`) stays here for now, along with
# `_spawn_task` and `_ship_bypass`, which it shares with the routes and which
# are published to the seam rather than copied.


# ── GDPR endpoints ────────────────────────────────────────────────────────────
# Extracted to warden/api/gdpr.py (Phase 3). Included via include_router.


# ── Rule ledger / admin rule-lifecycle / SOC2 audit endpoints ────────────────
# Extracted to warden/api/rules.py (Phase 3). RuleLedger, ReviewQueue, the
# in-memory dynamic-regex list, brain guard and AuditTrail are published to
# warden.runtime in lifespan. Included via app.include_router below.


# ── ThreatStore blocklist / attacker-profile endpoints ───────────────────────
# Extracted to warden/api/threats.py (Phase 3). ThreatStore singleton published
# to warden.runtime as "threat_store". Included via app.include_router below.


# ── ERS / Shadow Ban admin endpoints ─────────────────────────────────────────
# Extracted to warden/api/ers.py (Phase 3). ERS is a stateless Redis-backed
# module imported directly. Included via app.include_router below.


# ── Zero-Trust Agent Sandbox — manifest management + attestation ──────────────
# Extracted to warden/api/agent_sandbox.py (Phase 3). AgentMonitor singleton is
# published to warden.runtime in lifespan; sandbox registry imported directly.
# Included via app.include_router below.


# ── Threat Intelligence endpoints ────────────────────────────────────────────


# ── Threat Intelligence + ThreatVault endpoints ────────────────────────────────
# Extracted to warden/api/threats.py (Phase 3). Singletons (_threat_intel_store,
# _ti_scheduler, _threat_vault) are published to warden.runtime in lifespan and
# resolved there by the router. Included via app.include_router below.


# ── Billing usage/quota endpoints ─────────────────────────────────────────────
# Extracted to warden/api/billing_usage.py (Phase 3). BillingStore singleton is
# published to warden.runtime in lifespan. Included via app.include_router below.
# (Distinct from warden/billing/router.py — tier catalog + add-on checkout.)


# ── WebSocket endpoints ───────────────────────────────────────────────────────
#
# All four sockets live in routers, none inline here. /ws/events is
# warden/api/ws_events.py (OB-26); /ws/stream, /ws/monitor/{monitor_id} and
# /ws/filter moved to warden/api/ws_stream.py (P-2), which reads the pipeline and
# its guards through warden.runtime. Both are registered with
# register_router_safe above.
#
# main.py previously ALSO defined @app.websocket("/ws/events") plus a local
# _EventBus. Because the router is registered first and Starlette matches in
# registration order, that inline handler never ran — it served unauthenticated
# for months and nothing said so (PR #237). That is the reason no socket is
# defined inline any more; the pipeline's broadcast call feeds the router
# directly.


# ── Onboarding / MSP / Data-Policy / Threat-Feed endpoints ──────────────────
# Extracted to warden/api/onboarding.py, warden/api/policy.py and
# warden/api/feed.py (Phase 3). Backing singletons (onboarding, billing,
# policy, feed) are published to warden.runtime in lifespan; the report
# engine is a module-level singleton. Included via app.include_router below.


# ── Yellow Zone: /mask and /unmask ────────────────────────────────────────────
#
# POST /mask   — replace PII entities with reversible tokens
# POST /unmask — restore original values from a previous /mask session
#
# Use-case: the OpenAI proxy calls /mask before forwarding to an LLM, then
# /unmask on the response.  Can also be called directly from any client.
#
# Masking mode env var:
#   MASKING_MODE=off     — masking endpoints available but proxy does NOT auto-mask (default)
#   MASKING_MODE=auto    — proxy auto-masks user messages when PII detected


# Extracted to warden/api/masking.py (P-2). No main state was involved —
# every collaborator was already a plain import. Included via include_router.


# ── Lemon Squeezy subscription endpoints ─────────────────────────────────────
# Extracted to warden/api/subscription.py (Phase 3). Included via include_router.


# ── OWASP LLM Output Scanning ─────────────────────────────────────────────────
#
# POST /filter/output — scan AI-generated text *after* it returns from the model.
#
# Covers three OWASP LLM Top 10 categories:
#   LLM02 — Insecure Output Handling: XSS, HTML injection, Markdown link injection
#   LLM06 — Sensitive Information Disclosure: prompt leakage, system prompt echo
#   LLM08 — Excessive Agency: shell/SQL/SSRF/path-traversal in AI-generated content


# POST /filter/output extracted to warden/api/masking.py (P-2).


# ── Webhook management endpoints ──────────────────────────────────────────────
# Extracted to warden/api/webhook_config.py (Phase 3b). WebhookStore published to
# warden.runtime; shared limiter from warden.limiter. Included via include_router.


# ── SAML 2.0 SSO endpoints ────────────────────────────────────────────────────
#
# These routes are active only when SAML_SP_ENTITY_ID + SAML_SP_ACS_URL are set.
# If SAML is not configured, all three routes return 503.
#
# Integration guide (Okta):
#   1. In Okta: New App → SAML 2.0
#      • Single Sign-On URL (ACS URL): <SAML_SP_ACS_URL>
#      • Audience URI (Entity ID):     <SAML_SP_ENTITY_ID>
#      • Name ID format:               EmailAddress
#      • Attribute Statements:         displayName → user.displayName
#                                      groups      → user.groups  (requires Groups filter)
#   2. Download IdP metadata XML from Okta; set SAML_IDP_METADATA_URL
#      or paste XML into SAML_IDP_METADATA_XML.
#   3. Set SAML_JWT_SECRET (min 32 chars), SAML_SP_ENTITY_ID, SAML_SP_ACS_URL.
#
# Integration guide (Microsoft Entra ID / Azure AD):
#   1. Azure Portal → Entra ID → Enterprise Applications → New App → Create your own
#   2. Single sign-on → SAML → Basic SAML Configuration:
#      • Identifier (Entity ID):       <SAML_SP_ENTITY_ID>
#      • Reply URL (ACS URL):          <SAML_SP_ACS_URL>
#   3. SAML Certificates → Federation Metadata Document URL → set as SAML_IDP_METADATA_URL
#   4. Attributes & Claims: add "groups" claim (Security Groups or All Groups).


# ── SSO / SAML 2.0 endpoints ──────────────────────────────────────────────────
# Extracted to warden/api/saml.py (Phase 3). Provider on app.state.saml.
# Included via app.include_router below.


# ── Contact form ─────────────────────────────────────────────────────────────

# Public contact-form endpoint extracted to warden/api/contact.py (Phase 3).
from warden.api.contact import router as _contact_router  # noqa: E402

app.include_router(_contact_router)

# Subscription endpoints extracted to warden/api/subscription.py (Phase 3).
from warden.api.subscription import router as _subscription_router  # noqa: E402

app.include_router(_subscription_router)

# Threat Intelligence + ThreatVault endpoints extracted to warden/api/threats.py
# (Phase 3). Backing singletons are published to warden.runtime in lifespan.
from warden.api.threats import router as _threats_router  # noqa: E402

app.include_router(_threats_router)

# Zero-Trust Agent Sandbox endpoints extracted to warden/api/agent_sandbox.py
# (Phase 3). AgentMonitor singleton published to warden.runtime in lifespan.
from warden.api.agent_sandbox import router as _agent_sandbox_router  # noqa: E402

app.include_router(_agent_sandbox_router)

# Onboarding / MSP / Data-Policy / Threat-Feed endpoints extracted to
# warden/api/{onboarding,policy,feed}.py (Phase 3). Singletons published to
# warden.runtime in lifespan.
from warden.api.feed import router as _feed_router  # noqa: E402
from warden.api.onboarding import router as _onboarding_router  # noqa: E402
from warden.api.policy import router as _policy_router  # noqa: E402

app.include_router(_onboarding_router)
app.include_router(_policy_router)
app.include_router(_feed_router)

# Per-tenant billing usage/quota endpoints extracted to
# warden/api/billing_usage.py (Phase 3). BillingStore published to warden.runtime.
from warden.api.billing_usage import router as _billing_usage_router  # noqa: E402

app.include_router(_billing_usage_router)

# ERS / Shadow Ban admin endpoints extracted to warden/api/ers.py (Phase 3).
from warden.api.ers import router as _ers_router  # noqa: E402

app.include_router(_ers_router)

# Rule ledger / admin rule-lifecycle / SOC2 audit endpoints extracted to
# warden/api/rules.py (Phase 3). Singletons published to warden.runtime.
from warden.api.rules import router as _rules_router  # noqa: E402

app.include_router(_rules_router)

# PII masking (/mask, /unmask) + OWASP LLM output scanning (/filter/output)
# extracted to warden/api/masking.py (P-2). Needs no runtime slot, and unlike the
# Phase 3 extractions it needs no bottom-of-file E402-suppressed import either —
# every one of its dependencies (auth_guard, limiter, masking.engine,
# output_sanitizer, schemas, xai.explainer) is a leaf that main already imports
# at the top, so there is no cycle to dodge. Imported with the other top-level
# imports; only the include_router call has to live here, after `app` exists.
app.include_router(_masking_router)

# Admin weekly-report endpoint extracted to warden/api/admin_reports.py (Phase 3).
from warden.api.admin_reports import router as _admin_reports_router  # noqa: E402

app.include_router(_admin_reports_router)

# Per-tenant webhook config (/webhook) extracted to warden/api/webhook_config.py
# (Phase 3b). WebhookStore published to warden.runtime; shared limiter reused.
from warden.api.webhook_config import router as _webhook_config_router  # noqa: E402

app.include_router(_webhook_config_router)


from warden.app_factory import (  # noqa: E402, I001
    RouterSpec as _RouterSpec,
    register_router_safe,
    register_staff_routers as _register_staff_routers,
    run_turso_migrations as _run_turso_migrations,
)
_register_staff_routers(app)
register_router_safe(app, _RouterSpec("warden.mcp.gateway", label="MCP Paid Tools /mcp"))
register_router_safe(app, _RouterSpec("warden.api.acp", label="ACP Protocol /acp"))

# Turso schema migrations — only run when TURSO_AUTO_MIGRATE=true
if os.getenv("TURSO_AUTO_MIGRATE", "false").lower() == "true":
    try:
        _run_turso_migrations()
    except Exception as _e:
        log.warning("Turso auto-migrate failed (skipped): %s", _e)
register_router_safe(app, _RouterSpec("warden.api.billing_audit", label="Billing Audit Chain /billing/audit"))
register_router_safe(app, _RouterSpec("warden.api.kya",            label="KYA DIDs /kya"))
register_router_safe(app, _RouterSpec("warden.api.discovery",      label="Agent Discovery /.well-known"))


# ── Global error handler ──────────────────────────────────────────────────────

@app.exception_handler(Exception)
async def unhandled_exception(request: Request, exc: Exception):
    rid = getattr(request.state, "request_id", "-")
    log.exception(json.dumps({"event": "unhandled_error", "request_id": rid, "error": str(exc)}))
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal warden error.", "request_id": rid},
    )
