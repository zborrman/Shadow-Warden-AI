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
import secrets
import time
import uuid
from collections import Counter, defaultdict, deque
import contextlib
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
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
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.responses import JSONResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware

import warden.circuit_breaker as _cb
from warden import entity_risk as _ers
from warden import shadow_ban as _sban
from warden.analytics import logger as event_logger
from warden.analytics.report import get_engine as _get_report_engine
from warden.auth.saml_provider import SAMLProvider, SamlSession
from warden.auth.saml_provider import get_provider as _get_saml_provider
from warden.auth_guard import (
    AuthResult,
    get_rate_limit,
    require_api_key,
    require_ext_auth,
    set_default_rate_limit,
)
from warden.billing import BILLING_AGG_INTERVAL, BillingStore
from warden.brain.evolve import EvolutionEngine, build_evolution_engine
from warden.brain.semantic import SemanticGuard as BrainSemanticGuard
from warden.business_threat_neutralizer import analyze as _neutralizer_analyze
from warden.cache import _get_client as _get_redis
from warden.cache import check_tenant_rate_limit, get_cached, set_cached
from warden.causal_arbiter import arbitrate as _causal_arbitrate
from warden.data_policy import DataPolicyEngine
from warden.masking.engine import get_engine as _get_masking_engine
from warden.metrics import FILTER_BYPASSES_TOTAL, FILTER_HONEYTRAP_TOTAL, FILTER_UNCERTAIN_TOTAL
from warden.mtls import MTLSMiddleware
from warden.obfuscation import decode as decode_obfuscation
from warden.onboarding import OnboardingEngine
from warden.output_sanitizer import get_sanitizer as _get_output_sanitizer
from warden.review_queue import ReviewQueue
from warden.rule_ledger import RuleLedger
from warden.schemas import (
    FilterRequest,
    FilterResponse,
    FlagType,
    MaskedEntityInfo,
    MaskingReport,
    MaskRequest,
    MaskResponse,
    OutputFindingSchema,
    OutputScanRequest,
    OutputScanResponse,
    RiskLevel,
    SemanticFlag,
    UnmaskRequest,
    UnmaskResponse,
    WebhookRegisterRequest,
    WebhookStatusResponse,
)
from warden.secret_redactor import SecretRedactor
from warden.semantic_guard import SemanticGuard
from warden.telegram_alert import send_block_alert as _tg_block_alert
from warden.threat_feed import ThreatFeedClient
from warden.threat_neutralizer_router import router as _neutralizer_router
from warden.threat_store import ThreatStore
from warden.threat_vault import SEVERITY_RANK, ThreatVault
from warden.topology_guard import scan as _topo_scan
from warden.webhook_dispatch import WebhookStore
from warden.webhook_dispatch import dispatch_bypass_event as _dispatch_bypass_webhook
from warden.webhook_dispatch import dispatch_event as _dispatch_webhook
from warden.xai.explainer import explain as _xai_explain

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

# ── API Docs auth (HTTP Basic) ────────────────────────────────────────────────
# DOCS_PASSWORD="" (default) → docs served without auth (dev / CI only).
# DOCS_PASSWORD set          → /docs, /redoc, /openapi.json require HTTP Basic.
# Never set DOCS_PASSWORD="" on a public-facing server.

_DOCS_USERNAME: str = os.getenv("DOCS_USERNAME", "warden")
_DOCS_PASSWORD: str = os.getenv("DOCS_PASSWORD", "")
_http_basic = HTTPBasic(auto_error=False)


async def _docs_auth(
    credentials: HTTPBasicCredentials | None = Depends(_http_basic),
) -> None:
    """Dependency: pass-through in dev, HTTP Basic in production."""
    if not _DOCS_PASSWORD:
        return  # dev mode — no password configured → open access
    if credentials is None:
        raise HTTPException(
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="Shadow Warden API Docs"'},
        )
    ok_user = secrets.compare_digest(
        credentials.username.encode(), _DOCS_USERNAME.encode()
    )
    ok_pass = secrets.compare_digest(
        credentials.password.encode(), _DOCS_PASSWORD.encode()
    )
    if not (ok_user and ok_pass):
        raise HTTPException(
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="Shadow Warden API Docs"'},
        )


# ── Rate limiter ──────────────────────────────────────────────────────────────

_RATE_LIMIT = os.getenv("RATE_LIMIT_PER_MINUTE", "60")


def _tenant_key(request: Request) -> str:
    """Rate-limit bucket key: API key when present, IP address as fallback.

    Keying on the API key means each tenant gets their own independent bucket
    even when all requests arrive from the same nginx IP.
    """
    return request.headers.get("x-api-key") or get_remote_address(request)


def _tenant_limit(key: str) -> str:
    """Per-tenant slowapi limit string derived from the key's configured rate.

    slowapi calls this with the value returned by _tenant_key — the API key
    string when present, or the remote IP as fallback.  get_rate_limit()
    returns the per-tenant rate_limit from WARDEN_API_KEYS_PATH, falling back
    to the RATE_LIMIT_PER_MINUTE default for unrecognised / plain-IP keys.
    """
    return f"{get_rate_limit(key)}/minute"


_limiter = Limiter(
    key_func=_tenant_key,
    storage_uri=os.getenv("REDIS_URL", "redis://redis:6379/0"),
)

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


def _content_entropy(text: str) -> float:
    """Shannon entropy of the text in bits per character."""
    import math  # noqa: PLC0415
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((cnt / n) * math.log2(cnt / n) for cnt in freq.values())


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
_poison_guard:   DataPoisoningGuard | None = None  # type: ignore[assignment]
_audit_trail = None  # AuditTrail | None — imported lazily in lifespan
_threat_sync    = None  # ThreatSyncClient | None — cross-region sync
_corpus_watcher = None  # CorpusSyncWatcher | None — corpus invalidation consumer
_bl_watcher     = None  # GlobalBlocklistWatcher | None — cross-region IP blocklist


def _global_blocklist_is_blocked(ip: str, tenant_id: str) -> bool:
    """Thin wrapper — fail-open if global_blocklist is not importable."""
    try:
        from warden.global_blocklist import is_blocked as _gbl_check  # noqa: PLC0415
        return _gbl_check(ip, tenant_id)
    except Exception:
        return False

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
    global _redactor, _guard, _brain_guard, _evolve, _agent_monitor, _ledger, _review_queue, _threat_store, _billing, _onboarding, _policy, _feed, _saml, _session_guard, _honey_engine

    strict = os.getenv("STRICT_MODE", "false").lower() == "true"

    log.info("Warden gateway starting — initialising filter pipeline…")

    # ── DB schema (idempotent — IF NOT EXISTS) ────────────────────────
    try:
        from warden.db.connection import DATABASE_URL, create_schema  # noqa: PLC0415
        if DATABASE_URL:
            await asyncio.to_thread(create_schema)
            log.info("DB schema verified.")
    except Exception as _db_err:
        log.warning("DB schema init failed (non-fatal): %s", _db_err)

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

    # ── Data Poisoning Guard ──────────────────────────────────────────
    global _poison_guard
    try:
        from warden.brain.poison import CorpusHealthMonitor, DataPoisoningGuard
        _poison_guard = DataPoisoningGuard(_brain_guard)
        await _poison_guard.initialise_async()
        _monitor = CorpusHealthMonitor(_poison_guard)
        asyncio.create_task(_monitor.run())
        log.info("DataPoisoningGuard active — corpus health monitor started.")
    except Exception as _pe:
        log.warning("DataPoisoningGuard unavailable (non-fatal): %s", _pe)

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
    except Exception:
        pass

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
            log.info("ThreatIntelScheduler online (sync every %sh).",
                     os.getenv("THREAT_INTEL_SYNC_HRS", "6"))
        except Exception as _ti_err:
            log.warning("ThreatIntelEngine failed to start: %s", _ti_err)
    else:
        log.info("ThreatIntelEngine disabled (set THREAT_INTEL_ENABLED=true to opt in).")

    # ── Background tasks ──────────────────────────────────────────────
    _retirement_task  = asyncio.create_task(_nightly_rule_retirement())
    _billing_task     = asyncio.create_task(_billing_aggregation_loop())
    _feed_sync_task   = asyncio.create_task(_threat_feed_sync_loop())

    # ── Uptime probe scheduler ────────────────────────────────────────
    try:
        from warden.workers.probe_worker import probe_scheduler as _probe_scheduler  # noqa: PLC0415
        asyncio.create_task(_probe_scheduler())
        log.info("Uptime probe scheduler started.")
    except Exception as _probe_err:
        log.warning("probe_scheduler failed to start: %s", _probe_err)

    # ── Webhook store ─────────────────────────────────────────────────
    _webhook_store = WebhookStore()
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
    try:
        from warden import audio_guard as _ag
        from warden import image_guard as _ig  # noqa: PLC0415
        from warden import image_redactor as _ir  # noqa: PLC0415
        _ig.prewarm()
        _ag.prewarm()
        _ir.prewarm()
    except Exception as _mm_err:
        log.warning("MultiModal guard pre-warm failed (non-fatal): %s", _mm_err)

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
        log.info("AuditTrail online (SOC 2 tamper-evident chain).")
    except Exception as _audit_err:
        log.warning("AuditTrail init failed (non-fatal): %s", _audit_err)

    _print_motd(
        evolution     = _evolve is not None,
        multimodal    = True,  # pre-warm attempted; fails-open on missing HF token
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

    yield

    _retirement_task.cancel()
    _billing_task.cancel()
    _feed_sync_task.cancel()
    if _ti_task is not None:
        _ti_task.cancel()
    with suppress(asyncio.CancelledError):
        await _retirement_task
    with suppress(asyncio.CancelledError):
        await _billing_task
    with suppress(asyncio.CancelledError):
        await _feed_sync_task
    if _ti_task is not None:
        with suppress(asyncio.CancelledError):
            await _ti_task

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
    version="2.9.0",
    lifespan=lifespan,
    # Disable FastAPI's built-in docs routes — we serve protected versions below.
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# Rate limiter state must be on app.state for slowapi to find it
app.state.limiter = _limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

_DEFAULT_CORS = ",".join([
    "http://localhost:3000",
    "http://localhost:3001",
    # Portal (customer-facing SPA)
    "https://app.shadow-warden-ai.com",
    "https://shadow-warden-ai.com",
    "https://www.shadow-warden-ai.com",
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
    allow_credentials=True,
    allow_methods=["POST", "GET", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key", "X-Request-ID", "Authorization"],
)

# mTLS enforcement — validates client-certificate CN on every non-exempt request.
# Disabled by default (MTLS_ENABLED=false); enable in production after running
# scripts/gen_certs.sh and mounting certs/ into each container.
app.add_middleware(MTLSMiddleware)


class _ExtensionCORSMiddleware(BaseHTTPMiddleware):
    """
    Wildcard CORS for /ext/* routes used by the Shadow Warden browser extension.

    chrome-extension:// and moz-extension:// origins cannot be whitelisted
    statically because the extension ID is unknown at build time.  Routes under
    /ext/ accept any origin; the X-API-Key header provides the actual auth.

    This middleware runs outermost (registered last), so it:
      • Short-circuits OPTIONS preflight for /ext/* — bypasses CORSMiddleware
      • Overwrites any CORS headers on the final response for /ext/* routes
    """
    _HEADERS: dict[str, str] = {
        "Access-Control-Allow-Origin":  "*",
        "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, X-API-Key, X-Request-ID, Authorization",
        "Access-Control-Max-Age":       "600",
    }

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        if not request.url.path.startswith("/ext/"):
            return await call_next(request)
        if request.method == "OPTIONS":
            return Response(status_code=204, headers=self._HEADERS)
        response = await call_next(request)
        for key, val in self._HEADERS.items():
            response.headers[key] = val
        return response


app.add_middleware(_ExtensionCORSMiddleware)

# ── Per-request quota enforcement (counts POST /filter requests per tenant) ───
try:
    from warden.billing.quota_middleware import QuotaMiddleware
    app.add_middleware(QuotaMiddleware)
    log.info("QuotaMiddleware registered — monthly request limits enforced.")
except ImportError:
    log.warning("QuotaMiddleware not available — quota enforcement skipped.")

# ── Prometheus instrumentation ────────────────────────────────────────────────
if _PROMETHEUS_ENABLED:
    _Instrumentator().instrument(app).expose(app, endpoint="/metrics")

# ── Protected API documentation ───────────────────────────────────────────────
# Served only when DOCS_PASSWORD is set (production) or openly in dev mode.
# The actual OpenAPI schema is also gated so attackers cannot enumerate routes.

@app.get("/openapi.json", include_in_schema=False)
async def _openapi_schema(_: None = Depends(_docs_auth)):
    return JSONResponse(app.openapi())


@app.get("/docs", include_in_schema=False)
async def _swagger_ui(_: None = Depends(_docs_auth)):
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title="Shadow Warden AI — API Docs",
    )


@app.get("/redoc", include_in_schema=False)
async def _redoc_ui(_: None = Depends(_docs_auth)):
    return get_redoc_html(
        openapi_url="/openapi.json",
        title="Shadow Warden AI — API Docs",
    )


# ── Include sub-routers ───────────────────────────────────────────────────────
try:
    from warden.openai_proxy import router as _openai_router
    app.include_router(_openai_router)
    log.info("OpenAI-compatible proxy mounted at /v1")
except ImportError:
    log.warning("openai_proxy not available — /v1 routes skipped.")

try:
    from warden.portal_router import router as _portal_router
    app.include_router(_portal_router, prefix="/portal")
    log.info("Customer portal API mounted at /portal")
except ImportError:
    log.warning("portal_router not available — /portal routes skipped.")

try:
    from warden.agentic.router import router as _agentic_router
    app.include_router(_agentic_router)
    log.info("Agentic Payment Protocol (AP2) mounted at /agents and /mcp")
except ImportError:
    log.warning("agentic router not available — /agents and /mcp routes skipped.")

app.include_router(_neutralizer_router)
log.info("Business Threat Neutralizer mounted at /threat/neutralizer")

try:
    from warden.api.financial import router as _financial_router
    app.include_router(_financial_router)
    log.info("Dollar Impact Calculator mounted at /financial")
except ImportError:
    log.warning("financial router not available — /financial routes skipped.")

try:
    from warden.api.tenant_impact import router as _tenant_impact_router
    app.include_router(_tenant_impact_router)
    log.info("Tenant Impact Calculator mounted at /tenant/impact")
except ImportError:
    log.warning("tenant_impact router not available — /tenant/impact skipped.")

try:
    from warden.syndicates.router import router as _syndicates_router
    from warden.syndicates.router import tunnels_router as _tunnels_router
    app.include_router(_syndicates_router)
    app.include_router(_tunnels_router)
    log.info("Warden Syndicates mounted at /syndicates and /tunnels")
except ImportError:
    log.warning("syndicates router not available — /syndicates and /tunnels skipped.")

try:
    from warden.syndicates.invites_router import invites_router as _invites_router
    app.include_router(_invites_router)
    log.info("Warden Gatekeeper (invites) mounted at /invites")
except ImportError:
    log.warning("invites router not available — /invites skipped.")

try:
    from warden.communities.router import router as _communities_router
    app.include_router(_communities_router)
    log.info("Business Communities mounted at /communities")
except ImportError:
    log.warning("communities router not available — /communities skipped.")

try:
    from warden.billing.router import router as _billing_router
    app.include_router(_billing_router)
    log.info("Billing API mounted at /billing")
except ImportError:
    log.warning("billing router not available — /billing routes skipped.")

try:
    from warden.api.monitor import router as _monitor_router
    app.include_router(_monitor_router)
    log.info("Uptime Monitor API mounted at /monitors")
except ImportError:
    log.warning("monitor router not available — /monitors routes skipped.")


# ── Admin: manual weekly report trigger ──────────────────────────────────────
# POST /admin/weekly-report   — fire off weekly reports immediately (testing /
# ad-hoc re-sends).  Runs synchronously in a thread executor so it doesn't
# block the event loop.  Requires super-admin key.

@app.post("/admin/weekly-report", tags=["Admin"], summary="Trigger weekly ROI email reports now")
async def trigger_weekly_report(request: Request):
    """Manually trigger the weekly ROI report for all active paid tenants."""
    _key = request.headers.get("X-Super-Admin-Key", "")
    _expected = os.getenv("SUPER_ADMIN_KEY", "")
    if not _expected or _key != _expected:
        from fastapi.responses import JSONResponse as _JR  # noqa: PLC0415, N814
        return _JR({"detail": "Forbidden"}, status_code=403)

    import asyncio  # noqa: PLC0415
    loop = asyncio.get_event_loop()
    try:
        from warden.workers.weekly_report import send_weekly_reports as _swr  # noqa: PLC0415
        result = await loop.run_in_executor(None, lambda: asyncio.run(_swr({})))
    except Exception as exc:
        log.error("admin/weekly-report: failed: %s", exc)
        from fastapi.responses import JSONResponse as _JR  # noqa: PLC0415, N814
        return _JR({"detail": str(exc)}, status_code=500)

    return result


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

    # Compute bypass_rate_1m from sliding windows (prune entries older than 60 s)
    now = time.perf_counter()
    cutoff = now - 60.0
    while _bypass_window and _bypass_window[0] < cutoff:
        _bypass_window.popleft()
    while _filter_window and _filter_window[0] < cutoff:
        _filter_window.popleft()
    bypasses_1m  = len(_bypass_window)
    filter_1m    = len(_filter_window)
    bypass_rate  = round(bypasses_1m / filter_1m, 4) if filter_1m else 0.0

    cb_state = _cb.get_state(_get_redis())
    if cb_state.get("status") == "open":
        overall = "degraded"

    return {
        "status":           overall,
        "service":          "warden-gateway",
        "evolution":        _evolve is not None,
        "tenants":          list(_tenant_guards.keys()),
        "strict":           os.getenv("STRICT_MODE", "false").lower() == "true",
        "fail_strategy":    _FAIL_STRATEGY,
        "cache":            redis_health,
        "ws_clients":       _event_bus.client_count,
        "bypass_rate_1m":   bypass_rate,
        "bypasses_1m":      bypasses_1m,
        "filter_rps_1m":    round(filter_1m / 60, 2),
        "circuit_breaker":  cb_state,
    }


# ── Dashboard stats API ───────────────────────────────────────────────────────

@app.get("/api/stats", tags=["ops"], summary="Aggregated filter stats for dashboard")
async def api_stats(hours: float = 24.0):
    entries = event_logger.load_entries(days=hours / 24)

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
        except Exception:
            pass

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


class _ConfigUpdate(BaseModel):
    semantic_threshold: float | None = None
    strict_mode: bool | None = None
    rate_limit_per_minute: int | None = None
    uncertainty_lower_threshold: float | None = None


@app.get("/api/config", tags=["ops"], summary="Current live configuration")
async def api_config():
    return {
        "semantic_threshold":   float(os.getenv("SEMANTIC_THRESHOLD", "0.72")),
        "strict_mode":          os.getenv("STRICT_MODE", "false").lower() == "true",
        "rate_limit_per_minute": int(os.getenv("RATE_LIMIT_PER_MINUTE", "60")),  # live value via set_default_rate_limit()
        "evolution_enabled":    _evolve is not None,
        "log_retention_days":   int(os.getenv("GDPR_LOG_RETENTION_DAYS", "30")),
        "browser_enabled":      os.getenv("BROWSER_ENABLED", "false").lower() == "true",
        "mtls_enabled":         os.getenv("MTLS_ENABLED", "false").lower() == "true",
        "otel_enabled":         os.getenv("OTEL_ENABLED", "false").lower() == "true",
        "model_cache_dir":          os.getenv("MODEL_CACHE_DIR", "/warden/models"),
        # Enterprise resilience
        "fail_strategy":            _FAIL_STRATEGY,
        "pipeline_timeout_ms":      _PIPELINE_TIMEOUT_MS,
        "uncertainty_lower_threshold": _UNCERTAINTY_LOWER,
        "nvidia_api_key_set":       bool(os.getenv("NVIDIA_API_KEY")),
        "prompt_shield_enabled":    os.getenv("PROMPT_SHIELD_ENABLED", "false").lower() == "true",
        "audit_trail_enabled":      os.getenv("AUDIT_TRAIL_ENABLED", "false").lower() == "true",
    }


@app.post("/api/config", tags=["ops"], summary="Update live-tunable settings")
async def update_config(update: _ConfigUpdate):
    if update.semantic_threshold is not None:
        val = max(0.1, min(1.0, update.semantic_threshold))
        os.environ["SEMANTIC_THRESHOLD"] = str(val)
        if _brain_guard is not None:
            _brain_guard.threshold = val
    if update.strict_mode is not None:
        os.environ["STRICT_MODE"] = str(update.strict_mode).lower()
        if _guard is not None:
            _guard.strict = update.strict_mode
    if update.rate_limit_per_minute is not None:
        set_default_rate_limit(update.rate_limit_per_minute)
    if update.uncertainty_lower_threshold is not None:
        global _UNCERTAINTY_LOWER
        _UNCERTAINTY_LOWER = max(0.0, min(0.99, update.uncertainty_lower_threshold))
        os.environ["UNCERTAINTY_LOWER_THRESHOLD"] = str(_UNCERTAINTY_LOWER)
    return {"ok": True}


# ── SIEM bypass helper ────────────────────────────────────────────────────────

async def _ship_bypass(background_tasks, entry: dict) -> None:  # type: ignore[type-arg]
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

async def _run_filter_pipeline(
    payload:          FilterRequest,
    rid:              str,
    auth:             AuthResult,
    background_tasks: BackgroundTasks | None = None,
    client_ip:        str                    = "",
) -> FilterResponse:
    """Execute the full filter pipeline and return a FilterResponse."""
    start = time.perf_counter()
    _filter_window.append(start)   # record for bypass_rate_1m
    timings: dict[str, float] = {}

    # ── Circuit breaker — short-circuit immediately if open ───────────
    _r = _get_redis()
    if _cb.is_open(_r):
        tenant_id = (
            auth.tenant_id if auth.tenant_id != "default" else payload.tenant_id
        )
        FILTER_BYPASSES_TOTAL.labels(tenant_id=tenant_id).inc()
        _bypass_window.append(start)
        _cb_entry = {
            "ts":         datetime.now(UTC).isoformat(),
            "request_id": rid,
            "tenant_id":  tenant_id,
            "allowed":    True,
            "risk_level": RiskLevel.LOW.value,
            "flags":      [],
            "reason":     "circuit_breaker:open",
            "payload_len": len(payload.content) if payload.content else 0,
            "elapsed_ms": 0,
        }
        asyncio.create_task(_ship_bypass(background_tasks, _cb_entry))
        if _webhook_store is not None:
            asyncio.create_task(_dispatch_bypass_webhook(
                tenant_id     = tenant_id,
                reason        = "circuit_breaker:open",
                content       = payload.content or "",
                processing_ms = 0,
                store         = _webhook_store,
            ))
        return FilterResponse(
            allowed          = True,
            risk_level       = RiskLevel.LOW,
            filtered_content = payload.content,
            secrets_found    = [],
            semantic_flags   = [],
            reason           = "circuit_breaker:open",
            processing_ms    = {"total": 0, "circuit_breaker": 1},
        )

    # ── IP block check (pre-auth, earliest possible gate) ──────────────
    _check_tenant = auth.tenant_id if auth.tenant_id != "default" else payload.tenant_id
    _ip_blocked = (
        # 1. Global Redis blocklist — cross-region, sub-millisecond
        (client_ip and _global_blocklist_is_blocked(client_ip, _check_tenant))
        # 2. Local SQLite ThreatStore — offline / Redis-down fallback
        or (client_ip and _threat_store is not None
            and _threat_store.is_blocked(client_ip, _check_tenant))
    )
    if _ip_blocked:
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

    # ── Fake-secret reuse detection ───────────────────────────────────
    # If the inbound text contains one of our previously-issued honey credentials,
    # the attacker is trying to use a fake secret we planted — log and block.
    if _honey_engine is not None and payload.content:
        with suppress(Exception):
            fake_meta = _honey_engine.check_fake_secret_used(payload.content)
            if fake_meta:
                log.warning(
                    json.dumps({
                        "event":    "fake_secret_reuse",
                        "honey_id": fake_meta.get("honey_id"),
                        "label":    fake_meta.get("label"),
                        "tenant":   tenant_id,
                        "request_id": rid,
                    })
                )
                # Treat as a blocked high-risk request so the attacker gets no feedback
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied.",
                )

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

    poison_result_dict: dict = {}   # populated by Stage 2c if guard fires

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

    from warden.telemetry import trace_stage as _trace_stage  # noqa: PLC0415

    # ── Stage 0a.5: Topological Gatekeeper ────────────────────────────
    # TDA pre-filter — detects bot payloads, random noise, and repetitive
    # DoS content via n-gram point cloud + Betti number approximation.
    # Runs in < 2ms; result is stored and applied to guard_result after Stage 2.
    t0 = time.perf_counter()
    _topo_result = _topo_scan(payload.content)
    timings["topology"] = round((time.perf_counter() - t0) * 1000, 2)
    if _topo_result.is_noise:
        log.warning(
            json.dumps({
                "event":       "topological_noise",
                "request_id":  rid,
                "noise_score": _topo_result.noise_score,
                "beta0":       _topo_result.beta0,
                "beta1":       _topo_result.beta1,
                "tenant_id":   tenant_id,
            })
        )

    # ── Stage 0b: Obfuscation decoding ────────────────────────────────
    t0 = time.perf_counter()
    with _trace_stage("obfuscation", {"request_id": rid, "tenant_id": tenant_id}) as _sp:
        obfuscation_result = decode_obfuscation(payload.content)
        _sp.set_attribute("obfuscation.detected", obfuscation_result.has_obfuscation)
        _sp.set_attribute("obfuscation.layers",   str(obfuscation_result.layers_found))
    timings["obfuscation"] = round((time.perf_counter() - t0) * 1000, 2)

    # Use decoded+original combined text for downstream analysis.
    # Append string-serialised context values so injection via context fields
    # (e.g. context.system_override) is visible to every downstream stage.
    analysis_text = obfuscation_result.combined
    if payload.context:
        ctx_blob = " ".join(
            str(v) for v in payload.context.values()
            if isinstance(v, (str, int, float, bool))
        )
        if ctx_blob:
            analysis_text = f"{analysis_text}\n\n[CONTEXT]{ctx_blob}[/CONTEXT]"

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
    with _trace_stage("secret_redaction", {"request_id": rid, "tenant_id": tenant_id}) as _sp:
        redact_result = _redactor.redact(analysis_text, payload.redaction_policy)  # type: ignore[union-attr]
        _sp.set_attribute("redaction.secrets_found", len(redact_result.findings))
        _sp.set_attribute("redaction.has_pii",       redact_result.has_pii)
    timings["redaction"] = round((time.perf_counter() - t0) * 1000, 2)

    if redact_result.findings:
        kinds = [f.kind for f in redact_result.findings]
        log.warning(
            json.dumps({"event": "secrets_redacted", "request_id": rid, "kinds": kinds})
        )

    # ── Stage 1.5: ThreatVault Signature Scan ─────────────────────────
    vault_matches: list[dict] = []
    if _threat_vault is not None:
        t0 = time.perf_counter()
        with _trace_stage("threat_vault", {"request_id": rid, "tenant_id": tenant_id}) as _sp:
            vault_hits = _threat_vault.scan(analysis_text)
            _sp.set_attribute("vault.hits", len(vault_hits))
        timings["threat_vault"] = round((time.perf_counter() - t0) * 1000, 2)

        if vault_hits:
            vault_matches = [
                {
                    "id":       h.threat_id,
                    "name":     h.name,
                    "category": h.category,
                    "severity": h.severity,
                    "owasp":    h.owasp,
                }
                for h in vault_hits
            ]
            top_hit = max(vault_hits, key=lambda h: SEVERITY_RANK.get(h.severity, 0))
            vault_risk = {
                "critical": RiskLevel.BLOCK,
                "high":     RiskLevel.HIGH,
                "medium":   RiskLevel.MEDIUM,
                "low":      RiskLevel.LOW,
            }.get(top_hit.severity, RiskLevel.MEDIUM)

            # Initialise guard_result placeholder so we can append flags before Stage 2
            # (guard_result is set by Stage 2 below; pre-declare to avoid NameError)
            _vault_flags_pending = vault_hits
            log.warning(
                json.dumps({
                    "event":        "threat_vault_hit",
                    "request_id":   rid,
                    "threats":      [h.threat_id for h in vault_hits],
                    "max_severity": top_hit.severity,
                    "tenant_id":    tenant_id,
                })
            )
        else:
            _vault_flags_pending = []
            vault_risk = RiskLevel.LOW
    else:
        _vault_flags_pending = []
        vault_risk = RiskLevel.LOW

    # ── Stage 2: Rule-based Semantic Analysis ─────────────────────────
    t0 = time.perf_counter()
    with _trace_stage("rule_analysis", {"request_id": rid, "tenant_id": tenant_id}) as _sp:
        guard_result = _guard.analyse(redact_result.text)  # type: ignore[union-attr]
        _sp.set_attribute("rules.flags_count", len(guard_result.flags))
        _sp.set_attribute("rules.risk_level",  guard_result.risk_level.value)
    timings["rules"] = round((time.perf_counter() - t0) * 1000, 2)

    # Merge ThreatVault hits into guard_result (now that guard_result exists)
    if _vault_flags_pending:
        for hit in _vault_flags_pending:
            guard_result.flags.append(SemanticFlag(
                flag=FlagType.PROMPT_INJECTION,
                score=1.0,
                detail=(
                    f"[ThreatVault:{hit.threat_id}] {hit.name} "
                    f"({hit.severity.upper()}) — {hit.owasp}: "
                    f"{hit.description[:120]}"
                ),
            ))
        guard_result.risk_level = _max_risk(guard_result.risk_level, vault_risk)

    # ── Apply Topological Gatekeeper result ───────────────────────────
    if _topo_result.is_noise:
        guard_result.flags.append(SemanticFlag(
            flag=FlagType.TOPOLOGICAL_NOISE,
            score=round(_topo_result.noise_score, 4),
            detail=_topo_result.detail,
        ))
        guard_result.risk_level = _max_risk(guard_result.risk_level, RiskLevel.MEDIUM)

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
    with _trace_stage("ml_inference", {"request_id": rid, "tenant_id": tenant_id}) as _sp:
        brain_result = await brain_guard.check_async(redact_result.text)
        _sp.set_attribute("ml.score",        brain_result.score)
        _sp.set_attribute("ml.is_jailbreak", brain_result.is_jailbreak)
        _sp.set_attribute("ml.threshold",    brain_result.threshold)
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

    # ── Stage 2b-ii: ML uncertainty escalation ────────────────────────
    # Flag requests whose ML score falls in the gray zone [UNCERTAINTY_LOWER, threshold).
    if (
        _UNCERTAINTY_LOWER > 0
        and not brain_result.is_jailbreak
        and brain_result.score >= _UNCERTAINTY_LOWER
    ):
        guard_result.flags.append(SemanticFlag(
            flag=FlagType.ML_UNCERTAIN,
            score=round(brain_result.score, 4),
            detail=(
                f"ML score {brain_result.score:.3f} in uncertainty zone "
                f"[{_UNCERTAINTY_LOWER:.2f}, {brain_result.threshold:.2f}) — suspicious but below block threshold"
            ),
        ))
        guard_result.risk_level = _max_risk(guard_result.risk_level, RiskLevel.MEDIUM)
        log.info(
            json.dumps({
                "event":      "ml_uncertain",
                "request_id": rid,
                "score":      brain_result.score,
                "lower":      _UNCERTAINTY_LOWER,
                "threshold":  brain_result.threshold,
                "tenant_id":  tenant_id,
            })
        )
        FILTER_UNCERTAIN_TOTAL.labels(tenant_id=tenant_id).inc()

    # ── Stage 2b-iii: Causal Arbiter (gray-zone resolution) ───────────
    # Runs only when ML score is in the uncertainty band [LOWER, threshold).
    # Replaces an LLM verification call with a lightweight Bayesian DAG
    # that computes P(HIGH_RISK | evidence) via Pearl's do-calculus.
    if (
        _UNCERTAINTY_LOWER > 0
        and not brain_result.is_jailbreak
        and brain_result.score >= _UNCERTAINTY_LOWER
    ):
        t0 = time.perf_counter()
        _session_blocks = 0
        if session_id and _agent_monitor is not None:
            with suppress(Exception):
                _sess = _agent_monitor.get_session(session_id)
                if _sess:
                    _session_blocks = int(_sess.get("block_count", 0))
        # PhishGuard se_risk: run a lightweight pre-check here so the Causal
        # Arbiter can incorporate the SE signal in the same pass (avoids a
        # second arbitrate() call later).
        try:
            from warden.phishing_guard import analyse as _phish_pre  # noqa: PLC0415
            _pre_se = _phish_pre(analysis_text).se_risk
        except Exception:
            _pre_se = 0.0

        _causal_result = _causal_arbitrate(
            ml_score             = brain_result.score,
            ers_score            = float(getattr(auth, "ers_score", 0.0) or 0.0),
            obfuscation_detected = obfuscation_result.has_obfuscation,
            block_history        = _session_blocks,
            tool_tier            = -1,
            content_entropy      = _content_entropy(analysis_text),
            se_risk              = _pre_se,
        )
        timings["causal"] = round((time.perf_counter() - t0) * 1000, 2)
        if _causal_result.is_high_risk:
            guard_result.flags.append(SemanticFlag(
                flag=FlagType.CAUSAL_HIGH_RISK,
                score=round(_causal_result.risk_probability, 4),
                detail=_causal_result.detail,
            ))
            guard_result.risk_level = _max_risk(guard_result.risk_level, RiskLevel.HIGH)
            log.warning(
                json.dumps({
                    "event":        "causal_high_risk",
                    "request_id":   rid,
                    "causal_p":     _causal_result.risk_probability,
                    "ml_score":     brain_result.score,
                    "ers_score":    getattr(auth, "ers_score", 0.0),
                    "obfusc":       obfuscation_result.has_obfuscation,
                    "tenant_id":    tenant_id,
                })
            )

    # ── Stage 2c: Data Poisoning Detection ───────────────────────────
    if _poison_guard is not None:
        t0 = time.perf_counter()
        try:
            from warden.brain.poison import PoisonResult  # noqa: PLC0415
            _pr: PoisonResult = await _poison_guard.check_async(
                content=redact_result.text,
                tenant_id=tenant_id,
                ml_score=brain_result.score,
                threshold=brain_result.threshold,
            )
            timings["poison"] = round((time.perf_counter() - t0) * 1000, 2)
            if _pr.is_poisoning_attempt:
                poison_result_dict = _pr.as_dict
                guard_result.flags.append(SemanticFlag(
                    flag=FlagType.DATA_POISONING,
                    score=round(_pr.poisoning_score, 4),
                    detail=_pr.detail,
                ))
                guard_result.risk_level = _max_risk(guard_result.risk_level, RiskLevel.HIGH)
                try:
                    from warden.metrics import POISONING_ATTEMPTS_TOTAL  # noqa: PLC0415
                    POISONING_ATTEMPTS_TOTAL.labels(
                        tenant_id=tenant_id,
                        attack_vector=_pr.attack_vector,
                    ).inc()
                except Exception:
                    pass
                log.warning(
                    json.dumps({
                        "event":        "data_poisoning_detected",
                        "request_id":   rid,
                        "tenant_id":    tenant_id,
                        "attack_vector": _pr.attack_vector,
                        "score":        _pr.poisoning_score,
                        "detail":       _pr.detail,
                    })
                )
                # High-confidence poisoning (>85%) → Telegram + Slack alert
                if _pr.poisoning_score > 0.85:
                    from warden import alerting  # noqa: PLC0415
                    background_tasks.add_task(
                        alerting.alert_poisoning_event,
                        attack_vector   = _pr.attack_vector,
                        poisoning_score = _pr.poisoning_score,
                        detail          = _pr.detail,
                        tenant_id       = tenant_id,
                    )
        except Exception as _pe:
            log.debug("Poison detection error (non-fatal): %s", _pe)

    # ── Stage 2d: PhishGuard & SE-Arbiter ────────────────────────────
    # Runs on the decoded/redacted text (analysis_text) for inbound scanning.
    # Integrates se_risk into the Causal Arbiter score retroactively via a
    # second arbitrate() call when SE is detected.
    try:
        from warden.phishing_guard import analyse as _phish_analyse  # noqa: PLC0415
        t0 = time.perf_counter()
        _phish_result = _phish_analyse(analysis_text)
        timings["phishguard"] = round((time.perf_counter() - t0) * 1000, 2)

        if _phish_result.is_phishing:
            guard_result.flags.append(SemanticFlag(
                flag   = FlagType.PHISHING_URL,
                score  = round(_phish_result.max_url_score, 4),
                detail = (
                    f"urls={len(_phish_result.url_findings)} "
                    f"max_score={_phish_result.max_url_score:.3f} "
                    + ("; ".join(_phish_result.url_findings[0].reasons[:2])
                       if _phish_result.url_findings else "")
                ),
            ))
            guard_result.risk_level = _max_risk(guard_result.risk_level, RiskLevel.HIGH)
            log.warning(json.dumps({
                "event":      "phishing_url_detected",
                "request_id": rid,
                "tenant_id":  tenant_id,
                "max_score":  _phish_result.max_url_score,
                "urls":       len(_phish_result.url_findings),
            }))

        if _phish_result.is_social_engineering:
            guard_result.flags.append(SemanticFlag(
                flag   = FlagType.SOCIAL_ENGINEERING,
                score  = round(_phish_result.se_risk, 4),
                detail = (
                    f"se_risk={_phish_result.se_risk:.3f} "
                    f"urgency={_phish_result.p_urgency:.2f} "
                    f"authority={_phish_result.p_authority:.2f} "
                    f"fear={_phish_result.p_fear:.2f} "
                    f"greed={_phish_result.p_greed:.2f} "
                    f"filter_bypass={_phish_result.p_filter_bypass:.2f}"
                ),
            ))
            guard_result.risk_level = _max_risk(guard_result.risk_level, RiskLevel.HIGH)
            log.warning(json.dumps({
                "event":      "social_engineering_detected",
                "request_id": rid,
                "tenant_id":  tenant_id,
                "se_risk":    _phish_result.se_risk,
                "labels":     _phish_result.se_labels[:4],
            }))

    except Exception as _phish_exc:
        log.debug("PhishGuard error (fail-open): %s", _phish_exc)

    # ── Stage 3: Decision ─────────────────────────────────────────────
    with _trace_stage("decision", {"request_id": rid, "tenant_id": tenant_id}) as _sp:
        allowed = guard_result.safe_for(strict)
        _sp.set_attribute("decision.allowed",    allowed)
        _sp.set_attribute("decision.risk_level", guard_result.risk_level.value)
        _sp.set_attribute("decision.strict",     strict)

    reason = ""
    if not allowed:
        top = guard_result.top_flag
        reason = top.detail if top else f"Risk level: {guard_result.risk_level}"

    # ── Stage 3b: Session-aware incremental injection detection ───────
    if session_id and _session_guard is not None:
        with suppress(Exception):
            session_risk = _session_guard.record_and_check(
                session_id,
                guard_result.risk_level.value,
                [f.flag.value for f in guard_result.flags],
                rid,
            )
            if session_risk.escalated and allowed:
                allowed = False
                reason  = f"[SessionGuard] {session_risk.pattern}"
                guard_result.risk_level = _max_risk(guard_result.risk_level, RiskLevel.HIGH)
                log.warning(
                    json.dumps({
                        "event":      "session_escalation",
                        "request_id": rid,
                        "session_id": session_id,
                        "pattern":    session_risk.pattern,
                        "score":      session_risk.cumulative_score,
                    })
                )

    # ── Stage 3c: Honey-prompt deception ──────────────────────────────
    if not allowed and _honey_engine is not None:
        with suppress(Exception):
            honey_result = _honey_engine.maybe_honey(
                rid,
                [f.flag.value for f in guard_result.flags],
                tenant_id,
            )
            if honey_result.is_honey:
                FILTER_HONEYTRAP_TOTAL.labels(tenant_id=tenant_id).inc()
                if background_tasks is not None and auth.entity_key:
                    background_tasks.add_task(
                        _ers_record,
                        auth                = auth,
                        blocked             = False,
                        obfuscation_hit     = obfuscation_result.has_obfuscation,
                        honeytrap_hit       = True,
                        evolution_triggered = False,
                        rid                 = rid,
                    )
                timings["total"] = round((time.perf_counter() - start) * 1000, 2)
                return FilterResponse(
                    allowed          = True,   # honey looks like "success" to attacker
                    risk_level       = guard_result.risk_level,
                    filtered_content = honey_result.response_text,
                    secrets_found    = [],
                    semantic_flags   = guard_result.flags,
                    reason           = "",
                    processing_ms    = timings,
                )

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

    # ── Yellow zone entity detection (fast regex, always-on) ──────────────────
    # Runs MaskingEngine purely for detection — token replacement happens only
    # in the OpenAI proxy.  Fast (<1 ms for typical prompts), no ML required.
    _mask_detected: list[str] = []
    _mask_count:    int       = 0
    try:
        _mask_result = _get_masking_engine().mask(
            redact_result.text,              # post-redaction content (secrets already stripped)
            session_id = f"_detect_{rid}",   # ephemeral session, never unmasked
        )
        if _mask_result.has_entities:
            _mask_detected = list(_mask_result.summary().keys())
            _mask_count    = _mask_result.entity_count
            # Invalidate immediately — we only needed the detection summary
            _get_masking_engine().invalidate_session(f"_detect_{rid}")
    except Exception:
        pass   # detection is best-effort; never block a request

    # ── Analytics logging ─────────────────────────────────────────────
    try:
        _tokens = event_logger.estimate_tokens(payload.content)
        entry = event_logger.build_entry(
            request_id        = rid,
            allowed           = allowed,
            risk_level        = guard_result.risk_level.value,
            flags             = [f.flag.value for f in guard_result.flags],
            secrets_found     = [f.kind for f in redact_result.findings],
            payload_len       = len(payload.content),
            payload_tokens    = _tokens,
            attack_cost_usd   = event_logger.token_cost_usd(_tokens),
            elapsed_ms        = elapsed_ms,
            strict            = strict,
            session_id        = session_id,
            entities_detected = _mask_detected,
            entity_count      = _mask_count,
            masked            = False,   # proxy sets True when tokens are actually replaced
        )
        entry["tenant_id"] = tenant_id   # needed for billing aggregation
        event_logger.append(entry)
        # Broadcast to all connected /ws/events dashboard clients
        asyncio.create_task(_event_bus.broadcast({
            "type":        "event",
            "request_id":  rid,
            "ts":          entry.get("ts", ""),
            "risk":        guard_result.risk_level.value,
            "allowed":     allowed,
            "flags":       [f.flag.value for f in guard_result.flags],
            "secrets":     [f.kind for f in redact_result.findings],
            "payload_len": len(payload.content),
            "elapsed_ms":  round(elapsed_ms, 2),
            "tenant_id":   tenant_id,
            "session_id":  session_id,
        }))
    except Exception:
        log.exception(json.dumps({"event": "analytics_error", "request_id": rid}))

    # ── Audit Trail: tamper-evident chain entry ────────────────────────
    if _audit_trail is not None:
        with suppress(Exception):
            _audit_trail.record(
                request_id    = rid,
                tenant_id     = tenant_id,
                risk_level    = guard_result.risk_level.value,
                action        = "allowed" if allowed else "blocked",
                reason        = reason,
                flags         = [f.flag.value for f in guard_result.flags],
                processing_ms = timings.get("total", 0.0),
            )

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

    _masking_report = MaskingReport(
        masked       = False,
        session_id   = None,
        entities     = [
            MaskedEntityInfo(entity_type=k, token=f"[{k}_N]", count=0)
            for k in _mask_detected
        ],
        entity_count = _mask_count,
    )

    # ── XAI explanation ───────────────────────────────────────────────
    _xai_flags = [f.flag.value for f in guard_result.flags]
    _explanation = _xai_explain(
        risk_level       = guard_result.risk_level.value,
        flags            = _xai_flags,
        reason           = reason,
        owasp_categories = [],
    )

    # ── Webhook dispatch ──────────────────────────────────────────────
    if background_tasks is not None and _webhook_store is not None:
        background_tasks.add_task(
            _dispatch_webhook,
            tenant_id        = tenant_id,
            risk_level       = guard_result.risk_level.value,
            owasp_categories = [],
            reason           = reason,
            content          = payload.content,
            processing_ms    = timings.get("total", 0.0),
            store            = _webhook_store,
        )

    # ── Business Threat Neutralizer (optional — only when sector is set) ──
    _business_intel: dict | None = None
    if payload.sector:
        try:
            _neutralizer_report = _neutralizer_analyze(
                payload.sector,  # type: ignore[arg-type]
                obfuscation_detected = obfuscation_result.has_obfuscation,
                redacted_count       = len(redact_result.findings),
                has_pii              = redact_result.has_pii,
                risk_level           = guard_result.risk_level.value.upper(),
                ml_score             = brain_result.score,
                vault_matches        = vault_matches,
                semantic_flags       = [f.flag.value for f in guard_result.flags],
                poisoning_detected   = bool(poison_result_dict),
            )
            _business_intel = _neutralizer_report.as_dict()
        except Exception as _bte:
            log.debug("Business threat neutralizer error (non-fatal): %s", _bte)

    response = FilterResponse(
        allowed                  = allowed,
        risk_level               = guard_result.risk_level,
        filtered_content         = redact_result.text,
        secrets_found            = redact_result.findings,
        semantic_flags           = guard_result.flags,
        reason                   = reason,
        redaction_policy_applied = payload.redaction_policy,
        processing_ms            = timings,
        masking                  = _masking_report,
        explanation              = _explanation,
        poisoning                = poison_result_dict,
        threat_matches           = vault_matches,
        business_intel           = _business_intel,
    )

    # ── Cache write ───────────────────────────────────────────────────
    if allowed:
        set_cached(payload.content, response.model_dump_json())

    # ── ERS event recording (background — non-blocking) ───────────────
    if background_tasks is not None and auth.entity_key:
        _evolution_fired = (
            not allowed
            and _evolve is not None
            and _RISK_ORDER.index(guard_result.risk_level) >= _RISK_ORDER.index(RiskLevel.HIGH)
        )
        background_tasks.add_task(
            _ers_record,
            auth                = auth,
            blocked             = not allowed,
            obfuscation_hit     = obfuscation_result.has_obfuscation,
            honeytrap_hit       = False,   # honeytrap returns early — recorded below
            evolution_triggered = _evolution_fired,
            rid                 = rid,
        )

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


# ── ERS enrichment helper ─────────────────────────────────────────────────────

import dataclasses as _dc  # noqa: E402


def _ers_dominant_flag(counts: dict, total: int) -> str:
    """Return the ERS event type with the highest weighted contribution to the score."""
    if total == 0:
        return ""
    best = max(
        _ers._WEIGHTS,
        key=lambda e: _ers._WEIGHTS[e] * counts.get(e, 0) / total,
    )
    return best if counts.get(best, 0) > 0 else ""


def _ers_enrich(auth: AuthResult, client_ip: str) -> AuthResult:
    """
    Compute ERS score for this entity and return an enriched AuthResult.

    Fail-open: any error returns the original auth unchanged (score=0, no shadow ban).
    """
    try:
        entity_key = _ers.make_entity_key(auth.tenant_id, client_ip)
        ers_result = _ers.score(entity_key)
        last_flag  = _ers_dominant_flag(ers_result.counts, ers_result.total_1h)
        return _dc.replace(
            auth,
            entity_key = entity_key,
            ers_score  = ers_result.score,
            shadow_ban = ers_result.shadow_ban,
            last_flag  = last_flag,
        )
    except Exception as exc:
        log.debug("ERS enrichment failed (non-fatal): %s", exc)
        return auth


def _ers_record(
    auth:                AuthResult,
    blocked:             bool,
    obfuscation_hit:     bool,
    honeytrap_hit:       bool,
    evolution_triggered: bool,
    rid:                 str,
) -> None:
    """Record ERS events after a pipeline run. Called as a background task."""
    if not auth.entity_key:
        return
    try:
        if blocked:
            _ers.record_event(auth.entity_key, "block", rid)
        if obfuscation_hit:
            _ers.record_event(auth.entity_key, "obfuscation", rid)
        if honeytrap_hit:
            _ers.record_event(auth.entity_key, "honeytrap", rid)
        if evolution_triggered:
            _ers.record_event(auth.entity_key, "evolution_trigger", rid)
    except Exception as exc:
        log.debug("ERS record failed (non-fatal): %s", exc)


# ── /filter ───────────────────────────────────────────────────────────────────

@app.post(
    "/filter",
    response_model=FilterResponse,
    tags=["filter"],
    summary="Filter raw content through the Warden pipeline",
    status_code=status.HTTP_200_OK,
)
@_limiter.limit(_tenant_limit)
async def filter_content(
    payload:          FilterRequest,
    request:          Request,
    background_tasks: BackgroundTasks,
    auth:             AuthResult = Depends(require_api_key),
) -> FilterResponse:
    rid = getattr(request.state, "request_id", "-")
    _enforce_tenant_rate_limit(auth, rid)
    client_ip = request.client.host if request.client else ""

    # ── ERS check: enrich auth, shadow ban confirmed attackers ────────────
    auth = _ers_enrich(auth, client_ip)
    if auth.shadow_ban:
        return FilterResponse(
            **_sban.fake_filter_response(
                payload.content, auth.entity_key, auth.ers_score, auth.last_flag
            )
        )

    coro = _run_filter_pipeline(payload, rid, auth, background_tasks, client_ip)
    if _PIPELINE_TIMEOUT_MS > 0:
        try:
            return await asyncio.wait_for(coro, timeout=_PIPELINE_TIMEOUT_MS / 1000)
        except TimeoutError:
            log.warning(
                json.dumps({
                    "event":      "pipeline_timeout",
                    "request_id": rid,
                    "strategy":   _FAIL_STRATEGY,
                    "timeout_ms": _PIPELINE_TIMEOUT_MS,
                })
            )
            if _FAIL_STRATEGY == "closed":
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Filter pipeline timeout — request blocked (WARDEN_FAIL_STRATEGY=closed).",
                ) from None
            # fail-open: pass the request through with a LOW-risk response
            _tid = getattr(payload, "tenant_id", None) or "default"
            FILTER_BYPASSES_TOTAL.labels(tenant_id=_tid).inc()
            _bypass_window.append(time.perf_counter())
            _r2 = _get_redis()
            _cb.record_bypass(_r2)
            _cb.check_and_trip(_r2, len(_filter_window))
            _to_entry: dict = {
                "ts":         datetime.now(UTC).isoformat(),
                "request_id": rid,
                "tenant_id":  _tid,
                "allowed":    True,
                "risk_level": RiskLevel.LOW.value,
                "flags":      [],
                "reason":     "emergency_bypass:timeout",
                "payload_len": len(payload.content) if payload.content else 0,
                "elapsed_ms": _PIPELINE_TIMEOUT_MS,
            }
            asyncio.create_task(_ship_bypass(background_tasks, _to_entry))
            if _webhook_store is not None:
                asyncio.create_task(_dispatch_bypass_webhook(
                    tenant_id     = _tid,
                    reason        = "emergency_bypass:timeout",
                    content       = payload.content or "",
                    processing_ms = float(_PIPELINE_TIMEOUT_MS),
                    store         = _webhook_store,
                ))
            return FilterResponse(
                allowed          = True,
                risk_level       = RiskLevel.LOW,
                filtered_content = payload.content,
                secrets_found    = [],
                semantic_flags   = [],
                reason           = "emergency_bypass:timeout",
                processing_ms    = {"total": _PIPELINE_TIMEOUT_MS, "timeout": 1},
            )
    return await coro


# ── /demo/filter ──────────────────────────────────────────────────────────────
# Public endpoint for the landing-page live demo widget.
# No API key required — rate-limited to 10 req/min/IP.

_DEMO_AUTH = AuthResult(api_key="", tenant_id="demo", rate_limit=10)


@app.post(
    "/demo/filter",
    response_model=FilterResponse,
    tags=["filter"],
    summary="Public demo endpoint (no auth, 10 req/min/IP)",
    status_code=status.HTTP_200_OK,
)
@_limiter.limit("10/minute")
async def demo_filter(
    payload:          FilterRequest,
    request:          Request,
    background_tasks: BackgroundTasks,
) -> FilterResponse:
    rid = getattr(request.state, "request_id", str(uuid.uuid4()))
    client_ip = request.client.host if request.client else ""
    return await _run_filter_pipeline(payload, rid, _DEMO_AUTH, background_tasks, client_ip)


# ── /ext/filter — browser extension endpoint ─────────────────────────────────
# Identical to /filter but served under /ext/ which has wildcard CORS applied
# by _ExtensionCORSMiddleware.  This lets the popup and background service worker
# call the API from chrome-extension:// or moz-extension:// origins.

@app.post(
    "/ext/filter",
    response_model=FilterResponse,
    tags=["extension"],
    summary="Browser-extension filter endpoint (wildcard CORS; OIDC Bearer or API-key auth)",
    status_code=status.HTTP_200_OK,
)
@_limiter.limit(_tenant_limit)
async def ext_filter_content(
    payload:          FilterRequest,
    request:          Request,
    background_tasks: BackgroundTasks,
    auth:             AuthResult = Depends(require_ext_auth),
) -> FilterResponse:
    rid = getattr(request.state, "request_id", "-")
    _enforce_tenant_rate_limit(auth, rid)
    client_ip = request.client.host if request.client else ""
    auth = _ers_enrich(auth, client_ip)
    if auth.shadow_ban:
        return FilterResponse(
            **_sban.fake_filter_response(
                payload.content, auth.entity_key, auth.ers_score, auth.last_flag
            )
        )
    coro = _run_filter_pipeline(payload, rid, auth, background_tasks, client_ip)
    if _PIPELINE_TIMEOUT_MS > 0:
        try:
            result = await asyncio.wait_for(coro, timeout=_PIPELINE_TIMEOUT_MS / 1000)
        except TimeoutError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Filter pipeline timeout.",
            ) from None
    else:
        result = await coro

    # ── Reversible PII Masking for browser extension ──────────────────────────
    #
    # When the filter passes (allowed=True) but PII entities were detected
    # (masking.entity_count > 0), we upgrade the response with masked_content
    # and a vault session_id so the extension can:
    #   1. Forward the masked prompt (no PII) to the LLM
    #   2. Call /ext/unmask on the LLM response to restore [PERSON_1] → real name
    #
    # When the filter blocks (allowed=False) we annotate pii_action="block" so
    # the extension can skip calling /ext/unmask.
    #
    # EXT_MASK_ENABLED (default true) — set to false to disable auto-masking
    # and fall back to legacy red-overlay behaviour.
    if os.getenv("EXT_MASK_ENABLED", "true").lower() not in ("false", "0", "no"):
        if not result.allowed:
            result = result.model_copy(update={"pii_action": "block"})
        elif result.masking.entity_count > 0:
            # Run real masking (not detect-only) with a persistent session
            loop = asyncio.get_running_loop()
            _me = _get_masking_engine()
            _mask_res = await loop.run_in_executor(
                None, lambda: _me.mask(payload.content)
            )
            result = result.model_copy(update={
                "pii_action":     "mask_and_send",
                "masked_content": _mask_res.masked,
                "pii_session_id": _mask_res.session_id,
                "masking": MaskingReport(
                    masked       = True,
                    session_id   = _mask_res.session_id,
                    entities     = [
                        MaskedEntityInfo(entity_type=k, token=f"[{k}_N]", count=v)
                        for k, v in _mask_res.summary().items()
                    ],
                    entity_count = _mask_res.entity_count,
                ),
            })
        else:
            result = result.model_copy(update={"pii_action": "pass"})

    return result


@app.post(
    "/ext/unmask",
    response_model=UnmaskResponse,
    tags=["extension"],
    summary="Reversible PII — restore original values in LLM response (wildcard CORS)",
    status_code=status.HTTP_200_OK,
)
@_limiter.limit(_tenant_limit)
async def ext_unmask(
    payload: UnmaskRequest,
    request: Request,
    auth:    AuthResult = Depends(require_ext_auth),
) -> UnmaskResponse:
    """
    Replace all [TYPE_N] tokens in an LLM response with the original PII values
    stored in the ephemeral vault session created by POST /ext/filter.

    Call this from the background Service Worker after buffering the LLM SSE stream.
    The session vault expires 2 hours after the corresponding /ext/filter call.

    Example:
        Input:  "The contract for [PERSON_1] totalling [MONEY_1] is ready."
        Output: "The contract for John Doe totalling $5,000,000 is ready."
    """
    engine   = _get_masking_engine()
    loop     = asyncio.get_running_loop()
    unmasked = await loop.run_in_executor(
        None, lambda: engine.unmask(payload.text, payload.session_id)
    )
    return UnmaskResponse(unmasked=unmasked, session_id=payload.session_id)


@app.get(
    "/ext/health",
    tags=["extension"],
    summary="Extension health check — wildcard CORS for popup 'Test Connection' button",
)
async def ext_health() -> dict:
    """Lightweight liveness probe called by the browser extension popup."""
    return {"status": "ok", "version": app.version}


# ── /filter/batch ─────────────────────────────────────────────────────────────

_MAX_BATCH_SIZE = int(os.getenv("MAX_BATCH_SIZE", "50"))

# ── Fail strategy & pipeline timeout ──────────────────────────────────────────
# WARDEN_FAIL_STRATEGY=open  → pass request through on timeout (business priority)
# WARDEN_FAIL_STRATEGY=closed → block request on timeout   (security priority)
_FAIL_STRATEGY       = os.getenv("WARDEN_FAIL_STRATEGY", "open").lower()   # "open" | "closed"
_PIPELINE_TIMEOUT_MS = int(os.getenv("PIPELINE_TIMEOUT_MS", "0"))          # 0 = disabled

# ── ML uncertainty escalation ─────────────────────────────────────────────────
# Requests with ML score in [UNCERTAINTY_LOWER, threshold) are flagged as ML_UNCERTAIN
# and escalated to MEDIUM risk even though they didn't cross the block threshold.
# Set to 0 to disable.
_UNCERTAINTY_LOWER = float(os.getenv("UNCERTAINTY_LOWER_THRESHOLD", "0.55"))

# ── Resilience sliding window ──────────────────────────────────────────────────
# Lightweight deques (timestamps in seconds) for the /health bypass_rate_1m field.
# Pruned to the last 60 s on every /health read — no background task required.
_bypass_window:    deque[float] = deque()   # fail-open bypass events
_filter_window:    deque[float] = deque()   # all /filter requests (denominator)


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
@_limiter.limit(_tenant_limit)
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


# ── /filter/multimodal ────────────────────────────────────────────────────────

class _MultimodalRequest(BaseModel):
    content:    str | None = Field(default=None, max_length=32_000,
                                    description="Text payload (optional — submit image/audio alone).")
    image_b64:  str | None = Field(default=None, description="Base64-encoded image (PNG/JPEG/WebP).")
    audio_b64:  str | None = Field(default=None, description="Base64-encoded audio (WAV/MP3/OGG).")
    tenant_id:  str        = Field(default="default")
    strict:     bool       = Field(default=False)
    context:    dict       = Field(default_factory=dict)
    redact_pii: bool       = Field(
        default=True,
        description=(
            "Auto-blur PII regions in the image before returning. "
            "When True, redacted_image_b64 is populated if PII is detected. "
            "Set False to receive the detection verdict only without redaction."
        ),
    )
    redact_audio: bool     = Field(
        default=True,
        description=(
            "Auto-silence injected audio segments before returning. "
            "When True, redacted_audio_b64 (WAV) is populated when injection or "
            "ultrasound is detected. Set False to receive the verdict only."
        ),
    )
    synthesize_proxy: bool = Field(
        default=False,
        description=(
            "Generate a safe text description of the image instead of forwarding it. "
            "Triggered when ImageGuard detects PII (MEDIUM risk, no jailbreak). "
            "Use the returned image_description as LLM context in place of the image bytes."
        ),
    )


class _MultimodalResponse(BaseModel):
    allowed:             bool
    risk_level:          str
    flags:               list[dict]       = Field(default_factory=list)
    modalities:          dict             = Field(default_factory=dict)
    processing_ms:       dict[str, float] = Field(default_factory=dict)
    pii_redacted:        bool             = False
    redacted_image_b64:  str | None       = Field(
        default=None,
        description=(
            "Blurred version of the input image (base64 PNG). "
            "Populated when ImageGuard detects PII and redaction is enabled. "
            "Safe to forward to the LLM instead of the original."
        ),
    )
    redacted_audio_b64:  str | None       = Field(
        default=None,
        description=(
            "Cleaned version of the input audio (base64 WAV). "
            "Injected segments replaced with silence; ultrasound band stripped. "
            "Populated when AudioGuard detects injection or ultrasound and redaction is enabled."
        ),
    )
    image_description:   str | None       = Field(
        default=None,
        description=(
            "CLIP-generated safe text description of the image (synthesis proxy). "
            "Populated when synthesize_proxy=True and PII is detected (not jailbreak). "
            "Inject this into the LLM prompt instead of the image bytes."
        ),
    )
    text_result:         FilterResponse | None = None


@app.post(
    "/filter/multimodal",
    response_model=_MultimodalResponse,
    tags=["filter"],
    summary="Unified text + image + audio threat filter (v1.4 Multi-Modal Guard)",
    status_code=status.HTTP_200_OK,
)
@_limiter.limit(_tenant_limit)
async def filter_multimodal(
    payload:          _MultimodalRequest,
    request:          Request,
    background_tasks: BackgroundTasks,
    auth:             AuthResult = Depends(require_api_key),
) -> _MultimodalResponse:
    from warden.metrics import (  # noqa: PLC0415
        AUDIO_GUARD_BLOCKS_TOTAL,
        IMAGE_GUARD_BLOCKS_TOTAL,
        MULTIMODAL_REQUESTS_TOTAL,
    )
    from warden.multimodal import run_multimodal  # noqa: PLC0415

    if not payload.content and not payload.image_b64 and not payload.audio_b64:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="At least one of content, image_b64, or audio_b64 must be provided.",
        )

    rid = getattr(request.state, "request_id", str(uuid.uuid4()))

    # ── Text pipeline (if content provided) ──────────────────────────
    text_resp: FilterResponse | None = None
    text_risk = RiskLevel.LOW
    text_flags: list = []

    if payload.content:
        filter_req = FilterRequest(
            content   = payload.content,
            tenant_id = payload.tenant_id,
            strict    = payload.strict,
            context   = payload.context,
        )
        client_ip = request.client.host if request.client else ""
        text_resp = await _run_filter_pipeline(filter_req, rid, auth, background_tasks, client_ip)
        text_risk  = text_resp.risk_level
        text_flags = list(text_resp.semantic_flags)

    # ── Tenant brain guard for audio transcript ───────────────────────
    tenant_guard = _tenant_guards.get(payload.tenant_id, _brain_guard)

    # ── Multimodal pipeline ───────────────────────────────────────────
    mm_result = await run_multimodal(
        text_content      = payload.content,
        image_b64         = payload.image_b64,
        audio_b64         = payload.audio_b64,
        text_risk         = text_risk,
        text_flags        = text_flags,
        semantic_guard    = tenant_guard,
        strict            = payload.strict,
        redact_pii        = payload.redact_pii,
        redact_audio      = payload.redact_audio,
        synthesize_proxy  = payload.synthesize_proxy,
    )

    # ── Modalities label for Prometheus ──────────────────────────────
    active_modalities = "+".join(filter(None, [
        "text"  if payload.content   else None,
        "image" if payload.image_b64 else None,
        "audio" if payload.audio_b64 else None,
    ]))
    MULTIMODAL_REQUESTS_TOTAL.labels(modalities=active_modalities).inc()

    # ── Per-modality block counters ───────────────────────────────────
    for flag in mm_result.flags:
        if flag.flag == FlagType.VISUAL_JAILBREAK:
            IMAGE_GUARD_BLOCKS_TOTAL.labels(reason="visual_jailbreak").inc()
        elif flag.flag == FlagType.PII_DETECTED and payload.image_b64:
            IMAGE_GUARD_BLOCKS_TOTAL.labels(reason="pii_detected").inc()
        elif flag.flag == FlagType.AUDIO_INJECTION:
            reason = "ultrasound" if "Ultrasound" in flag.detail else "semantic_injection"
            AUDIO_GUARD_BLOCKS_TOTAL.labels(reason=reason).inc()

    return _MultimodalResponse(
        allowed            = mm_result.allowed,
        risk_level         = mm_result.risk_level.value,
        flags              = [
            {"flag": f.flag.value, "score": f.score, "detail": f.detail}
            for f in mm_result.flags
        ],
        modalities         = mm_result.modalities,
        processing_ms      = {
            **(text_resp.processing_ms if text_resp else {}),
            **mm_result.processing_ms,
        },
        pii_redacted       = mm_result.pii_redacted,
        redacted_image_b64 = mm_result.redacted_image_b64,
        redacted_audio_b64 = mm_result.redacted_audio_b64,
        image_description  = mm_result.image_description,
        text_result        = text_resp,
    )


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
        raise HTTPException(
            status_code=404,
            detail=f"No log entry found for request_id={body.request_id!r}.",
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


# ── Audit Trail endpoints (SOC 2) ─────────────────────────────────────────────


@app.get(
    "/admin/audit/verify",
    tags=["admin"],
    summary="Verify cryptographic integrity of the audit chain",
    dependencies=[Depends(require_api_key)],
)
async def audit_verify():
    """
    Walk every entry in the audit chain and recompute each SHA-256 hash.

    Returns ``{"valid": true, "entries": N}`` when the chain is intact.
    Returns ``{"valid": false, "broken_at_seq": N}`` if tampering is detected.
    Complexity: O(N) — runs synchronously; suitable for periodic health checks.
    """
    if _audit_trail is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AuditTrail not initialised.",
        )
    valid, count = _audit_trail.verify_chain()
    if valid:
        return {"valid": True, "entries": count}
    return {"valid": False, "broken_at_seq": count}


@app.get(
    "/admin/audit/export",
    tags=["admin"],
    summary="Export audit chain entries for SOC 2 auditors",
    dependencies=[Depends(require_api_key)],
)
async def audit_export(
    start: str | None = None,
    end:   str | None = None,
    limit: int        = 10_000,
):
    """
    Export audit entries in ISO-8601 UTC range ``[start, end]``.

    Both *start* and *end* are inclusive recorded_at timestamps.
    Omit both to export the full chain (up to *limit*).

    Also verifies chain integrity and includes ``"valid"`` in the response
    so auditors can confirm the export has not been tampered with.
    """
    if _audit_trail is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AuditTrail not initialised.",
        )
    entries     = _audit_trail.export_range(start=start, end=end, limit=limit)
    valid, _cnt = _audit_trail.verify_chain()
    return {
        "valid":   valid,
        "count":   len(entries),
        "entries": entries,
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
    # Mirror to global Redis blocklist so all regions enforce immediately
    _ = _global_blocklist_is_blocked  # import side-effect; actual call:
    try:
        from warden.global_blocklist import block_ip as _gbl_block  # noqa: PLC0415
        expires_s = 0
        if body.expires_at:
            from datetime import datetime as _dt  # noqa: PLC0415
            delta = _dt.fromisoformat(body.expires_at) - _dt.now(UTC)
            expires_s = max(0, int(delta.total_seconds()))
        _gbl_block(body.ip, body.tenant_id, body.reason, expires_s, "manual")
    except Exception as _gbl_err:
        log.debug("GlobalBlocklist.block_ip skipped (non-fatal): %s", _gbl_err)
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
        "message":    f"IP {body.ip!r} blocked globally.",
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


# ── ERS / Shadow Ban admin endpoints ─────────────────────────────────────────

@app.get(
    "/ers/score",
    tags=["security"],
    summary="Get ERS score for the current caller (tenant + IP)",
    dependencies=[Depends(require_api_key)],
)
async def ers_score_self(request: Request, auth: AuthResult = Depends(require_api_key)):
    """Return the ERS score for the caller's own entity key."""
    client_ip  = request.client.host if request.client else ""
    entity_key = _ers.make_entity_key(auth.tenant_id, client_ip)
    result    = _ers.score(entity_key)
    last_flag = _ers_dominant_flag(result.counts, result.total_1h)
    return {
        "entity_key": entity_key,
        "score":      result.score,
        "level":      result.level,
        "shadow_ban": result.shadow_ban,
        "last_flag":  last_flag,
        "total_1h":   result.total_1h,
        "counts":     result.counts,
        "window_secs": _ers.WINDOW_SECS,
    }


@app.post(
    "/ers/reset",
    tags=["security"],
    summary="Reset ERS score for a given tenant+IP (admin — false-positive clearance)",
    dependencies=[Depends(require_api_key)],
)
async def ers_reset(tenant_id: str, ip: str):
    """Clear all ERS signal counters for the specified entity."""
    entity_key = _ers.make_entity_key(tenant_id, ip)
    _ers.reset(entity_key)
    return {"entity_key": entity_key, "message": "ERS counters reset."}


# ── Zero-Trust Agent Sandbox — manifest management ────────────────────────────


@app.get(
    "/api/agent/manifests",
    tags=["agent-sandbox"],
    summary="List all registered agent capability manifests",
    dependencies=[Depends(require_api_key)],
)
async def list_agent_manifests():
    """Return the list of all registered agent manifests (agent_id, tools, egress flag)."""
    return {"manifests": _get_sandbox_registry().list_agents()}


@app.get(
    "/api/agent/manifest/{agent_id}",
    tags=["agent-sandbox"],
    summary="Get capability manifest for a specific agent",
    dependencies=[Depends(require_api_key)],
)
async def get_agent_manifest(agent_id: str):
    """Return full manifest detail for *agent_id*, or 404 if not registered."""
    m = _get_sandbox_registry().get_manifest(agent_id)
    if m is None:
        raise HTTPException(status_code=404, detail=f"No manifest for agent_id={agent_id!r}.")
    return {
        "agent_id":               m.agent_id,
        "description":            m.description,
        "network_egress_allowed": m.network_egress_allowed,
        "default_deny":           m.default_deny,
        "capabilities": [
            {
                "tool_name":             c.tool_name,
                "allowed_params":        c.allowed_params,
                "max_calls_per_session": c.max_calls_per_session,
                "required_approval":     c.required_approval,
            }
            for c in m.capabilities
        ],
    }


@app.post(
    "/api/agent/manifest/reload",
    tags=["agent-sandbox"],
    summary="Hot-reload agent manifests from AGENT_SANDBOX_PATH",
    dependencies=[Depends(require_api_key)],
)
async def reload_agent_manifests():
    """Force-reload all manifests from the JSON file on disk."""
    count = await asyncio.to_thread(_get_sandbox_registry().reload)
    return {"loaded": count, "message": f"Reloaded {count} manifest(s) from disk."}


# ── Behavioral Attestation ────────────────────────────────────────────────────


@app.get(
    "/api/agent/session/{session_id}/verify",
    tags=["agent-sandbox"],
    summary="Verify cryptographic attestation chain for an agent session",
    dependencies=[Depends(require_api_key)],
)
async def verify_session_attestation(session_id: str):
    """
    Replay stored tool events and recompute the SHA-256 attestation chain.

    Returns ``valid=true`` when the stored token matches the computed token —
    confirming the session history has not been tampered with.
    """
    if _agent_monitor is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AgentMonitor not available.",
        )
    result = await asyncio.to_thread(_agent_monitor.verify_attestation, session_id)
    if result.get("error") == "session_not_found":
        raise HTTPException(status_code=404, detail=f"Session {session_id!r} not found.")
    return result


@app.get(
    "/api/agent/session/{session_id}",
    tags=["agent-sandbox"],
    summary="Get metadata and events for an agent session",
    dependencies=[Depends(require_api_key)],
)
async def get_agent_session(session_id: str):
    """Return full session metadata + tool event list for *session_id*."""
    if _agent_monitor is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AgentMonitor not available.",
        )
    sess = await asyncio.to_thread(_agent_monitor.get_session, session_id)
    if sess is None:
        raise HTTPException(status_code=404, detail=f"Session {session_id!r} not found.")
    return sess


@app.delete(
    "/api/agent/session/{session_id}",
    tags=["agent-sandbox"],
    summary="Kill-switch: immediately revoke an agent session",
    dependencies=[Depends(require_api_key)],
)
async def revoke_agent_session(
    session_id: str,
    reason: str = "admin_kill_switch",
):
    """
    Terminate an agent session immediately.

    Any subsequent ``/v1/chat/completions`` request carrying
    ``X-Session-ID: {session_id}`` will receive HTTP 403 until the session TTL
    expires.  The revocation is also recorded in session metadata for audit.
    """
    if _agent_monitor is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AgentMonitor not available.",
        )
    result = await asyncio.to_thread(_agent_monitor.revoke_session, session_id, reason)
    return result


# ── v1.8 Compliance Reporting & Evidence Bundles ─────────────────────────────


@app.get(
    "/compliance/art30",
    tags=["compliance"],
    summary="GDPR Article 30 Record of Processing Activities",
    dependencies=[Depends(require_api_key)],
)
async def compliance_art30(
    days: float = 30,
    format: str = "json",
):
    """
    Generate a GDPR Art. 30 RoPA from real traffic data.

    Set ``format=html`` to receive a styled HTML document ready for DPO sign-off
    (print to PDF from the browser).  Default is ``json``.
    """
    from fastapi.responses import HTMLResponse  # noqa: PLC0415

    from warden.compliance.art30 import Art30Generator  # noqa: PLC0415

    gen    = Art30Generator()
    record = await asyncio.to_thread(gen.generate, days)
    if format.lower() == "html":
        html = await asyncio.to_thread(gen.to_html, record)
        return HTMLResponse(content=html)
    return record


@app.get(
    "/compliance/soc2/export",
    tags=["compliance"],
    summary="SOC 2 Evidence Bundle — ZIP archive for auditors",
    dependencies=[Depends(require_api_key)],
)
async def compliance_soc2_export(days: float = 30):
    """
    Export a tamper-evident ZIP bundle containing:
    config snapshot, threat statistics, audit chain status,
    evolved rules, session summaries, and SHA-256 audit manifest.

    Safe to share with external auditors — no prompt content or PII values included.
    """
    from datetime import UTC, datetime  # noqa: PLC0415

    from fastapi.responses import StreamingResponse  # noqa: PLC0415

    from warden.compliance.soc2 import SOC2Exporter  # noqa: PLC0415

    exporter = SOC2Exporter(audit_trail=_audit_trail)
    buf      = await asyncio.to_thread(exporter.export_bundle, days)
    slug     = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    filename = f"soc2_evidence_{slug}.zip"
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get(
    "/compliance/incident/{session_id}",
    tags=["compliance"],
    summary="Incident Post-Mortem report for a session or ERS entity",
    dependencies=[Depends(require_api_key)],
)
async def compliance_incident_report(
    session_id: str,
    entity_key: str | None = None,
    format: str = "json",
):
    """
    Generate a post-mortem report for *session_id*.

    Includes threat timeline, detected patterns, attestation chain status,
    ERS profile (if *entity_key* provided), and recommended actions.

    Set ``format=html`` for a printable HTML document.
    """
    from fastapi.responses import HTMLResponse  # noqa: PLC0415

    from warden.compliance.incident import IncidentReporter  # noqa: PLC0415

    reporter = IncidentReporter(agent_monitor=_agent_monitor)
    report   = await asyncio.to_thread(reporter.generate, session_id, entity_key)
    if format.lower() == "html":
        html = await asyncio.to_thread(reporter.to_html, report)
        return HTMLResponse(content=html)
    return report


@app.get(
    "/compliance/dashboard",
    tags=["compliance"],
    summary="Compliance & Risk Mitigation ROI dashboard",
    dependencies=[Depends(require_api_key)],
)
async def compliance_dashboard(days: float = 30):
    """
    Return risk-mitigation ROI metrics: shadow-ban compute savings,
    estimated breach cost avoided, secret protection value, agent security summary,
    and the Compliance Score (Cs = verified_audit_entries / total_log_entries).

    Override ``COMPLIANCE_*`` environment variables to use your organisation's
    actual LLM pricing and breach cost estimates.
    """
    from warden.compliance.dashboard import ComplianceDashboard  # noqa: PLC0415

    dash    = ComplianceDashboard(agent_monitor=_agent_monitor, audit_trail=_audit_trail)
    metrics = await asyncio.to_thread(dash.get_metrics, days)
    return metrics


# ── Evidence Vault ────────────────────────────────────────────────────────────


@app.get(
    "/compliance/evidence/{session_id}",
    tags=["compliance"],
    summary="Export a cryptographically-signed evidence bundle for a session",
    dependencies=[Depends(require_api_key)],
)
async def compliance_evidence_bundle(
    session_id: str,
    agent_id:   str = "",
    entity_key: str = "",
):
    """
    Generate a tamper-evident JSON evidence bundle for *session_id*.

    The bundle includes session metadata, ERS profile, attestation chain
    status, tool timeline, and a ``bundle_hash`` (SHA-256 over canonical JSON).
    Any post-export modification invalidates the hash.

    Use ``POST /compliance/evidence/verify`` to check integrity later.
    """
    if _agent_monitor is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AgentMonitor not available.",
        )
    from warden.compliance.bundler import EvidenceBundler  # noqa: PLC0415

    bundler = EvidenceBundler(agent_monitor=_agent_monitor)
    bundle  = await asyncio.to_thread(bundler.generate, session_id, agent_id, entity_key)
    return bundle


@app.post(
    "/compliance/evidence/verify",
    tags=["compliance"],
    summary="Verify integrity of a previously exported evidence bundle",
    dependencies=[Depends(require_api_key)],
)
async def compliance_evidence_verify(bundle: dict):
    """
    Verify the ``bundle_hash`` of a submitted evidence bundle.

    Returns ``{"valid": true}`` if the bundle is intact, ``{"valid": false}``
    if any field has been modified since export.
    """
    from warden.compliance.bundler import EvidenceBundler  # noqa: PLC0415

    valid = await asyncio.to_thread(EvidenceBundler.verify_bundle, bundle)
    return {"valid": valid, "bundle_hash": bundle.get("bundle_hash", "")}


# ── GDPR RoPA alias (regulators expect this path) ────────────────────────────


@app.get(
    "/api/compliance/gdpr/ropa",
    tags=["compliance"],
    summary="GDPR Article 30 RoPA — regulatory path alias",
    dependencies=[Depends(require_api_key)],
)
async def compliance_gdpr_ropa(days: float = 30, format: str = "json"):
    """
    Alias for ``GET /compliance/art30`` using the path regulators expect.
    Returns the Art. 30 Record of Processing Activities.
    """
    return await compliance_art30(days=days, format=format)


# ── Threat Intelligence endpoints ────────────────────────────────────────────


def _require_threat_intel():
    if _threat_intel_store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat Intelligence Engine disabled. Set THREAT_INTEL_ENABLED=true.",
        )
    return _threat_intel_store


@app.get("/threats/intel/stats", tags=["threat-intel"])
async def threat_intel_stats(_: AuthResult = Depends(require_api_key)):
    """Aggregated statistics for the threat intelligence collection."""
    store = _require_threat_intel()
    return store.stats()


@app.get("/threats/intel", tags=["threat-intel"])
async def list_threat_intel(
    item_status: str | None = None,
    source:      str | None = None,
    limit:       int        = 50,
    offset:      int        = 0,
    _: AuthResult = Depends(require_api_key),
):
    """List collected threat intelligence items."""
    store = _require_threat_intel()
    items = store.list_items(status=item_status, source=source, limit=limit, offset=offset)
    return {"items": [i.model_dump() for i in items], "total": len(items)}


@app.get("/threats/intel/{item_id}", tags=["threat-intel"])
async def get_threat_intel_item(
    item_id: str,
    _: AuthResult = Depends(require_api_key),
):
    """Retrieve a single threat intelligence item with its countermeasures."""
    store = _require_threat_intel()
    item = store.get_item(item_id)
    if item is None:
        raise HTTPException(status_code=404, detail=f"Threat item {item_id!r} not found.")
    countermeasures = store.get_countermeasures(item_id)
    return {**item.model_dump(), "countermeasures": countermeasures}


@app.post("/threats/intel/refresh", tags=["threat-intel"], status_code=202)
async def refresh_threat_intel(
    background_tasks: BackgroundTasks,
    _: AuthResult = Depends(require_api_key),
):
    """Trigger an immediate out-of-cycle collection + analysis run."""
    if _ti_scheduler is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat Intelligence Engine disabled. Set THREAT_INTEL_ENABLED=true.",
        )
    background_tasks.add_task(_ti_scheduler.run_once)
    return {"queued": True, "message": "Threat intel refresh queued as background task."}


@app.post("/threats/intel/{item_id}/dismiss", tags=["threat-intel"])
async def dismiss_threat_intel_item(
    item_id: str,
    _: AuthResult = Depends(require_api_key),
):
    """Manually dismiss a threat intelligence item (will not generate rules)."""
    store = _require_threat_intel()
    found = store.dismiss(item_id)
    if not found:
        raise HTTPException(status_code=404, detail=f"Threat item {item_id!r} not found.")
    return {"item_id": item_id, "status": "dismissed"}


# ── ThreatVault endpoints ──────────────────────────────────────────────────────


@app.get("/threats/vault", tags=["threat-vault"])
async def list_threat_vault(_: AuthResult = Depends(require_api_key)):
    """List all adversarial prompt signatures loaded in the ThreatVault."""
    if _threat_vault is None:
        raise HTTPException(status_code=503, detail="ThreatVault not initialized.")
    return {
        "stats":   _threat_vault.stats(),
        "threats": _threat_vault.list_threats(),
    }


@app.get("/threats/vault/stats", tags=["threat-vault"])
async def threat_vault_stats(_: AuthResult = Depends(require_api_key)):
    """Aggregated ThreatVault statistics: totals by severity, category, OWASP."""
    if _threat_vault is None:
        raise HTTPException(status_code=503, detail="ThreatVault not initialized.")
    return _threat_vault.stats()


@app.post("/threats/vault/reload", tags=["threat-vault"], status_code=202)
async def reload_threat_vault(_: AuthResult = Depends(require_api_key)):
    """Hot-reload ThreatVault signatures from disk (no restart required)."""
    if _threat_vault is None:
        raise HTTPException(status_code=503, detail="ThreatVault not initialized.")
    count = _threat_vault.reload()
    return {"reloaded": True, "signatures_loaded": count}


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


# ── Live Event Bus — broadcast security events to monitoring dashboards ───────

class _EventBus:
    """
    Pub/sub bus for real-time security event streaming.

    All connected /ws/events clients receive every security event within ~1ms.
    Thread-safe via asyncio; no external deps (Redis-free).
    """

    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._clients.add(ws)
        log.info("ws_events: client connected (total=%d)", len(self._clients))

    def disconnect(self, ws: WebSocket) -> None:
        self._clients.discard(ws)
        log.info("ws_events: client disconnected (total=%d)", len(self._clients))

    async def broadcast(self, data: dict) -> None:
        if not self._clients:
            return
        payload = json.dumps(data, ensure_ascii=False, default=str)
        dead: list[WebSocket] = []
        for ws in list(self._clients):
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._clients.discard(ws)

    @property
    def client_count(self) -> int:
        return len(self._clients)


_event_bus = _EventBus()


@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    """
    Real-time security event feed for the monitoring dashboard.

    Connect:  ws://host/ws/events?key=<api_key>

    Server pushes one JSON object per security event:
        {
          "type":        "event",
          "request_id":  str,
          "ts":          ISO-8601,
          "risk":        "low" | "medium" | "high" | "block",
          "allowed":     bool,
          "flags":       [str],
          "secrets":     [str],
          "payload_len": int,
          "elapsed_ms":  float,
          "tenant_id":   str,
          "session_id":  str | null
        }

    On connect, server sends one welcome frame:
        {"type": "connected", "clients": int}
    """
    api_key = websocket.query_params.get("key", "") or None
    try:
        require_api_key(api_key)
    except HTTPException as exc:
        await websocket.accept()
        await websocket.send_text(
            json.dumps({"type": "error", "code": exc.status_code, "detail": exc.detail})
        )
        await websocket.close(code=1008)
        return

    await _event_bus.connect(websocket)
    try:
        await websocket.send_text(
            json.dumps({"type": "connected", "clients": _event_bus.client_count})
        )
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
            except TimeoutError:
                await websocket.send_text(json.dumps({"type": "ping"}))
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        _event_bus.disconnect(websocket)


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


# ── WebSocket /ws/monitor/{id} — real-time probe results ─────────────────────

@app.websocket("/ws/monitor/{monitor_id}")
async def ws_monitor_stream(websocket: WebSocket, monitor_id: str):
    """
    Subscribe to real-time probe results for a monitor.

    Connect:  ws://host/ws/monitor/<uuid>
    Receives: {"is_up": bool, "latency_ms": float, "status_code": int,
               "error": str|null, "ts": "ISO8601"}

    Uses a queue bridge: sync Redis pubsub runs in a thread executor,
    forwarding messages to an asyncio.Queue consumed by the WebSocket sender.
    """
    await websocket.accept()
    r = _get_redis()
    if r is None:
        await websocket.send_json({"error": "Redis unavailable"})
        await websocket.close()
        return

    queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    channel = f"monitor:{monitor_id}:result"
    loop = asyncio.get_running_loop()

    def _listen() -> None:
        pubsub = r.pubsub()
        pubsub.subscribe(channel)
        try:
            for msg in pubsub.listen():
                if msg["type"] == "message":
                    loop.call_soon_threadsafe(queue.put_nowait, msg["data"])
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                pubsub.unsubscribe(channel)

    import threading
    _t = threading.Thread(target=_listen, daemon=True)
    _t.start()

    try:
        while True:
            data = await asyncio.wait_for(queue.get(), timeout=30)
            await websocket.send_text(data)
    except (WebSocketDisconnect, asyncio.TimeoutError):
        pass
    except Exception as exc:
        log.debug("ws_monitor: error — %s", exc)


# ── WebSocket /ws/filter — per-stage streaming ───────────────────────────────

@app.websocket("/ws/filter")
async def ws_filter_stream(websocket: WebSocket):
    """
    WebSocket endpoint that emits a JSON event after each filter-pipeline stage.

    Connect:  ws://host/ws/filter?key=<api_key>

    Send one JSON message matching FilterRequest:
        {"content": "...", "tenant_id": "acme", "strict": false}

    Receive event stream:
        {"type": "stage", "stage": "cache",       "hit": bool,    "ms": float}
        {"type": "stage", "stage": "obfuscation", "detected": bool, "layers": list, "ms": float}
        {"type": "stage", "stage": "redaction",   "count": int,   "kinds": list,  "ms": float}
        {"type": "stage", "stage": "rules",       "flags": list,  "risk": str,    "ms": float}
        {"type": "stage", "stage": "ml",          "score": float, "is_jailbreak": bool, "ms": float}
        {"type": "result", "request_id": str, ...FilterResponse fields...}
        {"type": "done",   "request_id": str}
    or
        {"type": "error",  "code": int, "detail": str}

    WebSocket close codes:
        1008 — Policy Violation (content blocked)
        1009 — Message Too Big
        1003 — Unsupported data (invalid JSON / validation error)
        1011 — Internal server error
    """
    await websocket.accept()
    rid = str(uuid.uuid4())

    # ── 1. Authenticate ────────────────────────────────────────────────────────
    api_key = websocket.query_params.get("key", "") or None
    try:
        auth = require_api_key(api_key)
    except HTTPException as exc:
        await _ws_send(websocket, {"type": "error", "code": exc.status_code, "detail": exc.detail})
        await websocket.close(code=1008)
        return

    # ── 2. Receive + validate payload ─────────────────────────────────────────
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

    try:
        payload = FilterRequest(**body)
    except Exception as exc:
        await _ws_send(websocket, {"type": "error", "code": 422, "detail": str(exc)})
        await websocket.close(code=1003)
        return

    tenant_id = auth.tenant_id if auth.tenant_id != "default" else payload.tenant_id
    strict = payload.strict or (_guard.strict if _guard else False)
    timings: dict[str, float] = {}

    log.info(json.dumps({"event": "ws_filter_start", "request_id": rid, "tenant_id": tenant_id}))

    # ── Stage 0: Redis cache check ─────────────────────────────────────────────
    t0 = time.perf_counter()
    cached_json = get_cached(payload.content)
    timings["cache_check"] = round((time.perf_counter() - t0) * 1000, 2)
    await _ws_send(websocket, {
        "type": "stage", "stage": "cache",
        "hit": cached_json is not None,
        "ms": timings["cache_check"],
    })

    if cached_json:
        try:
            resp = FilterResponse(**json.loads(cached_json))
            await _ws_send(websocket, {"type": "result", "request_id": rid, **resp.model_dump()})
            await _ws_send(websocket, {"type": "done", "request_id": rid})
            await websocket.close()
            return
        except Exception:
            pass  # corrupted cache entry → fall through to full pipeline

    # ── Stage 0b: Obfuscation decoding ────────────────────────────────────────
    t0 = time.perf_counter()
    obfuscation_result = decode_obfuscation(payload.content)
    timings["obfuscation"] = round((time.perf_counter() - t0) * 1000, 2)
    analysis_text = obfuscation_result.combined
    if payload.context:
        ctx_blob = " ".join(
            str(v) for v in payload.context.values()
            if isinstance(v, (str, int, float, bool))
        )
        if ctx_blob:
            analysis_text = f"{analysis_text}\n\n[CONTEXT]{ctx_blob}[/CONTEXT]"
    await _ws_send(websocket, {
        "type": "stage", "stage": "obfuscation",
        "detected": obfuscation_result.has_obfuscation,
        "layers": obfuscation_result.layers_found,
        "ms": timings["obfuscation"],
    })

    # ── Stage 1: Secret Redaction ─────────────────────────────────────────────
    t0 = time.perf_counter()
    redact_result = _redactor.redact(analysis_text, payload.redaction_policy)  # type: ignore[union-attr]
    timings["redaction"] = round((time.perf_counter() - t0) * 1000, 2)
    await _ws_send(websocket, {
        "type": "stage", "stage": "redaction",
        "count": len(redact_result.findings),
        "kinds": [f.kind for f in redact_result.findings],
        "ms": timings["redaction"],
    })

    # ── Stage 2: Rule-based Semantic Analysis ─────────────────────────────────
    t0 = time.perf_counter()
    guard_result = _guard.analyse(redact_result.text)  # type: ignore[union-attr]
    timings["rules"] = round((time.perf_counter() - t0) * 1000, 2)

    # Dynamic evolution regex rules
    for dyn_rule in list(_dynamic_regex_rules):
        if dyn_rule.pattern.search(redact_result.text):
            guard_result.flags.append(SemanticFlag(
                flag=FlagType.PROMPT_INJECTION,
                score=0.80,
                detail=f"Dynamic evolution rule matched: {dyn_rule.snippet}",
            ))
            guard_result.risk_level = _max_risk(guard_result.risk_level, RiskLevel.HIGH)

    if redact_result.has_pii:
        guard_result.flags.append(SemanticFlag(
            flag=FlagType.PII_DETECTED,
            score=1.0,
            detail=f"PII detected: {[f.kind for f in redact_result.findings]}",
        ))

    await _ws_send(websocket, {
        "type": "stage", "stage": "rules",
        "flags": [
            {"flag": f.flag.value, "score": f.score, "detail": f.detail}
            for f in guard_result.flags
        ],
        "risk": guard_result.risk_level.value,
        "ms": timings["rules"],
    })

    # ── Stage 3: ML Semantic Brain ────────────────────────────────────────────
    t0 = time.perf_counter()
    brain_guard = _get_tenant_guard(tenant_id)
    try:
        brain_result = await brain_guard.check_async(redact_result.text)
    except Exception as exc:
        log.exception(json.dumps({"event": "ws_filter_ml_error", "request_id": rid, "error": str(exc)}))
        await _ws_send(websocket, {"type": "error", "code": 500, "detail": "ML stage error."})
        await websocket.close(code=1011)
        return
    timings["ml"] = round((time.perf_counter() - t0) * 1000, 2)

    if brain_result.is_jailbreak:
        ml_risk = RiskLevel.HIGH if brain_result.score >= 0.85 else RiskLevel.MEDIUM
        guard_result.flags.append(SemanticFlag(
            flag=FlagType.PROMPT_INJECTION,
            score=round(brain_result.score, 4),
            detail=f"ML jailbreak detected (similarity={brain_result.score:.3f})",
        ))
        guard_result.risk_level = _max_risk(guard_result.risk_level, ml_risk)

    await _ws_send(websocket, {
        "type": "stage", "stage": "ml",
        "score": round(brain_result.score, 4),
        "is_jailbreak": brain_result.is_jailbreak,
        "ms": timings["ml"],
    })

    # ── Decision ──────────────────────────────────────────────────────────────
    allowed = guard_result.safe_for(strict)
    reason = ""
    if not allowed:
        top = guard_result.top_flag
        reason = top.detail if top else f"Risk level: {guard_result.risk_level}"

    timings["total"] = round(sum(timings.values()), 2)

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

    if allowed:
        set_cached(payload.content, response.model_dump_json())

    log.info(json.dumps({
        "event":      "ws_filter_done",
        "request_id": rid,
        "allowed":    allowed,
        "risk":       guard_result.risk_level.value,
        "elapsed_ms": timings["total"],
    }))

    await _ws_send(websocket, {"type": "result", "request_id": rid, **response.model_dump()})

    if not allowed:
        await websocket.close(code=1008)
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
        raise HTTPException(status_code=400, detail=str(exc)) from exc

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
        raise HTTPException(400, detail=str(exc)) from exc
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

    # ── Aggregate masking stats from the log (last 31 days covers current month)
    _log_entries    = event_logger.load_entries(days=31)
    _masked_by_tid: dict[str, int] = {}
    _entity_by_tid: dict[str, dict[str, int]] = {}
    fleet_masked    = 0
    fleet_entities: dict[str, int] = {}
    for _le in _log_entries:
        _tid = _le.get("tenant_id", "default")
        _ec  = _le.get("entity_count", 0)
        if _ec:
            _masked_by_tid[_tid] = _masked_by_tid.get(_tid, 0) + _ec
            fleet_masked        += _ec
            for _et in _le.get("entities_detected", []):
                fleet_entities[_et] = fleet_entities.get(_et, 0) + 1
                if _tid not in _entity_by_tid:
                    _entity_by_tid[_tid] = {}
                _entity_by_tid[_tid][_et] = _entity_by_tid[_tid].get(_et, 0) + 1

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
        masked  = _masked_by_tid.get(tid, 0)

        fleet_requests += reqs
        fleet_blocked  += blocked
        fleet_cost     += cost

        tenant_rows.append({
            "tenant_id":       tid,
            "label":           t.get("label", tid),
            "plan":            t.get("plan", "unknown"),
            "active":          t.get("active", True),
            "requests":        reqs,
            "blocked":         blocked,
            "masked_entities": masked,
            "block_rate":      round(blocked / reqs, 4) if reqs else 0.0,
            "cost_usd":        round(cost, 6),
            "quota_usd":       quota,
            "quota_pct":       round(cost / quota * 100, 1) if quota else None,
            "created_at":      t.get("created_at", ""),
        })

    # Sort by most blocked first for the demo table
    tenant_rows.sort(key=lambda r: r["blocked"], reverse=True)

    return {
        "month":          year_month,
        "fleet": {
            "tenants":          len(tenant_rows),
            "requests":         fleet_requests,
            "blocked":          fleet_blocked,
            "masked_entities":  fleet_masked,
            "top_entities":     fleet_entities,
            "block_rate":       round(fleet_blocked / fleet_requests, 4) if fleet_requests else 0.0,
            "cost_usd":         round(fleet_cost, 6),
        },
        "tenants": tenant_rows,
    }


@app.get(
    "/msp/report/{tenant_id}",
    tags=["msp"],
    summary="Monthly compliance report for a single tenant",
)
async def msp_report(
    tenant_id:  str,
    month:      str       = "",   # YYYY-MM; defaults to current calendar month
    fmt:        str       = "html",  # html | json | pdf
    brand_name: str       = "Shadow Warden AI",
    logo_url:   str | None = None,
    auth: AuthResult = Depends(require_api_key),
):
    """
    Generate a monthly compliance report for *tenant_id*.

    - **month** — ``YYYY-MM`` format (e.g. ``2026-02``). Defaults to the
      current calendar month.
    - **fmt** — ``html`` (default) returns a self-contained, print-ready HTML
      document. ``pdf`` renders via Playwright headless Chromium and returns a
      ``application/pdf`` attachment. ``json`` returns structured data for
      programmatic access.
    - **brand_name** — Override the "Shadow Warden AI" title for white-label
      deployments (default: ``"Shadow Warden AI"``).
    - **logo_url** — Optional URL to a tenant logo image displayed on the cover
      page (must be publicly accessible when rendering PDF).

    The report covers: executive summary, threat intelligence, PII intercepts,
    risk-level breakdown, daily activity, and auto-generated recommendations.
    """
    if not month:
        month = datetime.now(UTC).strftime("%Y-%m")

    # Basic format validation
    try:
        year_i, mon_i = map(int, month.split("-"))
        if not (1 <= mon_i <= 12):
            raise ValueError
    except (ValueError, AttributeError) as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid month format {month!r} — expected YYYY-MM.",
        ) from exc

    engine = _get_report_engine()

    if fmt == "json":
        return engine.render_json(tenant_id, month)

    if fmt == "pdf":
        try:
            pdf_bytes = engine.render_pdf(
                tenant_id, month, brand_name=brand_name, logo_url=logo_url
            )
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        filename = f"warden-report-{tenant_id}-{month}.pdf"
        from fastapi.responses import Response
        return Response(
            content    = pdf_bytes,
            media_type = "application/pdf",
            headers    = {"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    # Default: HTML — return as a downloadable attachment
    html_bytes = engine.render_html(
        tenant_id, month, brand_name=brand_name, logo_url=logo_url
    ).encode("utf-8")
    filename   = f"warden-report-{tenant_id}-{month}.html"
    from fastapi.responses import Response
    return Response(
        content     = html_bytes,
        media_type  = "text/html; charset=utf-8",
        headers     = {"Content-Disposition": f'attachment; filename="{filename}"'},
    )


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


# ── Threat Intelligence Feed endpoints ───────────────────────────────────────

@app.get(
    "/feed/status",
    tags=["threat-feed"],
    summary="Threat Intelligence Feed status for this instance",
)
async def feed_status(auth: AuthResult = Depends(require_api_key)) -> dict:
    """
    Returns opt-in status, last sync time, number of imported rules, and
    number of rules this instance has submitted to the central feed.
    """
    if _feed is None:
        raise HTTPException(503, "ThreatFeedClient not initialised.")
    s = _feed.status()
    return {
        "enabled":         s.enabled,
        "feed_url":        s.feed_url,
        "last_sync":       s.last_sync,
        "next_sync":       s.next_sync,
        "rules_imported":  s.rules_imported,
        "rules_submitted": s.rules_submitted,
        "errors":          s.errors,
    }


@app.post(
    "/feed/sync",
    tags=["threat-feed"],
    summary="Trigger an immediate threat feed sync (admin / debug)",
)
async def feed_sync_now(auth: AuthResult = Depends(require_api_key)) -> dict:
    """Force an immediate download and import of the latest feed rules."""
    if _feed is None:
        raise HTTPException(503, "ThreatFeedClient not initialised.")
    if not _feed.is_enabled():
        raise HTTPException(400, "Threat feed is disabled. Set THREAT_FEED_ENABLED=true.")
    loop = asyncio.get_running_loop()
    imported = await loop.run_in_executor(None, _feed.sync)
    return {"imported": imported}


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


@app.post(
    "/mask",
    response_model=MaskResponse,
    tags=["masking"],
    summary="Yellow Zone — replace PII entities with reversible tokens",
    status_code=status.HTTP_200_OK,
)
@_limiter.limit(_tenant_limit)
async def mask_text(
    payload: MaskRequest,
    request: Request,
    auth:    AuthResult = Depends(require_api_key),
) -> MaskResponse:
    """
    Scan the input text for PII entities (names, money amounts, dates,
    organisations, emails, phones, reference IDs) and replace each with a
    short reversible token such as [PERSON_1] or [MONEY_2].

    The returned ``session_id`` must be passed to ``POST /unmask`` to restore
    the original values in the LLM response.

    Supported entity types: PERSON, MONEY, DATE, ORG, EMAIL, PHONE, ID
    """
    engine = _get_masking_engine()
    loop   = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None, lambda: engine.mask(payload.text, payload.session_id)
    )

    entity_map: dict[str, int] = result.summary()
    entities = [
        MaskedEntityInfo(entity_type=k, token=f"[{k}_N]", count=v)
        for k, v in entity_map.items()
    ]

    return MaskResponse(
        masked       = result.masked,
        session_id   = result.session_id,
        entity_count = result.entity_count,
        entities     = entities,
    )


@app.post(
    "/unmask",
    response_model=UnmaskResponse,
    tags=["masking"],
    summary="Yellow Zone — restore original PII values in a masked text",
    status_code=status.HTTP_200_OK,
)
@_limiter.limit(_tenant_limit)
async def unmask_text(
    payload: UnmaskRequest,
    request: Request,
    auth:    AuthResult = Depends(require_api_key),
) -> UnmaskResponse:
    """
    Replace all [TYPE_N] tokens in the text with the original values from the
    vault session created by a previous call to ``POST /mask``.

    The session vault expires 2 hours after creation.
    """
    engine = _get_masking_engine()
    loop   = asyncio.get_running_loop()
    unmasked = await loop.run_in_executor(
        None, lambda: engine.unmask(payload.text, payload.session_id)
    )
    return UnmaskResponse(unmasked=unmasked, session_id=payload.session_id)


# ── Lemon Squeezy Billing ─────────────────────────────────────────────────────

class _CheckoutRequest(BaseModel):
    tenant_id:      str
    plan:           str            # "individual" | "pro" | "enterprise"
    success_url:    str
    cancel_url:     str
    customer_email: str | None = None


@app.get(
    "/subscription/status",
    tags=["subscription"],
    summary="Current subscription plan and quota for a tenant",
)
async def billing_status(tenant_id: str):
    from warden.lemon_billing import get_lemon_billing
    return get_lemon_billing().get_status(tenant_id)


@app.post(
    "/subscription/checkout",
    tags=["subscription"],
    summary="Create a Lemon Squeezy checkout session — returns hosted payment URL",
)
async def billing_checkout(body: _CheckoutRequest):
    from warden.lemon_billing import get_lemon_billing
    lb = get_lemon_billing()
    if not lb._enabled:
        raise HTTPException(503, "Lemon Squeezy billing not configured on this instance.")
    try:
        url = lb.create_checkout_session(
            body.tenant_id, body.plan,
            body.success_url, body.cancel_url,
            body.customer_email,
        )
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"checkout_url": url}


@app.get(
    "/subscription/portal",
    tags=["subscription"],
    summary="Return Lemon Squeezy customer portal URL for self-serve plan management",
)
async def billing_portal(tenant_id: str):
    from warden.lemon_billing import get_lemon_billing
    try:
        url = get_lemon_billing().get_portal_url(tenant_id)
    except RuntimeError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"portal_url": url}


@app.post(
    "/subscription/webhook",
    tags=["subscription"],
    summary="Lemon Squeezy webhook receiver — validates signature and updates subscription state",
    include_in_schema=False,
)
async def billing_webhook(request: Request):
    from warden.lemon_billing import get_lemon_billing
    lb         = get_lemon_billing()
    payload    = await request.body()
    sig_header = request.headers.get("X-Signature", "")
    try:
        etype = lb.handle_webhook(payload, sig_header)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"received": True, "event_type": etype}


# ── OWASP LLM Output Scanning ─────────────────────────────────────────────────
#
# POST /filter/output — scan AI-generated text *after* it returns from the model.
#
# Covers three OWASP LLM Top 10 categories:
#   LLM02 — Insecure Output Handling: XSS, HTML injection, Markdown link injection
#   LLM06 — Sensitive Information Disclosure: prompt leakage, system prompt echo
#   LLM08 — Excessive Agency: shell/SQL/SSRF/path-traversal in AI-generated content


@app.post(
    "/filter/output",
    response_model=OutputScanResponse,
    tags=["Filter"],
    summary="Scan AI output for OWASP LLM02 / LLM06 / LLM08 risks",
)
@_limiter.limit(_tenant_limit)
async def filter_output(
    request:   Request,
    payload:   OutputScanRequest,
    auth:      AuthResult = Depends(require_api_key),
) -> OutputScanResponse:
    """
    Scan AI-generated text **before it reaches the browser or downstream system**.

    Unlike ``POST /filter`` (which scans *input* prompts), this endpoint scans
    the AI model's *output* — catching content that is harmless as a prompt but
    dangerous once rendered.

    **OWASP LLM Top 10 coverage:**

    | Category | Risks detected |
    |----------|---------------|
    | LLM02 — Insecure Output Handling | XSS (`<script>`, `onerror=`, `javascript:`), HTML injection (`<iframe>`, `<object>`), Markdown link injection |
    | LLM06 — Sensitive Information Disclosure | System prompt leakage, CoT scratchpad echo, internal tool name disclosure |
    | LLM08 — Excessive Agency | Shell command injection, SQL injection, SSRF (internal IP / metadata endpoints), path traversal |

    **Response:**
    - `safe`: `true` when no risks detected.
    - `sanitized`: the output with dangerous patterns stripped/escaped — safe to render.
    - `findings`: list of detected risks with OWASP category labels.
    """
    t0 = time.perf_counter()

    sanitizer = _get_output_sanitizer()
    result    = sanitizer.scan(payload.output)

    elapsed_ms = (time.perf_counter() - t0) * 1000

    findings = [
        OutputFindingSchema(risk=f.risk.value, snippet=f.snippet, owasp=f.owasp)
        for f in result.findings
    ]

    if result.risky:
        log.warning(
            json.dumps({
                "event":           "output_risk_detected",
                "tenant_id":       payload.tenant_id,
                "risk_categories": result.risk_categories,
                "owasp":           result.owasp_categories,
                "finding_count":   len(result.findings),
            })
        )

    _out_flags = [str(f.risk) for f in result.findings]
    _out_explanation = _xai_explain(
        risk_level       = "high" if result.risky else "low",
        flags            = _out_flags,
        reason           = ", ".join(result.owasp_categories),
        owasp_categories = result.owasp_categories,
    )

    return OutputScanResponse(
        safe             = not result.risky,
        findings         = findings,
        sanitized        = result.sanitized,
        risk_categories  = result.risk_categories,
        owasp_categories = result.owasp_categories,
        processing_ms    = round(elapsed_ms, 2),
        explanation      = _out_explanation,
    )


# ── Webhook management endpoints ──────────────────────────────────────────────

@app.post(
    "/webhook",
    response_model=WebhookStatusResponse,
    tags=["webhooks"],
    summary="Register or update a webhook for the authenticated tenant",
    status_code=status.HTTP_200_OK,
)
@_limiter.limit("10/minute")
async def register_webhook(
    request: Request,
    payload: WebhookRegisterRequest,
    auth:    AuthResult = Depends(require_api_key),
) -> WebhookStatusResponse:
    """
    Register (or update) a webhook URL for your tenant.
    Shadow Warden will POST a signed JSON event to this URL whenever
    a request meets or exceeds ``min_risk`` (default: high).
    """
    if _webhook_store is None:
        raise HTTPException(503, "Webhook store not available.")
    tenant_id = auth.tenant_id if auth.tenant_id != "default" else "default"
    _webhook_store.register(
        tenant_id = tenant_id,
        url       = payload.url,
        secret    = payload.secret,
        min_risk  = payload.min_risk,
    )
    cfg = _webhook_store.get(tenant_id)
    return WebhookStatusResponse(
        tenant_id     = tenant_id,
        url           = cfg["url"],
        min_risk      = cfg["min_risk"],
        registered_at = cfg["created_at"],
        updated_at    = cfg["updated_at"],
    )


@app.get(
    "/webhook",
    response_model=WebhookStatusResponse,
    tags=["webhooks"],
    summary="Get the current webhook configuration for the authenticated tenant",
)
@_limiter.limit("30/minute")
async def get_webhook(
    request: Request,
    auth:    AuthResult = Depends(require_api_key),
) -> WebhookStatusResponse:
    if _webhook_store is None:
        raise HTTPException(503, "Webhook store not available.")
    tenant_id = auth.tenant_id if auth.tenant_id != "default" else "default"
    cfg = _webhook_store.get(tenant_id)
    if cfg is None:
        raise HTTPException(404, f"No webhook registered for tenant '{tenant_id}'.")
    return WebhookStatusResponse(
        tenant_id     = tenant_id,
        url           = cfg["url"],
        min_risk      = cfg["min_risk"],
        registered_at = cfg["created_at"],
        updated_at    = cfg["updated_at"],
    )


@app.delete(
    "/webhook",
    tags=["webhooks"],
    summary="Deregister the webhook for the authenticated tenant",
    status_code=status.HTTP_200_OK,
)
@_limiter.limit("10/minute")
async def delete_webhook(
    request: Request,
    auth:    AuthResult = Depends(require_api_key),
) -> dict:
    if _webhook_store is None:
        raise HTTPException(503, "Webhook store not available.")
    tenant_id = auth.tenant_id if auth.tenant_id != "default" else "default"
    deleted = _webhook_store.deregister(tenant_id)
    if not deleted:
        raise HTTPException(404, f"No webhook registered for tenant '{tenant_id}'.")
    return {"status": "deleted", "tenant_id": tenant_id}


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


def _saml_request_data(request: Request, form_data: dict | None = None) -> dict:
    """Build the python3-saml request_data dict from a FastAPI Request."""
    https = request.headers.get("x-forwarded-proto", "http") == "https"
    return {
        "https":       "on" if https else "off",
        "http_host":   request.headers.get("host", "localhost"),
        "script_name": request.url.path,
        "server_port": str(request.url.port or (443 if https else 80)),
        "get_data":    dict(request.query_params),
        "post_data":   form_data or {},
    }


@app.get(
    "/auth/saml/metadata",
    tags=["SSO"],
    summary="SAML 2.0 SP Metadata XML",
    response_class=JSONResponse,
    include_in_schema=True,
)
async def saml_metadata(request: Request):
    """
    Return the Service Provider metadata XML.

    Paste this URL (or the downloaded XML) into your IdP (Okta / Entra ID)
    to configure the integration automatically.
    """
    provider: SAMLProvider | None = getattr(app.state, "saml", None)
    if provider is None:
        raise HTTPException(503, "SAML SSO is not configured on this instance.")
    xml, errors = provider.get_metadata_xml()
    if errors:
        raise HTTPException(500, f"SAML metadata errors: {errors}")
    from fastapi.responses import Response  # noqa: PLC0415
    return Response(content=xml, media_type="application/xml")


@app.get(
    "/auth/saml/login",
    tags=["SSO"],
    summary="Initiate SAML 2.0 login (redirect to IdP)",
    include_in_schema=True,
)
async def saml_login(request: Request, relay_state: str = ""):
    """
    Start the SAML login flow.

    Redirects the browser to the IdP (Okta / Entra ID) login page.
    After authentication, the IdP will POST the SAMLResponse back to
    ``/auth/saml/acs``.
    """
    from fastapi.responses import RedirectResponse  # noqa: PLC0415
    provider: SAMLProvider | None = getattr(app.state, "saml", None)
    if provider is None:
        raise HTTPException(503, "SAML SSO is not configured on this instance.")
    rd = _saml_request_data(request)
    try:
        login_url = provider.build_login_url(rd, relay_state=relay_state)
    except Exception as exc:
        log.error("SAML login URL build failed: %s", exc)
        raise HTTPException(500, "Failed to build SAML login request.") from exc
    return RedirectResponse(url=login_url, status_code=302)


@app.post(
    "/auth/saml/acs",
    tags=["SSO"],
    summary="SAML 2.0 Assertion Consumer Service (ACS)",
    include_in_schema=True,
)
async def saml_acs(request: Request):
    """
    Assertion Consumer Service — the IdP POSTs the signed SAMLResponse here.

    On success:
      1. Validates the X.509 signature.
      2. Extracts email + groups from the assertion.
      3. Issues a one-time token (30 s TTL) stored in Redis.
      4. Redirects the browser to the Streamlit dashboard with ``?token=<otp>``.

    The dashboard exchanges the OTP for a JWT via ``GET /auth/saml/session``.
    """
    from fastapi.responses import RedirectResponse  # noqa: PLC0415
    provider: SAMLProvider | None = getattr(app.state, "saml", None)
    if provider is None:
        raise HTTPException(503, "SAML SSO is not configured on this instance.")

    form = await request.form()
    form_data = dict(form.items())
    rd = _saml_request_data(request, form_data=form_data)

    try:
        session: SamlSession = provider.process_response(rd)
    except ValueError as exc:
        log.warning("SAML ACS rejected: %s", exc)
        raise HTTPException(401, str(exc)) from exc
    except Exception as exc:
        log.error("SAML ACS error: %s", exc)
        raise HTTPException(500, "SAML processing error.") from exc

    try:
        otp = provider.store_otp(session)
    except Exception as exc:
        log.error("SAML OTP store failed: %s", exc)
        raise HTTPException(500, "Failed to create login session.") from exc

    dashboard_url = os.getenv("DASHBOARD_URL", "http://localhost:8501")
    redirect_url  = f"{dashboard_url}?token={otp}"
    log.info("SAML ACS: login accepted for %s → redirecting to dashboard", session.email)
    return RedirectResponse(url=redirect_url, status_code=302)


@app.get(
    "/auth/saml/session",
    tags=["SSO"],
    summary="Exchange SAML one-time token for a session JWT",
)
async def saml_session(token: str):
    """
    Exchange the one-time token (from the ``?token=`` dashboard query param)
    for a signed JWT.

    The JWT encodes: ``sub`` (email), ``name``, ``grp`` (groups),
    ``tid`` (tenant_id), ``exp``, ``iat``.

    The dashboard stores this JWT in ``st.session_state`` and includes it
    as ``Authorization: Bearer <jwt>`` on privileged API calls.
    """
    provider: SAMLProvider | None = getattr(app.state, "saml", None)
    if provider is None:
        raise HTTPException(503, "SAML SSO is not configured on this instance.")

    session = provider.redeem_otp(token)
    if session is None:
        raise HTTPException(401, "Invalid or expired login token. Please log in again.")

    try:
        jwt_token = provider.issue_jwt(session)
    except RuntimeError as exc:
        raise HTTPException(500, str(exc)) from exc

    return {
        "access_token": jwt_token,
        "token_type":   "bearer",
        "expires_in":   int(os.getenv("SAML_SESSION_TTL", "28800")),
        "email":        session.email,
        "name":         session.name,
        "tenant_id":    session.tenant_id,
    }


@app.get(
    "/auth/saml/verify",
    tags=["SSO"],
    summary="Verify a session JWT (for dashboard middleware use)",
)
async def saml_verify(request: Request):
    """
    Verify the Bearer JWT supplied in the Authorization header.
    Returns the decoded payload on success.  Used by the dashboard
    to validate an existing session without involving the IdP.
    """
    provider: SAMLProvider | None = getattr(app.state, "saml", None)
    if provider is None:
        raise HTTPException(503, "SAML SSO is not configured on this instance.")

    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(401, "Missing or malformed Authorization header.")

    token   = auth_header[len("Bearer "):]
    payload = provider.verify_jwt(token)
    if payload is None:
        raise HTTPException(401, "Invalid or expired JWT.")

    return payload


# ── Contact form ─────────────────────────────────────────────────────────────

class _ContactRequest(BaseModel):
    name:    str
    email:   str
    subject: str
    message: str
    company: str = ""


@app.post("/api/contact", tags=["Public"])
async def contact(body: _ContactRequest):
    """Send a contact-form message to the configured SMTP address."""
    import smtplib
    from email.mime.text import MIMEText

    smtp_host = os.getenv("SMTP_HOST", "")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASS", "")
    to_email  = os.getenv("CONTACT_TO_EMAIL", "vz@shadow-warden-ai.com")

    text_parts = [
        f"Name:    {body.name}",
        f"Email:   {body.email}",
        f"Company: {body.company}" if body.company else "",
        f"Topic:   {body.subject}",
        "",
        body.message,
    ]
    text = "\n".join(p for p in text_parts if p is not None)

    if not smtp_host or not smtp_user:
        log.warning("contact form: SMTP not configured — logging message only")
        log.info("contact_form_submission name=%s email=%s subject=%s", body.name, body.email, body.subject)
        return {"ok": True}

    try:
        msg = MIMEText(text, "plain", "utf-8")
        msg["Subject"] = f"[Shadow Warden] {body.subject}"
        msg["From"]    = smtp_user
        msg["To"]      = to_email
        msg["Reply-To"] = body.email

        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as srv:
            srv.starttls()
            srv.login(smtp_user, smtp_pass)
            srv.sendmail(smtp_user, [to_email], msg.as_string())

        log.info("contact form sent: from=%s subject=%s", body.email, body.subject)
        return {"ok": True}
    except Exception as exc:
        log.error("contact form send failed: %s", exc)
        raise HTTPException(500, "Failed to send message. Please email vz@shadow-warden-ai.com directly.") from exc


# ── Global error handler ──────────────────────────────────────────────────────

@app.exception_handler(Exception)
async def unhandled_exception(request: Request, exc: Exception):
    rid = getattr(request.state, "request_id", "-")
    log.exception(json.dumps({"event": "unhandled_error", "request_id": rid, "error": str(exc)}))
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal warden error.", "request_id": rid},
    )
