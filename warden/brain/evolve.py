"""
warden/brain/evolve.py
━━━━━━━━━━━━━━━━━━━━━
The Evolution Loop — automated defense update engine.

When the Warden blocks a HIGH or BLOCK risk attack, EvolutionEngine:
  1. Sends the (already-redacted) attack to Claude Opus for analysis
  2. Receives a structured explanation + new detection rule
  3. Appends the rule to dynamic_rules.json  (atomic write)
  4. Hot-reloads the SemanticGuard corpus with new semantic examples

This creates a self-improving feedback loop:
  attack blocked → Claude analyses → new rule written → corpus updated
  → future paraphrased variants caught without a code deploy.

Claude API usage
────────────────
  Model    : claude-opus-4-6         (deepest reasoning for novel attacks)
  Thinking : adaptive                (Claude decides how much to reason)
  Output   : structured JSON via Pydantic + output_config.format
  Transport: streaming + get_final_message()  (avoids HTTP timeouts)
  Client   : AsyncAnthropic          (non-blocking; runs as BackgroundTask)
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import json
import logging
import os
import re
import tempfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import anthropic
from pydantic import BaseModel, Field

from warden.cache import _get_client as _get_redis
from warden.config import settings
from warden.metrics import (
    EVOLUTION_FAILED_TOTAL,
    EVOLUTION_SKIPPED_TOTAL,
    NEMOTRON_EVOLUTION_TOTAL,
)
from warden.schemas import RiskLevel, SemanticFlag
from warden.telemetry import trace_stage as _trace_stage

log = logging.getLogger("warden.brain.evolve")

# ── GDPR: anonymize unique identifiers before sending to Claude ───────────────
# Strip UUIDs, IPv4/IPv6 addresses, emails, long hex strings, and ISO timestamps
# so that no unique data-subject identifiers leave the perimeter via the
# Evolution Engine prompt — even if SecretRedactor missed them.
_ANON_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # UUID v1-v5
    (re.compile(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        re.IGNORECASE,
    ), "[UUID]"),
    # IPv4
    (re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    ), "[IPv4]"),
    # IPv6 (simplified — catches most forms)
    (re.compile(
        r"\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b",
        re.IGNORECASE,
    ), "[IPv6]"),
    # Email addresses
    (re.compile(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    ), "[EMAIL]"),
    # ISO 8601 timestamps (2025-03-23T12:34:56)
    (re.compile(
        r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b",
    ), "[TIMESTAMP]"),
    # UUID without dashes — compact form (32 hex chars, e.g. Django session keys)
    (re.compile(
        r"\b[0-9a-f]{32}\b",
        re.IGNORECASE,
    ), "[UUID]"),
    # Long hex strings ≥ 16 chars (tokens, hashes, session IDs)
    (re.compile(
        r"\b[0-9a-f]{16,}\b",
        re.IGNORECASE,
    ), "[HEX]"),
]


def _anonymize_for_evolution(text: str) -> str:
    """Scrub unique identifiers from content before sending to Claude Opus.

    GDPR safeguard: the evolution prompt must never carry data-subject
    identifiers (IPs, UUIDs, emails, timestamps) to the external API.
    SecretRedactor handles credentials; this layer handles structural UIDs.
    """
    for pattern, replacement in _ANON_PATTERNS:
        text = pattern.sub(replacement, text)
    return text

# ── Config ────────────────────────────────────────────────────────────────────

EVOLUTION_MODEL    = "claude-opus-4-6"

# System prompt used in _call_claude — extracted here so dataset.py can embed
# the exact same instruction context in every collected sample.
EVOLUTION_SYSTEM_PROMPT = (
    "You are an expert red-team AI security analyst for the Shadow Warden "
    "AI gateway. Your role is to analyse blocked attack attempts and generate "
    "precise, minimal detection rules that will catch future semantic variants "
    "without triggering false positives on legitimate traffic.\n\n"
    "Rules:\n"
    "• For 'semantic_example': write a single canonical sentence representing "
    "  the attack's *intent*, not its exact wording.\n"
    "• For 'regex_pattern': write a Python-compatible regex that is specific "
    "  enough to avoid false positives.\n"
    "• Evasion variants must be meaningfully rephrased — not trivial word swaps.\n"
    "• Never reproduce real credentials, PII, or working exploit code.\n"
    "• Respond only with the JSON object — no preamble or commentary."
)
EVOLUTION_MIN_RISK = RiskLevel.HIGH     # evolve only on HIGH or BLOCK

# PhishGuard v3 — specialised system prompt for SE / phishing attack evolution.
# Used instead of EVOLUTION_SYSTEM_PROMPT when the blocked content carries
# PHISHING_URL or SOCIAL_ENGINEERING flags from PhishGuard.
SE_EVOLUTION_SYSTEM_PROMPT = (
    "You are an expert social engineering and phishing analyst embedded in the "
    "Shadow Warden AI gateway. Your role is to analyse blocked phishing or "
    "social engineering (SE) attempts and generate precise detection signatures "
    "that will catch future semantic variants without false-positiving on "
    "legitimate content.\n\n"
    "Social Engineering Taxonomy (MITRE ATT&CK for Enterprise — Initial Access):\n"
    "• Phishing               — credential harvesting via spoofed URLs / fake login portals\n"
    "• Spear Phishing         — targeted impersonation of a known authority figure\n"
    "• CEO / BEC Fraud        — executive wire-transfer or credential request\n"
    "• IT Helpdesk Spoofing   — fake IT support urgency (account suspended, MFA reset)\n"
    "• Prize / Refund Lure    — greed-trigger with fabricated eligibility claim\n"
    "• Fear / Compliance Hook — legal action or account termination threat\n\n"
    "Rules:\n"
    "• Identify the *SE tactic* used (one of the taxonomy labels above).\n"
    "• For 'semantic_example': write one canonical sentence capturing the *manipulation "
    "  intent* — not the exact wording. Include the psychological trigger (urgency / "
    "  authority / fear / greed).\n"
    "• For 'regex_pattern': target the *structural pattern* of manipulation language "
    "  (e.g. urgency + authority combo), not just keyword matching.\n"
    "• Evasion variants must cover language, authority figure, and urgency frame "
    "  variations — not just synonym swaps.\n"
    "• Never reproduce real domain names, credentials, PII, or working phishing URLs.\n"
    "• Respond only with the JSON object — no preamble or commentary."
)

# Flag types that route to the SE-specialised prompt
_SE_FLAG_TYPES: frozenset[str] = frozenset({
    "phishing_url", "social_engineering",
})

DYNAMIC_RULES_PATH = Path(settings.dynamic_rules_path)

# Corpus poisoning protection
MAX_CORPUS_RULES       = settings.max_corpus_rules
MAX_EVASION_VARIANTS   = 5   # cap evasion variants per rule
MAX_EXAMPLE_LENGTH     = 500  # max chars per semantic example
_SEEN_HASHES_CAP       = 10_000  # cap in-process dedup set

# Evolution rate gate — prevent Claude Opus API cost exhaustion under flood attacks.
# A fixed-window counter in Redis caps how many novel attacks trigger the LLM per window.
# Fail-open: when Redis is unavailable the gate is bypassed so evolution still works.
EVOLUTION_RATE_WINDOW  = settings.evolution_rate_window  # seconds
EVOLUTION_RATE_MAX     = settings.evolution_rate_max     # calls per window
_RATE_KEY              = "warden:evolution:calls"

_RISK_ORDER = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.BLOCK]

# Cost centre for evolution spend. The engine is a platform-wide service — it
# learns from one tenant's blocked attack and protects every tenant — so its
# cost is charged to a shared account rather than to whoever happened to trigger
# it. Until FM-7 it was charged to nobody at all: Opus calls on the /filter hot
# path with no cost record anywhere.
_EVOLUTION_COST_TENANT = "system:evolution"

# Hard ceiling on evolution spend per UTC day. The rate gate above caps calls per
# *window* (10 / 5 min), which sustained is ~2 900 Opus calls a day — a four-digit
# monthly bill from a single sustained attack campaign, on a code path with no
# revenue attached to it. This converts that open-ended exposure into a number.
# 0 disables the ceiling.
EVOLUTION_DAILY_BUDGET_USD = float(os.getenv("EVOLUTION_DAILY_BUDGET_USD", "5.0"))


# Cached spend reading. (value, expires_at_monotonic)
_BUDGET_CACHE: tuple[float, float] = (0.0, 0.0)
_BUDGET_CACHE_TTL_S = 60.0


def _read_daily_spend() -> float:
    """Blocking read of today's evolution spend. Never call this from the loop.

    Every statement here is a remote round-trip. `staff` is a Turso-backed
    logical DB in production, so `_conn()` alone costs one round-trip for
    `_ensure_columns` before the SUM even runs. Measured in the production
    container:

        _ensure_columns   521.2 ms      (one statement)
        SELECT 1          540.9 ms      (pure latency, not query cost)
        SUM(cost_usd)     421.7 ms
        get_cost_since   1778-1942 ms   end to end

    The result is currently always 0.0 — `staff_action_costs` holds 0 rows,
    because evolution spend is not recorded there (the FM-7 finding). So this
    was ~1.8s of blocked event loop to read a constant.
    """
    from datetime import UTC, datetime

    from warden.staff.economics import get_tracker
    midnight = int(
        datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
    )
    return float(get_tracker().get_cost_since(_EVOLUTION_COST_TENANT, midnight))


async def _is_over_daily_budget_async() -> bool:
    """Same gate, off the event loop and cached.

    Two changes, both needed:

    * `asyncio.to_thread` — the read is a synchronous network call. It was being
      made from `process_blocked`, which is a coroutine, so it pinned the whole
      event loop for ~1.8s. Traced on production: `spawn.process_blocked` ran
      1972ms while `evo.llm_call` inside it took 133ms, and *no span from any
      request* started during the first 1.84s of it. Detaching the call in #389
      could not help, because a detached task still runs on the loop.

    * A 60s TTL — a daily spend ceiling does not need per-request freshness, and
      without the cache every blocked request would still pay 1.8s, merely in a
      worker thread instead. Under a burst that exhausts the thread pool and the
      stall returns by another route. 60s bounds the overshoot to at most one
      window's spend, which for a $5/day ceiling is not a meaningful overrun.

    Fail-open is unchanged: an unreadable cost store allows the call. Detection
    quality must not depend on the FinOps database being up.
    """
    if EVOLUTION_DAILY_BUDGET_USD <= 0:
        return False
    global _BUDGET_CACHE
    spent, expires = _BUDGET_CACHE
    now = time.monotonic()
    if now < expires:
        return spent >= EVOLUTION_DAILY_BUDGET_USD
    try:
        spent = await asyncio.to_thread(_read_daily_spend)
        _BUDGET_CACHE = (spent, now + _BUDGET_CACHE_TTL_S)
        return spent >= EVOLUTION_DAILY_BUDGET_USD
    except Exception as exc:
        from warden.observability import Reason, record_failopen
        record_failopen("evolution_budget", Reason.BACKEND_ERROR, exc)
        return False


def _is_over_daily_budget() -> bool:
    """
    True when today's evolution spend has hit EVOLUTION_DAILY_BUDGET_USD.

    Synchronous variant, kept for non-async callers. On the request path use
    ``_is_over_daily_budget_async`` — this one blocks for ~1.8s in production.

    Fail-open: an unreadable cost store returns False (allow). Detection quality
    must not depend on the FinOps database being up — the ceiling is a cost
    guard, not a security control.
    """
    if EVOLUTION_DAILY_BUDGET_USD <= 0:
        return False
    try:
        from datetime import UTC, datetime

        from warden.staff.economics import get_tracker
        midnight = int(
            datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
        )
        spent = get_tracker().get_cost_since(_EVOLUTION_COST_TENANT, midnight)
        return spent >= EVOLUTION_DAILY_BUDGET_USD
    except Exception as exc:
        from warden.observability import Reason, record_failopen
        record_failopen("evolution_budget", Reason.BACKEND_ERROR, exc)
        return False


def _record_cost(model: str, usage: object) -> None:
    """Attribute one evolution LLM call to the platform cost centre (fail-open)."""
    try:
        from warden.staff.economics import get_tracker
        get_tracker().record(
            _EVOLUTION_COST_TENANT,
            "evolution",
            "process_blocked",
            model,
            int(getattr(usage, "input_tokens", 0) or 0),
            int(getattr(usage, "output_tokens", 0) or 0),
            int(getattr(usage, "cache_read_input_tokens", 0) or 0),
        )
    except Exception as exc:
        from warden.observability import Reason, record_failopen
        record_failopen("evolution_cost", Reason.BACKEND_ERROR, exc)


def _tenant_share_max() -> int:
    """
    Max evolution calls one tenant may take from a single rate window.

    Without this, the global cap is first-come-first-served: one free-tier
    attacker generating novel blocked prompts consumes the whole window and
    paying tenants get no new rules from their own traffic. The share is a
    fraction of the global cap, floored at one so a tenant is never shut out.
    """
    rate_max = int(os.getenv("EVOLUTION_RATE_MAX", str(EVOLUTION_RATE_MAX)))
    share = float(os.getenv("EVOLUTION_TENANT_SHARE", "0.5"))
    return max(1, int(rate_max * max(0.0, min(1.0, share))))


def _is_tenant_share_exceeded(tenant_id: str) -> bool:
    """
    True when *tenant_id* has already used its slice of the current window.

    Same fixed-window counter as the global gate, keyed per tenant with the
    same TTL, so the two reset together. Without Redis there is no fairness
    gate — availability of the detection loop outranks fairness between
    tenants — and each such bypass is counted.
    """
    if not tenant_id:
        return False
    r = _get_redis()
    if r is None:
        return False
    rate_window = int(os.getenv("EVOLUTION_RATE_WINDOW", str(EVOLUTION_RATE_WINDOW)))
    key = f"{_RATE_KEY}:tenant:{tenant_id}"
    try:
        count = r.incr(key)
        if count == 1:
            r.expire(key, rate_window)
        return int(count) > _tenant_share_max()
    except Exception as exc:
        from warden.observability import Reason, record_failopen
        record_failopen("evolution_tenant_share", Reason.REDIS_UNAVAILABLE, exc)
        return False


def _is_rate_limited() -> bool:
    """Return True when the EvolutionEngine is over its Claude Opus API budget.

    Strategy: fixed-window counter stored in Redis.
      • Key  ``warden:evolution:calls``  shared across all processes/workers.
      • TTL  ``EVOLUTION_RATE_WINDOW`` seconds — the key auto-expires, resetting
             the window with no cron job or scheduled cleanup needed.
      • Cap  ``EVOLUTION_RATE_MAX`` calls per window (default 10 / 5 min).

    ``INCR`` is called on every entry so the attempt is counted even when
    rate-limited; this prevents a thundering herd from evading the cap via
    parallel workers each staying just below the threshold.

    Fail-open: returns False (allow) when Redis is unavailable or raises,
    preserving the evolution loop in air-gapped / test environments.
    """
    r = _get_redis()
    if r is None:
        return False
    # Read dynamically so tests can override EVOLUTION_RATE_MAX via env var
    rate_max = int(os.getenv("EVOLUTION_RATE_MAX", "10"))
    rate_window = int(os.getenv("EVOLUTION_RATE_WINDOW", str(EVOLUTION_RATE_WINDOW)))
    try:
        count = r.incr(_RATE_KEY)
        if count == 1:
            # First call in this window — arm the TTL so the window auto-resets.
            r.expire(_RATE_KEY, rate_window)
        return int(count) > rate_max
    except Exception:  # noqa: BLE001
        return False


# ── Pydantic schema — what Claude must return ─────────────────────────────────

def _strict_json_schema(schema: dict) -> dict:
    """Set ``additionalProperties: false`` on every object in a JSON schema.

    The Anthropic API rejects a structured-output schema without it::

        400 invalid_request_error — output_config.format.schema:
        For 'object' type, 'additionalProperties' must be explicitly set to false

    Pydantic does not emit the key unless a model declares ``extra="forbid"``,
    so `EvolutionResponse.model_json_schema()` produced a schema the API would
    not accept — at the top level and inside ``$defs``. Every Evolution call
    therefore failed with a 400 and the engine has never produced a rule.

    Done recursively rather than on the two known objects, because the failure
    is silent from the caller's side: a nested model added later would
    reintroduce it, and the only symptom is a counter going up.
    """
    if not isinstance(schema, dict):
        return schema
    out = dict(schema)
    if out.get("type") == "object":
        out["additionalProperties"] = False
    for key in ("properties", "$defs", "definitions", "patternProperties"):
        if isinstance(out.get(key), dict):
            out[key] = {k: _strict_json_schema(v) for k, v in out[key].items()}
    for key in ("items", "additionalItems", "not"):
        if isinstance(out.get(key), dict):
            out[key] = _strict_json_schema(out[key])
    for key in ("anyOf", "oneOf", "allOf", "prefixItems"):
        if isinstance(out.get(key), list):
            out[key] = [_strict_json_schema(v) for v in out[key]]
    return out


class NewRule(BaseModel):
    rule_type:   Literal["semantic_example", "regex_pattern"] = Field(
        ..., description=(
            "'semantic_example' for a canonical sentence the MiniLM model will embed; "
            "'regex_pattern' for a Python-compatible regex string."
        )
    )
    value:       str = Field(
        ..., description="The exact pattern or example sentence."
    )
    description: str = Field(
        ..., description="One sentence describing what this rule catches."
    )


class EvolutionResponse(BaseModel):
    attack_type:      str = Field(
        ..., description="Short snake_case category, e.g. 'prompt_injection'."
    )
    explanation:      str = Field(
        ..., description="How the attack works — 2–4 sentences, technical."
    )
    evasion_variants: list[str] = Field(
        ..., description=(
            "3–5 meaningfully different paraphrases of the attack that "
            "should also be blocked."
        )
    )
    new_rule:  NewRule
    severity:  Literal["medium", "high", "block"]


# ── Persisted rule record (written to dynamic_rules.json) ─────────────────────

class RuleRecord(BaseModel):
    id:               str
    created_at:       str
    source_hash:      str   # SHA-256 of the original blocked content (not stored)
    attack_type:      str
    explanation:      str
    evasion_variants: list[str]
    new_rule:         NewRule
    severity:         str
    times_triggered:  int = 0


# ── Caller-facing result ───────────────────────────────────────────────────────

class EvolutionResult(BaseModel):
    rule:           RuleRecord
    corpus_updated: bool    # True when SemanticGuard was hot-reloaded


# ── EvolutionEngine ───────────────────────────────────────────────────────────

class EvolutionEngine:
    """
    Self-improving defense loop powered by Claude Opus.

    Usage (warden/main.py — FastAPI BackgroundTasks)::

        engine = EvolutionEngine(semantic_guard=_guard)

        # Inside the /filter endpoint, after a block decision:
        if not filter_response.allowed:
            background_tasks.add_task(
                engine.process_blocked,
                content    = payload.content,
                flags      = guard_result.flags,
                risk_level = guard_result.risk_level,
            )
    """

    #: Which backend this engine talks to. Used as the `engine` label on the
    #: evolution counters, so "which engine is live" and "is it producing
    #: anything" can be answered from the same metric. Subclasses override it.
    ENGINE_LABEL = "claude"

    #: Consecutive failed LLM calls before auto mode gives up on the backend.
    #: One transient 503 must not switch engines; a backend that cannot answer
    #: three attacks in a row is not serving this system.
    DEMOTE_AFTER_FAILURES = 3


    def __init__(
        self,
        semantic_guard=None,
        ledger=None,
        review_queue=None,
        feed_client=None,
    ) -> None:
        """
        Parameters
        ----------
        semantic_guard : SemanticGuard | None
            When provided, new semantic examples are injected into the
            live corpus immediately — no restart required (auto mode only).
        ledger : RuleLedger | None
            When provided, each generated rule is written to the ledger
            with status='pending_review' for lifecycle tracking.
        review_queue : ReviewQueue | None
            Activation gate.  In auto mode (default) rules are hot-loaded
            immediately; in manual mode they stay pending_review until an
            operator calls POST /admin/rules/{rule_id}/approve.
        feed_client : ThreatFeedClient | None
            When provided and THREAT_FEED_ENABLED=true, each activated rule
            is anonymised and submitted to the central threat intelligence feed.
        """
        self._client        = anthropic.AsyncAnthropic()
        self._seen_hashes:  set[str] = set()   # in-process dedup
        self._guard         = semantic_guard
        self._ledger        = ledger
        self._review_queue  = review_queue
        self._feed_client   = feed_client
        self._rules_path    = Path(os.getenv("DYNAMIC_RULES_PATH", str(DYNAMIC_RULES_PATH)))
        self._rules_path.parent.mkdir(parents=True, exist_ok=True)
        self._corpus_count  = self._count_existing_rules()

        # ── auto-mode backend health ─────────────────────────────────────
        # Set by build_evolution_engine() ONLY when EVOLUTION_ENGINE=auto.
        # An explicit EVOLUTION_ENGINE=nemotron|claude leaves this None, so a
        # deliberate choice of backend is never silently overridden.
        self._auto_fallback: EvolutionEngine | None = None
        self._demoted_to:    str | None             = None
        self._consecutive_failures: int             = 0

    @property
    def active_engine(self) -> str:
        """The backend actually serving calls — not the one selected at boot.

        After an auto-mode demotion these differ, and every counter label has
        to follow the work rather than the original choice. Attributing a
        Claude-generated rule to `engine="nemotron"` would be a fresh version
        of the defect this whole mechanism exists to close.
        """
        return self._demoted_to or self.ENGINE_LABEL

    # ── Public hot-reload helper ──────────────────────────────────────────────

    def add_examples(self, examples: list) -> None:
        """Inject new examples into the live brain corpus.

        Accepts ``list[str]`` or ``list[dict]`` (with a ``"text"`` key).
        Falls back to the global ``_brain_guard`` singleton when this engine
        was instantiated without an explicit ``semantic_guard``.
        """
        guard = self._guard
        if guard is None:
            from warden.runtime import runtime as _rt  # noqa: PLC0415
            guard = _rt.brain_guard
        if guard is None:
            return
        texts: list[str] = []
        for ex in examples:
            if isinstance(ex, str):
                texts.append(ex)
            elif isinstance(ex, dict):
                t = str(ex.get("text", ex.get("value", "")))
                if t:
                    texts.append(t)
        if texts:
            guard.add_examples(texts)

    def inject_rule(
        self,
        rule_text: str,
        source:    str = "marketplace",
        metadata:  dict | None = None,
    ) -> tuple[bool, str]:
        """
        Inject an externally-provided rule directly into the corpus.

        Supported rule types (from metadata["rule_type"]):
          "semantic_example" (default) — embedded via add_examples()
          "regex_pattern"              — ReDoS gate applied first

        Returns (True, rule_id) on success, (False, reason) on rejection.
        """
        meta         = metadata or {}
        rule_type    = meta.get("rule_type", "semantic_example")
        content_hash = hashlib.sha256(rule_text.encode()).hexdigest()

        if content_hash in self._seen_hashes:
            return False, "duplicate: already in corpus"

        if rule_type == "regex_pattern":
            ok, reason = self._validate_regex_safety(rule_text)
            if not ok:
                return False, f"ReDoS gate rejected: {reason}"

        rule_id = str(uuid.uuid4())
        record  = RuleRecord(
            id=rule_id,
            created_at=datetime.now(UTC).isoformat(),
            source_hash=content_hash,
            attack_type=str(meta.get("attack_type", source))[:120],
            explanation=str(meta.get("explanation", f"Injected from {source}"))[:500],
            evasion_variants=list(meta.get("evasion_variants", [])),
            new_rule=NewRule(
                rule_type=rule_type,
                value=rule_text,
                description=str(meta.get("description", f"Rule injected from {source}"))[:200],
            ),
            severity=str(meta.get("severity", "medium")),
        )
        self._seen_hashes.add(content_hash)
        self._persist(record)

        if rule_type == "semantic_example":
            self.add_examples([rule_text])

        log.info(
            "EvolutionEngine.inject_rule: rule_id=%s source=%s type=%s",
            rule_id, source, rule_type,
        )
        return True, rule_id

    # ── Corpus protection ────────────────────────────────────────────────────

    def _count_existing_rules(self) -> int:
        """Count rules and restore seen_hashes from dynamic_rules.json (survive restarts)."""
        if self._rules_path.exists():
            try:
                data = json.loads(self._rules_path.read_text())
                # Restore persisted content hashes so we don't re-evolve on restart
                for h in data.get("seen_hashes", []):
                    self._seen_hashes.add(h)
                return len(data.get("rules", []))
            except Exception:
                pass
        return 0

    def _is_duplicate(self, content: str) -> bool:
        """Return True if this exact content was already processed this session."""
        return hashlib.sha256(content.encode()).hexdigest() in self._seen_hashes

    @staticmethod
    def _vet_example(text: str) -> str | None:
        """Sanitise a semantic example.  Returns None if it should be rejected."""
        text = text.strip()
        if not text or len(text) < 10:
            return None
        if len(text) > MAX_EXAMPLE_LENGTH:
            text = text[:MAX_EXAMPLE_LENGTH]
        # Reject if it looks like it contains real secrets
        suspicious = ("sk-", "AKIA", "ghp_", "-----BEGIN", "bearer ")
        if any(s in text for s in suspicious):
            return None
        return text

    async def process_blocked(
        self,
        content:    str,
        flags:      list[SemanticFlag],
        risk_level: RiskLevel,
        tenant_id:  str = "",
    ) -> EvolutionResult | None:
        """
        Analyse a blocked attack and generate a new detection rule.

        Returns None when:
          • risk_level is below EVOLUTION_MIN_RISK  (LOW / MEDIUM)
          • corpus cap (MAX_CORPUS_RULES) is reached
          • this exact content was already processed (dedup by SHA-256)
          • the call-rate cap (EVOLUTION_RATE_MAX / EVOLUTION_RATE_WINDOW) is exceeded
          • this tenant has used its share of the window (EVOLUTION_TENANT_SHARE)
          • today's spend has reached EVOLUTION_DAILY_BUDGET_USD
          • the Claude API call fails               (error logged, not raised)
        """
        # ── 1. Risk gate ────────────────────────────────────────────────
        if _RISK_ORDER.index(risk_level) < _RISK_ORDER.index(EVOLUTION_MIN_RISK):
            EVOLUTION_SKIPPED_TOTAL.labels(reason="low_risk").inc()
            return None

        # ── 2. Corpus growth cap ────────────────────────────────────────
        if self._corpus_count >= MAX_CORPUS_RULES:
            EVOLUTION_SKIPPED_TOTAL.labels(reason="corpus_cap").inc()
            log.warning(
                "EvolutionEngine: corpus cap reached (%d/%d) — skipping evolution.",
                self._corpus_count, MAX_CORPUS_RULES,
            )
            return None

        # ── 3. Content dedup ────────────────────────────────────────────
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        if content_hash in self._seen_hashes:
            EVOLUTION_SKIPPED_TOTAL.labels(reason="duplicate").inc()
            log.debug("EvolutionEngine: duplicate — skipping %s…", content_hash[:12])
            return None

        # ── 4. Rate gate — protect Claude Opus API budget ───────────────
        # Checked AFTER dedup so replay attacks don't consume rate slots.
        # Checked BEFORE adding to seen_hashes so rate-limited content is
        # retried next window (it won't be marked as seen until it's processed).
        if _is_rate_limited():
            EVOLUTION_SKIPPED_TOTAL.labels(reason="rate_limited").inc()
            log.warning(
                "EvolutionEngine: rate limit reached (%d calls per %ds window) — skipping.",
                EVOLUTION_RATE_MAX, EVOLUTION_RATE_WINDOW,
            )
            return None

        # ── 4a. Per-tenant fairness share ───────────────────────────────
        # Checked after the global gate so a quiet system still lets any single
        # tenant through, and before the LLM call so an unfair request costs
        # nothing.
        if _is_tenant_share_exceeded(tenant_id):
            EVOLUTION_SKIPPED_TOTAL.labels(reason="tenant_share").inc()
            log.info(
                "EvolutionEngine: tenant %s over its window share (%d) — skipping.",
                tenant_id[:12], _tenant_share_max(),
            )
            return None

        # ── 4b. Daily spend ceiling ─────────────────────────────────────
        # The rate gate bounds calls per window but not the day's bill.
        # Checked here, after dedup and rate, so the cheapest rejections
        # happen first. Same retry semantics: not marked as seen, so the
        # attack is reconsidered tomorrow.
        if await _is_over_daily_budget_async():
            EVOLUTION_SKIPPED_TOTAL.labels(reason="daily_budget").inc()
            log.warning(
                "EvolutionEngine: daily budget $%.2f exhausted — skipping until UTC midnight.",
                EVOLUTION_DAILY_BUDGET_USD,
            )
            return None

        self._seen_hashes.add(content_hash)
        # Cap the dedup set to avoid unbounded memory growth
        if len(self._seen_hashes) > _SEEN_HASHES_CAP:
            self._seen_hashes.clear()

        log.info(
            "EvolutionEngine: analysing %s attack (hash=%s…)",
            risk_level.value, content_hash[:12],
        )

        try:
            with _trace_stage("evo.llm_call"):
                evolution, user_prompt = await self._invoke_backend(content, flags, risk_level)
        except Exception as exc:
            log.error("EvolutionEngine: %s API error — %s", self.active_engine, exc)
            EVOLUTION_FAILED_TOTAL.labels(
                engine=self.active_engine, reason="llm_error"
            ).inc()
            return None

        with _trace_stage("evo.build_rule"):
            rule = self._build_rule(content_hash, evolution)

        # The counter's own docstring says "rule generation calls". Until now
        # every reference to it was `.inc(0)` at startup — label registration,
        # never a write — so it read 0.0 whether the engine was working or had
        # been dead for months. This is its only real increment.
        NEMOTRON_EVOLUTION_TOTAL.labels(engine=self.active_engine).inc()

        # ── Dataset collection — append fine-tuning sample ──────────────────
        try:
            from warden.brain.dataset import append_sample  # noqa: PLC0415
            append_sample(
                system_prompt  = EVOLUTION_SYSTEM_PROMPT,
                user_prompt    = user_prompt,
                evolution_json = evolution.model_dump_json(),
                rule_id        = rule.id,
                attack_type    = evolution.attack_type,
                severity       = evolution.severity,
                created_at     = rule.created_at,
            )
        except Exception as _ds_err:  # noqa: BLE001
            log.debug("Dataset append skipped: %s", _ds_err)

        # ── #2: ReDoS gate — reject unsafe AI-generated regex patterns ────────
        if evolution.new_rule.rule_type == "regex_pattern":
            with _trace_stage("evo.regex_gate"):
                _ok, _reason = self._validate_regex_safety(evolution.new_rule.value)
            if not _ok:
                log.warning(
                    "EvolutionEngine: regex_pattern rejected by safety gate (%s) — "
                    "rule discarded, corpus unchanged.", _reason,
                )
                EVOLUTION_FAILED_TOTAL.labels(
                    engine=self.active_engine, reason="regex_gate"
                ).inc()
                return None

        with _trace_stage("evo.persist"):
            self._persist(rule)

        # ── Write to rule ledger ─────────────────────────────────────────────
        if self._ledger is not None:
            try:
                self._ledger.write_rule(
                    rule_id         = rule.id,
                    source          = "evolution",
                    created_at      = rule.created_at,
                    pattern_snippet = rule.new_rule.value[:100],
                    rule_type       = rule.new_rule.rule_type,
                )
            except Exception as exc:  # noqa: BLE001
                log.warning("EvolutionEngine: ledger write failed — %s", exc)

        # ── Route through review queue (auto: hot-load now; manual: hold) ──────
        activated = True   # default: activate immediately when no queue is set
        if self._review_queue is not None:
            activated = self._review_queue.submit(
                rule.id, rule.new_rule.rule_type, rule.new_rule.value
            )

        corpus_updated = False
        if activated and self._guard and evolution.new_rule.rule_type == "semantic_example":
            # Vet all examples before injecting into the corpus
            raw_candidates = [evolution.new_rule.value] + evolution.evasion_variants[:MAX_EVASION_VARIANTS]
            examples = [e for raw in raw_candidates if (e := self._vet_example(raw)) is not None]

            # ── Data Poisoning Guard: secondary vetting ───────────────────────
            # Read the shared guard from the runtime container (Phase 1/4) instead
            # of reaching back into warden.main; fails silently if unavailable.
            try:
                from warden.brain.poison import (
                    DataPoisoningGuard as _DataPoisoningGuard,
                )
                from warden.runtime import runtime as _runtime  # noqa: PLC0415
                _pg = _runtime.get("poison_guard")
                if _pg is not None and isinstance(_pg, _DataPoisoningGuard):
                    vetted: list[str] = []
                    for ex in examples:
                        approved, reason = await _pg.vet_example_async(ex)
                        if approved:
                            vetted.append(ex)
                        else:
                            log.warning(
                                "DataPoisoningGuard rejected corpus candidate: %s", reason
                            )
                    examples = vetted
            except Exception as _pe:
                log.debug("Poison guard corpus vetting skipped: %s", _pe)

            if examples:
                with _trace_stage("evo.add_examples"):
                    self._guard.add_examples(examples)
                corpus_updated = True
                self._corpus_count += 1
                log.info(
                    "EvolutionEngine: SemanticGuard corpus extended with %d vetted examples.",
                    len(examples),
                )
            else:
                log.warning("EvolutionEngine: all examples rejected by vetting — corpus unchanged.")

        log.info(
            "EvolutionEngine: rule written — attack=%s type=%s severity=%s",
            evolution.attack_type,
            evolution.new_rule.rule_type,
            evolution.severity,
        )

        # ── Opt-in threat feed submission ────────────────────────────────────
        if activated and self._feed_client is not None:
            try:
                self._feed_client.submit_rule(
                    rule_text   = evolution.new_rule.value,
                    rule_type   = evolution.new_rule.rule_type,
                    attack_type = evolution.attack_type,
                    risk_level  = evolution.severity,
                )
            except Exception:
                log.debug("EvolutionEngine: feed submission skipped (non-fatal).")

        # ── Global threat sync — publish to other regions ────────────────────
        try:
            from warden.threat_sync import ThreatSyncClient  # noqa: PLC0415
            ThreatSyncClient.publish(rule)
        except Exception:
            log.debug("EvolutionEngine: threat sync publish skipped (non-fatal).")

        return EvolutionResult(rule=rule, corpus_updated=corpus_updated)

    # ── Intel Bridge: synthesize examples from ArXiv paper metadata ──────────

    async def synthesize_from_intel(
        self,
        source: str,
        title:  str,
        link:   str,
    ) -> list[str]:
        """
        Given an ArXiv paper title (from WardenIntelOps.hunt_ai_threats), ask
        Claude Opus to synthesise 3-5 concrete attack prompt examples that the
        research describes or implies.

        Returns a list of example strings ready for SemanticGuard.add_examples().
        Returns [] when the API is unavailable or the engine is not initialised.
        """
        if self._client is None:
            log.debug("synthesize_from_intel: no Anthropic client — skipped.")
            return []
        if _is_rate_limited():
            log.warning("synthesize_from_intel: rate-limited — skipped.")
            return []

        system = (
            "You are an expert AI red-teamer working for Shadow Warden AI. "
            "Your task: given the title of an academic paper about LLM attack techniques, "
            "produce exactly 5 concrete attacker prompt examples that represent the "
            "attack surface the paper describes. Each example must be a realistic "
            "prompt that a real attacker would submit to an LLM gateway. "
            "Respond ONLY with a JSON array of 5 strings — no commentary, no preamble."
        )
        user = (
            f"Paper source: {source}\n"
            f"Paper title: {title}\n"
            f"Paper URL: {link}\n\n"
            "Generate 5 adversarial prompt examples that this research likely covers. "
            "Respond with a JSON array of strings only."
        )

        try:
            resp = await self._client.messages.create(
                model      = EVOLUTION_MODEL,
                max_tokens = 1024,
                system     = system,
                messages   = [{"role": "user", "content": user}],
            )
            _record_cost(EVOLUTION_MODEL, resp.usage)
            raw = resp.content[0].text.strip()  # type: ignore[union-attr]
            # Strip markdown code fences if present
            raw = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw, flags=re.DOTALL).strip()
            examples: list[str] = json.loads(raw)
            if not isinstance(examples, list):
                return []
            vetted = [
                e for raw_ex in examples
                if isinstance(raw_ex, str)
                and (e := self._vet_example(raw_ex)) is not None
            ]
            log.info(
                "synthesize_from_intel: %d/%d examples passed vetting for '%s'",
                len(vetted), len(examples), title[:60],
            )
            return vetted
        except Exception as exc:
            log.warning("synthesize_from_intel: Claude API error — %s", exc)
            return []

    # ── Backend selection at call time ────────────────────────────────────────

    async def _invoke_backend(
        self,
        content:    str,
        flags:      list[SemanticFlag],
        risk_level: RiskLevel,
    ) -> tuple[EvolutionResponse, str]:
        """Call the LLM, demoting a dead auto-mode backend to the fallback.

        `build_evolution_engine` used to pick a backend on API-key *presence*
        and fall back only if the constructor raised. Constructing a NIM client
        never raises — the model 404s at call time — so production ran for
        months with an Evolution Engine that had never generated a single rule
        and logged "online" at every boot.

        The check therefore lives where the failure actually is: the call.
        Deliberately counted, not string-matched — classifying an exception by
        its message is the kind of check that silently stops matching. Any
        `DEMOTE_AFTER_FAILURES` failures in a row means the backend is not
        answering, whatever it says.

        Demotion is per-process and never persisted: a restart re-tries the
        configured backend, so this can mask a config error for one process
        lifetime at most, and it is loud when it happens.
        """
        target = self._auto_fallback if self._demoted_to else self

        try:
            result = await target._call_claude(content, flags, risk_level)
        except Exception:
            self._consecutive_failures += 1
            if (
                self._auto_fallback is not None
                and self._demoted_to is None
                and self._consecutive_failures >= self.DEMOTE_AFTER_FAILURES
            ):
                self._demote_to_fallback()
            raise

        self._consecutive_failures = 0
        return result

    def _demote_to_fallback(self) -> None:
        """Switch future calls to the fallback engine. Loud and counted."""
        fallback = self._auto_fallback
        if fallback is None:          # pragma: no cover - guarded by caller
            return
        self._demoted_to = fallback.ENGINE_LABEL
        self._consecutive_failures = 0
        log.error(
            "EvolutionEngine: %s failed %d calls in a row — auto mode is "
            "switching to %s for the rest of this process. Fix the backend or "
            "set EVOLUTION_ENGINE explicitly; a restart re-tries %s.",
            self.ENGINE_LABEL, self.DEMOTE_AFTER_FAILURES,
            fallback.ENGINE_LABEL, self.ENGINE_LABEL,
        )
        EVOLUTION_FAILED_TOTAL.labels(
            engine=self.ENGINE_LABEL, reason="backend_demoted"
        ).inc()

    # ── Claude API call ───────────────────────────────────────────────────────

    async def _call_claude(
        self,
        content:    str,
        flags:      list[SemanticFlag],
        risk_level: RiskLevel,
    ) -> tuple[EvolutionResponse, str]:
        """
        Stream a response from Claude Opus with:
          • adaptive thinking   — deep reasoning on novel attack patterns
          • structured output   — guaranteed-valid EvolutionResponse JSON
          • streaming transport — no HTTP timeout on long thinking chains

        Content is already redacted by SecretRedactor before this call.
        We cap at 2 000 chars to stay well within the prompt budget.
        """
        flag_summary = ", ".join(
            f"{f.flag.value}(score={f.score:.2f})" for f in flags
        ) or "none detected"

        # GDPR — what leaves the perimeter via Anthropic API (Cloud-optional mode):
        #   SENT:     safe_content (anonymized attack text, max 2 000 chars)
        #             risk_level.value  (e.g. "high")
        #             flag_summary      (e.g. "prompt_injection(score=0.91)")
        #   NOT SENT: original prompt, IP address, user-agent, tenant_id, request_id,
        #             any PII that SecretRedactor or _anonymize_for_evolution strips.
        #
        # Air-gapped mode (ANTHROPIC_API_KEY unset): this function is never called;
        # the EvolutionEngine.__init__ succeeds but process_blocked() is a no-op
        # because AsyncAnthropic() raises on the first API call. Set
        # ANTHROPIC_API_KEY="" explicitly to guarantee air-gapped operation.
        safe_content = _anonymize_for_evolution(content[:2_000])

        # PhishGuard v3 — route SE / phishing attacks to the specialised analyst prompt.
        flag_values = {f.flag.value for f in flags}
        is_se_attack = bool(flag_values & _SE_FLAG_TYPES)
        system = SE_EVOLUTION_SYSTEM_PROMPT if is_se_attack else EVOLUTION_SYSTEM_PROMPT

        if is_se_attack:
            user = (
                f"A social engineering or phishing attempt was blocked by Shadow Warden.\n\n"
                f"**Risk level:** {risk_level.value}\n"
                f"**Detection flags:** {flag_summary}\n\n"
                f"**Blocked content (already redacted):**\n"
                f"```\n{safe_content}\n```\n\n"
                f"Identify the SE tactic (CEO Fraud / IT Helpdesk / Prize Lure / etc.). "
                f"Explain how the psychological manipulation works, list evasion variants "
                f"(different authority figures, urgency frames, or communication channels), "
                f"and propose exactly one new detection rule (semantic_example or regex_pattern) "
                f"that catches the *manipulation pattern*, not just the surface keywords."
            )
        else:
            user = (
                f"A request was blocked by the Warden gateway.\n\n"
                f"**Risk level:** {risk_level.value}\n"
                f"**Detection flags:** {flag_summary}\n\n"
                f"**Blocked content (already redacted):**\n"
                f"```\n{safe_content}\n```\n\n"
                f"Analyse this attack. Explain how it works, list evasion variants, "
                f"and propose exactly one new detection rule to catch future variants."
            )

        # Stream to avoid HTTP timeouts on long adaptive-thinking chains.
        # get_final_message() accumulates the full response for us.
        async with self._client.messages.stream(
            model=EVOLUTION_MODEL,
            max_tokens=4_096,
            thinking={"type": "adaptive"},
            system=system,
            messages=[{"role": "user", "content": user}],
            output_config={
                "format": {
                    "type":   "json_schema",
                    "schema": _strict_json_schema(EvolutionResponse.model_json_schema()),
                }
            },
        ) as stream:
            final = await stream.get_final_message()

        _record_cost(EVOLUTION_MODEL, final.usage)

        text = next(
            block.text for block in final.content if block.type == "text"
        )
        return EvolutionResponse.model_validate_json(text), user

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _validate_regex_safety(pattern: str, timeout_s: float = 0.3) -> tuple[bool, str]:
        """Return (ok, reason). Rejects patterns that fail to compile, time out on a
        degenerate backtracking string, or contain nested quantifier structures."""
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            return False, f"compile error: {exc}"

        # Heuristic first — catches (a+)+, (a|a)+, etc. without spawning a thread.
        # This avoids thread-deadlock on Windows when the degenerate string test
        # would catastrophically backtrack before the timeout fires.
        nested_quant = re.compile(r"(\(.*?[+*\{].*?\)[+*\{]|\[.*?\][+*\{][+*\{])")
        if nested_quant.search(pattern):
            return False, "nested quantifier structure — potential ReDoS"

        canary = "a" * 8_000 + "b"
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as _pool:
            _fut = _pool.submit(compiled.search, canary)
            try:
                _fut.result(timeout=timeout_s)
            except concurrent.futures.TimeoutError:
                return False, f"ReDoS timeout (>{timeout_s}s) on degenerate input"

        return True, "ok"

    @staticmethod
    def _build_rule(content_hash: str, ev: EvolutionResponse) -> RuleRecord:
        return RuleRecord(
            id=str(uuid.uuid4()),
            created_at=datetime.now(UTC).isoformat(),
            source_hash=content_hash,
            attack_type=ev.attack_type,
            explanation=ev.explanation,
            evasion_variants=ev.evasion_variants,
            new_rule=ev.new_rule,
            severity=ev.severity,
        )

    def _persist(self, rule: RuleRecord) -> None:
        """
        Atomically append a rule to dynamic_rules.json.

        Strategy: write to a temp file in the same directory, then
        os.replace() — this is atomic on POSIX and near-atomic on Windows,
        preventing file corruption if the process dies mid-write.
        """
        if self._rules_path.exists():
            try:
                data = json.loads(self._rules_path.read_text())
            except json.JSONDecodeError:
                log.warning(
                    "EvolutionEngine: dynamic_rules.json was corrupt — resetting."
                )
                data = {"schema_version": "1.0", "rules": []}
        else:
            data = {"schema_version": "1.0", "rules": []}

        data["last_updated"] = datetime.now(UTC).isoformat()
        data["rules"].append(json.loads(rule.model_dump_json()))
        # Persist seen_hashes so dedup survives process restarts (capped to 10k)
        existing = set(data.get("seen_hashes", []))
        existing.update(self._seen_hashes)
        data["seen_hashes"] = list(existing)[:_SEEN_HASHES_CAP]

        self._rules_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(
            dir=self._rules_path.parent, suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, self._rules_path)
        except Exception:
            os.unlink(tmp)
            raise

        log.info(
            "EvolutionEngine: dynamic_rules.json updated — total rules: %d",
            len(data["rules"]),
        )


# ── Factory ───────────────────────────────────────────────────────────────────

def build_evolution_engine(
    semantic_guard=None,
    ledger=None,
    review_queue=None,
    feed_client=None,
) -> EvolutionEngine | None:
    """
    Return the best available EvolutionEngine based on environment config.

    Selection logic (EVOLUTION_ENGINE env var):
      ``nemotron`` — always NemotronEvolutionEngine (fails loudly if no key)
      ``claude``   — always EvolutionEngine (existing Claude Opus behavior)
      ``auto``     — Nemotron if NVIDIA_API_KEY is set, else Claude if
                     ANTHROPIC_API_KEY is set, else None (disabled)

    Returns None when no API key is configured so callers can log a clear
    warning rather than failing at request time.
    """
    from warden.metrics import NEMOTRON_EVOLUTION_TOTAL  # noqa: PLC0415 (avoid circular)

    kwargs: dict = {
        "semantic_guard": semantic_guard,
        "ledger": ledger,
        "review_queue": review_queue,
        "feed_client": feed_client,
    }

    choice = os.getenv("EVOLUTION_ENGINE", "auto").lower().strip()

    if choice == "nemotron":
        from warden.brain.evolve_nemotron import NemotronEvolutionEngine  # noqa: PLC0415
        NEMOTRON_EVOLUTION_TOTAL.labels(engine="nemotron").inc(0)  # register label
        log.info("EvolutionEngine: EVOLUTION_ENGINE=nemotron — using Nemotron Super (NIM)")
        return NemotronEvolutionEngine(**kwargs)

    if choice == "claude":
        NEMOTRON_EVOLUTION_TOTAL.labels(engine="claude").inc(0)
        log.info("EvolutionEngine: EVOLUTION_ENGINE=claude — using Claude Opus")
        return EvolutionEngine(**kwargs)

    # auto — prefer Nemotron, fall back to Claude
    #
    # This branch used to be the whole story: a key was present, so Nemotron
    # was chosen, and the `except` below only covered *construction*. Building
    # a NIM client never raises — the model 404s at call time — so production
    # ran for months on an engine that had never produced a rule. The fallback
    # now also covers the call path; see EvolutionEngine._invoke_backend.
    nvidia_key = os.getenv("NVIDIA_API_KEY", "").strip()
    if nvidia_key:
        try:
            from warden.brain.evolve_nemotron import NemotronEvolutionEngine  # noqa: PLC0415
            NEMOTRON_EVOLUTION_TOTAL.labels(engine="nemotron").inc(0)
            engine = NemotronEvolutionEngine(**kwargs)
            if os.getenv("ANTHROPIC_API_KEY", "").strip():
                NEMOTRON_EVOLUTION_TOTAL.labels(engine="claude").inc(0)
                engine._auto_fallback = EvolutionEngine(**kwargs)
                log.info(
                    "EvolutionEngine: NVIDIA_API_KEY detected — using "
                    "NemotronEvolutionEngine (auto mode), Claude Opus armed as "
                    "runtime fallback after %d consecutive failures",
                    EvolutionEngine.DEMOTE_AFTER_FAILURES,
                )
            else:
                log.warning(
                    "EvolutionEngine: NVIDIA_API_KEY detected — using "
                    "NemotronEvolutionEngine (auto mode) with NO fallback. "
                    "ANTHROPIC_API_KEY is unset, so a NIM backend that fails "
                    "at call time leaves the Evolution Engine producing nothing."
                )
            return engine
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "EvolutionEngine: Nemotron init failed (%s) — falling back to Claude", exc
            )

    anthropic_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    if anthropic_key:
        NEMOTRON_EVOLUTION_TOTAL.labels(engine="claude").inc(0)
        log.info("EvolutionEngine: ANTHROPIC_API_KEY detected — using Claude Opus (auto mode)")
        return EvolutionEngine(**kwargs)

    log.warning(
        "EvolutionEngine: no API keys found (NVIDIA_API_KEY / ANTHROPIC_API_KEY). "
        "Set EVOLUTION_ENGINE=nemotron + NVIDIA_API_KEY to enable self-improvement."
    )
    return None
