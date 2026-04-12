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

import hashlib
import json
import logging
import os
import re
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import anthropic
from pydantic import BaseModel, Field

from warden.cache import _get_client as _get_redis
from warden.metrics import EVOLUTION_SKIPPED_TOTAL
from warden.schemas import RiskLevel, SemanticFlag

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

DYNAMIC_RULES_PATH = Path(
    os.getenv("DYNAMIC_RULES_PATH", "/warden/data/dynamic_rules.json")
)

# Corpus poisoning protection
MAX_CORPUS_RULES       = int(os.getenv("MAX_CORPUS_RULES", "500"))
MAX_EVASION_VARIANTS   = 5   # cap evasion variants per rule
MAX_EXAMPLE_LENGTH     = 500  # max chars per semantic example
_SEEN_HASHES_CAP       = 10_000  # cap in-process dedup set

# Evolution rate gate — prevent Claude Opus API cost exhaustion under flood attacks.
# A fixed-window counter in Redis caps how many novel attacks trigger the LLM per window.
# Fail-open: when Redis is unavailable the gate is bypassed so evolution still works.
EVOLUTION_RATE_WINDOW  = int(os.getenv("EVOLUTION_RATE_WINDOW", "300"))  # seconds
EVOLUTION_RATE_MAX     = int(os.getenv("EVOLUTION_RATE_MAX",    "10"))   # calls per window
_RATE_KEY              = "warden:evolution:calls"

_RISK_ORDER = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.BLOCK]


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
    try:
        count = r.incr(_RATE_KEY)
        if count == 1:
            # First call in this window — arm the TTL so the window auto-resets.
            r.expire(_RATE_KEY, EVOLUTION_RATE_WINDOW)
        return int(count) > EVOLUTION_RATE_MAX
    except Exception:  # noqa: BLE001
        return False


# ── Pydantic schema — what Claude must return ─────────────────────────────────

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
        self._rules_path    = DYNAMIC_RULES_PATH
        self._rules_path.parent.mkdir(parents=True, exist_ok=True)
        self._corpus_count  = self._count_existing_rules()

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
    ) -> EvolutionResult | None:
        """
        Analyse a blocked attack and generate a new detection rule.

        Returns None when:
          • risk_level is below EVOLUTION_MIN_RISK  (LOW / MEDIUM)
          • corpus cap (MAX_CORPUS_RULES) is reached
          • this exact content was already processed (dedup by SHA-256)
          • the call-rate cap (EVOLUTION_RATE_MAX / EVOLUTION_RATE_WINDOW) is exceeded
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

        self._seen_hashes.add(content_hash)
        # Cap the dedup set to avoid unbounded memory growth
        if len(self._seen_hashes) > _SEEN_HASHES_CAP:
            self._seen_hashes.clear()

        log.info(
            "EvolutionEngine: analysing %s attack (hash=%s…)",
            risk_level.value, content_hash[:12],
        )

        try:
            evolution, user_prompt = await self._call_claude(content, flags, risk_level)
        except Exception as exc:
            log.error("EvolutionEngine: Claude API error — %s", exc)
            return None

        rule = self._build_rule(content_hash, evolution)

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
            # Import lazily to avoid circular imports; fails silently if unavailable.
            try:
                import warden.main as _main  # noqa: PLC0415
                from warden.brain.poison import (
                    DataPoisoningGuard as _DataPoisoningGuard,  # noqa: PLC0415
                )
                _pg = getattr(_main, "_poison_guard", None)
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

        # GDPR: strip structural UIDs (UUIDs, IPs, emails, timestamps, hex tokens)
        # before the content leaves the perimeter via the Anthropic API.
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
                    "schema": EvolutionResponse.model_json_schema(),
                }
            },
        ) as stream:
            final = await stream.get_final_message()

        text = next(
            block.text for block in final.content if block.type == "text"
        )
        return EvolutionResponse.model_validate_json(text), user

    # ── Helpers ───────────────────────────────────────────────────────────────

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
    nvidia_key = os.getenv("NVIDIA_API_KEY", "").strip()
    if nvidia_key:
        try:
            from warden.brain.evolve_nemotron import NemotronEvolutionEngine  # noqa: PLC0415
            NEMOTRON_EVOLUTION_TOTAL.labels(engine="nemotron").inc(0)
            log.info(
                "EvolutionEngine: NVIDIA_API_KEY detected — "
                "using NemotronEvolutionEngine (auto mode)"
            )
            return NemotronEvolutionEngine(**kwargs)
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
