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
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import anthropic
from pydantic import BaseModel, Field

from warden.schemas import RiskLevel, SemanticFlag

log = logging.getLogger("warden.brain.evolve")

# ── Config ────────────────────────────────────────────────────────────────────

EVOLUTION_MODEL    = "claude-opus-4-6"
EVOLUTION_MIN_RISK = RiskLevel.HIGH     # evolve only on HIGH or BLOCK

DYNAMIC_RULES_PATH = Path(
    os.getenv("DYNAMIC_RULES_PATH", "/warden/data/dynamic_rules.json")
)

_RISK_ORDER = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.BLOCK]


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

    def __init__(self, semantic_guard=None) -> None:
        """
        Parameters
        ----------
        semantic_guard : SemanticGuard | None
            When provided, new semantic examples are injected into the
            live corpus immediately — no restart required.
        """
        self._client        = anthropic.AsyncAnthropic()
        self._seen_hashes:  set[str] = set()   # in-process dedup
        self._guard         = semantic_guard
        self._rules_path    = DYNAMIC_RULES_PATH
        self._rules_path.parent.mkdir(parents=True, exist_ok=True)

    # ── Public API ────────────────────────────────────────────────────────────

    def _is_duplicate(self, content: str) -> bool:
        """Return True if this exact content was already processed this session."""
        return hashlib.sha256(content.encode()).hexdigest() in self._seen_hashes

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
          • this exact content was already processed (dedup by SHA-256)
          • the Claude API call fails               (error logged, not raised)
        """
        if _RISK_ORDER.index(risk_level) < _RISK_ORDER.index(EVOLUTION_MIN_RISK):
            return None

        content_hash = hashlib.sha256(content.encode()).hexdigest()
        if content_hash in self._seen_hashes:
            log.debug("EvolutionEngine: duplicate — skipping %s…", content_hash[:12])
            return None
        self._seen_hashes.add(content_hash)

        log.info(
            "EvolutionEngine: analysing %s attack (hash=%s…)",
            risk_level.value, content_hash[:12],
        )

        try:
            evolution = await self._call_claude(content, flags, risk_level)
        except Exception as exc:
            log.error("EvolutionEngine: Claude API error — %s", exc)
            return None

        rule = self._build_rule(content_hash, evolution)
        self._persist(rule)

        corpus_updated = False
        if self._guard and evolution.new_rule.rule_type == "semantic_example":
            examples = [evolution.new_rule.value] + evolution.evasion_variants
            self._guard.add_examples(examples)
            corpus_updated = True
            log.info(
                "EvolutionEngine: SemanticGuard corpus extended with %d examples.",
                len(examples),
            )

        log.info(
            "EvolutionEngine: rule written — attack=%s type=%s severity=%s",
            evolution.attack_type,
            evolution.new_rule.rule_type,
            evolution.severity,
        )
        return EvolutionResult(rule=rule, corpus_updated=corpus_updated)

    # ── Claude API call ───────────────────────────────────────────────────────

    async def _call_claude(
        self,
        content:    str,
        flags:      list[SemanticFlag],
        risk_level: RiskLevel,
    ) -> EvolutionResponse:
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

        safe_content = content[:2_000]

        system = (
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
        return EvolutionResponse.model_validate_json(text)

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
