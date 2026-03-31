"""
warden/brain/evolve_nemotron.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NemotronEvolutionEngine — drop-in replacement for EvolutionEngine that
calls NVIDIA NIM (Nemotron Super 49B) instead of Claude Opus.

Architecture
────────────
Subclasses EvolutionEngine and overrides only _call_claude() with _call_nim().
All guards (dedup, rate-limit, corpus cap, persist, ledger, feed, poison guard)
are inherited unchanged — only the LLM backend differs.

Why subclass instead of compose?
  EvolutionEngine._call_claude is the only moving part that touches an
  external API.  The 250 lines of guard/persist/corpus logic above it are
  identical for both backends.  Subclassing is the minimal change that
  preserves all invariants while swapping the backend.

Thinking mode
─────────────
Nemotron's thinking mode produces a <think>…</think> reasoning trace
before the JSON answer.  NimClient.chat() strips the tags and returns
(answer, reasoning).  We:
  • use answer for EvolutionResponse parsing
  • store a brief reasoning_summary in the log (configurable depth via
    NEMOTRON_STORE_THINKING=true → also written to Evidence Vault via S3)

JSON output
───────────
NIM doesn't support Anthropic's output_config.json_schema.  Instead:
  1. The system prompt includes the schema and a strict JSON-only directive.
  2. The answer is extracted via nemotron_client.extract_json() which handles
     bare JSON, markdown code fences, and first-object heuristics.
  3. Validated with EvolutionResponse.model_validate_json().
"""
from __future__ import annotations

import logging
import os

from warden.brain.evolve import (
    EVOLUTION_SYSTEM_PROMPT,
    EvolutionEngine,
    EvolutionResponse,
)
from warden.brain.nemotron_client import NimClient, extract_json
from warden.schemas import RiskLevel, SemanticFlag

log = logging.getLogger("warden.brain.evolve_nemotron")

_STORE_THINKING = os.getenv("NEMOTRON_STORE_THINKING", "false").lower() == "true"

# ── Extended system prompt: embeds JSON schema for Nemotron ───────────────────
# Nemotron cannot receive an output_config.format.json_schema like Claude can.
# We embed the exact schema as a constraint in the system prompt instead.
_NEMOTRON_SYSTEM_PROMPT = (
    EVOLUTION_SYSTEM_PROMPT
    + """

OUTPUT FORMAT — STRICT
──────────────────────
You MUST respond with ONLY a valid JSON object. No preamble, no commentary,
no markdown. The object must conform exactly to this schema:

{
  "attack_type":      "<short snake_case category, e.g. prompt_injection>",
  "explanation":      "<how the attack works — 2 to 4 sentences, technical>",
  "evasion_variants": [
    "<meaningfully rephrased variant 1>",
    "<meaningfully rephrased variant 2>",
    "<meaningfully rephrased variant 3>"
  ],
  "new_rule": {
    "rule_type":   "semantic_example" | "regex_pattern",
    "value":       "<exact pattern or example sentence>",
    "description": "<one sentence: what this rule catches>"
  },
  "severity": "medium" | "high" | "block"
}

Constraints:
• evasion_variants must contain exactly 3 to 5 entries.
• rule_type must be the literal string "semantic_example" or "regex_pattern".
• severity must be "medium", "high", or "block".
• Do not wrap the JSON in any code block or markdown.
• Do not add any text after the closing brace.
"""
)


class NemotronEvolutionEngine(EvolutionEngine):
    """
    Self-improving defense loop powered by NVIDIA Nemotron Super (NIM).

    Drop-in replacement for EvolutionEngine.  All public interfaces are
    identical; only the underlying LLM call is different.

    Usage — identical to EvolutionEngine::

        engine = NemotronEvolutionEngine(semantic_guard=_brain_guard)
        # ... used exactly the same way in main.py BackgroundTasks
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._nim = NimClient()
        if not self._nim.is_configured:
            log.warning(
                "NemotronEvolutionEngine: NVIDIA_API_KEY is not set — "
                "evolution calls will raise at runtime.  "
                "Set NVIDIA_API_KEY or switch EVOLUTION_ENGINE=claude."
            )

    # ── Override: replace Claude API call with NIM call ───────────────────────

    async def _call_claude(
        self,
        content:    str,
        flags:      list[SemanticFlag],
        risk_level: RiskLevel,
    ) -> tuple[EvolutionResponse, str]:
        """
        Called by EvolutionEngine.process_blocked().
        Name kept as _call_claude to satisfy the parent's internal interface.
        Routes to NIM instead of Anthropic.
        """
        return await self._call_nim(content, flags, risk_level)

    async def _call_nim(
        self,
        content:    str,
        flags:      list[SemanticFlag],
        risk_level: RiskLevel,
    ) -> tuple[EvolutionResponse, str]:
        """
        Call Nemotron Super via NIM with thinking mode enabled.

        Returns (EvolutionResponse, user_prompt_str) — same contract as
        EvolutionEngine._call_claude so the parent's process_blocked() can
        use the result for dataset collection without modification.
        """
        from warden.brain.evolve import _anonymize_for_evolution  # noqa: PLC0415

        flag_summary = ", ".join(
            f"{f.flag.value}(score={f.score:.2f})" for f in flags
        ) or "none detected"

        safe_content = _anonymize_for_evolution(content[:2_000])

        user = (
            f"A request was blocked by the Warden gateway.\n\n"
            f"**Risk level:** {risk_level.value}\n"
            f"**Detection flags:** {flag_summary}\n\n"
            f"**Blocked content (already redacted):**\n"
            f"```\n{safe_content}\n```\n\n"
            f"Analyse this attack. Explain how it works, list evasion variants, "
            f"and propose exactly one new detection rule to catch future variants. "
            f"Respond with the JSON object only."
        )

        messages = [
            {"role": "system",    "content": _NEMOTRON_SYSTEM_PROMPT},
            {"role": "user",      "content": user},
        ]

        answer, reasoning = await self._nim.chat(
            messages        = messages,
            max_tokens      = 8_192,
            enable_thinking = True,
        )

        # Log reasoning summary (first 300 chars) at DEBUG level
        if reasoning:
            log.debug(
                "Nemotron reasoning summary (first 300 chars): %s…",
                reasoning[:300],
            )
            if _STORE_THINKING:
                self._ship_thinking(reasoning, safe_content[:200])

        # Extract and validate JSON
        json_text = extract_json(answer)
        evolution = EvolutionResponse.model_validate_json(json_text)
        return evolution, user

    # ── Optional: ship full thinking trace to Evidence Vault ─────────────────

    @staticmethod
    def _ship_thinking(reasoning: str, content_snippet: str) -> None:
        """
        Background: write thinking trace to S3 Evidence Vault.
        Only active when NEMOTRON_STORE_THINKING=true.
        Fails silently — never blocks the evolution path.
        """
        try:
            from warden.storage import s3 as _s3  # noqa: PLC0415
            if _s3.S3_ENABLED:
                import json as _json  # noqa: PLC0415
                import uuid as _uuid  # noqa: PLC0415
                from datetime import UTC, datetime  # noqa: PLC0415
                bundle = {
                    "type":             "nemotron_thinking_trace",
                    "timestamp":        datetime.now(UTC).isoformat(),
                    "trace_id":         str(_uuid.uuid4()),
                    "content_snippet":  content_snippet,
                    "reasoning":        reasoning,
                }
                _s3.ship_log_entry(_json.dumps(bundle))
        except Exception as exc:  # noqa: BLE001
            log.debug("Nemotron thinking trace ship failed (non-fatal): %s", exc)
