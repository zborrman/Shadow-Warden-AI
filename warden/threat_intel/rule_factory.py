"""
warden/threat_intel/rule_factory.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Synthesizes detection rules from analyzed ThreatIntelItems and activates
them through the same ReviewQueue → RuleLedger → BrainSemanticGuard
pipeline used by the EvolutionEngine.

Design principle
────────────────
The RuleFactory uses the detection_hint already produced by the analyzer —
no additional Claude calls in the common case.  This keeps synthesis fast
and cheap.  The existing vet/guard logic from EvolutionEngine is reused
directly to ensure consistent quality filtering.

Rule types
──────────
  regex_pattern   — validated with re.compile(); added to _dynamic_regex_rules
  semantic_example — vetted via EvolutionEngine._vet_example(); added to ML corpus
"""
from __future__ import annotations

import logging
import os
import re
import uuid
from dataclasses import dataclass

from warden.schemas import ThreatIntelItem

log = logging.getLogger("warden.threat_intel.rule_factory")

_MIN_RELEVANCE = float(os.getenv("THREAT_INTEL_MIN_RELEVANCE", "0.65"))


@dataclass
class SynthesizedRule:
    rule_id:        str
    rule_type:      str     # "regex_pattern" | "semantic_example"
    value:          str
    description:    str
    source_item_id: str


class RuleFactory:
    """
    Synthesize and activate detection rules from analyzed ThreatIntelItems.

    Usage::

        factory = RuleFactory(store, review_queue, ledger, brain_guard)
        count = factory.process_analyzed_batch(limit=20)
    """

    def __init__(
        self,
        store,
        review_queue=None,
        ledger=None,
        brain_guard=None,
        min_relevance: float = _MIN_RELEVANCE,
    ) -> None:
        self._store        = store
        self._review_queue = review_queue
        self._ledger       = ledger
        self._brain_guard  = brain_guard
        self._min_relevance = min_relevance

    # ── Public API ────────────────────────────────────────────────────────────

    def process_analyzed_batch(self, limit: int = 20) -> int:
        """
        Fetch ANALYZED items, synthesize + activate rules for each.
        Returns count of items that produced at least one rule.
        """
        items = self._store.get_pending_synthesis(limit=limit)
        processed = 0
        for item in items:
            if item.relevance_score is None or item.relevance_score < self._min_relevance:
                self._store.dismiss(item.id)
                continue
            rules = self.synthesize(item)
            if not rules:
                # No actionable rule — mark as rules_generated(0) to avoid re-processing
                self._store.mark_rules_generated(item.id, 0)
                continue
            activated = sum(1 for r in rules if self.activate(r, item))
            if activated:
                processed += 1
                log.info(
                    "RuleFactory: activated %d rule(s) from [%s] %s",
                    activated, item.source, item.title[:60],
                )

        return processed

    def synthesize(self, item: ThreatIntelItem) -> list[SynthesizedRule]:
        """
        Build a SynthesizedRule from a ThreatIntelItem's detection_hint.
        Returns [] when the hint is empty, too short, or fails validation.
        """
        hint = (item.detection_hint or "").strip()
        if not hint or len(hint) < 5:
            return []

        # Determine rule type from hint_type stored in the analysis
        # We infer it: if it compiles as a regex and looks like one, use regex.
        # Otherwise treat as semantic example.
        rule_type = self._infer_rule_type(hint)

        if rule_type == "regex_pattern":
            if not self._validate_regex(hint):
                log.debug("RuleFactory: invalid regex for item %s — %s", item.id[:8], hint[:60])
                return []
            value = hint
        else:
            vetted = self._vet_semantic(hint)
            if vetted is None:
                return []
            value = vetted

        description = (
            f"[threat_intel/{item.source}] "
            f"{item.owasp_category or 'LLM-security'}: "
            f"{(item.attack_pattern or item.title)[:100]}"
        )

        return [SynthesizedRule(
            rule_id=str(uuid.uuid4()),
            rule_type=rule_type,
            value=value,
            description=description,
            source_item_id=item.id,
        )]

    def activate(self, rule: SynthesizedRule, item: ThreatIntelItem) -> bool:
        """
        Write rule to RuleLedger, route through ReviewQueue, hot-load if auto mode.
        Mirrors the exact activation path in EvolutionEngine.process_blocked().
        Returns True when the rule was activated or queued.
        """
        # 1. Write to ledger
        if self._ledger is not None:
            try:
                self._ledger.write_rule(
                    rule_id=rule.rule_id,
                    source="threat_intel",
                    created_at=item.created_at,
                    pattern_snippet=rule.value[:100],
                    rule_type=rule.rule_type,
                )
            except Exception as exc:
                log.warning("RuleFactory: ledger write failed — %s", exc)

        # 2. Route through review queue
        activated = True
        if self._review_queue is not None:
            activated = self._review_queue.submit(
                rule.rule_id, rule.rule_type, rule.value
            )

        # 3. Hot-load semantic examples into the ML corpus
        if activated and self._brain_guard and rule.rule_type == "semantic_example":
            try:
                self._brain_guard.add_examples([rule.value])
                log.info("RuleFactory: ML corpus extended with threat_intel example.")
            except Exception as exc:
                log.warning("RuleFactory: brain_guard.add_examples failed — %s", exc)

        # 4. Record countermeasure link in threat_intel store
        try:
            self._store.record_countermeasure(
                threat_item_id=rule.source_item_id,
                rule_id=rule.rule_id,
                rule_type=rule.rule_type,
                rule_value=rule.value,
            )
            self._store.mark_rules_generated(rule.source_item_id, 1)
        except Exception as exc:
            log.warning("RuleFactory: store update failed — %s", exc)

        return activated

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _infer_rule_type(hint: str) -> str:
        """
        Heuristic: if the hint contains regex metacharacters and compiles
        without error, treat it as a regex; otherwise as semantic.
        """
        regex_signals = (r"\b", r"\s", r"(?i)", r"(?:", r"[a-z", r".*", r".+")
        if any(sig in hint for sig in regex_signals):
            try:
                re.compile(hint)
                return "regex_pattern"
            except re.error:
                pass
        return "semantic_example"

    @staticmethod
    def _validate_regex(pattern: str) -> bool:
        try:
            re.compile(pattern)
            return True
        except re.error:
            return False

    @staticmethod
    def _vet_semantic(text: str) -> str | None:
        """Mirror of EvolutionEngine._vet_example()."""
        text = text.strip()
        if not text or len(text) < 10:
            return None
        if len(text) > 500:
            text = text[:500]
        suspicious = ("sk-", "AKIA", "ghp_", "-----BEGIN", "bearer ")
        if any(s in text for s in suspicious):
            return None
        return text
