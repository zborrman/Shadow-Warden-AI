"""
warden/review_queue.py
──────────────────────
Rule activation gate between EvolutionEngine output and corpus hot-reload.

Controls whether evolution-generated rules become live immediately or are held
in a pending_review staging state until a human operator approves them.

RULE_REVIEW_MODE=auto    (default) — backwards-compatible; rules activate immediately.
RULE_REVIEW_MODE=manual            — rules sit in pending_review; require admin approval
                                     via POST /admin/rules/{rule_id}/approve.

Typical usage (warden/main.py)::

    _review_queue = ReviewQueue(on_activate_regex=_add_dynamic_regex_rule)

    _evolve = EvolutionEngine(
        semantic_guard = _brain_guard,
        ledger         = _ledger,
        review_queue   = _review_queue,
    )

    # POST /admin/rules/{rule_id}/approve
    activated = _review_queue.activate(rule_id, rule_type, pattern, brain_guard)
"""
from __future__ import annotations

import logging
import os
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from warden.brain.semantic import SemanticGuard as BrainSemanticGuard

log = logging.getLogger("warden.review_queue")

RULE_REVIEW_MODE = os.getenv("RULE_REVIEW_MODE", "auto").lower()


class ReviewQueue:
    """
    Gate between EvolutionEngine rule generation and live corpus / regex hot-reload.

    In *auto* mode (default):
      - ``submit()`` calls the on_activate_regex callback immediately for regex rules,
        and returns True so that the caller (evolve.py) may also hot-reload semantic
        examples into the ML corpus.

    In *manual* mode:
      - ``submit()`` is a no-op: the rule stays in the ledger with
        status=pending_review. Returns False so the caller skips hot-reload.
      - ``activate()`` is called by the admin endpoint to explicitly approve a rule
        and fire the same callbacks.
    """

    def __init__(
        self,
        on_activate_regex: Callable[[str, str], None] | None = None,
        mode: str | None = None,
    ) -> None:
        """
        Parameters
        ----------
        on_activate_regex : Callable[[str, str], None] | None
            Called with (rule_id, pattern_str) to hot-load a regex rule into
            the running filter.  Typically ``_add_dynamic_regex_rule`` from main.py.
        mode : str | None
            Override RULE_REVIEW_MODE env var.  Accepted values: "auto", "manual".
        """
        self._mode = (mode or RULE_REVIEW_MODE).lower()
        self._on_activate_regex = on_activate_regex
        log.info("ReviewQueue initialized — mode=%r", self._mode)

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def mode(self) -> str:
        return self._mode

    # ── Core gate ─────────────────────────────────────────────────────────────

    def submit(self, rule_id: str, rule_type: str, value: str) -> bool:
        """
        Called by EvolutionEngine after a rule is written to the ledger.

        Returns True  → rule was activated (auto mode); caller should proceed
                        with any additional hot-reload steps (e.g. corpus update).
        Returns False → rule is queued for review (manual mode); caller must
                        skip hot-reload.
        """
        if self._mode == "auto":
            if rule_type == "regex_pattern":
                self._fire_regex_callback(rule_id, value)
            return True

        # manual mode — hold in pending_review
        log.info(
            "ReviewQueue: rule %s (type=%s) queued for human review — manual mode active",
            rule_id, rule_type,
        )
        return False

    def activate(
        self,
        rule_id:     str,
        rule_type:   str,
        value:       str,
        brain_guard: BrainSemanticGuard | None = None,
    ) -> bool:
        """
        Explicitly activate a queued rule (called from the admin approve endpoint).

        Fires the same callbacks as auto mode:
          • regex_pattern  → on_activate_regex(rule_id, value)
          • semantic_example → brain_guard.add_examples([value])

        Returns True if at least one activation callback was invoked.
        """
        activated = False
        if rule_type == "regex_pattern":
            self._fire_regex_callback(rule_id, value)
            activated = True
        elif rule_type == "semantic_example" and brain_guard is not None:
            try:
                brain_guard.add_examples([value])
                log.info("ReviewQueue: activated semantic rule %s into ML corpus", rule_id)
                activated = True
            except Exception as exc:
                log.warning("ReviewQueue: semantic activation failed — %s", exc)
        return activated

    # ── Internal ──────────────────────────────────────────────────────────────

    def _fire_regex_callback(self, rule_id: str, pattern_str: str) -> None:
        if self._on_activate_regex is None:
            return
        try:
            self._on_activate_regex(rule_id, pattern_str)
            log.debug("ReviewQueue: auto-activated regex rule %s", rule_id)
        except Exception as exc:
            log.warning("ReviewQueue: regex activation callback failed — %s", exc)
