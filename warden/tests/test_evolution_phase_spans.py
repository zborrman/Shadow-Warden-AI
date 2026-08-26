"""warden/tests/test_evolution_phase_spans.py

process_blocked() blocks the event loop for ~1.9s per blocked request. That is
measured, not inferred — across three production traces on 4ef4bba0, the
2066/2016/2006ms `spawn.process_blocked` windows contain **zero** span starts
from any trace for the first ~1.9s, then everything resumes in a 20ms burst:

    +1972.2ms  spawn.alert_block_event
    +1984.7ms  spawn.alert_push_verdict
    +1988.3ms  BackgroundTask append
    +1988.9ms  POST /filter http send

Awaited I/O interleaves; silence-then-burst is a blocked loop. Detaching the
call in #389 could not help, because a detached task still runs *on* the loop.

Which statement blocks is still unknown. Excluded by direct measurement on the
box: MiniLM encode (~20ms for 1-16 examples), the AsyncAnthropic call (loop lag
max 4.0ms during a real round trip), and the corpus/index rebuild (76x384).

So the phases are instrumented rather than guessed at — the same move that found
the previous two defects in this chain. This test keeps them instrumented.
"""
from __future__ import annotations

from pathlib import Path

import pytest

_PHASES = ("llm_call", "build_rule", "regex_gate", "persist", "add_examples")


@pytest.fixture(scope="module")
def source() -> str:
    return (Path(__file__).resolve().parents[1] / "brain" / "evolve.py").read_text(
        encoding="utf-8"
    )


@pytest.mark.parametrize("phase", _PHASES)
def test_phase_is_instrumented(source: str, phase: str) -> None:
    needle = f'_trace_stage("evo.{phase}")'
    assert needle in source, (
        f"{needle} is gone from process_blocked. It is there because the ~1.9s "
        "of loop-blocking work in that function has not been attributed to a "
        "statement yet; removing the span removes the only evidence that would."
    )


def test_the_statements_those_spans_wrap_still_exist(source: str) -> None:
    """Guard the guard: a span around a call that no longer happens proves nothing."""
    for call in ("self._call_claude(", "self._build_rule(",
                 "self._validate_regex_safety(", "self._persist(",
                 "self._guard.add_examples("):
        assert call in source, (
            f"{call} no longer appears in evolve.py — the phase spans above may "
            "now wrap nothing, which would make this suite pass while measuring "
            "nothing at all"
        )
