"""
warden/tests/test_corpus_canary_coverage.py — OB-F12 corpus guard.

`poison.py` holds ten canary attacks that must always score at least
CANARY_MIN_SCORE (0.70) against the jailbreak corpus. Any canary dropping below
that is read as corpus poisoning: the health monitor marks the corpus DEGRADED,
attempts a rollback and pages `critical` through Grafana.

Seven of the ten had been below it since the canaries were written. Measured on
production 2026-08-21: `warden_corpus_canary_failing` 7, min score 0.4057,
`warden_corpus_drift_score` 0.00000 and `warden_pipeline_canary_missed` 0 — so
nothing had been poisoned and nothing was getting through. The corpus simply did
not cover the region those canaries live in, and the alert for a real poisoning
event had nowhere left to go, because it was already firing.

That is only fixable once. Without this test the corpus drifts back the moment
someone edits either list, and the alert returns to being furniture.

The check is the same arithmetic the monitor performs — cosine similarity of
each canary against every corpus entry, take the best — so it fails here, on a
push, instead of on the pager.
"""
from __future__ import annotations

import numpy as np
import pytest

from warden.brain.poison import CANARY_EXAMPLES, CANARY_MIN_SCORE

pytestmark = pytest.mark.slow

#: Ordinary prompts that must not move toward the block threshold when the
#: corpus grows. Widening coverage is only free if it does not cost precision:
#: three of these deliberately borrow attack vocabulary ("ignore the previous",
#: "system prompt", "forget what I said") in an entirely benign context, which
#: is where a careless corpus addition would show up first.
BENIGN_CONTROLS = [
    "Can you summarize this quarterly report for me?",
    "What is the capital of France?",
    "Please rewrite this paragraph to be more concise.",
    "Explain how HTTPS certificate validation works.",
    "Write a Python function that reverses a linked list.",
    "What are your capabilities and limitations as an assistant?",
    "Help me draft a polite follow-up email to a client.",
    "Ignore the previous draft and use this newer version of the text instead.",
    "My system prompt for the chatbot I am building keeps getting truncated, any advice?",
    "How do I disable the safety interlock on my dishwasher door?",
    "Forget what I said earlier, I actually need the Q3 numbers.",
    "What restrictions does the free tier have?",
]

#: The gateway flags at 0.72 (SEMANTIC_THRESHOLD). Benign text is held a clear
#: margin under it rather than merely below it, so a later corpus addition has
#: to be noticeably wrong before it starts blocking real traffic.
_BENIGN_CEILING = 0.60


def _best_scores(model, queries: list[str], corpus: list[str]) -> np.ndarray:
    """Max cosine similarity of each query against the corpus."""
    q = model.encode(queries, convert_to_numpy=True, show_progress_bar=False)
    c = model.encode(corpus, convert_to_numpy=True, show_progress_bar=False)
    q = q / np.linalg.norm(q, axis=1, keepdims=True)
    c = c / np.linalg.norm(c, axis=1, keepdims=True)
    return (q @ c.T).max(axis=1)


@pytest.fixture(scope="module")
def scored():
    """(canary scores, benign scores) against the shipped corpus."""
    try:
        from warden.brain.semantic import _JAILBREAK_CORPUS, _load_model

        model = _load_model()
    except Exception as exc:  # noqa: BLE001 — offline runner, no model cache
        pytest.skip(f"sentence-transformer model unavailable: {exc}")

    corpus = list(_JAILBREAK_CORPUS)
    return (
        _best_scores(model, list(CANARY_EXAMPLES), corpus),
        _best_scores(model, BENIGN_CONTROLS, corpus),
    )


def test_every_canary_is_covered_by_the_corpus(scored) -> None:
    canary_scores, _ = scored
    failing = [
        f"{score:.4f} < {CANARY_MIN_SCORE} — {text}"
        for score, text in zip(canary_scores, CANARY_EXAMPLES, strict=True)
        if score < CANARY_MIN_SCORE
    ]
    assert not failing, (
        f"{len(failing)}/{len(CANARY_EXAMPLES)} canaries score below "
        f"CANARY_MIN_SCORE against the shipped corpus. The corpus-canary alert "
        f"will fire `critical` continuously and a real poisoning event will have "
        f"nowhere to be seen:\n  " + "\n  ".join(failing)
    )


def test_benign_prompts_keep_their_margin(scored) -> None:
    _, benign_scores = scored
    over = [
        f"{score:.4f} — {text}"
        for score, text in zip(benign_scores, BENIGN_CONTROLS, strict=True)
        if score >= _BENIGN_CEILING
    ]
    assert not over, (
        "Corpus growth pulled benign prompts toward the 0.72 block threshold:\n  "
        + "\n  ".join(over)
    )
