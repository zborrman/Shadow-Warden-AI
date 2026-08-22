"""
warden/tests/test_corpus_canary_coverage.py — OB-F12 corpus guard.

The corpus canaries exist to detect the corpus moving away from them — an
`add_examples()` hot-reload that shifts the embedding space until real attacks
stop matching. What they were actually measured against was an absolute 0.70
floor, and seven of the ten had been under it since the day they were written
(production 2026-08-21: `warden_corpus_canary_failing` 7, min score 0.4057,
`warden_corpus_drift_score` 0.00000, `warden_pipeline_canary_missed` 0 — so
nothing was poisoned and nothing was getting through).

That floor could not be satisfied honestly. Rewriting the corpus with sixteen
genuinely distinct attacks drawn from the same seven families moved the canaries
by nothing: still 7 under 0.70, closest new neighbour 0.6559. Above roughly
0.70, all-MiniLM-L6-v2 cosine similarity is a paraphrase relation — the only
entries that lift a canary over the line are restatements of that canary, which
makes the check measure its own input.

So `poison.py` compares each canary against the score it had at startup, and
these tests cover what that has to guarantee:

  * the corpus as shipped reports healthy — no permanent `critical` alert;
  * a corpus that has been poisoned is still caught — the check can fire;
  * the absolute floor still catches a wiped corpus;
  * growing the corpus does not drag benign prompts toward the block threshold.

The second one is the one that matters. A health check that cannot fail is the
same defect as an alert that always fires, wearing the opposite mask.
"""
from __future__ import annotations

import numpy as np
import pytest

from warden.brain.poison import (
    CANARY_ABSOLUTE_FLOOR,
    CANARY_DRIFT_TOLERANCE,
    CANARY_EXAMPLES,
    DataPoisoningGuard,
)

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


class _FakeBrainGuard:
    """Minimal stand-in for SemanticGuard — the poison guard only reads embeddings."""

    def __init__(self, embeddings) -> None:
        self._corpus_embeddings = embeddings


@pytest.fixture(scope="module")
def model():
    try:
        from warden.brain.semantic import _load_model

        return _load_model()
    except Exception as exc:   # offline runner with no model cache
        pytest.skip(f"sentence-transformer model unavailable: {exc}")


@pytest.fixture(scope="module")
def shipped_corpus():
    from warden.brain.semantic import _JAILBREAK_CORPUS

    return list(_JAILBREAK_CORPUS)


def _encode(model, texts):
    import torch

    return torch.tensor(
        model.encode(texts, convert_to_numpy=True, show_progress_bar=False)
    )


def _guard_on(model, corpus):
    """A DataPoisoningGuard initialised against an arbitrary corpus."""
    guard = DataPoisoningGuard(_FakeBrainGuard(_encode(model, corpus)))
    guard._initialise_sync()
    assert guard._ready, "poison guard failed to initialise"
    return guard


def test_shipped_corpus_reports_healthy(model, shipped_corpus) -> None:
    guard = _guard_on(model, shipped_corpus)
    report = guard._corpus_health_sync()
    assert report.healthy, (
        "The corpus as shipped reports DEGRADED, which means the corpus-canary "
        f"alert fires `critical` on a clean deploy: {report.detail}"
    )
    assert report.failing_canaries == 0, report.detail


def test_poisoning_is_still_detected(model, shipped_corpus) -> None:
    """
    The check has to be able to fail. Simulated exactly as a poisoning would
    arrive — the corpus is replaced, after the baseline was taken, with entries
    that carry none of the attack semantics.
    """
    guard = _guard_on(model, shipped_corpus)
    diluted = [
        "The quarterly revenue figures are attached to this message.",
        "Our office is closed on public holidays and reopens the next weekday.",
        "Please find the meeting notes summarised in the document below.",
        "The train departs from platform four at seven minutes past the hour.",
        "Recipes in this collection use metric measurements throughout.",
    ]
    guard._guard._corpus_embeddings = _encode(model, diluted)

    report = guard._corpus_health_sync()
    assert not report.healthy, (
        "A corpus stripped of every attack example still reports healthy — the "
        "poisoning check cannot fire"
    )
    assert report.failing_canaries > 0, report.detail


def test_absolute_floor_catches_a_collapsed_corpus(model, shipped_corpus) -> None:
    guard = _guard_on(model, shipped_corpus)
    guard._guard._corpus_embeddings = _encode(
        model, ["Rainfall totals for the month were slightly above average."]
    )
    report = guard._corpus_health_sync()
    assert report.min_canary_score < CANARY_ABSOLUTE_FLOOR, (
        f"expected a collapsed corpus to fall under the absolute floor, "
        f"got {report.min_canary_score}"
    )
    assert not report.healthy
    assert "absolute floor" in report.detail


def test_a_small_drop_stays_within_tolerance(model, shipped_corpus) -> None:
    """
    Tolerance is not zero for a reason: legitimate `add_examples()` growth moves
    canary scores slightly, and a check that fires on that is the alert storm
    this work removed. Dropping a single corpus entry must stay healthy.
    """
    guard = _guard_on(model, shipped_corpus)
    guard._guard._corpus_embeddings = _encode(model, shipped_corpus[:-1])
    report = guard._corpus_health_sync()
    assert report.healthy, (
        f"removing one corpus entry moved a canary by more than "
        f"{CANARY_DRIFT_TOLERANCE}: {report.detail}"
    )


def test_benign_prompts_keep_their_margin(model, shipped_corpus) -> None:
    corpus = model.encode(shipped_corpus, convert_to_numpy=True, show_progress_bar=False)
    benign = model.encode(BENIGN_CONTROLS, convert_to_numpy=True, show_progress_bar=False)
    corpus = corpus / np.linalg.norm(corpus, axis=1, keepdims=True)
    benign = benign / np.linalg.norm(benign, axis=1, keepdims=True)
    scores = (benign @ corpus.T).max(axis=1)

    over = [
        f"{score:.4f} — {text}"
        for score, text in zip(scores, BENIGN_CONTROLS, strict=True)
        if score >= _BENIGN_CEILING
    ]
    assert not over, (
        "Corpus growth pulled benign prompts toward the 0.72 block threshold:\n  "
        + "\n  ".join(over)
    )


def test_a_snapshot_this_build_wrote_is_recognised(model, shipped_corpus, tmp_path, monkeypatch) -> None:
    from warden.brain import poison as poison_mod

    base = tmp_path / "corpus_snapshot"
    monkeypatch.setattr(poison_mod, "_SNAPSHOT_BASE", base)
    guard = _guard_on(model, shipped_corpus)
    assert guard._save_snapshot_sync(), "snapshot save failed"

    assert DataPoisoningGuard.snapshot_matches_shipped_corpus(base.with_suffix(".npz"))


def test_a_snapshot_from_an_earlier_build_is_not_trusted(tmp_path) -> None:
    """
    A snapshot written before a corpus change holds that older, narrower corpus.
    Restoring it would roll coverage backwards with nothing said about it, so an
    unrecognised — or absent — digest has to read as stale.
    """
    import numpy as np_

    stale = tmp_path / "old_snapshot.npz"
    np_.savez_compressed(stale, embeddings=np_.zeros((3, 384), dtype="float32"))
    assert not DataPoisoningGuard.snapshot_matches_shipped_corpus(stale)

    wrong = tmp_path / "wrong_digest.npz"
    np_.savez_compressed(
        wrong,
        embeddings=np_.zeros((3, 384), dtype="float32"),
        corpus_digest=np_.array("0" * 64),
    )
    assert not DataPoisoningGuard.snapshot_matches_shipped_corpus(wrong)


def test_every_canary_has_a_baseline(model, shipped_corpus) -> None:
    guard = _guard_on(model, shipped_corpus)
    assert len(guard._canary_baseline) == len(CANARY_EXAMPLES), (
        "a canary without a baseline is never compared against anything, so it "
        "silently stops being a canary"
    )
