"""
warden/brain/conformal.py
━━━━━━━━━━━━━━━━━━━━━━━━━
Split-conformal threshold calibration (Deep-Eng Phase 3).

Replaces a hand-picked static threshold (e.g. SEMANTIC_THRESHOLD=0.72) with a
threshold derived from a held-out calibration set, giving a *bounded*
false-positive rate guarantee rather than an intuition-based cutoff.

Given a calibration set of benign-text scores (the same score the live
detector would compute — cosine/hyperbolic similarity, topology noise score,
etc.), :func:`split_conformal_threshold` returns the smallest threshold such
that, under exchangeability of the calibration set and future benign inputs,
at most ``epsilon`` of future benign texts score at or above it:

    P(benign_score >= threshold) <= epsilon

This is a pure function — no I/O, no model loading — so it is cheap to unit
test and safe to call from any recalibration job (e.g. nightly, from labeled
logs) without touching live detection behaviour until a caller explicitly
wires the result in.

Not wired into any live detector by this module. Call sites choose whether
and how to use the returned threshold.
"""
from __future__ import annotations

import math
from collections.abc import Sequence


def split_conformal_threshold(
    calibration_scores: Sequence[float], epsilon: float
) -> float:
    """
    Compute the split-conformal threshold bounding the false-positive rate at
    ``epsilon`` over a calibration set of benign-text scores.

    ``epsilon`` must be in (0, 1) — e.g. 0.05 for a 5% false-positive-rate
    bound. Uses the standard finite-sample conformal correction: for ``n``
    calibration scores sorted ascending, the threshold is the score at rank
    ``ceil((n + 1) * (1 - epsilon))``. When that rank exceeds ``n`` (too few
    calibration samples to guarantee the bound), returns ``math.inf`` — a
    threshold that never flags, rather than a coverage guarantee that can't
    be honestly made.

    Monotonic: a smaller ``epsilon`` (stricter FPR bound) never yields a
    lower threshold — fewer false positives requires a higher bar.
    """
    if not calibration_scores:
        raise ValueError("calibration_scores must be non-empty")
    if not 0.0 < epsilon < 1.0:
        raise ValueError("epsilon must be in (0, 1)")

    scores = sorted(float(s) for s in calibration_scores)
    n = len(scores)
    rank = math.ceil((n + 1) * (1 - epsilon))
    if rank > n:
        return math.inf
    return scores[rank - 1]


def empirical_false_positive_rate(
    calibration_scores: Sequence[float], threshold: float
) -> float:
    """Fraction of ``calibration_scores`` that would be flagged at ``threshold``.

    A sanity-check helper for the caller: after calibrating, verify the
    realized FPR on the same (or a fresh held-out) calibration set is at or
    below the target ``epsilon``.
    """
    if not calibration_scores:
        return 0.0
    flagged = sum(1 for s in calibration_scores if s >= threshold)
    return flagged / len(calibration_scores)
