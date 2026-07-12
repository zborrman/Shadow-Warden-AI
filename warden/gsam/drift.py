"""
GSAM drift & anti-inflation math — pure functions, no I/O.

Behavioural drift of an agent is measured as the EWMA of the total-variation
distance between its per-bucket action-frequency vector and a slowly-moving
baseline. The baseline update is poisoning-resistant: it only moves when the
current drift is *below* the quarantine threshold, mirroring the CausalArbiter
CPT 25%-shift gate (a burst of anomalous behaviour cannot drag the baseline out
to meet it).

Everything here is a pure function of its inputs so it can be property-tested
(drift ∈ [0,1], EWMA monotonic under constant input, baseline frozen while
quarantined). Persistence lives in `warden/gsam/rollup.py`.
"""
from __future__ import annotations

from collections.abc import Mapping

FreqVector = Mapping[str, float]


def normalize(counts: Mapping[str, float]) -> dict[str, float]:
    """L1-normalize a count vector into a probability distribution.

    An empty or all-zero input returns an empty distribution (distance to any
    other vector is then that vector's own mass / 2 ≤ 1 — still bounded).
    """
    total = float(sum(v for v in counts.values() if v > 0))
    if total <= 0:
        return {}
    return {k: float(v) / total for k, v in counts.items() if v > 0}


def total_variation(p: FreqVector, q: FreqVector) -> float:
    """Total-variation distance ½·Σ|p_i − q_i| over the key union.

    For two probability distributions this is in [0, 1]: 0 = identical, 1 =
    disjoint support. Inputs are normalized defensively so callers may pass raw
    counts.
    """
    pn = normalize(p) if p else {}
    qn = normalize(q) if q else {}
    keys = set(pn) | set(qn)
    if not keys:
        return 0.0
    l1 = sum(abs(pn.get(k, 0.0) - qn.get(k, 0.0)) for k in keys)
    return max(0.0, min(1.0, 0.5 * l1))


def ewma_drift(prev_drift: float, instantaneous_tv: float, lam: float) -> float:
    """EWMA update D_t = λ·tv + (1−λ)·D_{t−1}, clamped to [0, 1].

    λ (``settings.gsam_drift_lambda``, default 0.2) weights the newest sample.
    """
    lam = max(0.0, min(1.0, lam))
    tv = max(0.0, min(1.0, instantaneous_tv))
    prev = max(0.0, min(1.0, prev_drift))
    return max(0.0, min(1.0, lam * tv + (1.0 - lam) * prev))


def update_baseline(
    prev_mu: Mapping[str, float],
    current_freq: Mapping[str, float],
    lam: float,
    drift: float,
    quarantine_threshold: float,
) -> dict[str, float]:
    """Poisoning-resistant baseline update μ_t = (1−λ)·μ_{t−1} + λ·f_t.

    The baseline moves **only** when ``drift < quarantine_threshold``. While an
    agent is over threshold its baseline is frozen, so a sustained attack cannot
    normalize itself into the baseline. Returns the (possibly unchanged) μ.
    """
    prev = normalize(prev_mu) if prev_mu else {}
    if drift >= quarantine_threshold:
        return dict(prev)  # frozen while anomalous

    f = normalize(current_freq) if current_freq else {}
    if not prev:
        return dict(f)  # first observation seeds the baseline

    lam = max(0.0, min(1.0, lam))
    keys = set(prev) | set(f)
    updated = {k: (1.0 - lam) * prev.get(k, 0.0) + lam * f.get(k, 0.0) for k in keys}
    # Re-normalize to guard against float drift away from a unit distribution.
    return normalize(updated)


def anti_inflation_clamp(trust_gain: float, distinct_counterparts: int) -> float:
    """Clamp a positive trust gain to 0 unless it co-occurs with ≥2 distinct
    counterpart contracts in the window.

    Prevents an agent from inflating its own ``trust_score`` via self-dealing or
    a single colluding partner. Losses (negative gains) always apply.
    """
    if trust_gain <= 0:
        return trust_gain
    return trust_gain if distinct_counterparts >= 2 else 0.0
