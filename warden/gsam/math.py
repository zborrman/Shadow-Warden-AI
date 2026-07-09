"""
GSAM math engine — pure functions (predictive.py style, no numpy/scipy).

Everything here is deterministic and side-effect free so it can be unit-tested
without a DB, ClickHouse, or Redis:

  • session_cost()            — token + compute + MCP fee roll-up
  • roi()                     — return-on-investment with zero-cost guard
  • frequency_vector()        — normalised event-label distribution
  • weighted_cosine_distance()— 1 − weighted cosine similarity (behavioural drift)
  • ewma_drift()              — exponentially-weighted drift index
  • anti_inflation_score()    — marketplace anti-inflation compliance score

GDPR: these operate on counters / labels / costs only — never content.
"""
from __future__ import annotations

import math
from collections.abc import Mapping, Sequence

from warden.staff.economics import compute_cost_usd

# ── Cost / ROI ──────────────────────────────────────────────────────────────────


def session_cost(
    input_tokens: int,
    output_tokens: int,
    model: str = "",
    *,
    vm_seconds: float = 0.0,
    cpu_rate: float = 0.0,
    mcp_calls: int = 0,
    mcp_fee: float = 0.0,
) -> float:
    """Total USD cost of one agent session.

    tokens·price (via the shared staff pricing table) + compute-time
    (vm_seconds·cpu_rate) + MCP tool fees (mcp_calls·mcp_fee).
    """
    token_cost = compute_cost_usd(model, int(input_tokens), int(output_tokens))
    compute_cost = max(0.0, float(vm_seconds)) * max(0.0, float(cpu_rate))
    mcp_cost = max(0, int(mcp_calls)) * max(0.0, float(mcp_fee))
    return token_cost + compute_cost + mcp_cost


def roi(value_usd: float, cost_usd: float) -> float:
    """Return-on-investment ratio ((value − cost) / cost).

    Zero-cost guard: a non-positive cost yields 0.0 (no division, no infinity).
    """
    if cost_usd <= 0:
        return 0.0
    return (float(value_usd) - float(cost_usd)) / float(cost_usd)


# ── Drift ───────────────────────────────────────────────────────────────────────

# Security-relevant event labels weigh more in the drift distance so a shift in
# credential / payment behaviour dominates a shift in benign chatter.
DRIFT_WEIGHTS: dict[str, float] = {
    "mcp_call":            2.0,
    "billing_event":       1.5,
    "marketplace_action":  1.5,
    "token_cost":          1.0,
    "agent_span":          1.0,
}


def frequency_vector(labels: Sequence[str]) -> dict[str, float]:
    """Normalised frequency distribution of event labels (sums to 1.0)."""
    counts: dict[str, int] = {}
    for label in labels:
        key = str(label)
        counts[key] = counts.get(key, 0) + 1
    total = sum(counts.values())
    if total == 0:
        return {}
    return {k: v / total for k, v in counts.items()}


def weighted_cosine_distance(
    a: Mapping[str, float],
    b: Mapping[str, float],
    weights: Mapping[str, float] | None = None,
) -> float:
    """1 − weighted cosine similarity, clamped to [0, 1].

    An empty vector on either side is treated as maximal distance (1.0) so a
    brand-new behaviour profile registers as a full deviation.
    """
    keys = set(a) | set(b)
    if not keys:
        return 0.0

    def w(k: str) -> float:
        return float(weights.get(k, 1.0)) if weights else 1.0

    dot = sum(w(k) * a.get(k, 0.0) * b.get(k, 0.0) for k in keys)
    na = math.sqrt(sum(w(k) * a.get(k, 0.0) ** 2 for k in keys))
    nb = math.sqrt(sum(w(k) * b.get(k, 0.0) ** 2 for k in keys))
    if na == 0.0 or nb == 0.0:
        return 1.0
    cos = dot / (na * nb)
    return max(0.0, min(1.0, 1.0 - cos))


def ewma_drift(prev: float, dist: float, lam: float) -> float:
    """Exponentially-weighted moving-average drift index.

    lam·dist + (1 − lam)·prev, with lam clamped to [0, 1].
    """
    lam = max(0.0, min(1.0, float(lam)))
    return lam * float(dist) + (1.0 - lam) * float(prev)


def blend_vectors(
    prev: Mapping[str, float],
    new: Mapping[str, float],
    lam: float,
) -> dict[str, float]:
    """EWMA-blend two frequency vectors so the baseline profile tracks slowly."""
    lam = max(0.0, min(1.0, float(lam)))
    keys = set(prev) | set(new)
    return {k: lam * new.get(k, 0.0) + (1.0 - lam) * prev.get(k, 0.0) for k in keys}


# ── Anti-inflation compliance ────────────────────────────────────────────────────

# Strong patterns are high-confidence inflation signals (weight 3.0); weak ones
# are soft signals (weight 1.0). A CRITICAL dimension only trips when two or more
# distinct STRONG patterns co-occur — a single strong signal must never trip it.
STRONG_PATTERNS: frozenset[str] = frozenset({
    "repeated_identical_calls",
    "cost_spike_no_value",
    "circular_agent_calls",
    "token_padding",
    "self_dealing",
})
WEAK_PATTERNS: frozenset[str] = frozenset({
    "elevated_frequency",
    "off_baseline_model",
    "minor_latency_drift",
    "new_counterparty",
})

_STRONG_W = 3.0
_WEAK_W = 1.0
# Penalty normaliser — total weighted penalty of this size drives the score to 0.
_PENALTY_NORM = 10.0
# When a critical dimension trips, the score is hard-capped no higher than this.
_CRITICAL_CAP = 0.4


def anti_inflation_score(patterns: Sequence[str]) -> dict:
    """Marketplace anti-inflation compliance score in [0, 1] (1.0 = clean).

    Returns the score plus the classification breakdown so callers can render
    an explanation. ``critical`` is True only when ≥2 distinct strong patterns
    co-occur (co-occurrence rule).
    """
    strong = sorted({p for p in patterns if p in STRONG_PATTERNS})
    weak = sorted({p for p in patterns if p in WEAK_PATTERNS})
    penalty = _STRONG_W * len(strong) + _WEAK_W * len(weak)
    critical = len(strong) >= 2

    score = max(0.0, 1.0 - penalty / _PENALTY_NORM)
    if critical:
        score = min(score, _CRITICAL_CAP)

    return {
        "score":           round(score, 4),
        "critical":        critical,
        "penalty":         round(penalty, 4),
        "strong_patterns": strong,
        "weak_patterns":   weak,
    }
