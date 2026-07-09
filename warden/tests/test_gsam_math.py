"""GSAM PR 3 — math engine (GSAM-03): pure functions, no DB/CH/Redis."""
from __future__ import annotations

import pytest

from warden.gsam.math import (
    anti_inflation_score,
    blend_vectors,
    ewma_drift,
    frequency_vector,
    roi,
    session_cost,
    weighted_cosine_distance,
)

# ── session_cost ─────────────────────────────────────────────────────────────────

def test_session_cost_tokens_only() -> None:
    # Haiku: $0.80/MTok in, $4.00/MTok out
    cost = session_cost(1_000_000, 1_000_000, "claude-haiku-4-5-20251001")
    assert abs(cost - (0.80 + 4.00)) < 1e-9


def test_session_cost_adds_compute_and_mcp() -> None:
    cost = session_cost(
        0, 0, "claude-haiku-4-5-20251001",
        vm_seconds=10.0, cpu_rate=0.001, mcp_calls=5, mcp_fee=0.01,
    )
    assert abs(cost - (10.0 * 0.001 + 5 * 0.01)) < 1e-9


def test_session_cost_negative_inputs_clamped() -> None:
    cost = session_cost(0, 0, "", vm_seconds=-5, cpu_rate=1.0, mcp_calls=-3, mcp_fee=1.0)
    assert cost == 0.0


# ── roi ──────────────────────────────────────────────────────────────────────────

def test_roi_positive() -> None:
    assert roi(150.0, 100.0) == pytest.approx(0.5)


def test_roi_zero_cost_guard() -> None:
    assert roi(100.0, 0.0) == 0.0
    assert roi(100.0, -5.0) == 0.0


def test_roi_loss() -> None:
    assert roi(50.0, 100.0) == pytest.approx(-0.5)


# ── frequency_vector ─────────────────────────────────────────────────────────────

def test_frequency_vector_normalises() -> None:
    vec = frequency_vector(["a", "a", "b", "c"])
    assert vec["a"] == pytest.approx(0.5)
    assert vec["b"] == pytest.approx(0.25)
    assert abs(sum(vec.values()) - 1.0) < 1e-9


def test_frequency_vector_empty() -> None:
    assert frequency_vector([]) == {}


# ── weighted_cosine_distance ─────────────────────────────────────────────────────

def test_cosine_distance_identical_is_zero() -> None:
    v = {"a": 0.5, "b": 0.5}
    assert weighted_cosine_distance(v, v) == pytest.approx(0.0, abs=1e-9)


def test_cosine_distance_orthogonal_is_one() -> None:
    assert weighted_cosine_distance({"a": 1.0}, {"b": 1.0}) == pytest.approx(1.0)


def test_cosine_distance_empty_side_is_max() -> None:
    assert weighted_cosine_distance({}, {"a": 1.0}) == 1.0


def test_cosine_distance_both_empty_is_zero() -> None:
    assert weighted_cosine_distance({}, {}) == 0.0


def test_cosine_distance_weights_amplify() -> None:
    a = {"mcp_call": 0.5, "agent_span": 0.5}
    b = {"mcp_call": 0.9, "agent_span": 0.1}
    weights = {"mcp_call": 5.0, "agent_span": 1.0}
    d_weighted = weighted_cosine_distance(a, b, weights)
    d_plain = weighted_cosine_distance(a, b)
    assert 0.0 <= d_weighted <= 1.0
    assert d_weighted != d_plain


# ── ewma_drift + convergence ─────────────────────────────────────────────────────

def test_ewma_drift_step() -> None:
    assert ewma_drift(0.0, 1.0, 0.2) == pytest.approx(0.2)
    assert ewma_drift(0.2, 1.0, 0.2) == pytest.approx(0.36)


def test_ewma_drift_converges_to_constant_distance() -> None:
    val = 0.0
    for _ in range(200):
        val = ewma_drift(val, 0.8, 0.2)
    assert val == pytest.approx(0.8, abs=1e-3)


def test_ewma_lambda_clamped() -> None:
    # lambda > 1 clamps to 1 → output equals the new distance
    assert ewma_drift(0.3, 0.9, 5.0) == pytest.approx(0.9)
    # lambda < 0 clamps to 0 → output equals prev
    assert ewma_drift(0.3, 0.9, -1.0) == pytest.approx(0.3)


def test_ewma_crosses_quarantine_threshold() -> None:
    """A sustained high distance eventually pushes EWMA past 0.85."""
    val = 0.0
    crossings = 0
    for _ in range(50):
        val = ewma_drift(val, 1.0, 0.2)
        if val >= 0.85:
            crossings += 1
    assert crossings > 0
    assert val < 1.0  # never overshoots the driving distance


# ── blend_vectors ────────────────────────────────────────────────────────────────

def test_blend_vectors_tracks_new() -> None:
    prev = {"a": 1.0}
    new = {"b": 1.0}
    merged = blend_vectors(prev, new, 0.5)
    assert merged["a"] == pytest.approx(0.5)
    assert merged["b"] == pytest.approx(0.5)


# ── anti_inflation_score ─────────────────────────────────────────────────────────

def test_anti_inflation_clean() -> None:
    res = anti_inflation_score([])
    assert res["score"] == 1.0
    assert res["critical"] is False


def test_anti_inflation_single_strong_does_not_trip_critical() -> None:
    """Co-occurrence rule: one strong pattern must NOT trip a critical dimension."""
    res = anti_inflation_score(["cost_spike_no_value"])
    assert res["critical"] is False
    # 1 strong (w=3) → penalty 3 → score 0.7, well above the critical cap
    assert res["score"] == pytest.approx(0.7)


def test_anti_inflation_two_strong_trips_critical() -> None:
    res = anti_inflation_score(["cost_spike_no_value", "circular_agent_calls"])
    assert res["critical"] is True
    assert res["score"] <= 0.4


def test_anti_inflation_weak_only() -> None:
    res = anti_inflation_score(["elevated_frequency", "new_counterparty"])
    assert res["critical"] is False
    assert res["score"] == pytest.approx(0.8)


def test_anti_inflation_dedups_patterns() -> None:
    res = anti_inflation_score(["token_padding", "token_padding", "token_padding"])
    assert res["strong_patterns"] == ["token_padding"]
    assert res["critical"] is False


def test_anti_inflation_ignores_unknown_patterns() -> None:
    res = anti_inflation_score(["not_a_real_pattern", "another_fake"])
    assert res["score"] == 1.0
    assert res["strong_patterns"] == []
    assert res["weak_patterns"] == []
