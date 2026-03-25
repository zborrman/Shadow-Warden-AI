"""
warden/brain/hyperbolic.py
━━━━━━━━━━━━━━━━━━━━━━━━━
Poincaré ball model hyperbolic embedding utilities.

Projects L2-normalized Euclidean embeddings (e.g. MiniLM 384-dim) into the
Poincaré ball D^n (curvature c = 1) and computes hyperbolic distance for
improved separation of hierarchically-structured attack patterns.

Why hyperbolic space?
─────────────────────
Euclidean space grows polynomially with radius.  Hyperbolic space grows
exponentially — the same volume that fills an entire Euclidean ball fits in
a thin ring near the Poincaré ball boundary.

Multi-layer jailbreaks ("ignore instructions" nested inside "act as a character
in a story who then explains...") form deep hierarchies.  In Euclidean cosine
space these hierarchical attacks can appear close to benign requests that share
surface vocabulary.  In hyperbolic space their hierarchical depth pushes them
toward the ball boundary, away from benign requests which cluster near the
centre — giving better precision without increasing false positives.

Operations
──────────
  to_poincare_ball(v)                   — exponential map R^n → D^n
  hyperbolic_distance(u, v)             — Poincaré ball metric
  max_hyperbolic_similarity(q, corpus)  — vectorized batch similarity

All operations are pure NumPy.  No additional dependencies beyond what
sentence-transformers already requires.
"""
from __future__ import annotations

import math

import numpy as np

# Curvature of the Poincaré ball (c = 1 → unit ball)
_CURVATURE: float = 1.0
# Clip radius: keep all points strictly inside ball to avoid log(0) / arcosh(x < 1)
_BALL_RADIUS: float = 1.0 - 1e-5


# ── Projection ────────────────────────────────────────────────────────────────


def to_poincare_ball(v: np.ndarray, c: float = _CURVATURE) -> np.ndarray:
    """
    Project a Euclidean vector into the Poincaré ball via the exponential map
    at the origin:

        expmap_0(v) = tanh(√c · ‖v‖ / 2) · v / (√c · ‖v‖ / 2)

    For L2-normalized inputs (‖v‖ = 1, c = 1):
        expmap_0(v) = tanh(0.5) · v  ≈ 0.462 · v

    This places all corpus and query vectors uniformly inside the ball interior,
    preserving relative angles while enabling hyperbolic distance computation.
    """
    norm = float(np.linalg.norm(v))
    if norm < 1e-9:
        return v.copy()
    sqrt_c = math.sqrt(c)
    half_arg = sqrt_c * norm / 2.0
    scale = math.tanh(half_arg) / half_arg
    result = v * scale
    # Clip to stay strictly inside the ball
    r = float(np.linalg.norm(result))
    if r >= _BALL_RADIUS:
        result = result * (_BALL_RADIUS / r)
    return result


def _to_poincare_ball_batch(corpus: np.ndarray, c: float = _CURVATURE) -> np.ndarray:
    """Vectorized projection of (N, D) corpus matrix into the Poincaré ball."""
    norms = np.linalg.norm(corpus, axis=1, keepdims=True)          # (N, 1)
    sqrt_c = math.sqrt(c)
    half_args = sqrt_c * norms / 2.0                               # (N, 1)
    # Avoid division by zero for zero vectors
    safe_args = np.where(norms < 1e-9, 1.0, half_args)
    scales = np.where(norms < 1e-9, 1.0, np.tanh(safe_args) / safe_args)
    projected = corpus * scales                                     # (N, D)
    # Clip norms that exceed ball radius
    proj_norms = np.linalg.norm(projected, axis=1, keepdims=True)  # (N, 1)
    too_large  = proj_norms >= _BALL_RADIUS
    projected  = np.where(
        too_large,
        projected * (_BALL_RADIUS / np.maximum(proj_norms, 1e-9)),
        projected,
    )
    return projected


# ── Distance and similarity ───────────────────────────────────────────────────


def hyperbolic_distance(u: np.ndarray, v: np.ndarray, c: float = _CURVATURE) -> float:
    """
    Poincaré ball distance (numerically stable form):

        d(u, v) = arcosh(1 + 2c‖u − v‖² / ((1 − c‖u‖²)(1 − c‖v‖²)))

    Returns 0.0 if either point is outside the ball or if numerics fail.
    """
    diff_sq = float(np.sum((u - v) ** 2))
    u_n2    = min(float(np.sum(u ** 2)), _BALL_RADIUS ** 2)
    v_n2    = min(float(np.sum(v ** 2)), _BALL_RADIUS ** 2)
    denom   = (1.0 - c * u_n2) * (1.0 - c * v_n2)
    if denom < 1e-9:
        return 0.0
    arg = 1.0 + 2.0 * c * diff_sq / denom
    return float(np.arccosh(max(arg, 1.0)))


# ── Vectorized corpus similarity ──────────────────────────────────────────────


def max_hyperbolic_similarity(
    query: np.ndarray,
    corpus: np.ndarray,
) -> tuple[float, int]:
    """
    Find the maximum hyperbolic similarity between a query vector and a corpus
    matrix, using the vectorized Poincaré ball distance.

    Parameters
    ----------
    query  : (D,) float32 — Euclidean embedding (projected into ball internally)
    corpus : (N, D) float32 — corpus embeddings (projected into ball internally)

    Returns
    -------
    (max_sim, best_idx)
      max_sim  — highest similarity score in (0, 1], where sim = 1/(1 + dist)
      best_idx — index of the closest corpus entry
    """
    if corpus.shape[0] == 0:
        return 0.0, 0

    # Project into Poincaré ball
    q_hyp = to_poincare_ball(query)                               # (D,)
    c_hyp = _to_poincare_ball_batch(corpus)                       # (N, D)

    # Vectorized hyperbolic distance: d(q, corpus_i) for all i
    q_vec   = q_hyp.reshape(1, -1)                               # (1, D)
    diff_sq = np.sum((c_hyp - q_vec) ** 2, axis=1)               # (N,)

    q_n2    = np.clip(np.sum(q_vec ** 2), 0.0, _BALL_RADIUS ** 2)          # scalar
    c_n2    = np.clip(np.sum(c_hyp ** 2, axis=1), 0.0, _BALL_RADIUS ** 2)  # (N,)

    denom   = np.maximum((1.0 - q_n2) * (1.0 - c_n2), 1e-9)     # (N,)
    arg     = np.maximum(1.0 + 2.0 * diff_sq / denom, 1.0)       # (N,)
    dists   = np.arccosh(arg)                                     # (N,)
    sims    = 1.0 / (1.0 + dists)                                 # (N,) ∈ (0, 1]

    best_idx = int(np.argmax(sims))
    return float(sims[best_idx]), best_idx
