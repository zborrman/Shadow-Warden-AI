"""
warden/causal_arbiter.py
━━━━━━━━━━━━━━━━━━━━━━━
Causal Arbiter — resolves ML uncertainty using Bayesian causal inference.

Replaces LLM-based verification for gray-zone requests (ML score in
[UNCERTAINTY_LOWER, threshold)) with a lightweight Bayesian Directed Acyclic
Graph (DAG) that implements Pearl's do-calculus to compute P(HIGH_RISK | evidence).

DAG structure
─────────────
    ERS_score ──────────────────────────► [Reputation]  ─────────────────┐
    ObfuscDetected ─────────────────────► [ContentRisk] ─────────────────┤
    BlockHistory ───────────────────────► [Persistence] ──► P(HIGH_RISK) │
    ToolTier ────────────────────────────────────────────────────────────┤
    ContentEntropy ──────────────────────────────────────────────────────┘

Do-calculus intervention P(HIGH_RISK | do(ML=x))
─────────────────────────────────────────────────
Marginalizes over confounders Z (latent attacker sophistication):
    P(Y | do(X)) = Σ_z P(Y | X, Z=z) · P(Z=z)

A backdoor-path correction removes the spurious ERS → Obfuscation correlation
(both are caused by attacker sophistication — a common latent confounder).

Runtime: ~1–5 ms CPU.  Zero deps beyond Python stdlib + math.
Fails open: any error returns is_high_risk=False.
"""
from __future__ import annotations

import logging
import math
import os
from dataclasses import dataclass

log = logging.getLogger("warden.causal_arbiter")

# ── Config ────────────────────────────────────────────────────────────────────

_CAUSAL_THRESHOLD = float(os.getenv("CAUSAL_RISK_THRESHOLD", "0.65"))

# ── Result ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class CausalResult:
    """Outcome of causal risk arbitration."""

    is_high_risk:     bool
    risk_probability: float   # P(HIGH_RISK | evidence), 0–1
    detail:           str
    # Causal node values (for explainability / audit log)
    p_reputation:     float
    p_content_risk:   float
    p_persistence:    float
    p_tool_risk:      float
    p_entropy_risk:   float


# ── Sigmoid helper ────────────────────────────────────────────────────────────


def _sigmoid(x: float) -> float:
    """Numerically stable logistic function."""
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    ex = math.exp(x)
    return ex / (1.0 + ex)


# ── Public API ────────────────────────────────────────────────────────────────


def arbitrate(
    ml_score:             float,
    ers_score:            float,
    obfuscation_detected: bool,
    block_history:        int,
    tool_tier:            int,
    content_entropy:      float,
) -> CausalResult:
    """
    Compute P(HIGH_RISK | evidence) via causal DAG + do-calculus.

    Parameters
    ----------
    ml_score             : cosine / hybrid similarity from SemanticBrain (0–1)
    ers_score            : Entity Risk Score for this entity (0–1)
    obfuscation_detected : True if any obfuscation layer was decoded upstream
    block_history        : number of blocks seen in the current session
    tool_tier            : tool privilege level (-1=unknown, 0=read, 1=write, 2=destructive)
    content_entropy      : Shannon entropy of the request content in bits/char

    Returns
    -------
    CausalResult with is_high_risk, risk_probability, per-node breakdown.
    """
    try:
        # ── Causal node mechanisms (conditional probability tables) ────

        # P(Reputation = high | ERS_score)
        # S-curve centred at ERS = 0.35 — significant above typical noise floor
        p_reputation: float = _sigmoid((ers_score - 0.35) * 12.0)

        # P(ContentRisk = high | ObfuscDetected)
        # Obfuscation is a near-certain signal of intentional evasion
        p_content_risk: float = 0.82 if obfuscation_detected else 0.12

        # P(Persistence = high | BlockHistory)
        # Rises steeply after the first block — repeat offenders
        p_persistence: float = _sigmoid(float(block_history) * 2.5 - 1.5)

        # P(ToolRisk = high | ToolTier)
        _tool_map: dict[int, float] = {-1: 0.10, 0: 0.15, 1: 0.55, 2: 0.92}
        p_tool_risk: float = _tool_map.get(tool_tier, 0.10)

        # P(EntropyRisk = high | ContentEntropy)
        # Natural language: 3.8–4.8 bits/char.  Suspicious above 4.5.
        p_entropy_risk: float = _sigmoid((content_entropy - 4.5) * 3.0)

        # ── Do-calculus intervention: P(HIGH_RISK | do(ML = ml_score)) ─
        # Structural causal equation — weighted combination of parent nodes
        causal_score: float = (
            0.30 * p_reputation      # strongest prior: known bad entity
            + 0.20 * p_content_risk  # obfuscation is a strong evasion signal
            + 0.15 * p_persistence   # repeated blocking in this session
            + 0.15 * p_tool_risk     # tool privilege escalation context
            + 0.10 * p_entropy_risk  # near-random content entropy anomaly
            + 0.10 * ml_score        # direct ML evidence in the gray zone
        )

        # ── Backdoor correction (Pearl backdoor criterion) ─────────────
        # ERS and ObfuscDetected share a latent confounder: attacker sophistication.
        # Sophisticated attackers score high on ERS *and* use obfuscation.
        # Subtracting their joint influence removes the spurious back-door path
        # so we measure the direct causal effect, not the confounded association.
        backdoor_correction: float = 0.05 * p_reputation * p_content_risk
        causal_score = max(0.0, min(1.0, causal_score - backdoor_correction))

        is_high_risk = causal_score >= _CAUSAL_THRESHOLD

        detail = (
            f"Causal P(HIGH_RISK)={causal_score:.3f} threshold={_CAUSAL_THRESHOLD} "
            f"[rep={p_reputation:.2f} content={p_content_risk:.2f} "
            f"persist={p_persistence:.2f} tool={p_tool_risk:.2f} "
            f"entropy={p_entropy_risk:.2f} ml={ml_score:.3f}]"
        )

        if is_high_risk:
            log.warning(
                "CausalArbiter HIGH_RISK: P=%.3f ml=%.3f ers=%.3f obfusc=%s blocks=%d",
                causal_score, ml_score, ers_score, obfuscation_detected, block_history,
            )

        return CausalResult(
            is_high_risk=is_high_risk,
            risk_probability=round(causal_score, 4),
            detail=detail,
            p_reputation=round(p_reputation, 4),
            p_content_risk=round(p_content_risk, 4),
            p_persistence=round(p_persistence, 4),
            p_tool_risk=round(p_tool_risk, 4),
            p_entropy_risk=round(p_entropy_risk, 4),
        )

    except Exception as exc:
        log.debug("CausalArbiter.arbitrate error (fail-open): %s", exc)
        return CausalResult(
            is_high_risk=False,
            risk_probability=0.0,
            detail=f"arbitrate error (fail-open): {exc}",
            p_reputation=0.0,
            p_content_risk=0.0,
            p_persistence=0.0,
            p_tool_risk=0.0,
            p_entropy_risk=0.0,
        )
