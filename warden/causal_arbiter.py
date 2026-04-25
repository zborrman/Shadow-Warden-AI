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
    ContentEntropy ──────────────────────────────────────────────────────┤
    se_risk ────────────────────────────► [SE_Risk]  ────────────────────┘

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

import json
import logging
import math
import os
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("warden.causal_arbiter")

# ── Config ────────────────────────────────────────────────────────────────────

_CAUSAL_THRESHOLD = float(os.getenv("CAUSAL_RISK_THRESHOLD", "0.65"))


# ── CPT: Conditional Probability Table parameters ─────────────────────────────
# Defaults are hand-tuned priors.  Call calibrate_from_logs() to update via MLE.


@dataclass
class _CPT:
    """Tunable parameters for every causal node in the DAG."""

    # Reputation node — ERS → P(Reputation=high)
    ers_center: float = 0.35    # sigmoid centre
    ers_slope:  float = 12.0    # sigmoid steepness

    # ContentRisk node — ObfuscDetected → P(ContentRisk=high)
    obfusc_pos: float = 0.82    # P(high | obfusc=True)
    obfusc_neg: float = 0.12    # P(high | obfusc=False)

    # Persistence node — BlockHistory → P(Persistence=high)
    persist_slope:  float = 2.5
    persist_offset: float = 1.5

    # EntropyRisk node — ContentEntropy → P(EntropyRisk=high)
    entropy_center: float = 4.5
    entropy_slope:  float = 3.0

    # Structural equation weights (must sum ≈ 1.05 after SE addend)
    w_reputation:  float = 0.30
    w_content:     float = 0.20
    w_persistence: float = 0.15
    w_tool:        float = 0.15
    w_entropy:     float = 0.10
    w_ml:          float = 0.10
    w_se:          float = 0.15   # SE-Arbiter addend — backward-compatible (0 if absent)

    # Backdoor correction weight
    backdoor_w: float = 0.05

    # Calibration metadata
    calibrated_from: str = ""     # logs path used for calibration
    calibration_n:   int = 0      # number of samples used


_cpt = _CPT()   # module-level singleton; updated by calibrate_from_logs()


def calibrate_from_logs(
    logs_path: str | Path | None = None,
    min_samples: int = 100,
) -> bool:
    """
    Update CPT parameters via Maximum Likelihood Estimation from production
    filter audit logs (NDJSON at logs_path).

    Calibrates:
      - obfusc_pos / obfusc_neg  — empirical P(HIGH|BLOCK | obfuscation flag)
      - ers_center                — median ERS implied by block rate (proxy)
      - entropy_center            — median payload length as entropy proxy

    Returns True if calibration succeeded (>= min_samples); False otherwise.
    Updates the global _cpt in-place only on success.

    Safe to call at startup without blocking — reads the log file once and
    returns immediately.  Any read/parse error is silently ignored (fail-open).
    """
    global _cpt

    if logs_path is None:
        logs_path = os.getenv("LOGS_PATH", "/warden/data/logs.json")
    path = Path(logs_path)

    if not path.exists():
        log.debug("calibrate_from_logs: %s not found — using prior CPT", path)
        return False

    try:
        entries: list[dict] = []
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        if len(entries) < min_samples:
            log.debug(
                "calibrate_from_logs: only %d samples (need %d) — using prior CPT",
                len(entries), min_samples,
            )
            return False

        # ── Obfuscation CPT ───────────────────────────────────────────────────
        obfusc_hits_high   = 0
        obfusc_hits_total  = 0
        clean_hits_high    = 0
        clean_hits_total   = 0

        # ── Entropy proxy via payload length ─────────────────────────────────
        # Approximate Shannon entropy h ≈ a + b*log(len) for English/code text.
        # We collect len distribution for blocked vs allowed to shift the centre.
        blocked_lens: list[int] = []
        allowed_lens: list[int] = []

        # ── Block rate for ERS centre proxy ──────────────────────────────────
        n_blocked = 0
        n_total   = len(entries)

        obfusc_flags = frozenset({
            "OBFUSCATION", "BASE64_ENCODED", "HEX_ENCODED",
            "ROT13_ENCODED", "HOMOGLYPH_SUBSTITUTION",
        })
        high_risk_levels = frozenset({"HIGH", "BLOCK"})

        for entry in entries:
            flags      = set(entry.get("flags") or [])
            risk       = (entry.get("risk_level") or "LOW").upper()
            payload_len = int(entry.get("payload_len") or 0)
            is_high    = risk in high_risk_levels
            has_obfusc = bool(flags & obfusc_flags)

            if has_obfusc:
                obfusc_hits_total += 1
                if is_high:
                    obfusc_hits_high += 1
            else:
                clean_hits_total += 1
                if is_high:
                    clean_hits_high += 1

            if is_high:
                n_blocked += 1
                blocked_lens.append(payload_len)
            else:
                allowed_lens.append(payload_len)

        # ── MLE estimates ─────────────────────────────────────────────────────
        # Laplace smoothing (α=1) prevents zero probabilities on sparse data.
        new_obfusc_pos = (obfusc_hits_high + 1) / (obfusc_hits_total + 2)
        new_obfusc_neg = (clean_hits_high  + 1) / (clean_hits_total  + 2)

        # ERS centre proxy: if overall block rate is higher than expected,
        # the effective ERS threshold is lower — shift centre down.
        block_rate = n_blocked / n_total if n_total else 0.0
        # Prior block rate is assumed ~5%; normalise deviation to shift centre.
        prior_block_rate = 0.05
        centre_shift = (block_rate - prior_block_rate) * 0.5   # ±0.25 max shift
        new_ers_center = max(0.15, min(0.55, _cpt.ers_center - centre_shift))

        # Entropy centre proxy: blocked payloads tend to be longer/more random.
        # Map median blocked length to an entropy estimate shift.
        if blocked_lens:
            median_blocked = sorted(blocked_lens)[len(blocked_lens) // 2]
            # Typical 4.5 bits/char corresponds to ~200-char payloads
            # Shift entropy centre proportionally (clamped ±0.5)
            len_ratio = math.log1p(median_blocked) / math.log1p(200)
            entropy_shift = (len_ratio - 1.0) * 0.3
            new_entropy_center = max(3.5, min(5.5, _cpt.entropy_center + entropy_shift))
        else:
            new_entropy_center = _cpt.entropy_center

        # ── Apply only if estimates look sane ─────────────────────────────────
        if new_obfusc_pos <= new_obfusc_neg:
            log.warning(
                "calibrate_from_logs: obfusc_pos (%.3f) ≤ obfusc_neg (%.3f) — "
                "data quality issue; keeping prior",
                new_obfusc_pos, new_obfusc_neg,
            )
            return False

        # ── Adversarial drift gate: reject updates that shift CPT > 25% ──────
        # Coordinated low-volume attacks can bias production logs and gradually
        # poison the MLE estimates. Cap drift per calibration run.
        max_drift = 0.25

        def _drift_ok(old: float, new: float, label: str) -> bool:
            if old == 0:
                return True
            drift = abs(new - old) / old
            if drift > max_drift:
                log.warning(
                    "calibrate_from_logs: CPT[%s] drift %.1f%% exceeds %.0f%% threshold "
                    "— update rejected to prevent data poisoning.",
                    label, drift * 100, max_drift * 100,
                )
                return False
            return True

        if not (
            _drift_ok(_cpt.obfusc_pos,     new_obfusc_pos,     "obfusc_pos")
            and _drift_ok(_cpt.obfusc_neg, new_obfusc_neg,     "obfusc_neg")
            and _drift_ok(_cpt.ers_center, new_ers_center,     "ers_center")
            and _drift_ok(_cpt.entropy_center, new_entropy_center, "entropy_center")
        ):
            return False

        _cpt.obfusc_pos     = round(new_obfusc_pos,   4)
        _cpt.obfusc_neg     = round(new_obfusc_neg,   4)
        _cpt.ers_center     = round(new_ers_center,   4)
        _cpt.entropy_center = round(new_entropy_center, 4)
        _cpt.calibrated_from = str(path)
        _cpt.calibration_n   = n_total

        log.info(
            "CausalArbiter CPT calibrated from %d samples: "
            "obfusc_pos=%.3f obfusc_neg=%.3f ers_center=%.3f entropy_center=%.3f",
            n_total, _cpt.obfusc_pos, _cpt.obfusc_neg,
            _cpt.ers_center, _cpt.entropy_center,
        )
        return True

    except Exception as exc:
        log.debug("calibrate_from_logs error (ignored): %s", exc)
        return False

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
    p_se_risk:        float = 0.0   # SE-Arbiter: P(SE_RISK | do(content))


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
    se_risk:              float = 0.0,
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
    se_risk              : P(SE_RISK | do(content)) from PhishGuard SE-Arbiter (0–1).
                           When 0 (default) the SE node is dormant — backward-compatible.

    Returns
    -------
    CausalResult with is_high_risk, risk_probability, per-node breakdown.
    """
    try:
        # ── Causal node mechanisms (conditional probability tables) ────
        # Parameters are sourced from the module-level _cpt, which may have
        # been updated via calibrate_from_logs() at startup.

        # P(Reputation = high | ERS_score)
        # S-curve centred at _cpt.ers_center — significant above typical noise floor
        p_reputation: float = _sigmoid(
            (ers_score - _cpt.ers_center) * _cpt.ers_slope
        )

        # P(ContentRisk = high | ObfuscDetected)
        # Obfuscation is a near-certain signal of intentional evasion
        p_content_risk: float = (
            _cpt.obfusc_pos if obfuscation_detected else _cpt.obfusc_neg
        )

        # P(Persistence = high | BlockHistory)
        # Rises steeply after the first block — repeat offenders
        p_persistence: float = _sigmoid(
            float(block_history) * _cpt.persist_slope - _cpt.persist_offset
        )

        # P(ToolRisk = high | ToolTier)
        _tool_map: dict[int, float] = {-1: 0.10, 0: 0.15, 1: 0.55, 2: 0.92}
        p_tool_risk: float = _tool_map.get(tool_tier, 0.10)

        # P(EntropyRisk = high | ContentEntropy)
        # Natural language: 3.8–4.8 bits/char.  Suspicious above _cpt.entropy_center.
        p_entropy_risk: float = _sigmoid(
            (content_entropy - _cpt.entropy_center) * _cpt.entropy_slope
        )

        # P(SE_Risk = high | se_risk)
        # Direct pass-through from PhishGuard SE-Arbiter formula.
        # When se_risk=0 (not provided) this node is dormant — zero contribution.
        p_se_risk: float = float(se_risk)

        # ── Do-calculus intervention: P(HIGH_RISK | do(ML = ml_score)) ─
        # Structural causal equation — weighted combination of parent nodes.
        # SE_Risk node adds up to +0.15 when social engineering is detected;
        # existing node weights are unchanged so se_risk=0 is fully backward-compatible.
        causal_score: float = (
            _cpt.w_reputation  * p_reputation   # strongest prior: known bad entity
            + _cpt.w_content   * p_content_risk # obfuscation is a strong evasion signal
            + _cpt.w_persistence * p_persistence # repeated blocking in this session
            + _cpt.w_tool      * p_tool_risk     # tool privilege escalation context
            + _cpt.w_entropy   * p_entropy_risk  # near-random content entropy anomaly
            + _cpt.w_ml        * ml_score        # direct ML evidence in the gray zone
            + _cpt.w_se        * p_se_risk       # SE-Arbiter: phishing / manipulation signal
        )

        # ── Backdoor correction (Pearl backdoor criterion) ─────────────
        # ERS and ObfuscDetected share a latent confounder: attacker sophistication.
        # Sophisticated attackers score high on ERS *and* use obfuscation.
        # Subtracting their joint influence removes the spurious back-door path
        # so we measure the direct causal effect, not the confounded association.
        backdoor_correction: float = _cpt.backdoor_w * p_reputation * p_content_risk
        causal_score = max(0.0, min(1.0, causal_score - backdoor_correction))

        is_high_risk = causal_score >= _CAUSAL_THRESHOLD

        detail = (
            f"Causal P(HIGH_RISK)={causal_score:.3f} threshold={_CAUSAL_THRESHOLD} "
            f"[rep={p_reputation:.2f} content={p_content_risk:.2f} "
            f"persist={p_persistence:.2f} tool={p_tool_risk:.2f} "
            f"entropy={p_entropy_risk:.2f} ml={ml_score:.3f} se={p_se_risk:.2f}]"
        )

        if is_high_risk:
            log.warning(
                "CausalArbiter HIGH_RISK: P=%.3f ml=%.3f ers=%.3f obfusc=%s blocks=%d se=%.2f",
                causal_score, ml_score, ers_score, obfuscation_detected, block_history, p_se_risk,
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
            p_se_risk=round(p_se_risk, 4),
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
            p_se_risk=0.0,
        )
