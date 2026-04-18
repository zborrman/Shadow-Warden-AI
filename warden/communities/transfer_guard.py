"""
warden/communities/transfer_guard.py
──────────────────────────────────────
Causal Transfer Guard — anomaly detection for SEP document transfers.

Integrates the CausalArbiter's Bayesian DAG (Pearl do-calculus) into the
Syndicate Exchange Protocol to distinguish routine audit transfers from
suspicious exfiltration patterns before a document moves communities.

Decision latency target: < 20ms (Bayesian inference is pure-Python math,
no LLM involved).

Evidence mapping  (CausalArbiter node → SEP transfer context)
──────────────────────────────────────────────────────────────
  ml_score           ← entity data-class risk  (PHI/CLASSIFIED → 0.85+)
  ers_score          ← transfer velocity       (≥5 transfers/h → high)
  obfuscation_detected ← unusual peering policy (FULL_SYNC + new peering → True)
  block_history      ← previously REJECTED transfers in this peering
  tool_tier          ← peering policy tier     (MIRROR=0, REWRAP=1, FULL_SYNC=2)
  content_entropy    ← data-class entropy      (CLASSIFIED=3.9, GENERAL=1.0)
  se_risk            ← sequential-transfer burst flag (>10 in 5 min → 0.9)

Threshold: P(HIGH_RISK | evidence) ≥ TRANSFER_RISK_THRESHOLD (default 0.70)
→ transfer BLOCKED with reason detail.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass

log = logging.getLogger("warden.communities.transfer_guard")

# Block if posterior risk probability meets or exceeds this threshold.
_RISK_THRESHOLD = float(os.getenv("TRANSFER_RISK_THRESHOLD", "0.70"))

# Data-class → base ML-score mapping (mirrors SemanticBrain risk levels)
_DATA_CLASS_RISK: dict[str, float] = {
    "CLASSIFIED": 0.90,
    "PHI":        0.80,
    "FINANCIAL":  0.65,
    "PII":        0.55,
    "GENERAL":    0.20,
}

# Peering policy → tool_tier mapping (higher tier = more trust granted = lower risk)
_POLICY_TIER: dict[str, int] = {
    "MIRROR_ONLY":    0,  # read-only
    "REWRAP_ALLOWED": 1,  # can re-share internally
    "FULL_SYNC":      2,  # bidirectional
}

# Content entropy estimates per data class (bits/char)
_DATA_CLASS_ENTROPY: dict[str, float] = {
    "CLASSIFIED": 4.2,
    "PHI":        3.8,
    "FINANCIAL":  3.5,
    "PII":        3.0,
    "GENERAL":    1.8,
}


@dataclass
class TransferRiskDecision:
    allowed:    bool
    score:      float          # P(HIGH_RISK | evidence), 0–1
    reason:     str
    detail:     dict           # per-node breakdown from CausalArbiter
    latency_ms: float


def _redis():
    try:
        import redis as _r
        url = os.getenv("REDIS_URL", "redis://localhost:6379")
        if url.startswith("memory://"):
            return None
        return _r.from_url(url, decode_responses=True)
    except Exception:
        return None


def _transfer_velocity(source_community_id: str, window_seconds: int = 3600) -> int:
    """Count recent transfers from *source_community_id* in the last *window_seconds*."""
    r = _redis()
    if not r:
        return 0
    key = f"sep:transfer_velocity:{source_community_id}"
    try:
        now = int(time.time())
        # Remove old entries and count remaining
        r.zremrangebyscore(key, "-inf", now - window_seconds)
        count = r.zcard(key)
        # Record this transfer probe
        r.zadd(key, {f"{now}-{count}": now})
        r.expire(key, window_seconds * 2)
        return int(count)
    except Exception:
        return 0


def _burst_velocity(source_community_id: str, window_seconds: int = 300) -> int:
    """Count transfers from *source_community_id* in the last 5 minutes (burst detection)."""
    r = _redis()
    if not r:
        return 0
    key = f"sep:transfer_burst:{source_community_id}"
    try:
        now = int(time.time())
        r.zremrangebyscore(key, "-inf", now - window_seconds)
        count = r.zcard(key)
        r.zadd(key, {f"{now}-{count}": now})
        r.expire(key, window_seconds * 4)
        return int(count)
    except Exception:
        return 0


def _rejected_count(peering_id: str) -> int:
    """Count REJECTED transfers in this peering (from SQLite)."""
    try:
        from warden.communities.peering import list_transfers
        records = list_transfers(peering_id=peering_id, limit=50)
        return sum(1 for r in records if r.status == "REJECTED")
    except Exception:
        return 0


def evaluate_transfer_risk(
    source_community_id: str,
    target_community_id: str,
    peering_id:          str,
    entity_id:           str,
    data_class:          str = "GENERAL",
    peering_policy:      str = "MIRROR_ONLY",
    peering_age_days:    float = 30.0,
) -> TransferRiskDecision:
    """
    Evaluate P(HIGH_RISK | evidence) for a proposed community transfer.

    Maps SEP transfer context to CausalArbiter inputs and runs the
    Bayesian DAG.  Falls back to a simple weighted sum if the arbiter
    module is unavailable.

    Parameters
    ----------
    source_community_id : GUID of the source community.
    target_community_id : GUID of the target community.
    peering_id          : Active peering UUID.
    entity_id           : Entity being transferred.
    data_class          : Sovereign pod tag data class (GENERAL/PII/PHI/etc.).
    peering_policy      : MIRROR_ONLY | REWRAP_ALLOWED | FULL_SYNC.
    peering_age_days    : Days since peering was activated (newer = higher risk).

    Returns
    -------
    TransferRiskDecision with allowed flag, score, and reason.
    """
    t0 = time.perf_counter()

    # ── Build evidence ────────────────────────────────────────────────────────
    hourly_velocity = _transfer_velocity(source_community_id)
    burst_velocity  = _burst_velocity(source_community_id)
    rejected_count  = _rejected_count(peering_id)

    # Map to CausalArbiter inputs
    ml_score             = _DATA_CLASS_RISK.get(data_class.upper(), 0.20)
    ers_score            = min(1.0, hourly_velocity / 20.0)   # 20 transfers/h → max risk
    obfuscation_detected = (
        peering_policy == "FULL_SYNC" and peering_age_days < 7.0
    )  # fresh FULL_SYNC peering is unusual
    block_history        = rejected_count
    tool_tier            = _POLICY_TIER.get(peering_policy, 0)
    content_entropy      = _DATA_CLASS_ENTROPY.get(data_class.upper(), 1.8)
    se_risk              = min(1.0, burst_velocity / 10.0)    # >10 in 5min → burst flag

    detail: dict = {
        "ml_score":             round(ml_score, 3),
        "ers_score":            round(ers_score, 3),
        "obfuscation_detected": obfuscation_detected,
        "block_history":        block_history,
        "tool_tier":            tool_tier,
        "content_entropy":      round(content_entropy, 3),
        "se_risk":              round(se_risk, 3),
        "hourly_velocity":      hourly_velocity,
        "burst_velocity":       burst_velocity,
    }

    # ── Run CausalArbiter ─────────────────────────────────────────────────────
    score = 0.0
    arbiter_available = False
    try:
        from warden.causal_arbiter import arbitrate
        result = arbitrate(
            ml_score             = ml_score,
            ers_score            = ers_score,
            obfuscation_detected = obfuscation_detected,
            block_history        = block_history,
            tool_tier            = tool_tier,
            content_entropy      = content_entropy,
            se_risk              = se_risk,
        )
        score             = result.risk_probability
        arbiter_available = True
        detail["arbiter"] = {
            "p_reputation":   round(result.p_reputation, 3),
            "p_content_risk": round(result.p_content_risk, 3),
            "p_persistence":  round(result.p_persistence, 3),
            "p_tool_risk":    round(result.p_tool_risk, 3),
            "p_entropy_risk": round(result.p_entropy_risk, 3),
            "p_se_risk":      round(result.p_se_risk, 3),
        }
    except ImportError:
        # Fallback: simple weighted sum (same nodes, no do-calculus)
        score = (
            0.30 * ml_score
            + 0.25 * ers_score
            + 0.15 * (1.0 if obfuscation_detected else 0.0)
            + 0.15 * min(1.0, block_history / 3.0)
            + 0.10 * se_risk
            + 0.05 * min(1.0, content_entropy / 5.0)
        )
        detail["arbiter"] = "fallback_weighted_sum"
    except Exception as exc:
        log.warning("transfer_guard: arbiter error: %s", exc)
        score             = ml_score * 0.5 + ers_score * 0.3 + se_risk * 0.2
        detail["arbiter"] = f"error: {exc}"

    latency_ms = round((time.perf_counter() - t0) * 1000, 2)
    allowed    = score < _RISK_THRESHOLD

    if not allowed:
        reason = (
            f"Causal transfer guard blocked: P(HIGH_RISK)={score:.3f} ≥ "
            f"threshold={_RISK_THRESHOLD}. "
            + (f"Burst velocity={burst_velocity}/5min. " if burst_velocity > 5 else "")
            + (f"Data class={data_class}. " if ml_score > 0.6 else "")
            + (f"Hourly velocity={hourly_velocity}. " if hourly_velocity > 10 else "")
        )
    else:
        reason = (
            f"Transfer allowed: P(HIGH_RISK)={score:.3f} < threshold={_RISK_THRESHOLD}."
        )

    log.info(
        "transfer_guard: src=%s tgt=%s entity=%s score=%.3f allowed=%s latency=%.1fms"
        " arbiter=%s",
        source_community_id[:8], target_community_id[:8], entity_id[:8],
        score, allowed, latency_ms, "ok" if arbiter_available else "fallback",
    )

    return TransferRiskDecision(
        allowed    = allowed,
        score      = round(score, 4),
        reason     = reason,
        detail     = detail,
        latency_ms = latency_ms,
    )
