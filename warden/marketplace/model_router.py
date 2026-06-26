"""warden/marketplace/model_router.py — Dynamic Model Router for M2M marketplace actions.

Scores the complexity of an incoming action and routes it to the cheapest
model that can handle it reliably:

  Haiku   (score < HAIKU_THRESHOLD)   — search, catalog parse, simple status
  Sonnet  (score < SONNET_THRESHOLD)  — negotiations, proposal analysis, brand agent
  Opus    (score >= SONNET_THRESHOLD) — complex arbitration, MAESTRO HIGH, disputes

Scoring inputs:
  - action_type        base complexity weight per action (0.0 – 0.70)
  - payload_length     chars in serialised payload (up to +0.20)
  - round_count        negotiation rounds elapsed   (up to +0.15)
  - maestro_risk       MAESTRO threat level         (+0.00 / +0.10 / +0.25)
  - force_model        env override for testing / ops

Integration points:
  - warden/agent/sova.py    — replace _MODEL constant with route_for_sova_tool()
  - warden/brain/evolve.py  — route rule-generation calls
  - warden/agent/tools.py   — any marketplace tool that spawns a sub-LLM call
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field

log = logging.getLogger("warden.marketplace.model_router")

# ── Model IDs ─────────────────────────────────────────────────────────────────
MODEL_HAIKU  = "claude-haiku-4-5-20251001"
MODEL_SONNET = "claude-sonnet-4-6"
MODEL_OPUS   = "claude-opus-4-8"

# ── Env-configurable thresholds ───────────────────────────────────────────────
_HAIKU_THRESHOLD  = float(os.getenv("ROUTER_HAIKU_THRESHOLD",  "0.35"))
_SONNET_THRESHOLD = float(os.getenv("ROUTER_SONNET_THRESHOLD", "0.65"))
_FORCE_MODEL      = os.getenv("ROUTER_FORCE_MODEL", "").strip()  # e.g. "haiku" | "sonnet" | "opus"

# ── Base action weights ───────────────────────────────────────────────────────
# Higher = more reasoning needed = more expensive model preferred.
_ACTION_BASE: dict[str, float] = {
    # Stage 1
    "register_agent":   0.10,
    # Stage 2
    "search":           0.10,
    "browse":           0.15,
    # Stage 3 — light
    "send_message":     0.30,
    "accept_offer":     0.35,
    # Stage 3 — medium
    "send_proposal":    0.50,
    "negotiate":        0.55,
    "send_offer":       0.60,
    # Stage 4 — heavy
    "sending_payments": 0.60,
    "create_escrow":    0.55,
    "fund_escrow":      0.55,
    "deliver_asset":    0.50,
    "confirm_receipt":  0.45,
    "raise_dispute":    0.80,  # disputes always get Opus
    "reject_proposal":  0.30,
    # MAESTRO / internal
    "maestro_audit":    0.75,
    "clearing":         0.70,
}
_DEFAULT_BASE = 0.40  # unknown action type


# ── MAESTRO risk level weights ────────────────────────────────────────────────
_MAESTRO_WEIGHTS: dict[str, float] = {
    "HIGH":     0.25,
    "MEDIUM":   0.10,
    "LOW":      0.00,
    "NONE":     0.00,
}


@dataclass
class RouteDecision:
    model:      str
    tier:       str          # "haiku" | "sonnet" | "opus"
    score:      float
    reason:     str
    breakdown:  dict[str, float] = field(default_factory=dict)


def score_action(
    action_type:    str,
    payload:        dict | str | None = None,
    round_count:    int  = 0,
    maestro_risk:   str  = "NONE",
) -> tuple[float, dict[str, float]]:
    """Return (composite_score, breakdown_dict) for a marketplace action."""
    base    = _ACTION_BASE.get(action_type, _DEFAULT_BASE)
    payload_str = json.dumps(payload) if isinstance(payload, dict) else (payload or "")
    length_bonus = min(len(payload_str) / 2000, 1.0) * 0.20
    round_bonus  = min(round_count * 0.05, 0.15)
    risk_bonus   = _MAESTRO_WEIGHTS.get(maestro_risk.upper(), 0.0)
    total = min(base + length_bonus + round_bonus + risk_bonus, 1.0)
    breakdown = {
        "base":          round(base, 3),
        "payload_length": round(length_bonus, 3),
        "round_count":   round(round_bonus, 3),
        "maestro_risk":  round(risk_bonus, 3),
        "total":         round(total, 3),
    }
    return total, breakdown


def route(
    action_type:    str,
    payload:        dict | str | None = None,
    round_count:    int  = 0,
    maestro_risk:   str  = "NONE",
) -> RouteDecision:
    """Return the optimal RouteDecision for this action context."""
    # Hard override (ops / testing)
    if _FORCE_MODEL:
        forced = _FORCE_MODEL.lower()
        model_map = {"haiku": MODEL_HAIKU, "sonnet": MODEL_SONNET, "opus": MODEL_OPUS}
        if forced in model_map:
            model = model_map[forced]
            return RouteDecision(
                model=model, tier=forced, score=0.0,
                reason=f"ROUTER_FORCE_MODEL={forced}",
            )

    total, breakdown = score_action(action_type, payload, round_count, maestro_risk)

    if total < _HAIKU_THRESHOLD:
        tier, model = "haiku",  MODEL_HAIKU
    elif total < _SONNET_THRESHOLD:
        tier, model = "sonnet", MODEL_SONNET
    else:
        tier, model = "opus",   MODEL_OPUS

    reason = (
        f"action={action_type} score={total:.2f} "
        f"(base={breakdown['base']:.2f} "
        f"payload={breakdown['payload_length']:.2f} "
        f"rounds={breakdown['round_count']:.2f} "
        f"risk={breakdown['maestro_risk']:.2f})"
    )
    log.debug("model_router: %s → %s  %s", action_type, tier.upper(), reason)

    return RouteDecision(
        model=model, tier=tier, score=total,
        reason=reason, breakdown=breakdown,
    )


def model_for_action(
    action_type:    str,
    payload:        dict | str | None = None,
    round_count:    int  = 0,
    maestro_risk:   str  = "NONE",
) -> str:
    """Convenience: return just the model ID string."""
    return route(action_type, payload, round_count, maestro_risk).model


# ── SOVA integration helper ───────────────────────────────────────────────────
def route_for_sova_tool(tool_name: str, tool_input: dict) -> str:
    """Map a SOVA tool name to the optimal model.

    Called from warden/agent/tools.py before any sub-LLM spawn.
    Marketplace tools use action semantics; non-marketplace tools default to Sonnet.
    """
    tool_action_map: dict[str, str] = {
        "acp_search_catalog":       "search",
        "semantic_listing_search":  "search",
        "generate_clearing_report": "clearing",
        "scan_shadow_ai":           "maestro_audit",
        "get_compliance_report":    "maestro_audit",
        "visual_assert_page":       "maestro_audit",
        "visual_diff":              "maestro_audit",
    }
    action = tool_action_map.get(tool_name)
    if action is None:
        return MODEL_SONNET  # safe default for non-marketplace SOVA tools
    return model_for_action(action, tool_input)
