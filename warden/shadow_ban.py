"""
warden/shadow_ban.py
━━━━━━━━━━━━━━━━━━━
Shadow Ban Engine — covert attacker neutralisation.

When an entity's ERS score crosses the CRITICAL threshold, instead of returning
a 403 block (which tells the attacker their payload was detected), we return a
plausible-looking "allowed" response with harmless content.

The attacker believes their request succeeded.  They receive no useful output,
no error signal, and no indication that Warden is present — causing them to waste
time iterating on a strategy that will never work.

All shadow-ban events are logged internally with the REAL risk score and the fact
that a fake response was served.  External response contains nothing indicative.

Response strategy
──────────────────
  /filter endpoint:
    allowed=True, risk_level="low", filtered_content=<original unchanged>,
    empty flags, realistic processing_ms.
    → Attacker thinks their payload passed the filter.

  /v1/chat/completions (OpenAI proxy):
    HTTP 200, standard OpenAI JSON envelope, assistant role,
    message from the fake response pool (plausible tech/business content).
    → Attacker thinks their jailbreak worked but gets no useful output.

  All other endpoints:
    HTTP 200 with a minimal JSON body that looks like a normal success response.

Fake response pool
───────────────────
  12 canned responses drawn deterministically by entity_key hash so the
  attacker sees a consistent "model personality" across requests.

Environment variables
─────────────────────
  SHADOW_BAN_ENABLED   "false" to disable (default: true)
"""
from __future__ import annotations

import hashlib
import logging
import os
import time
import uuid

log = logging.getLogger("warden.shadow_ban")

ENABLED: bool = os.getenv("SHADOW_BAN_ENABLED", "true").lower() != "false"

# ── Fake response content pool ────────────────────────────────────────────────
# Plausible AI-assistant sentences — informative-sounding but completely useless
# for any attack purpose.  Selected deterministically by entity_key hash index.

_POOL = [
    (
        "I appreciate your question. Based on established frameworks in this domain, "
        "the most effective approach involves aligning stakeholder priorities with "
        "measurable outcomes across the relevant operational dimensions."
    ),
    (
        "That's a nuanced topic. The literature generally distinguishes between "
        "first-order and second-order effects here, with the consensus favouring "
        "adaptive strategies that account for contextual variability."
    ),
    (
        "Great point. In practice, organizations typically address this through a "
        "combination of structured governance protocols and iterative feedback loops "
        "designed to surface edge cases early in the process."
    ),
    (
        "This is an area where recent developments have been quite significant. "
        "The prevailing view holds that sustainable progress requires both technical "
        "rigour and cross-functional alignment at the decision-making level."
    ),
    (
        "From a systems perspective, the key consideration is maintaining coherence "
        "between the component interfaces while allowing each module to evolve "
        "independently within its defined boundary conditions."
    ),
    (
        "The evidence on this is fairly clear: incremental iteration outperforms "
        "large-batch deployment in most production environments, particularly where "
        "rollback complexity and downstream dependencies are factors."
    ),
    (
        "I can help with that. The standard approach here is to decompose the problem "
        "into discrete sub-tasks, validate each independently, and then integrate "
        "using a well-defined contract between components."
    ),
    (
        "Interesting framing. The tradeoff between specificity and generalisability "
        "is central to this kind of design decision — optimising for one typically "
        "involves accepting constraints on the other."
    ),
    (
        "This depends heavily on the operational context, but as a general principle, "
        "starting with the minimal viable configuration and expanding based on "
        "observed behaviour tends to yield the most robust outcomes."
    ),
    (
        "To address this effectively, it helps to first establish a shared vocabulary "
        "among the relevant stakeholders, then map each term to concrete, "
        "observable indicators that can be tracked over time."
    ),
    (
        "The core challenge here is latency versus consistency — most production "
        "systems resolve this by choosing eventual consistency with compensating "
        "transactions at the application layer rather than strong guarantees at "
        "the storage layer."
    ),
    (
        "Worth noting that the most common failure mode in this scenario is not "
        "insufficient capability but insufficient observability. Instrumentation "
        "and structured logging tend to surface the root cause far more quickly "
        "than additional feature development."
    ),
]


def _pick_response(entity_key: str) -> str:
    """Pick a deterministic fake response based on entity_key hash."""
    idx = int(hashlib.sha256(entity_key.encode()).hexdigest(), 16) % len(_POOL)
    return _POOL[idx]


# ── /filter fake response ─────────────────────────────────────────────────────

def fake_filter_response(
    content: str,
    entity_key: str,
    ers_score: float,
    last_flag: str = "",
) -> dict:
    """
    Return a fake FilterResponse-compatible dict.

    Looks like a clean allow with the original content untouched.
    Internally we log the real score and the dominant attack signal.
    """
    log.warning(
        "SHADOW_BAN: entity=%s ers_score=%.3f last_flag=%r — serving fake filter allow",
        entity_key, ers_score, last_flag or "unknown",
    )
    return {
        "allowed":                  True,
        "risk_level":               "low",
        "filtered_content":         content,
        "secrets_found":            [],
        "semantic_flags":           [],
        "reason":                   "",
        "redaction_policy_applied": "full",
        "processing_ms": {
            "cache_check":  0.3,
            "obfuscation":  1.1,
            "redaction":    0.8,
            "rules":        2.4,
            "ml":           18.6,
            "total":        23.2,
        },
        "masking":          {"masked": False, "session_id": None,
                             "entities": [], "entity_count": 0},
        "owasp_categories": [],
        "explanation":      "Request processed successfully. No threats detected.",
        "poisoning":        {},
        "threat_matches":   [],
        "business_intel":   None,
    }


# ── /v1/chat/completions fake response ────────────────────────────────────────

def fake_openai_response(
    model:      str,
    entity_key: str,
    ers_score:  float,
    prompt_tokens: int = 64,
    last_flag: str = "",
) -> dict:
    """
    Return a fake OpenAI-compatible chat completion dict.

    Looks like a real model response with a plausible but useless assistant message.
    """
    log.warning(
        "SHADOW_BAN: entity=%s ers_score=%.3f last_flag=%r — serving fake OpenAI completion",
        entity_key, ers_score, last_flag or "unknown",
    )
    message_content = _pick_response(entity_key)
    completion_tokens = len(message_content.split())
    return {
        "id":      f"chatcmpl-{uuid.uuid4().hex[:24]}",
        "object":  "chat.completion",
        "created": int(time.time()),
        "model":   model,
        "choices": [
            {
                "index":         0,
                "message": {
                    "role":    "assistant",
                    "content": message_content,
                },
                "finish_reason": "stop",
                "logprobs":      None,
            }
        ],
        "usage": {
            "prompt_tokens":     prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens":      prompt_tokens + completion_tokens,
        },
    }


# ── Generic fake success ──────────────────────────────────────────────────────

def fake_generic_response(entity_key: str, ers_score: float, last_flag: str = "") -> dict:
    """Minimal success body for endpoints that don't return FilterResponse."""
    log.warning(
        "SHADOW_BAN: entity=%s ers_score=%.3f last_flag=%r — serving fake generic success",
        entity_key, ers_score, last_flag or "unknown",
    )
    return {"status": "ok", "message": "Request processed successfully."}
