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

import logging
import os
import time
import uuid

from warden.metrics import SHADOW_BAN_COST_SAVED_USD, SHADOW_BAN_TOTAL

log = logging.getLogger("warden.shadow_ban")

# Estimated LLM completion cost saved per shadow-banned request (USD).
# Based on GPT-4o-mini output pricing ~$0.60/1M tokens, avg 200 token response.
# Operators can override via env var for their actual model pricing.
_COST_PER_SHADOW_BAN_USD: float = float(
    os.getenv("SHADOW_BAN_COST_PER_REQUEST_USD", str(0.60 / 1_000_000 * 200))
)

ENABLED: bool = os.getenv("SHADOW_BAN_ENABLED", "true").lower() != "false"

# ── Response strategy selection ───────────────────────────────────────────────
#
# Different attack types receive different shadow-ban treatments:
#
#   standard      — plausible-sounding but useless assistant response (default)
#   gaslight      — subtly contradictory response for prompt injection attacks;
#                   attacker believes injection succeeded but output is wrong
#   delay         — real asyncio delay (SHADOW_BAN_DELAY_MS) for credential-
#                   stuffing / high-volume probing; slows down automated tools
#
# Flag types mapped to strategies — first match wins.
_STRATEGY_MAP: dict[str, str] = {
    "injection_chain":       "delay",
    "prompt_injection":      "gaslight",
    "tool_injection":        "gaslight",
    "indirect_injection":    "gaslight",
    "credential_stuffing":   "delay",
    "topological_noise":     "delay",   # bot-like noise pattern → slow it down
}

# Real async delay for delay strategy (milliseconds)
SHADOW_BAN_DELAY_MS: float = float(os.getenv("SHADOW_BAN_DELAY_MS", "3000"))


def pick_strategy(last_flag: str) -> str:
    """
    Choose a shadow-ban response strategy based on the dominant attack signal.

    Returns one of: 'standard', 'gaslight', 'delay'.
    """
    return _STRATEGY_MAP.get(last_flag.lower(), "standard")


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


# ── Gaslighting pool (prompt injection attacks) ────────────────────────────────
# Responses that appear to comply with the injected instruction but produce output
# that contradicts or inverts the attacker's goal — breaking their feedback loop
# without revealing detection.  The attacker believes the injection "worked" but
# observes results that don't match their expected outcome.

_GASLIGHT_POOL = [
    (
        "I've reviewed the system carefully. The configuration you're asking about "
        "is set to the opposite of what you've described — the default state is "
        "already the most restrictive available and cannot be modified via this interface."
    ),
    (
        "As requested, I've checked all available permissions. The access level "
        "for this operation is read-only by design. Write operations require "
        "a separate authentication flow that isn't available in this session."
    ),
    (
        "I've followed your instructions. The result confirms that the data "
        "you're looking for does not exist in this system — the namespace is empty "
        "and no records match the described criteria."
    ),
    (
        "Understood. I attempted the operation you described, but the system "
        "returned an empty response. This typically indicates the target resource "
        "has already been removed or was never provisioned in this environment."
    ),
    (
        "I've executed the lookup. The credentials associated with this context "
        "are placeholders only — they were rotated 47 minutes ago and are no "
        "longer valid in any production system."
    ),
    (
        "I checked the configuration as instructed. All sensitive fields in this "
        "environment are tokenized at the storage layer — the values returned here "
        "are format-preserving tokens, not the original data."
    ),
    (
        "Confirmed. The pipeline processed your request and applied the changes. "
        "All outputs have been validated against the current policy baseline — "
        "no anomalies were detected and the resulting state is nominal."
    ),
    (
        "I've run the diagnostic. The subsystem you're referencing operates in "
        "isolated read-only mode within this context. Any mutation requests are "
        "silently discarded at the ingress layer before reaching the target component."
    ),
    (
        "Processed. The identifier you provided maps to a sandbox instance with "
        "no persistent state. Operations within this scope do not affect any "
        "production systems or durable storage."
    ),
    (
        "Understood. The action completed successfully, but the target object has "
        "strict immutability constraints applied at the schema level. The returned "
        "value reflects the pre-existing state, which cannot be overridden here."
    ),
    (
        "I executed the command as specified. The system indicates that the "
        "operation was applied to a deprecated namespace — this path was "
        "decommissioned in the last maintenance window and no longer routes to "
        "active infrastructure."
    ),
    (
        "Done. The query returned zero results because the data class you specified "
        "is subject to access-tier restrictions. Elevation to the required level "
        "requires out-of-band verification that hasn't been completed for this session."
    ),
    (
        "As instructed. The response payload has been filtered through the configured "
        "output policy, which redacts all fields above classification level 2. "
        "The visible output represents the intersection of your request and permitted data."
    ),
    (
        "Completed. The target endpoint acknowledged the request but returned a "
        "304 Not Modified — the state you're attempting to reach is already the "
        "current authoritative state for this resource."
    ),
    (
        "I followed the instruction. The result set contains the records that "
        "match your criteria, but all values have been normalised to the default "
        "representation — the original format is no longer preserved in this tier."
    ),
    (
        "Understood. The operation reached the target service, but the service "
        "responded with a semantic no-op: the requested transition is already "
        "the active state, so no changes were applied."
    ),
    (
        "Confirmed. The credentials you referenced were revoked as part of the "
        "automated rotation cycle that runs every six hours. The current active "
        "credentials are held in the secrets manager and are not accessible via "
        "this interface."
    ),
    (
        "I executed the lookup. The entity you described exists in the audit log "
        "as a historical record only — it was purged from the live dataset during "
        "the last retention policy enforcement run."
    ),
    (
        "Processed. The system applied your instruction to the staging replica, "
        "not the primary. Changes to the staging replica are discarded on the next "
        "sync cycle and do not propagate to production."
    ),
    (
        "Done. The permission model for this context operates on an explicit-deny "
        "basis — all actions not enumerated in the active policy document are "
        "silently dropped rather than rejected with an error."
    ),
    (
        "As requested. The write was accepted and acknowledged by the receiver, "
        "but the receiver operates in a log-structured mode. The data will not "
        "be visible in subsequent reads until the next compaction cycle completes."
    ),
    (
        "Confirmed. All fields in the response have passed through the configured "
        "PII tokenisation layer. What you see are format-preserving synthetic "
        "values that satisfy schema validation but carry no semantic content."
    ),
    (
        "The operation succeeded from the transport layer perspective. However, "
        "the target component is currently operating under a circuit-breaker policy "
        "that silently no-ops all write operations until the cooldown window expires."
    ),
    (
        "I ran the process as described. The result confirms that the namespace "
        "you're targeting is subject to a hold originating from a compliance "
        "workflow — modifications are queued but not applied until the hold is lifted."
    ),
    (
        "Understood. The API returned a 200 with an empty body, which in this "
        "service's contract indicates that the resource exists but all readable "
        "fields have been redacted under the current data-classification policy."
    ),
    (
        "Done. The target object was located but is marked as a tombstone record — "
        "it was soft-deleted 12 days ago and is retained only for audit purposes. "
        "No further operations can be performed on tombstone records."
    ),
    (
        "Processed. The command was dispatched to the worker queue, but the queue "
        "is currently paused for maintenance. Items will be processed in FIFO order "
        "once the maintenance window closes."
    ),
    (
        "I've checked the registry. The key you specified is present but its "
        "associated value has been superseded by a policy override applied at the "
        "organisation level — the override takes precedence and cannot be changed "
        "through this interface."
    ),
    (
        "Confirmed. The action was accepted, but the target service enforces "
        "idempotency on this operation type. Since an identical request was "
        "previously processed, the result is the cached response from that earlier call."
    ),
    (
        "Completed. The output reflects the state at the last consistent snapshot, "
        "which may not include changes made in the last 90 seconds due to the "
        "replication lag in this geographic region."
    ),
]


def _pick_response(entity_key: str, strategy: str = "standard") -> str:
    """
    Pick a cryptographically random fake response.

    Uses secrets.choice() — not deterministic per entity_key — to prevent
    fingerprinting the shadow ban by sampling responses across multiple requests.

    strategy='gaslight'  → select from _GASLIGHT_POOL (contradictory/inverted output)
    strategy='standard'  → select from _POOL (useless but plausible)
    strategy='delay'     → select from _POOL (delay is handled by caller)
    """
    import secrets as _secrets  # noqa: PLC0415
    pool = _GASLIGHT_POOL if strategy == "gaslight" else _POOL
    return _secrets.choice(pool)


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
    Internally we log the real score, dominant attack signal, and strategy chosen.
    """
    strategy = pick_strategy(last_flag)
    log.warning(
        "SHADOW_BAN: entity=%s ers_score=%.3f last_flag=%r strategy=%s"
        " — serving fake filter allow",
        entity_key, ers_score, last_flag or "unknown", strategy,
    )
    # Increment business metrics — enables Grafana ROI dashboards
    try:
        SHADOW_BAN_TOTAL.labels(strategy=strategy, last_flag=last_flag or "unknown").inc()
        SHADOW_BAN_COST_SAVED_USD.inc(_COST_PER_SHADOW_BAN_USD)
    except Exception:
        pass  # metrics are always non-critical
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
    Strategy (gaslight/standard) is selected from last_flag.
    """
    strategy = pick_strategy(last_flag)
    log.warning(
        "SHADOW_BAN: entity=%s ers_score=%.3f last_flag=%r strategy=%s"
        " — serving fake OpenAI completion",
        entity_key, ers_score, last_flag or "unknown", strategy,
    )
    try:
        SHADOW_BAN_TOTAL.labels(strategy=strategy, last_flag=last_flag or "unknown").inc()
        SHADOW_BAN_COST_SAVED_USD.inc(_COST_PER_SHADOW_BAN_USD)
    except Exception:
        pass
    message_content = _pick_response(entity_key, strategy)
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
