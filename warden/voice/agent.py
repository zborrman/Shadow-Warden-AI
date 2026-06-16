"""
warden/voice/agent.py
SOVA voice tool handlers — tools #62-67.

All tools follow the thin-HTTP pattern: call localhost:8001 or invoke
local voice modules directly when the HTTP path is impractical (audio bytes).
"""
from __future__ import annotations

import logging
import os
from typing import Any

log = logging.getLogger("warden.voice.agent")

_BASE    = "http://localhost:8001"
_API_KEY = os.getenv("WARDEN_API_KEY", "")
_TIMEOUT = 30.0


def _headers(tenant: str = "default") -> dict:
    return {"X-API-Key": _API_KEY, "X-Tenant-ID": tenant, "Content-Type": "application/json"}


async def _post(path: str, body: dict, tenant: str = "default") -> Any:
    import httpx  # noqa: PLC0415
    async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
        r = await c.post(f"{_BASE}{path}", json=body, headers=_headers(tenant))
        r.raise_for_status()
        return r.json()


async def _get(path: str, tenant: str = "default", params: dict | None = None) -> Any:
    import httpx  # noqa: PLC0415
    async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
        r = await c.get(f"{_BASE}{path}", headers=_headers(tenant), params=params or {})
        r.raise_for_status()
        return r.json()


# ── Tool #62: voice_search ─────────────────────────────────────────────────────

async def voice_search(
    transcript:   str,
    community_id: str = "default",
    tenant_id:    str = "default",
    **_,
) -> dict:
    """Tool #62 — Full voice search: transcript → NLU → UCP catalog search → TTS response."""
    from warden.voice.nlu import parse_intent  # noqa: PLC0415
    try:
        intent = await parse_intent(transcript)
        product = intent.entities.get("product", transcript[:80])
        results = await _post(
            "/marketplace/listings/search",
            {"query": product, "community_id": community_id, "limit": 5},
            tenant=tenant_id,
        )
        items   = results.get("listings", results.get("results", []))
        summary = f"Found {len(items)} result(s) for '{product}'."
        return {
            "intent":   intent.intent_type,
            "entities": intent.entities,
            "results":  items[:5],
            "speech":   summary,
        }
    except Exception as exc:
        return {"error": str(exc), "speech": "Sorry, the search could not be completed."}


# ── Tool #63: voice_buy ────────────────────────────────────────────────────────

async def voice_buy(
    transcript:   str,
    community_id: str = "default",
    listing_id:   str = "",
    tenant_id:    str = "default",
    **_,
) -> dict:
    """Tool #63 — Voice purchase: NLU → AP2 mandate check → order placement."""
    from warden.voice.nlu import parse_intent  # noqa: PLC0415
    try:
        intent = await parse_intent(transcript)
        if not listing_id:
            return {
                "speech":  "Please specify a listing ID or search first.",
                "action":  "clarify",
                "missing": "listing_id",
            }
        result = await _post(
            f"/marketplace/listings/{listing_id}/purchase",
            {
                "buyer_agent_id": "sova",
                "community_id":   community_id,
                "max_price":      intent.entities.get("max_price"),
            },
            tenant=tenant_id,
        )
        return {
            "intent":  intent.intent_type,
            "order":   result,
            "speech":  f"Order placed successfully for listing {listing_id}.",
        }
    except Exception as exc:
        return {"error": str(exc), "speech": "Purchase could not be completed."}


# ── Tool #64: voice_negotiate ──────────────────────────────────────────────────

async def voice_negotiate(
    session_id:   str,
    transcript:   str,
    community_id: str = "default",
    tenant_id:    str = "default",
    **_,
) -> dict:
    """Tool #64 — Voice negotiation: DialogueManager → MCP → counter-offer."""
    from warden.voice.dialogue import DialogueManager  # noqa: PLC0415
    try:
        dm   = DialogueManager()
        resp = await dm.process_turn(session_id, transcript)
        return {
            "session_id": resp.session_id,
            "turn":       resp.turn,
            "action":     resp.action,
            "speech":     resp.text_response,
            "payload":    resp.action_payload,
        }
    except Exception as exc:
        return {"error": str(exc), "speech": "Negotiation step failed."}


# ── Tool #65: voice_auction ────────────────────────────────────────────────────

async def voice_auction(
    transcript:   str,
    community_id: str = "default",
    tenant_id:    str = "default",
    **_,
) -> dict:
    """Tool #65 — Initiate multi-agent auction via voice command."""
    from warden.voice.nlu import parse_intent  # noqa: PLC0415
    try:
        intent  = await parse_intent(transcript)
        product = intent.entities.get("product", "")
        max_px  = intent.entities.get("max_price")
        result  = await _post(
            "/marketplace/auctions",
            {
                "community_id": community_id,
                "product":      product,
                "max_price":    max_px,
                "initiated_by": "voice",
            },
            tenant=tenant_id,
        )
        return {
            "auction":  result,
            "speech":   f"Auction started for '{product}'. Awaiting bids...",
            "entities": intent.entities,
        }
    except Exception as exc:
        return {"error": str(exc), "speech": "Auction initiation failed."}


# ── Tool #66: voice_compliance_check ──────────────────────────────────────────

async def voice_compliance_check(
    community_id: str = "default",
    tenant_id:    str = "default",
    **_,
) -> str:
    """Tool #66 — Speak current compliance posture for the community."""
    try:
        data  = await _get("/compliance/posture", tenant=tenant_id)
        score = data.get("overall_score", data.get("score", 0))
        tier  = data.get("tier", "unknown")
        return f"Compliance posture: {score}% ({tier}). All systems nominal."
    except Exception as exc:
        return f"Compliance check unavailable: {exc}"


# ── Tool #67: voice_trust_query ────────────────────────────────────────────────

async def voice_trust_query(
    agent_id:  str,
    tenant_id: str = "default",
    **_,
) -> str:
    """Tool #67 — Speak agent reputation for given agent_id."""
    try:
        data  = await _get(f"/marketplace/agents/{agent_id}/reputation", tenant=tenant_id)
        score = data.get("reputation_score", data.get("score", 0))
        level = data.get("trust_level", data.get("level", "unknown"))
        return f"Agent {agent_id}: trust level {level}, reputation score {score:.1f}/100."
    except Exception as exc:
        return f"Trust query failed for {agent_id}: {exc}"


# ── Anthropic tool schemas ─────────────────────────────────────────────────────

VOICE_TOOLS = [
    {
        "name":        "voice_search",
        "description": "Voice-driven marketplace search: transcript → NLU → catalog results + speech response.",
        "input_schema": {
            "type": "object",
            "properties": {
                "transcript":   {"type": "string", "description": "Voice transcript to parse."},
                "community_id": {"type": "string", "description": "Target community ID."},
            },
            "required": ["transcript"],
        },
    },
    {
        "name":        "voice_buy",
        "description": "Voice-driven purchase: NLU → AP2 mandate check → marketplace order.",
        "input_schema": {
            "type": "object",
            "properties": {
                "transcript":   {"type": "string"},
                "community_id": {"type": "string"},
                "listing_id":   {"type": "string", "description": "Specific listing to purchase."},
            },
            "required": ["transcript"],
        },
    },
    {
        "name":        "voice_negotiate",
        "description": "Voice negotiation turn: DialogueManager routes to MCP counter-offer.",
        "input_schema": {
            "type": "object",
            "properties": {
                "session_id":   {"type": "string", "description": "Dialogue session ID."},
                "transcript":   {"type": "string"},
                "community_id": {"type": "string"},
            },
            "required": ["session_id", "transcript"],
        },
    },
    {
        "name":        "voice_auction",
        "description": "Initiate a multi-agent marketplace auction via voice command.",
        "input_schema": {
            "type": "object",
            "properties": {
                "transcript":   {"type": "string"},
                "community_id": {"type": "string"},
            },
            "required": ["transcript"],
        },
    },
    {
        "name":        "voice_compliance_check",
        "description": "Speak the current compliance posture score for a community.",
        "input_schema": {
            "type": "object",
            "properties": {
                "community_id": {"type": "string"},
            },
        },
    },
    {
        "name":        "voice_trust_query",
        "description": "Speak the reputation and trust level of a marketplace agent.",
        "input_schema": {
            "type": "object",
            "properties": {
                "agent_id": {"type": "string", "description": "Agent ID to query."},
            },
            "required": ["agent_id"],
        },
    },
]

VOICE_TOOL_HANDLERS: dict = {
    "voice_search":           voice_search,
    "voice_buy":              voice_buy,
    "voice_negotiate":        voice_negotiate,
    "voice_auction":          voice_auction,
    "voice_compliance_check": voice_compliance_check,
    "voice_trust_query":      voice_trust_query,
}
