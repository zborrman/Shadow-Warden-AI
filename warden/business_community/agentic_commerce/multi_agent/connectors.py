"""
multi_agent/connectors.py
Unified connector for Claude, Gemini, and GPT procurement agents.
Each connector receives a purchase request and returns a structured proposal.
"""
from __future__ import annotations

import logging
import os
from typing import Any

log = logging.getLogger("warden.commerce.connectors")

_ANTHROPIC_KEY = os.getenv("ANTHROPIC_API_KEY", "")
_OPENAI_KEY    = os.getenv("OPENAI_API_KEY", "")
_GEMINI_KEY    = os.getenv("GEMINI_API_KEY", "")

_PROPOSAL_PROMPT = """You are a procurement agent. Given this purchase request:
{request}

Return a JSON proposal with fields:
- recommended_vendor: string (domain)
- estimated_price_usd: float
- delivery_days: int
- risk_score: float (0-1, lower is better)
- rationale: string (1 sentence)

Respond with ONLY valid JSON."""


class AgentProposal:
    def __init__(self, agent: str, data: dict[str, Any]) -> None:
        self.agent = agent
        self.vendor: str   = data.get("recommended_vendor", "")
        self.price: float  = float(data.get("estimated_price_usd", 0))
        self.delivery: int = int(data.get("delivery_days", 0))
        self.risk: float   = float(data.get("risk_score", 0.5))
        self.rationale: str = data.get("rationale", "")
        self.raw = data

    def score(self) -> float:
        price_norm = min(self.price / 1000, 1.0)
        delivery_norm = min(self.delivery / 30, 1.0)
        return 0.5 * price_norm + 0.3 * self.risk + 0.2 * delivery_norm


async def claude_proposal(request: str) -> AgentProposal | None:
    if not _ANTHROPIC_KEY:
        return None
    try:
        import json as _json

        import anthropic
        client = anthropic.AsyncAnthropic(api_key=_ANTHROPIC_KEY)
        msg = await client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=256,
            messages=[{"role": "user", "content": _PROPOSAL_PROMPT.format(request=request)}],
        )
        data = _json.loads(msg.content[0].text)
        return AgentProposal("claude", data)
    except Exception as exc:
        log.debug("Claude proposal failed: %s", exc)
        return None


async def gemini_proposal(request: str) -> AgentProposal | None:
    if not _GEMINI_KEY:
        return None
    try:
        import json as _json

        import httpx
        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"gemini-1.5-flash-latest:generateContent?key={_GEMINI_KEY}"
        )
        payload = {"contents": [{"parts": [{"text": _PROPOSAL_PROMPT.format(request=request)}]}]}
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(url, json=payload)
            r.raise_for_status()
            text = r.json()["candidates"][0]["content"]["parts"][0]["text"]
            data = _json.loads(text)
            return AgentProposal("gemini", data)
    except Exception as exc:
        log.debug("Gemini proposal failed: %s", exc)
        return None


async def gpt_proposal(request: str) -> AgentProposal | None:
    if not _OPENAI_KEY:
        return None
    try:
        import json as _json

        import httpx
        headers = {"Authorization": f"Bearer {_OPENAI_KEY}", "Content-Type": "application/json"}
        payload = {
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": _PROPOSAL_PROMPT.format(request=request)}],
            "max_tokens": 256,
            "response_format": {"type": "json_object"},
        }
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post("https://api.openai.com/v1/chat/completions",
                                  headers=headers, json=payload)
            r.raise_for_status()
            text = r.json()["choices"][0]["message"]["content"]
            data = _json.loads(text)
            return AgentProposal("gpt", data)
    except Exception as exc:
        log.debug("GPT proposal failed: %s", exc)
        return None
