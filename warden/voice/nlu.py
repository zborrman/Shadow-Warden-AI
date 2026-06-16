"""
warden/voice/nlu.py
Voice NLU — Claude Haiku intent extraction with deterministic rule-based fallback.

Intent types: search | buy | negotiate | inquire | cancel | status | help
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field

log = logging.getLogger("warden.voice.nlu")

_ANTHROPIC_KEY = os.getenv("ANTHROPIC_API_KEY", "")
_NLU_MODEL     = os.getenv("VOICE_NLU_MODEL", "claude-haiku-4-5-20251001")

_SEARCH_RE     = re.compile(r"\b(find|search|look for|show me|looking for|find me)\b", re.I)
_BUY_RE        = re.compile(r"\b(buy|purchase|order|checkout|get me|i'll take|i want to buy)\b", re.I)
_NEGOTIATE_RE  = re.compile(r"\b(negotiate|counter|offer|how about|make an offer|can you do|haggle)\b", re.I)
_CANCEL_RE     = re.compile(r"\b(cancel|stop|abort|never mind|forget it|quit)\b", re.I)
_STATUS_RE     = re.compile(r"\b(status|where is|track|order status|my orders?)\b", re.I)
_HELP_RE       = re.compile(r"\b(help|what can you|how do i|commands?|options?)\b", re.I)
_PRICE_RE      = re.compile(r"\$(\d+(?:\.\d+)?)|(\d+(?:\.\d+)?)\s*(?:dollars?|usd|bucks?)", re.I)
_QTY_RE        = re.compile(r"\b(\d+)\s*(?:units?|items?|pieces?|of)\b", re.I)
_PRODUCT_RE    = re.compile(
    r"\b(?:buy|find|order|search for|looking for|get me|purchase)\s+"
    r"(?:(?:a|an|some|the)\s+)?(.+?)(?:\s+for\b|\s+under\b|\s+below\b|\s+at\b|$)",
    re.I,
)


@dataclass
class VoiceIntent:
    intent_type:     str  = "inquire"
    entities:        dict = field(default_factory=dict)
    confidence:      float = 0.8
    raw_transcript:  str  = ""
    source:          str  = "rule"   # "rule" | "llm"


async def parse_intent(transcript: str, context: dict | None = None) -> VoiceIntent:
    """Parse voice transcript → VoiceIntent.  LLM when key present, rules fallback."""
    if _ANTHROPIC_KEY:
        try:
            return await _llm_parse(transcript, context or {})
        except Exception as exc:
            log.warning("NLU LLM failed, using rules: %s", exc)
    return _rule_parse(transcript, context or {})


def _rule_parse(transcript: str, _context: dict) -> VoiceIntent:
    t        = transcript.strip()
    entities: dict = {}

    if _CANCEL_RE.search(t):
        intent_type = "cancel"
    elif _HELP_RE.search(t):
        intent_type = "help"
    elif _STATUS_RE.search(t):
        intent_type = "status"
    elif _BUY_RE.search(t):
        intent_type = "buy"
    elif _NEGOTIATE_RE.search(t):
        intent_type = "negotiate"
    elif _SEARCH_RE.search(t):
        intent_type = "search"
    else:
        intent_type = "inquire"

    m = _PRICE_RE.search(t)
    if m:
        entities["max_price"] = float(m.group(1) or m.group(2))

    m = _QTY_RE.search(t)
    if m:
        entities["quantity"] = int(m.group(1))

    m = _PRODUCT_RE.search(t)
    if m:
        entities["product"] = m.group(1).strip()

    return VoiceIntent(
        intent_type=intent_type,
        entities=entities,
        confidence=0.75,
        raw_transcript=transcript,
        source="rule",
    )


async def _llm_parse(transcript: str, context: dict) -> VoiceIntent:
    import anthropic  # noqa: PLC0415
    client = anthropic.AsyncAnthropic(api_key=_ANTHROPIC_KEY)
    system = (
        "Extract structured commerce intents from voice transcripts. "
        "Return ONLY JSON with keys: "
        "intent_type (search|buy|negotiate|inquire|cancel|status|help), "
        "entities (object with optional: product, quantity, max_price, merchant), "
        "confidence (0.0-1.0)."
    )
    msg = await client.messages.create(
        model=_NLU_MODEL,
        max_tokens=256,
        system=system,
        messages=[{"role": "user", "content": f"Transcript: {transcript}\nContext: {json.dumps(context)}"}],
    )
    data = json.loads(msg.content[0].text.strip())
    return VoiceIntent(
        intent_type=data.get("intent_type", "inquire"),
        entities=data.get("entities", {}),
        confidence=float(data.get("confidence", 0.9)),
        raw_transcript=transcript,
        source="llm",
    )


class VoiceNLU:
    """Stateful NLU with per-instance conversation history."""

    def __init__(self) -> None:
        self._history: list[VoiceIntent] = []

    async def parse(self, transcript: str, context: dict | None = None) -> VoiceIntent:
        ctx = {
            "turn": len(self._history),
            "prior_intents": [i.intent_type for i in self._history[-3:]],
            **(context or {}),
        }
        intent = await parse_intent(transcript, ctx)
        self._history.append(intent)
        return intent
