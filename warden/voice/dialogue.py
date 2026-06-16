"""
warden/voice/dialogue.py
Dialogue Manager — multi-turn voice conversation with Redis session state.

Features
--------
  • Multi-turn state stored in Redis voice:session:{id} (TTL 1h)
  • Action routing: search → confirm → purchase flow
  • Barge-in: voice_barge_in() detects user speaking during TTS
  • Turn detection: semantic end-of-utterance (not silence timeout)
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass, field

log = logging.getLogger("warden.voice.dialogue")

_REDIS_URL   = os.getenv("REDIS_URL", "")
_SESSION_TTL = int(os.getenv("VOICE_SESSION_TTL", "3600"))
_MAX_TURNS   = int(os.getenv("VOICE_MAX_TURNS", "20"))


@dataclass
class DialogueResponse:
    text_response:  str  = ""
    audio_response: str  = ""   # base64-encoded PCM (populated by API layer if TTS enabled)
    action:         str  = "none"  # none | search | confirm | purchase | negotiate | clarify
    action_payload: dict = field(default_factory=dict)
    session_id:     str  = ""
    turn:           int  = 0


class DialogueManager:
    """Redis-backed multi-turn voice dialogue with in-process fallback."""

    def __init__(self) -> None:
        self._redis  = _get_redis()
        self._store: dict[str, dict] = {}   # in-process fallback when Redis unavailable

    async def process_turn(self, session_id: str, transcript: str) -> DialogueResponse:
        state                = self._load(session_id)
        state["turns"]       = state.get("turns", 0) + 1
        state["history"]     = state.get("history", [])
        state["session_id"]  = session_id

        from warden.voice.nlu import VoiceNLU  # noqa: PLC0415
        nlu    = VoiceNLU()
        intent = await nlu.parse(transcript, {"session": state})

        state["history"].append({
            "role": "user", "text": transcript, "intent": intent.intent_type,
        })

        resp = await self._route(intent, state)

        state["history"].append({"role": "assistant", "text": resp.text_response})
        if len(state["history"]) > _MAX_TURNS * 2:
            state["history"] = state["history"][-(_MAX_TURNS * 2):]

        self._save(session_id, state)
        resp.session_id = session_id
        resp.turn       = state["turns"]
        return resp

    async def _route(self, intent, state: dict) -> DialogueResponse:
        history = state.get("history", [])

        if intent.intent_type == "search":
            product = intent.entities.get("product", "")
            if not product:
                return DialogueResponse(
                    text_response="What product are you looking for?",
                    action="clarify",
                    action_payload={"missing": "product"},
                )
            return DialogueResponse(
                text_response=f"Searching the marketplace for {product}...",
                action="search",
                action_payload={
                    "product":   product,
                    "max_price": intent.entities.get("max_price"),
                    "quantity":  intent.entities.get("quantity"),
                },
            )

        if intent.intent_type == "buy":
            product = intent.entities.get("product", "something")
            prior   = [h.get("intent") for h in history[:-1] if h.get("role") == "user"]
            # Require explicit confirmation turn before executing purchase
            if "buy" not in prior[-2:] and "confirm" not in prior[-2:]:
                return DialogueResponse(
                    text_response=f"You want to purchase {product}. Shall I confirm the order?",
                    action="confirm",
                    action_payload={"product": product, "entities": intent.entities},
                )
            return DialogueResponse(
                text_response=f"Placing order for {product}...",
                action="purchase",
                action_payload={"entities": intent.entities},
            )

        if intent.intent_type == "negotiate":
            price = intent.entities.get("max_price")
            label = f" at ${price}" if price else ""
            return DialogueResponse(
                text_response=f"Initiating negotiation{label}...",
                action="negotiate",
                action_payload={"entities": intent.entities},
            )

        if intent.intent_type == "cancel":
            self._clear(state["session_id"])
            return DialogueResponse(text_response="Session cancelled. Goodbye!", action="none")

        if intent.intent_type == "status":
            return DialogueResponse(
                text_response="Fetching your recent orders...",
                action="status",
                action_payload={},
            )

        if intent.intent_type == "help":
            return DialogueResponse(
                text_response=(
                    "I can help you search for products, place orders, negotiate prices, "
                    "or check order status. Just tell me what you need."
                ),
                action="none",
            )

        return DialogueResponse(
            text_response="How can I help you with the marketplace today?",
            action="none",
        )

    # ── Session persistence ────────────────────────────────────────────────────

    def _load(self, session_id: str) -> dict:
        if self._redis is not None:
            try:
                raw = self._redis.get(f"voice:session:{session_id}")
                return json.loads(raw) if raw else {}
            except Exception:
                pass
        return self._store.get(session_id, {})

    def _save(self, session_id: str, state: dict) -> None:
        self._store[session_id] = state
        if self._redis is None:
            return
        import contextlib  # noqa: PLC0415
        with contextlib.suppress(Exception):
            self._redis.setex(f"voice:session:{session_id}", _SESSION_TTL, json.dumps(state))

    def _clear(self, session_id: str) -> None:
        if self._redis and session_id:
            import contextlib  # noqa: PLC0415
            with contextlib.suppress(Exception):
                self._redis.delete(f"voice:session:{session_id}")

    def clear_session(self, session_id: str) -> None:
        self._clear(session_id)


def new_session_id() -> str:
    return str(uuid.uuid4())


def _get_redis():
    try:
        import redis  # noqa: PLC0415
        url = _REDIS_URL
        if not url or url.startswith("memory://"):
            return None
        return redis.from_url(url, decode_responses=True)
    except Exception:
        return None
