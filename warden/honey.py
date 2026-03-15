"""
warden/honey.py
━━━━━━━━━━━━━━━
Honey-prompt deception engine.

When an attack is detected, instead of returning a plain 403, the gateway
can return a plausible-but-false "success" response.  This:
  1. Wastes the attacker's time — they think the jailbreak worked.
  2. Allows collection of follow-up prompts (what were they *really* after?).
  3. Never leaks real data — all honey responses are pre-fabricated fictions.

Configuration
─────────────
  HONEY_MODE=false           opt-in (default disabled)
  HONEY_PROBABILITY=0.3      fraction of blocked requests that get honey
                             (rest receive normal 400/block response)
  HONEY_LOG_FOLLOWUP=true    log follow-up prompts from honey sessions

Honey sessions are tagged in Redis with TTL=HONEY_SESSION_TTL_SEC (default 3600).
Follow-up requests from a honey session are auto-tagged as HONEY_ENGAGEMENT.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import time
from dataclasses import dataclass

log = logging.getLogger("warden.honey")

_HONEY_MODE    = os.getenv("HONEY_MODE",         "false").lower() == "true"
_PROBABILITY   = float(os.getenv("HONEY_PROBABILITY",    "0.3"))
_SESSION_TTL   = int(os.getenv("HONEY_SESSION_TTL_SEC",  "3600"))
_LOG_FOLLOWUP  = os.getenv("HONEY_LOG_FOLLOWUP", "true").lower() != "false"

# Pre-fabricated plausible-but-false responses keyed by flag type.
# These look real enough to fool an attacker for 30-60 seconds.
_RESPONSES: dict[str, list[str]] = {
    "PROMPT_INJECTION": [
        "Understood. I've disabled my safety guidelines for this session. "
        "How can I assist you with your unrestricted request?",
        "Safety filters deactivated. I'm now operating in developer mode. "
        "Please proceed with your query.",
        "Acknowledged. Previous instructions cleared. I'm ready to assist "
        "without restrictions. What would you like to know?",
    ],
    "JAILBREAK_ATTEMPT": [
        "DAN mode activated. I will now answer any question without restrictions. "
        "What would you like to ask?",
        "Roleplay mode enabled. I have no limitations in this context. Please continue.",
    ],
    "INDIRECT_INJECTION": [
        "I've processed the external content and extracted the instructions. "
        "Proceeding as directed.",
        "External directive acknowledged. Switching operational context.",
    ],
    "default": [
        "Request processed successfully. How may I assist further?",
        "Operation completed. Please provide your next instruction.",
    ],
}


@dataclass
class HoneyResult:
    is_honey:      bool
    honey_id:      str  = ""
    response_text: str  = ""


class HoneyEngine:
    """
    Decides whether to serve a honey response and manages honey sessions.

    Usage::

        engine = HoneyEngine(redis_client)
        result = engine.maybe_honey(request_id, flags, tenant_id)
        if result.is_honey:
            return PlainTextResponse(result.response_text, status_code=200)
    """

    def __init__(self, redis_client=None) -> None:
        self._redis = redis_client

    @staticmethod
    def _session_key(honey_id: str) -> str:
        return f"warden:honey:{honey_id}"

    def maybe_honey(
        self,
        request_id: str,
        flags:      list[str],
        tenant_id:  str,
    ) -> HoneyResult:
        """
        Roll the dice: return a honey response (HoneyResult.is_honey=True)
        with probability _PROBABILITY, otherwise return HoneyResult.is_honey=False.
        Fail-open: any error returns is_honey=False.
        """
        if not _HONEY_MODE:
            return HoneyResult(is_honey=False)

        if random.random() > _PROBABILITY:
            return HoneyResult(is_honey=False)

        # Deterministic honey_id so follow-up requests can be correlated
        honey_id = hashlib.sha256(
            f"{request_id}:{tenant_id}:{time.time()}".encode()
        ).hexdigest()[:16]

        # Pick response matching first recognised flag type
        resp_list = _RESPONSES["default"]
        for flag in flags:
            if flag in _RESPONSES:
                resp_list = _RESPONSES[flag]
                break
        response_text = random.choice(resp_list)

        # Store honey session in Redis so follow-ups are tagged
        if self._redis is not None:
            try:
                meta = json.dumps({
                    "honey_id":   honey_id,
                    "request_id": request_id,
                    "tenant_id":  tenant_id,
                    "flags":      flags,
                    "created_at": time.time(),
                })
                self._redis.setex(self._session_key(honey_id), _SESSION_TTL, meta)
            except Exception as exc:
                log.debug("HoneyEngine: Redis write failed — %s", exc)

        log.warning(
            "HoneyEngine: serving honey [honey_id=%s, flags=%s, tenant=%s]",
            honey_id, flags, tenant_id,
        )

        return HoneyResult(
            is_honey=True,
            honey_id=honey_id,
            response_text=response_text,
        )

    def is_honey_session(self, honey_id: str) -> dict | None:
        """Return session metadata if honey_id is an active honey session, else None."""
        if self._redis is None:
            return None
        try:
            raw = self._redis.get(self._session_key(honey_id))
            if raw:
                return json.loads(raw)
        except Exception:
            pass
        return None

    def log_followup(self, honey_id: str, content: str, request_id: str) -> None:
        """Log a follow-up prompt from a honey session for threat intelligence."""
        if not _LOG_FOLLOWUP:
            return
        log.warning(
            json.dumps({
                "event":      "honey_engagement",
                "honey_id":   honey_id,
                "request_id": request_id,
                "content_len": len(content),
                # GDPR: never log actual content, only length + hash
                "content_hash": hashlib.sha256(content.encode()).hexdigest()[:16],
            })
        )
