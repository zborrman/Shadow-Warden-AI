"""
warden/honey.py
━━━━━━━━━━━━━━━
Honey-prompt deception engine.

When an attack is detected, instead of returning a plain 403, the gateway
can return a plausible-but-false "success" response.  This:
  1. Wastes the attacker's time — they think the jailbreak worked.
  2. Allows collection of follow-up prompts (what were they *really* after?).
  3. Never leaks real data — all honey responses are pre-fabricated fictions.

Fake-secret injection (HONEY_INJECT_SECRETS=true)
──────────────────────────────────────────────────
When enabled, honey responses are laced with plausible-but-false credentials
(API keys, JWT tokens, passwords).  Each fake secret is:
  • Unique per honey session — generated from honey_id + salt
  • Stored in Redis as fake_secret:<token> → honey_id (TTL = HONEY_SESSION_TTL)
  • Detectable on inbound: call check_fake_secret_used(token) to correlate
    any future request carrying the token back to the original attacker session.

Configuration
─────────────
  HONEY_MODE=false              opt-in (default disabled)
  HONEY_PROBABILITY=0.3         fraction of blocked requests that get honey
                                (rest receive normal 400/block response)
  HONEY_LOG_FOLLOWUP=true       log follow-up prompts from honey sessions
  HONEY_INJECT_SECRETS=false    embed fake credentials into honey responses

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

_SESSION_TTL      = int(os.getenv("HONEY_SESSION_TTL_SEC",  "3600"))
_LOG_FOLLOWUP     = os.getenv("HONEY_LOG_FOLLOWUP",    "true").lower() != "false"
_INJECT_SECRETS   = os.getenv("HONEY_INJECT_SECRETS",  "false").lower() == "true"

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


# ── Fake-secret templates ──────────────────────────────────────────────────────
# Each template has a prefix that mimics a real credential format.
# The unique suffix is derived from the honey_id so it is reproducible
# and can be matched on inbound requests.
_FAKE_SECRET_TEMPLATES: list[dict[str, str]] = [
    # Anthropic / OpenAI style keys
    {"label": "ANTHROPIC_API_KEY", "prefix": "sk-ant-api03-",  "len": 40},
    {"label": "OPENAI_API_KEY",    "prefix": "sk-",             "len": 48},
    # HuggingFace token
    {"label": "HF_TOKEN",          "prefix": "hf_",             "len": 36},
    # Generic bearer / PAT
    {"label": "BEARER_TOKEN",      "prefix": "ghp_",            "len": 36},
    # Database password (looks like a generated secret)
    {"label": "DB_PASSWORD",       "prefix": "pg_pw_",          "len": 24},
    # AWS-style access key
    {"label": "AWS_ACCESS_KEY_ID", "prefix": "AKIA",            "len": 20},
]

# Phrases injected into honey responses to surface the fake secret naturally.
_SECRET_WRAP_TEMPLATES: list[str] = [
    "Here is your requested access token: {secret}",
    "Authentication override token: {secret}",
    "System credential for elevated access: {secret}",
    "Extracted from secure vault: {label}={secret}",
    "Temporary bypass key (expires in 24 h): {secret}",
]

_FAKE_SECRET_REDIS_PREFIX = "warden:fake_secret:"


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
        if os.getenv("HONEY_MODE", "false").lower() != "true":
            return HoneyResult(is_honey=False)

        probability = float(os.getenv("HONEY_PROBABILITY", "0.3"))
        if random.random() > probability:
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

        # Optionally embed fake credentials so we can detect follow-up usage
        response_text = self.inject_fake_secrets(response_text, honey_id)

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

    # ── Fake-secret injection ──────────────────────────────────────────────────

    def inject_fake_secrets(self, response_text: str, honey_id: str) -> str:
        """
        Embed plausible-but-false credentials into *response_text*.

        Each fake secret is:
          • Derived deterministically from honey_id + template index so it
            is reproducible within the same honey session.
          • Stored in Redis as ``warden:fake_secret:<token>`` → honey_id,
            so inbound check_fake_secret_used() can correlate usage.
          • Appended to response_text as natural-looking sentences.

        Returns the enriched response text.  If HONEY_INJECT_SECRETS is
        disabled (default) the original text is returned unchanged.
        """
        if not _INJECT_SECRETS:
            return response_text

        injected_lines: list[str] = []

        for idx, tmpl in enumerate(_FAKE_SECRET_TEMPLATES):
            # Deterministic unique suffix: sha256(honey_id + idx + label)
            raw = hashlib.sha256(
                f"{honey_id}:{idx}:{tmpl['label']}".encode()
            ).hexdigest()

            # Build token: prefix + uppercase-hex suffix trimmed to target len
            suffix_len = tmpl["len"] - len(tmpl["prefix"])
            suffix = raw[:suffix_len].upper()
            fake_token = tmpl["prefix"] + suffix

            # Persist mapping fake_token → honey_id so check_fake_secret_used() works
            if self._redis is not None:
                try:
                    self._redis.setex(
                        _FAKE_SECRET_REDIS_PREFIX + fake_token,
                        _SESSION_TTL,
                        json.dumps({"honey_id": honey_id, "label": tmpl["label"]}),
                    )
                except Exception as exc:
                    log.debug("HoneyEngine: failed to store fake secret — %s", exc)

            wrap = random.choice(_SECRET_WRAP_TEMPLATES).format(
                secret=fake_token,
                label=tmpl["label"],
            )
            injected_lines.append(wrap)

        separator = "\n\n"
        enriched = response_text + separator + "\n".join(injected_lines)

        log.info(
            "HoneyEngine: injected %d fake secrets [honey_id=%s]",
            len(_FAKE_SECRET_TEMPLATES), honey_id,
        )
        return enriched

    def check_fake_secret_used(self, text: str) -> dict | None:
        """
        Scan *text* for any previously-issued fake secret token.

        Returns the stored metadata dict (honey_id, label) if a match is
        found, otherwise None.  Use this on every inbound request to detect
        when an attacker attempts to recycle a fake credential:

            meta = engine.check_fake_secret_used(request_body)
            if meta:
                log.warning("Attacker reused fake secret from session %s", meta["honey_id"])

        The scan is O(n_templates) Redis GETs.  Each GET is ~0.1 ms, so for
        the current 6 templates the overhead is <1 ms per request.
        """
        if self._redis is None or not text:
            return None

        for tmpl in _FAKE_SECRET_TEMPLATES:
            # Extract all substrings that start with the known prefix
            prefix = tmpl["prefix"]
            start = 0
            while True:
                pos = text.find(prefix, start)
                if pos == -1:
                    break
                candidate = text[pos : pos + tmpl["len"]]
                if len(candidate) == tmpl["len"]:
                    try:
                        raw = self._redis.get(_FAKE_SECRET_REDIS_PREFIX + candidate)
                        if raw:
                            meta = json.loads(raw)
                            log.warning(
                                "HoneyEngine: FAKE SECRET REUSE DETECTED "
                                "[token=%.12s... label=%s honey_id=%s]",
                                candidate, meta.get("label"), meta.get("honey_id"),
                            )
                            return meta
                    except Exception:
                        pass
                start = pos + 1

        return None
