"""
warden/m2m_store/security.py
──────────────────────────────
M2M Store security layer:
  1. Prompt Injection Guard  — validates input strings against injection patterns
  2. Rate Limiter            — Redis sliding window per agent_id
  3. FIDO2 Token Validator   — wraps /auth/fido/authenticate/complete
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any

log = logging.getLogger("warden.m2m_store.security")

_RATE_LIMIT = int(os.getenv("M2M_RATE_LIMIT_PER_MINUTE", "100"))
_RATE_WINDOW = 60  # seconds

# Prompt injection + SQL injection patterns to block in content strings
_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.IGNORECASE),
    re.compile(r"(DROP|DELETE|INSERT|UPDATE|SELECT)\s+", re.IGNORECASE),
    re.compile(r"<script[^>]*>", re.IGNORECASE),
    re.compile(r"\bsystem\s*prompt\b", re.IGNORECASE),
    re.compile(r"--\s*$", re.MULTILINE),
    re.compile(r";\s*(DROP|DELETE|INSERT)", re.IGNORECASE),
    re.compile(r"\{\{.*?\}\}"),   # template injection
    re.compile(r"\$\{.*?\}"),     # shell/JS injection
]

_MAX_STRING_LEN = 500


class PromptInjectionError(ValueError):
    pass


def validate_content_string(value: str, field_name: str = "field") -> str:
    """Raise PromptInjectionError if the string looks malicious."""
    if len(value) > _MAX_STRING_LEN:
        raise PromptInjectionError(
            f"{field_name} exceeds max length {_MAX_STRING_LEN}: got {len(value)}"
        )
    for pat in _INJECTION_PATTERNS:
        if pat.search(value):
            raise PromptInjectionError(
                f"{field_name} contains disallowed pattern: {pat.pattern[:40]}"
            )
    return value


def validate_offer_request(product_id: str, agent_id: str) -> None:
    """Validate OfferRequest fields for injection."""
    validate_content_string(product_id, "product_id")
    validate_content_string(agent_id, "agent_id")


def validate_order_request(offer_id: str, mandate_id: str, payment_token: str) -> None:
    """Validate OrderRequest fields for injection."""
    validate_content_string(offer_id, "offer_id")
    validate_content_string(mandate_id, "mandate_id")
    # payment_token is a WebAuthn assertion: parsed and verified by signature,
    # never read as text, so a content heuristic on its base64 adds nothing.


# ── Rate limiter ──────────────────────────────────────────────────────────────

def _redis():
    try:
        import redis as _r
        url = os.getenv("REDIS_URL", "redis://localhost:6379")
        if "memory://" in url:
            return None
        return _r.from_url(url, decode_responses=True, socket_connect_timeout=1)
    except Exception:
        return None


# In-process fallback rate limiter (used when Redis unavailable)
_mem_counters: dict[str, list[float]] = {}


def check_rate_limit(agent_id: str) -> bool:
    """
    Returns True (allowed) / False (rate limit exceeded).
    Uses Redis sliding window; falls back to in-process dict.
    """
    key = f"m2m:rl:{agent_id}"
    now = time.time()
    window_start = now - _RATE_WINDOW

    r = _redis()
    if r is not None:
        try:
            pipe = r.pipeline()
            pipe.zremrangebyscore(key, 0, window_start)
            pipe.zadd(key, {str(now): now})
            pipe.zcard(key)
            pipe.expire(key, _RATE_WINDOW * 2)
            results = pipe.execute()
            count = results[2]
            return count <= _RATE_LIMIT
        except Exception:
            pass

    # In-process fallback
    hits = _mem_counters.setdefault(agent_id, [])
    # Prune old entries
    _mem_counters[agent_id] = [t for t in hits if t > window_start]
    _mem_counters[agent_id].append(now)
    return len(_mem_counters[agent_id]) <= _RATE_LIMIT


# ── FIDO2 token validation ────────────────────────────────────────────────────

def order_challenge_purpose(offer_id: str) -> str:
    return f"m2m_order:{offer_id}"


def issue_order_challenge(tenant_id: str, offer_id: str) -> dict[str, Any]:
    """WebAuthn options whose challenge authorises exactly one order on one offer."""
    from warden.auth.fido import FIDOProvider
    return FIDOProvider().issue_bound_challenge(tenant_id, order_challenge_purpose(offer_id))


def validate_fido2_token(token: str, tenant_id: str, offer_id: str) -> dict[str, Any]:
    """
    The buyer's passkey approval of one offer: ``token`` is the WebAuthn
    assertion (JSON) answering the challenge from ``issue_order_challenge``.
    Returns {"valid": bool, "reason": str}. Fails CLOSED on every error.

    This used to look up ``warden.auth.fido.verify_assertion``, which never
    existed, so no token could pass in production (and before M1, every token
    passed). The challenge is bound to the offer and single-use, so one
    approval cannot be replayed onto another offer or onto the same one twice.
    """
    if not token or not tenant_id or not offer_id:
        return {"valid": False, "reason": "missing_token"}
    try:
        assertion = json.loads(token)
    except (TypeError, ValueError):
        return {"valid": False, "reason": "malformed_assertion"}
    try:
        from warden.auth.fido import FIDOProvider
        result = FIDOProvider().verify_bound(tenant_id, order_challenge_purpose(offer_id), assertion)
    except Exception as exc:
        log.warning("FIDO2 validation error: %s", type(exc).__name__)
        return {"valid": False, "reason": "fido2_error"}
    return {"valid": bool(result.get("verified")), "reason": result.get("reason", "")}
