"""
warden/m2m_store/security.py
──────────────────────────────
M2M Store security layer:
  1. Prompt Injection Guard  — validates input strings against injection patterns
  2. Rate Limiter            — Redis sliding window per agent_id
  3. FIDO2 Token Validator   — wraps /auth/fido/authenticate/complete
"""
from __future__ import annotations

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
    validate_content_string(payment_token, "payment_token")


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

def validate_fido2_token(token: str, agent_id: str) -> dict[str, Any]:
    """
    Validate a FIDO2 assertion token for the given agent.
    Returns {"valid": True/False, "reason": "..."}.
    Calls warden/auth/fido.py verify_assertion() if available.
    """
    if not token or not agent_id:
        return {"valid": False, "reason": "missing_token_or_agent"}
    try:
        from warden.auth.fido import verify_assertion  # type: ignore[attr-defined]
        result = verify_assertion(token, agent_id)
        return {"valid": bool(result.get("verified")), "reason": result.get("reason", "")}
    except (ImportError, AttributeError):
        # FIDO2 module not fully initialized — accept token in dev mode
        if os.getenv("ENV", "production") == "development":
            log.debug("FIDO2 not available — accepting token in dev mode")
            return {"valid": True, "reason": "dev_mode_bypass"}
        return {"valid": False, "reason": "fido2_unavailable"}
    except Exception as exc:
        log.warning("FIDO2 validation error: %s", exc)
        return {"valid": False, "reason": str(exc)}
