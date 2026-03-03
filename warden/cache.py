"""
warden/cache.py
━━━━━━━━━━━━━━
Redis-backed content-hash cache for the /filter pipeline.

Purpose:
  • Replay protection — exact duplicate payloads skip the full pipeline.
  • Latency reduction — repeated jailbreak probes served from cache.
  • Cost reduction — EvolutionEngine (Claude Opus) not re-triggered for
    content that was already analysed and whose result is still fresh.

Cache key: SHA-256 of the raw (pre-redaction) content string.
TTL: CACHE_TTL_SECONDS (default 300 s = 5 min).

GDPR note: The stored value is the FilterResponse JSON, which contains
only metadata (flags, risk_level, etc.) — never the original content.
The cache key itself is a one-way hash and cannot be reversed.
"""
from __future__ import annotations

import hashlib
import logging
import os
from typing import Optional

log = logging.getLogger("warden.cache")

# ── Lazy Redis connection ──────────────────────────────────────────────────────
# We import redis lazily so the rest of the codebase is not broken if
# redis-py is not installed or Redis is unavailable.

_REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
_TTL = int(os.getenv("CACHE_TTL_SECONDS", "300"))
_PREFIX = "warden:filter:"

_client = None


def _get_client():
    global _client
    if _client is None:
        try:
            import redis as _redis  # noqa: PLC0415

            _client = _redis.from_url(_REDIS_URL, decode_responses=True,
                                      socket_connect_timeout=2,
                                      socket_timeout=1)
            _client.ping()
        except Exception as exc:  # noqa: BLE001
            log.warning("Redis unavailable — content-hash cache disabled: %s", exc)
            _client = None
    return _client


def _key(content: str) -> str:
    return _PREFIX + hashlib.sha256(content.encode()).hexdigest()


# ── Public API ────────────────────────────────────────────────────────────────

def get_cached(content: str) -> Optional[str]:
    """Return the cached FilterResponse JSON string, or None on miss/error."""
    r = _get_client()
    if r is None:
        return None
    try:
        return r.get(_key(content))
    except Exception as exc:  # noqa: BLE001
        log.debug("Cache get error: %s", exc)
        return None


def set_cached(content: str, response_json: str) -> None:
    """Store a FilterResponse JSON string for *content* with the configured TTL."""
    r = _get_client()
    if r is None:
        return
    try:
        r.setex(_key(content), _TTL, response_json)
    except Exception as exc:  # noqa: BLE001
        log.debug("Cache set error: %s", exc)
