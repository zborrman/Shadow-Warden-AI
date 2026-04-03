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
import time

from warden.config import settings

log = logging.getLogger("warden.cache")

# ── Lazy Redis connection ──────────────────────────────────────────────────────
# We import redis lazily so the rest of the codebase is not broken if
# redis-py is not installed or Redis is unavailable.

_REDIS_URL = settings.redis_url
_TTL = settings.cache_ttl_seconds
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

def get_cached(content: str) -> str | None:
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


# ── Token-bucket Lua script ───────────────────────────────────────────────────
# Executed atomically by Redis (single-threaded Lua VM) — no TOCTOU race.
#
# KEYS[1]  warden:tokens:{tenant_id}
# ARGV[1]  capacity      — maximum token count (= limit)
# ARGV[2]  refill_rate   — tokens added per second (= limit / 60)
# ARGV[3]  now           — current Unix timestamp (float)
# ARGV[4]  ttl           — key TTL in seconds; idle buckets expire automatically
#
# Returns 1 if the request is allowed (token consumed), 0 if rate-limited.
_TOKEN_BUCKET_LUA = """
local key      = KEYS[1]
local capacity = tonumber(ARGV[1])
local rate     = tonumber(ARGV[2])
local now      = tonumber(ARGV[3])
local ttl      = tonumber(ARGV[4])

local raw = redis.call('GET', key)
local tokens, last
if raw then
    local sep = string.find(raw, ':', 1, true)
    tokens    = tonumber(string.sub(raw, 1, sep - 1))
    last      = tonumber(string.sub(raw, sep + 1))
else
    tokens = capacity
    last   = now
end

-- Refill proportionally to elapsed time, capped at capacity
local elapsed = now - last
tokens = math.min(capacity, tokens + elapsed * rate)

-- Consume one token if available
local allowed
if tokens >= 1.0 then
    tokens  = tokens - 1.0
    allowed = 1
else
    allowed = 0
end

redis.call('SET', key, tostring(tokens) .. ':' .. tostring(now), 'EX', ttl)
return allowed
"""


def check_tenant_rate_limit(tenant_id: str, limit: int) -> bool:
    """Return True if *tenant_id* has exceeded *limit* requests per minute.

    Implements a token-bucket algorithm via an atomic Redis Lua script:
      • Capacity  = limit (full per-minute burst allowed from a cold start).
      • Refill    = limit / 60 tokens per second (steady-state throughput).
      • Key       = warden:tokens:{tenant_id}  (single key, no window rotation).
      • TTL       = 120 s  (idle buckets auto-expire; no manual cleanup needed).

    Fail-open: returns False (allow) when Redis is unavailable or errors.
    """
    r = _get_client()
    if r is None:
        return False

    key = f"warden:tokens:{tenant_id}"
    try:
        result = r.eval(
            _TOKEN_BUCKET_LUA,
            1,              # number of KEYS
            key,            # KEYS[1]
            float(limit),   # ARGV[1] — capacity
            limit / 60.0,   # ARGV[2] — refill_rate (tokens/sec)
            time.time(),    # ARGV[3] — now
            120,            # ARGV[4] — TTL seconds
        )
        return result == 0  # 0 → no token → blocked (True); 1 → allowed (False)
    except Exception as exc:  # noqa: BLE001
        log.debug("Tenant rate limit check error: %s", exc)
        return False
