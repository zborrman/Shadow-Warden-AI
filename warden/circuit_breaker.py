"""
warden/circuit_breaker.py
━━━━━━━━━━━━━━━━━━━━━━━━
Redis-backed circuit breaker for the /filter pipeline.

Problem solved
──────────────
When the ML pipeline is overloaded, requests time out and the gateway
fail-opens.  A sustained burst of timeouts makes things worse: every
new request still attempts the full pipeline before timing out, burning
CPU and blocking the thread pool.

The circuit breaker detects this condition and short-circuits the
pipeline immediately — returning a fail-open response without executing
any ML inference — until the system recovers.

State machine
─────────────
  CLOSED (normal)  ──bypass_rate > THRESHOLD──►  OPEN (cooldown)
       ▲                                               │
       └────────────── TTL expires (auto-reset) ───────┘

  OPEN: every /filter request returns immediately with
        reason="circuit_breaker:open" (same shape as timeout bypass).
        No ML inference runs.  Bypass counter still increments.

  After COOLDOWN_SECS the Redis key expires → circuit auto-resets to CLOSED.
  The next real request goes through the pipeline.  If it times out again,
  the circuit reopens.

Redis keys
──────────
  warden:cb:state     — string "1", TTL=COOLDOWN_SECS.  Present = OPEN.
  warden:cb:bypasses  — sorted set, score = Unix timestamp of each bypass.
                        Pruned to WINDOW_SECS on every write.

Fail-safe
─────────
All public functions return safe defaults on Redis errors (fail-open):
  is_open()           → False  (don't accidentally block all traffic)
  record_bypass()     → no-op
  check_and_trip()    → False  (don't trip on Redis error)
"""
from __future__ import annotations

import logging
import os
import time

log = logging.getLogger("warden.circuit_breaker")

# ── Tunables (env-configurable) ───────────────────────────────────────────────

# Sliding window duration in seconds.
WINDOW_SECS: int   = int(os.getenv("CB_WINDOW_SECS",    "60"))

# Fraction of /filter requests in the window that must be bypasses to trip.
THRESHOLD:   float = float(os.getenv("CB_BYPASS_THRESHOLD", "0.10"))

# Minimum requests in the window before the circuit can trip.
# Prevents cold-start false trips (e.g. 1 bypass out of 2 requests = 50%).
MIN_REQUESTS: int  = int(os.getenv("CB_MIN_REQUESTS",   "10"))

# How long (seconds) the circuit stays OPEN before auto-resetting.
COOLDOWN_SECS: int = int(os.getenv("CB_COOLDOWN_SECS",  "30"))

# ── Redis keys ────────────────────────────────────────────────────────────────

_STATE_KEY  = "warden:cb:state"      # present → OPEN
_BYPASS_KEY = "warden:cb:bypasses"   # sorted set of bypass timestamps

# ── Monotonic member key ──────────────────────────────────────────────────────
# Sorted-set members must be unique.  Combine float timestamp with a
# per-process sequence number to avoid collisions under concurrent load.

_seq: int = 0


def _member() -> str:
    global _seq
    _seq += 1
    return f"{time.time():.6f}:{_seq}"


# ── Public API ────────────────────────────────────────────────────────────────

def is_open(r) -> bool:
    """Return True if the circuit is currently OPEN (bypass all requests).

    Fails open on Redis error — never accidentally blocks traffic.
    """
    if r is None:
        return False
    try:
        return bool(r.exists(_STATE_KEY))
    except Exception as exc:  # noqa: BLE001
        log.debug("CB is_open error: %s", exc)
        return False


def record_bypass(r) -> None:
    """Record a bypass event in the Redis sorted set.

    Prunes entries older than WINDOW_SECS atomically via pipeline.
    No-op on Redis error.
    """
    if r is None:
        return
    cutoff = time.time() - WINDOW_SECS
    try:
        pipe = r.pipeline(transaction=False)
        pipe.zadd(_BYPASS_KEY, {_member(): time.time()})
        pipe.zremrangebyscore(_BYPASS_KEY, "-inf", cutoff)
        pipe.expire(_BYPASS_KEY, WINDOW_SECS + 10)
        pipe.execute()
    except Exception as exc:  # noqa: BLE001
        log.debug("CB record_bypass error: %s", exc)


def check_and_trip(r, total_in_window: int) -> bool:
    """Evaluate whether the circuit should trip; open it if so.

    Args:
        r:                Redis client (may be None).
        total_in_window:  Number of /filter requests in the last WINDOW_SECS
                          (from the in-process _filter_window deque).

    Returns:
        True if the circuit was just tripped, False otherwise.
    """
    if r is None or total_in_window < MIN_REQUESTS:
        return False
    try:
        cutoff = time.time() - WINDOW_SECS
        r.zremrangebyscore(_BYPASS_KEY, "-inf", cutoff)
        bypasses = r.zcard(_BYPASS_KEY)
        rate = bypasses / total_in_window
        if rate >= THRESHOLD:
            r.set(_STATE_KEY, "1", ex=COOLDOWN_SECS)
            log.warning(
                "Circuit breaker OPENED — bypass_rate=%.1f%% (%d/%d) "
                "cooldown=%ds",
                rate * 100, bypasses, total_in_window, COOLDOWN_SECS,
            )
            return True
    except Exception as exc:  # noqa: BLE001
        log.debug("CB check_and_trip error: %s", exc)
    return False


def get_state(r) -> dict:
    """Return a diagnostic snapshot for /health or /api/config.

    Always returns a dict — falls back to {"status": "unknown"} on error.
    """
    if r is None:
        return {"status": "disabled", "reason": "Redis unavailable"}
    try:
        cutoff = time.time() - WINDOW_SECS
        r.zremrangebyscore(_BYPASS_KEY, "-inf", cutoff)
        bypasses = r.zcard(_BYPASS_KEY)
        ttl      = r.ttl(_STATE_KEY)   # -2 = key absent (CLOSED), >0 = OPEN
        open_    = ttl > 0
        return {
            "status":           "open" if open_ else "closed",
            "bypasses_in_window": int(bypasses),
            "window_secs":      WINDOW_SECS,
            "threshold":        THRESHOLD,
            "cooldown_remaining_s": max(ttl, 0) if open_ else 0,
        }
    except Exception as exc:  # noqa: BLE001
        log.debug("CB get_state error: %s", exc)
        return {"status": "unknown", "error": str(exc)}
