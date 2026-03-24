"""
warden/entity_risk.py
━━━━━━━━━━━━━━━━━━━━
Entity Risk Scoring (ERS) — behavioural threat scoring per caller.

Tracks attack signals from each entity (tenant + IP pair) over a 1-hour sliding
window and produces a composite risk score 0.0–1.0.  Entities with high scores
are silently shadow-banned rather than hard-blocked, preventing adversaries from
learning that their attacks were detected.

Entity key
───────────
  SHA-256[:16] of "{tenant_id}:{ip}"   — GDPR-safe, no raw PII stored in Redis.

Tracked signals
────────────────
  block            — request decision was HIGH or BLOCK                 weight 0.50
  obfuscation      — ObfuscationDecoder fired (base64/hex/ROT13/glyphs) weight 0.25
  honeytrap        — HoneyEngine deception trap triggered               weight 0.15
  evolution_trigger — EvolutionEngine auto-rule generation fired        weight 0.10

Score formula (per 1-hour window)
───────────────────────────────────
  block_rate        = blocks_1h  / max(total_1h, 1)
  obfusc_rate       = obfusc_1h  / max(total_1h, 1)
  honeytrap_rate    = honey_1h   / max(total_1h, 1)
  evolution_rate    = evol_1h    / max(total_1h, 1)

  raw_score = (0.50 * block_rate  + 0.25 * obfusc_rate
             + 0.15 * honeytrap_rate + 0.10 * evolution_rate)

  score = min(1.0, raw_score)   — clamped; requires MIN_REQUESTS to activate

Risk levels
────────────
  LOW       [0.00, 0.30)  — normal behaviour
  MEDIUM    [0.30, 0.55)  — elevated, watch
  HIGH      [0.55, 0.75)  — likely attacker, log + alert
  CRITICAL  [0.75, 1.00]  — confirmed attacker → shadow ban

Redis storage
──────────────
  Per entity, per event type: ZSET  warden:ers:{entity_key}:{event}
    score  = unix timestamp (float)
    member = request_id
  TTL auto-cleanup: ZREMRANGEBYSCORE to prune entries older than WINDOW_SECS.
  Total request counter: ZSET  warden:ers:{entity_key}:total

Environment variables
─────────────────────
  ERS_ENABLED               "false" to disable (default: true)
  ERS_WINDOW_SECS           Sliding window size in seconds (default: 3600)
  ERS_MIN_REQUESTS          Minimum requests before scoring activates (default: 5)
  ERS_MEDIUM_THRESHOLD      Score threshold for MEDIUM risk (default: 0.30)
  ERS_HIGH_THRESHOLD        Score threshold for HIGH risk (default: 0.55)
  ERS_SHADOW_BAN_THRESHOLD  Score threshold for shadow ban / CRITICAL (default: 0.75)
"""
from __future__ import annotations

import hashlib
import logging
import os
import time
from dataclasses import dataclass
from typing import Literal

log = logging.getLogger("warden.entity_risk")

# ── Config ────────────────────────────────────────────────────────────────────

ENABLED:       bool  = os.getenv("ERS_ENABLED", "true").lower() != "false"
WINDOW_SECS:   int   = int(os.getenv("ERS_WINDOW_SECS",   "3600"))
MIN_REQUESTS:  int   = int(os.getenv("ERS_MIN_REQUESTS",  "5"))
THRESH_MEDIUM: float = float(os.getenv("ERS_MEDIUM_THRESHOLD",     "0.30"))
THRESH_HIGH:   float = float(os.getenv("ERS_HIGH_THRESHOLD",       "0.55"))
THRESH_CRIT:   float = float(os.getenv("ERS_SHADOW_BAN_THRESHOLD", "0.75"))

_EVENTS  = ("block", "obfuscation", "honeytrap", "evolution_trigger")
_WEIGHTS = {
    "block":             0.50,
    "obfuscation":       0.25,
    "honeytrap":         0.15,
    "evolution_trigger": 0.10,
}

ERSLevel = Literal["low", "medium", "high", "critical"]


# ── Entity key ────────────────────────────────────────────────────────────────

def make_entity_key(tenant_id: str, ip: str) -> str:
    """
    Return a GDPR-safe 16-char entity identifier.
    Combines tenant + IP so two tenants from the same IP get different keys.
    """
    raw = f"{tenant_id}:{ip}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ── Result ────────────────────────────────────────────────────────────────────

@dataclass
class ERSResult:
    entity_key:  str
    score:       float      = 0.0
    level:       ERSLevel   = "low"
    shadow_ban:  bool       = False
    counts:      dict       = None   # type: ignore[assignment]
    total_1h:    int        = 0

    def __post_init__(self):
        if self.counts is None:
            self.counts = {e: 0 for e in _EVENTS}


# ── Redis operations ──────────────────────────────────────────────────────────

def _redis():
    """Return the shared Redis client (from cache.py). Returns None if unavailable."""
    try:
        from warden.cache import _get_client  # noqa: PLC0415
        return _get_client()
    except Exception:
        return None


def record_event(entity_key: str, event: str, request_id: str = "") -> None:
    """
    Record a single attack signal for entity_key.

    Uses a Redis ZSET (score=timestamp) for sliding-window counting.
    Fail-open: any Redis error is silently swallowed.
    """
    if not ENABLED or event not in _EVENTS:
        return
    r = _redis()
    if r is None:
        return
    try:
        now = time.time()
        cutoff = now - WINDOW_SECS
        member = request_id or str(now)

        pipe = r.pipeline(transaction=False)
        # Record event
        event_key = f"warden:ers:{entity_key}:{event}"
        pipe.zadd(event_key, {member: now})
        pipe.zremrangebyscore(event_key, "-inf", cutoff)
        pipe.expire(event_key, WINDOW_SECS + 60)
        # Record total
        total_key = f"warden:ers:{entity_key}:total"
        pipe.zadd(total_key, {member: now})
        pipe.zremrangebyscore(total_key, "-inf", cutoff)
        pipe.expire(total_key, WINDOW_SECS + 60)
        pipe.execute()
    except Exception as exc:
        log.debug("ERS.record_event failed (non-fatal): %s", exc)


def score(entity_key: str) -> ERSResult:
    """
    Compute the current ERS score for entity_key.

    Returns ERSResult with score=0.0 and level="low" on any Redis error (fail-open).
    """
    result = ERSResult(entity_key=entity_key)

    if not ENABLED:
        return result

    r = _redis()
    if r is None:
        return result

    try:
        now    = time.time()
        cutoff = now - WINDOW_SECS

        pipe = r.pipeline(transaction=False)
        for event in _EVENTS:
            pipe.zcount(f"warden:ers:{entity_key}:{event}", cutoff, now)
        pipe.zcount(f"warden:ers:{entity_key}:total", cutoff, now)
        counts_raw = pipe.execute()

        counts   = dict(zip(_EVENTS, counts_raw[:len(_EVENTS)]))
        total_1h = int(counts_raw[-1]) or 0

        result.counts   = counts
        result.total_1h = total_1h

        if total_1h < MIN_REQUESTS:
            return result  # not enough data — default LOW

        raw = sum(
            _WEIGHTS[e] * (counts[e] / total_1h)
            for e in _EVENTS
        )
        s = min(1.0, raw)

        result.score = round(s, 4)
        result.level = (
            "critical" if s >= THRESH_CRIT  else
            "high"     if s >= THRESH_HIGH  else
            "medium"   if s >= THRESH_MEDIUM else
            "low"
        )
        result.shadow_ban = (s >= THRESH_CRIT)

        if result.level in ("high", "critical"):
            log.warning(
                "ERS: entity=%s score=%.3f level=%s shadow_ban=%s "
                "blocks=%d obfusc=%d honey=%d evol=%d total=%d",
                entity_key, s, result.level, result.shadow_ban,
                counts["block"], counts["obfuscation"],
                counts["honeytrap"], counts["evolution_trigger"],
                total_1h,
            )

        return result

    except Exception as exc:
        log.debug("ERS.score failed (non-fatal): %s", exc)
        return result


def reset(entity_key: str) -> None:
    """
    Delete all ERS data for an entity (admin use — e.g. false-positive clearance).
    """
    r = _redis()
    if r is None:
        return
    try:
        keys = [f"warden:ers:{entity_key}:{e}" for e in _EVENTS]
        keys.append(f"warden:ers:{entity_key}:total")
        r.delete(*keys)
        log.info("ERS: reset entity_key=%s", entity_key)
    except Exception as exc:
        log.debug("ERS.reset failed: %s", exc)
