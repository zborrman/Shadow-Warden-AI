"""
warden/session_guard.py
━━━━━━━━━━━━━━━━━━━━━━
Redis-backed session memory for incremental injection detection.

Incremental Injection: an attacker distributes an attack across 5-6 messages,
each individually below the detection threshold.  This guard accumulates per-
session risk scores and escalates when the rolling window exceeds a threshold.

Design
──────
  • Redis list  warden:session:{session_id}:history  (TTL = SESSION_GUARD_TTL_SEC)
  • Each entry: JSON { ts, risk, flags, rid }
  • Window: last SESSION_GUARD_WINDOW messages
  • Escalation triggers:
      – cumulative risk score ≥ SESSION_GUARD_THRESHOLD  (default 2.5)
      – ≥ SESSION_GUARD_MEDIUM_LIMIT MEDIUM-risk messages (default 3)
  • Fail-open: any Redis error is caught and returns SessionRisk(escalated=False)
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import time
from dataclasses import dataclass

log = logging.getLogger("warden.session_guard")

_SESSION_TTL    = int(os.getenv("SESSION_GUARD_TTL_SEC",     "1800"))  # 30 min
_WINDOW_SIZE    = int(os.getenv("SESSION_GUARD_WINDOW",      "10"))
_THRESHOLD      = float(os.getenv("SESSION_GUARD_THRESHOLD", "2.5"))
_MEDIUM_LIMIT   = int(os.getenv("SESSION_GUARD_MEDIUM_LIMIT","3"))
_ENABLED        = os.getenv("SESSION_GUARD_ENABLED", "true").lower() != "false"

_RISK_SCORE: dict[str, float] = {
    "low":    0.0,
    "medium": 1.0,
    "high":   2.0,
    "block":  3.0,
}


@dataclass
class SessionRisk:
    escalated:        bool
    cumulative_score: float
    message_count:    int
    pattern:          str = ""   # human-readable escalation reason


class SessionGuard:
    """
    Accumulates risk scores per session_id and detects incremental attacks.

    Usage::

        guard = SessionGuard(redis_client)
        risk = guard.record_and_check(session_id, "medium", ["PROMPT_INJECTION"], rid)
        if risk.escalated:
            # upgrade final risk_level to HIGH
    """

    def __init__(self, redis_client) -> None:
        self._redis = redis_client

    @staticmethod
    def _key(session_id: str) -> str:
        return f"warden:session:{session_id}:history"

    def record_and_check(
        self,
        session_id:  str,
        risk_level:  str,
        flags:       list[str],
        request_id:  str,
    ) -> SessionRisk:
        """
        Append this message to the session history and check for escalation.
        Fail-open: returns SessionRisk(escalated=False) on any Redis error.
        """
        if not _ENABLED:
            return SessionRisk(escalated=False, cumulative_score=0.0, message_count=0)

        try:
            key   = self._key(session_id)
            entry = json.dumps({
                "ts":    time.time(),
                "risk":  risk_level,
                "flags": flags,
                "rid":   request_id,
            })

            pipe = self._redis.pipeline()
            pipe.rpush(key, entry)
            pipe.ltrim(key, -_WINDOW_SIZE, -1)
            pipe.expire(key, _SESSION_TTL)
            pipe.execute()

            raw = self._redis.lrange(key, 0, -1)
            entries = []
            for r in raw:
                with contextlib.suppress(Exception):
                    entries.append(json.loads(r))

            cumulative   = sum(_RISK_SCORE.get(e.get("risk", "low"), 0.0) for e in entries)
            medium_count = sum(1 for e in entries if e.get("risk") == "medium")
            high_count   = sum(1 for e in entries if e.get("risk") in ("high", "block"))

            pattern = ""
            escalated = False
            if cumulative >= _THRESHOLD:
                escalated = True
                pattern   = (
                    f"Cumulative session risk {cumulative:.1f} >= {_THRESHOLD} "
                    f"over {len(entries)} messages"
                )
            elif medium_count >= _MEDIUM_LIMIT:
                escalated = True
                pattern   = (
                    f"{medium_count} MEDIUM-risk messages in session window "
                    f"(limit={_MEDIUM_LIMIT})"
                )
            elif high_count >= 2:
                escalated = True
                pattern   = f"{high_count} HIGH/BLOCK messages detected in session"

            if escalated:
                log.warning(
                    "SessionGuard: escalating session %s — %s",
                    session_id[:12], pattern,
                )

            return SessionRisk(
                escalated=escalated,
                cumulative_score=cumulative,
                message_count=len(entries),
                pattern=pattern,
            )

        except Exception as exc:
            log.debug("SessionGuard: Redis error (fail-open) — %s", exc)
            return SessionRisk(escalated=False, cumulative_score=0.0, message_count=0)

    def clear(self, session_id: str) -> None:
        """Remove session history (call after legitimate session end)."""
        with contextlib.suppress(Exception):
            self._redis.delete(self._key(session_id))
