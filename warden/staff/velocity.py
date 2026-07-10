"""
Velocity Guard — STAFF-01 Rec-2.

Detects two patterns:
  1. Hourly rate excess  — agent exceeds max_calls_per_hour
  2. Loop detection      — same (tool, input_hash) appears > N times
     within loop_detection_window_s seconds

Both use Redis sorted-set sliding windows (same pattern as ERS/CircuitBreaker).
Falls back silently when Redis is unavailable so the happy path is never blocked.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass

from warden.observability import Reason, record_failopen

log = logging.getLogger(__name__)

_HOUR_KEY = "staff:velocity:hourly:{agent_id}"
_LOOP_KEY = "staff:velocity:loop:{agent_id}:{call_hash}"


@dataclass
class VelocityAlert:
    agent_id: str
    kind: str          # "rate_exceeded" | "loop_detected"
    detail: str
    tool_name: str
    count: int
    window_s: int


class VelocityGuard:
    """Stateless checker; pass redis client on construction."""

    def __init__(self, redis=None) -> None:
        self._r = redis

    def _call_hash(self, tool_name: str, tool_input: dict) -> str:
        canonical = json.dumps({"t": tool_name, "i": tool_input}, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]

    def record_and_check(
        self,
        agent_id: str,
        tool_name: str,
        tool_input: dict,
        max_per_hour: int,
        loop_window_s: int,
        loop_max: int,
    ) -> VelocityAlert | None:
        if self._r is None:
            return None
        now = time.time()
        try:
            alert = self._check_hourly(agent_id, tool_name, now, max_per_hour)
            if alert:
                return alert
            return self._check_loop(
                agent_id, tool_name, tool_input, now, loop_window_s, loop_max
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("VelocityGuard fail-open: %s", exc)
            record_failopen("velocity_guard", Reason.REDIS_UNAVAILABLE, exc)
            return None

    def _check_hourly(
        self, agent_id: str, tool_name: str, now: float, limit: int
    ) -> VelocityAlert | None:
        key = _HOUR_KEY.format(agent_id=agent_id)
        member = f"{now:.6f}-{uuid.uuid4().hex[:8]}"  # unique: avoid ZADD overwrite on same-µs calls
        cutoff = now - 3600
        pipe = self._r.pipeline(transaction=False)
        pipe.zadd(key, {member: now})
        pipe.zremrangebyscore(key, "-inf", cutoff)
        pipe.zcard(key)
        pipe.expire(key, 3610)
        results = pipe.execute()
        count = results[2]
        if count > limit:
            return VelocityAlert(
                agent_id=agent_id,
                kind="rate_exceeded",
                detail=f"{count} calls in last hour (limit {limit})",
                tool_name=tool_name,
                count=count,
                window_s=3600,
            )
        return None

    def _check_loop(
        self,
        agent_id: str,
        tool_name: str,
        tool_input: dict,
        now: float,
        window_s: int,
        loop_max: int,
    ) -> VelocityAlert | None:
        h = self._call_hash(tool_name, tool_input)
        key = _LOOP_KEY.format(agent_id=agent_id, call_hash=h)
        member = f"{now:.6f}-{uuid.uuid4().hex[:8]}"  # unique: avoid ZADD overwrite on same-µs calls
        cutoff = now - window_s
        pipe = self._r.pipeline(transaction=False)
        pipe.zadd(key, {member: now})
        pipe.zremrangebyscore(key, "-inf", cutoff)
        pipe.zcard(key)
        pipe.expire(key, window_s + 5)
        results = pipe.execute()
        count = results[2]
        if count > loop_max:
            return VelocityAlert(
                agent_id=agent_id,
                kind="loop_detected",
                detail=(
                    f"Identical call to '{tool_name}' repeated {count}× "
                    f"in {window_s}s window — possible agent loop"
                ),
                tool_name=tool_name,
                count=count,
                window_s=window_s,
            )
        return None
