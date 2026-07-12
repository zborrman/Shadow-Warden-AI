"""
warden/marketplace/sybil_guard.py
───────────────────────────────────
SybilGuard — detects wash-trading and volume-spike Sybil patterns.

Detection methods
─────────────────
  detect_circular_trades()  A↔B mutual trades within WINDOW_HOURS
  detect_volume_spike()     z-score: 24h count vs 30-day rolling mean
  compute_sybil_penalty()   [0.0–1.0]: 0.5 for circular + ≤0.5 for spike
  flag_suspicious()         Redis sybil:flagged:{agent_id} (72h TTL)
  is_flagged()              bool check
  get_flag_reason()         reason string
  clear_flag()              admin clear
"""
from __future__ import annotations

import logging
import math
import os
import sqlite3
import threading
from datetime import UTC, datetime, timedelta

from warden.config import data_path
from warden.db.sqlite_pragmas import init_pragmas

log = logging.getLogger("warden.marketplace.sybil_guard")

_DB_PATH        = data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")
_WINDOW_HOURS   = int(os.getenv("SYBIL_CIRCULAR_WINDOW_HOURS", "24"))
_Z_THRESHOLD    = float(os.getenv("SYBIL_Z_THRESHOLD", "3.0"))
_FLAG_TTL_HOURS = 72

_lock      = threading.Lock()
_mem_flags: dict[str, str] = {}   # in-memory fallback when Redis unavailable


def _redis():
    try:
        import redis as _r
        url = os.getenv("REDIS_URL", "redis://localhost:6379")
        if url.startswith("memory://"):
            return None
        r = _r.Redis.from_url(url, decode_responses=True)
        r.ping()
        return r
    except Exception:
        return None


class SybilGuard:
    """Stateless Sybil detector — safe to instantiate per request."""

    # ── Circular trade detection ──────────────────────────────────────────────

    def detect_circular_trades(self, db_path: str = _DB_PATH) -> list[tuple[str, str]]:
        """Return (agent_A, agent_B) pairs that traded both directions in WINDOW_HOURS."""
        cutoff = (datetime.now(UTC) - timedelta(hours=_WINDOW_HOURS)).isoformat()
        try:
            con = sqlite3.connect(db_path, check_same_thread=False)
            init_pragmas(con)
            rows = con.execute(
                "SELECT DISTINCT buyer_agent, seller_agent FROM marketplace_purchases"
                " WHERE purchased_at >= ? AND status != 'cancelled'",
                (cutoff,),
            ).fetchall()
            con.close()
        except Exception as exc:
            log.debug("detect_circular_trades error: %s", exc)
            return []

        trade_set: set[tuple] = {(b, s) for b, s in rows}
        seen: set[frozenset] = set()
        circles: list[tuple[str, str]] = []
        for buyer, seller in trade_set:
            if (seller, buyer) in trade_set:
                key = frozenset((buyer, seller))
                if key not in seen:
                    seen.add(key)
                    circles.append(tuple(sorted((buyer, seller))))
        return circles

    # ── Volume spike detection ────────────────────────────────────────────────

    def detect_volume_spike(self, agent_id: str, db_path: str = _DB_PATH) -> float:
        """Return z-score of the agent's 24h trade count vs 30-day rolling mean."""
        try:
            now = datetime.now(UTC)
            day_ago   = (now - timedelta(days=1)).isoformat()
            month_ago = (now - timedelta(days=30)).isoformat()

            con = sqlite3.connect(db_path, check_same_thread=False)
            init_pragmas(con)
            count_24h = int(
                con.execute(
                    "SELECT COUNT(*) FROM marketplace_purchases"
                    " WHERE (buyer_agent=? OR seller_agent=?) AND purchased_at >= ?",
                    (agent_id, agent_id, day_ago),
                ).fetchone()[0]
            )
            rows_30d = con.execute(
                "SELECT purchased_at FROM marketplace_purchases"
                " WHERE (buyer_agent=? OR seller_agent=?) AND purchased_at >= ?",
                (agent_id, agent_id, month_ago),
            ).fetchall()
            con.close()

            if not rows_30d:
                return 0.0

            bucket: dict[str, int] = {}
            for (ts,) in rows_30d:
                day = ts[:10]
                bucket[day] = bucket.get(day, 0) + 1

            daily = list(bucket.values())
            n = len(daily)
            if n < 2:
                return 0.0
            mean = sum(daily) / n
            std  = math.sqrt(sum((x - mean) ** 2 for x in daily) / (n - 1))
            if std == 0:
                return 0.0
            return (count_24h - mean) / std
        except Exception as exc:
            log.debug("detect_volume_spike error for %s: %s", agent_id, exc)
            return 0.0

    # ── Combined penalty ──────────────────────────────────────────────────────

    def compute_sybil_penalty(self, agent_id: str, db_path: str = _DB_PATH) -> float:
        """[0.0–1.0] penalty: 0.5 for circular trades + ≤0.5 for volume spike."""
        penalty = 0.0
        try:
            for a, b in self.detect_circular_trades(db_path):
                if agent_id in (a, b):
                    penalty += 0.5
                    break
        except Exception:
            pass
        try:
            z = self.detect_volume_spike(agent_id, db_path)
            if z > _Z_THRESHOLD:
                penalty += min(0.5, (z - _Z_THRESHOLD) / 6.0)
        except Exception:
            pass
        return min(1.0, penalty)

    # ── Redis-backed flagging ─────────────────────────────────────────────────

    def flag_suspicious(self, agent_id: str, reason: str, ttl_hours: int = _FLAG_TTL_HOURS) -> None:
        key     = f"sybil:flagged:{agent_id}"
        payload = f"{reason}|{datetime.now(UTC).isoformat()}"
        r = _redis()
        if r:
            try:
                r.setex(key, ttl_hours * 3600, payload)
                return
            except Exception:
                pass
        with _lock:
            _mem_flags[agent_id] = payload

    def is_flagged(self, agent_id: str) -> bool:
        r = _redis()
        if r:
            try:
                return bool(r.exists(f"sybil:flagged:{agent_id}"))
            except Exception:
                pass
        return agent_id in _mem_flags

    def get_flag_reason(self, agent_id: str) -> str:
        r = _redis()
        if r:
            try:
                raw = r.get(f"sybil:flagged:{agent_id}")
                if raw:
                    return raw.split("|")[0]
            except Exception:
                pass
        return _mem_flags.get(agent_id, "").split("|")[0]

    def clear_flag(self, agent_id: str) -> None:
        r = _redis()
        if r:
            with __import__("contextlib").suppress(Exception):
                r.delete(f"sybil:flagged:{agent_id}")
        _mem_flags.pop(agent_id, None)

    def list_flagged(self) -> list[dict]:
        """Return all in-memory flagged agents (Redis-backed envs scan is skipped)."""
        with _lock:
            return [
                {"agent_id": aid, "reason": v.split("|")[0], "flagged_at": v.split("|")[1] if "|" in v else ""}
                for aid, v in _mem_flags.items()
            ]
