"""
warden/marketplace/memory.py
─────────────────────────────
Layer 2: AgentHandoffMemory — context offloading for M2M agent handoffs.

Instead of re-sending full negotiation/escrow history to each sub-agent on
handoff (expensive), each agent writes a compact fact record (~50 tokens) to
Redis and the next agent reads it by (session_id, step) key.

Estimated token savings: ~61% on multi-step marketplace flows where the full
history would otherwise be injected into every sub-agent system prompt.

Storage backends (in priority order):
  1. Redis — async, sub-ms, preferred
  2. SQLite at HANDOFF_DB_PATH — in-process fallback (REDIS_URL="memory://" or
     Redis unreachable); persists across process restarts; still fast enough
     for all non-latency-critical handoffs
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from typing import Any

log = logging.getLogger("warden.marketplace.memory")

_REDIS_URL   = os.getenv("REDIS_URL", "redis://localhost:6379")
_FALLBACK_DB = os.getenv("HANDOFF_DB_PATH", "/tmp/warden_handoff.db")
_TTL         = int(os.getenv("HANDOFF_MEMORY_TTL", "3600"))   # 1 hour


# ── SQLite helpers ─────────────────────────────────────────────────────────────

def _sqlite_ensure() -> None:
    con = sqlite3.connect(_FALLBACK_DB)
    con.execute(
        "CREATE TABLE IF NOT EXISTS handoff_memory "
        "(key TEXT PRIMARY KEY, payload TEXT, expires_at REAL)"
    )
    con.commit()
    con.close()


def _sqlite_write(key: str, payload: str, ttl: int) -> None:
    con = sqlite3.connect(_FALLBACK_DB)
    con.execute(
        "INSERT OR REPLACE INTO handoff_memory (key, payload, expires_at) VALUES (?,?,?)",
        (key, payload, time.time() + ttl),
    )
    con.commit()
    con.close()


def _sqlite_read(key: str) -> str | None:
    con = sqlite3.connect(_FALLBACK_DB)
    row = con.execute(
        "SELECT payload, expires_at FROM handoff_memory WHERE key=?", (key,)
    ).fetchone()
    con.close()
    if row and row[1] > time.time():
        return row[0]
    return None


# ── Key format ─────────────────────────────────────────────────────────────────

def _mk_key(session_id: str, step: str) -> str:
    return f"marketplace:handoff:{session_id}:{step}"


# ── AgentHandoffMemory ─────────────────────────────────────────────────────────

class AgentHandoffMemory:
    """Compact shared memory for M2M agent handoffs.

    Usage pattern (Layer 2 context offloading):

        # In agent A — before handing off to agent B:
        mem = AgentHandoffMemory()
        key = await mem.write(session_id, "negotiation_done", {
            "negotiation_id": neg.negotiation_id,
            "agreed_price": 42.0,
            "seller_agent": "did:shadow:...",
        })
        # Pass `key` (not the full conversation!) to agent B's initial prompt.

        # In agent B — at the start of its turn:
        mem = AgentHandoffMemory()
        facts = await mem.read(session_id, "negotiation_done")
        prompt = mem.compact_prompt(facts)  # ~50 tokens
    """

    def __init__(self, redis_url: str = _REDIS_URL) -> None:
        self._redis_url  = redis_url
        self._redis: Any = None
        self._use_sqlite = (redis_url == "memory://")
        _sqlite_ensure()

    async def _get_redis(self) -> Any | None:
        if self._use_sqlite:
            return None
        if self._redis is None:
            try:
                import redis.asyncio as aioredis  # noqa: PLC0415
                client = aioredis.from_url(
                    self._redis_url,
                    socket_connect_timeout=5,
                    socket_timeout=3,
                    decode_responses=True,
                )
                await client.ping()
                self._redis = client
            except Exception as exc:
                log.warning("AgentHandoffMemory: Redis unavailable (%s) — SQLite fallback", exc)
                self._use_sqlite = True
        return self._redis

    # ── Write ──────────────────────────────────────────────────────────────────

    async def write(
        self,
        session_id: str,
        step: str,
        facts: dict[str, Any],
        ttl: int = _TTL,
    ) -> str:
        """Persist compact fact record. Returns the Redis/SQLite key.

        Include this key (not the full transcript) in the next agent's prompt.
        """
        key     = _mk_key(session_id, step)
        payload = json.dumps({"ts": time.time(), "step": step, "facts": facts})
        r = await self._get_redis()
        if r:
            try:
                await r.setex(key, ttl, payload)
                return key
            except Exception as exc:
                log.warning("AgentHandoffMemory.write Redis error: %s", exc)
        _sqlite_write(key, payload, ttl)
        return key

    # ── Read ───────────────────────────────────────────────────────────────────

    async def read(
        self,
        session_id: str,
        step: str,
    ) -> dict[str, Any] | None:
        """Return the fact dict, or None if expired / not found."""
        key = _mk_key(session_id, step)
        r = await self._get_redis()
        if r:
            try:
                raw = await r.get(key)
                if raw:
                    return json.loads(raw)["facts"]
            except Exception as exc:
                log.warning("AgentHandoffMemory.read Redis error: %s", exc)
        raw = _sqlite_read(key)
        if raw:
            return json.loads(raw)["facts"]
        return None

    # ── Prompt helper ──────────────────────────────────────────────────────────

    @staticmethod
    def compact_prompt(facts: dict[str, Any] | None) -> str:
        """Format fact dict as a compact LLM prompt snippet (~50 tokens).

        This string replaces the full conversation history in the next agent's
        system prompt — the primary mechanism for token cost reduction.
        """
        if not facts:
            return "[HANDOFF FACTS]\n(none)\n[END HANDOFF FACTS]"
        lines = [f"- {k}: {v}" for k, v in facts.items()]
        return "[HANDOFF FACTS]\n" + "\n".join(lines) + "\n[END HANDOFF FACTS]"

    # ── Convenience: estimate saved tokens ────────────────────────────────────

    @staticmethod
    def estimate_savings(full_history_tokens: int, compact_tokens: int = 50) -> dict:
        """Return a dict with token savings estimate for observability / logging."""
        saved = max(0, full_history_tokens - compact_tokens)
        pct   = round(100 * saved / max(full_history_tokens, 1), 1)
        return {
            "full_history_tokens": full_history_tokens,
            "compact_tokens":      compact_tokens,
            "saved_tokens":        saved,
            "savings_pct":         pct,
        }
