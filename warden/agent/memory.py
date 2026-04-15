"""
warden/agent/memory.py
──────────────────────
Redis-backed short-term memory for SOVA.

Keys
────
  sova:conv:{session_id}     JSON list of messages (last N turns)
  sova:state:{key}           Persistent agent state (rotation timestamps, etc.)
  sova:brief:last_ts         ISO timestamp of last morning brief
  sova:rotation:checked_at   ISO timestamp of last rotation check
"""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

log = logging.getLogger("warden.agent.memory")

_MAX_TURNS    = 20      # keep last 20 message pairs per session
_STATE_TTL    = 86400 * 30   # 30 days
_CONV_TTL     = 3600 * 6     # 6 hours


def _redis():
    try:
        from warden.cache import _get_client
        return _get_client()
    except Exception:
        return None


# ── Conversation history ──────────────────────────────────────────────────────

def load_history(session_id: str) -> list[dict]:
    r = _redis()
    if r is None:
        return []
    try:
        raw = r.get(f"sova:conv:{session_id}")
        return json.loads(raw) if raw else []
    except Exception as exc:
        log.debug("memory: load_history error: %s", exc)
        return []


def save_history(session_id: str, messages: list[dict]) -> None:
    r = _redis()
    if r is None:
        return
    try:
        trimmed = messages[-(_MAX_TURNS * 2):]   # keep last N turns (user+assistant pairs)
        r.setex(f"sova:conv:{session_id}", _CONV_TTL, json.dumps(trimmed))
    except Exception as exc:
        log.debug("memory: save_history error: %s", exc)


def clear_history(session_id: str) -> None:
    r = _redis()
    if r:
        import contextlib
        with contextlib.suppress(Exception):
            r.delete(f"sova:conv:{session_id}")


# ── Persistent state ──────────────────────────────────────────────────────────

def get_state(key: str) -> str | None:
    r = _redis()
    if r is None:
        return None
    try:
        val = r.get(f"sova:state:{key}")
        return val.decode() if isinstance(val, bytes) else val
    except Exception:
        return None


def set_state(key: str, value: str) -> None:
    r = _redis()
    if r is None:
        return
    try:
        r.setex(f"sova:state:{key}", _STATE_TTL, value)
    except Exception as exc:
        log.debug("memory: set_state error: %s", exc)


def now_iso() -> str:
    return datetime.now(UTC).isoformat()
