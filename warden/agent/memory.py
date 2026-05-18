"""
warden/agent/memory.py
──────────────────────
Redis-backed short-term memory for SOVA, with optional pgvector semantic
search over past conversations (AG-24).

Keys
────
  sova:conv:{session_id}     JSON list of messages (last N turns)
  sova:state:{key}           Persistent agent state (rotation timestamps, etc.)
  sova:brief:last_ts         ISO timestamp of last morning brief
  sova:rotation:checked_at   ISO timestamp of last rotation check

pgvector (AG-24)
────────────────
  Activated when PGVECTOR_URL is set (postgres connection string with pgvector
  extension).  Embeds each SOVA assistant message using MiniLM and stores in
  `sova_memory` table for semantic similarity search.

  Falls back to Redis-only when pgvector unavailable.
"""
from __future__ import annotations

import json
import logging
import os
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


# ── pgvector semantic memory (AG-24) ──────────────────────────────────────────

_PG_URL = os.getenv("PGVECTOR_URL", "")
_pgconn = None   # lazy psycopg2 connection


def _pgvector_conn():
    """Return a psycopg2 connection to the pgvector database, or None."""
    global _pgconn
    if not _PG_URL:
        return None
    try:
        if _pgconn is None or _pgconn.closed:
            import psycopg2  # type: ignore[import]  # noqa: PLC0415
            _pgconn = psycopg2.connect(_PG_URL)
            _ensure_schema(_pgconn)
        return _pgconn
    except Exception as exc:
        log.debug("pgvector: connection failed: %s", exc)
        return None


def _ensure_schema(conn) -> None:
    with conn.cursor() as cur:
        cur.execute("CREATE EXTENSION IF NOT EXISTS vector")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS sova_memory (
                id          BIGSERIAL PRIMARY KEY,
                session_id  TEXT NOT NULL,
                role        TEXT NOT NULL,
                content     TEXT NOT NULL,
                embedding   vector(384),
                created_at  TIMESTAMPTZ DEFAULT now()
            )
        """)
        cur.execute(
            "CREATE INDEX IF NOT EXISTS sova_memory_emb_idx ON sova_memory "
            "USING ivfflat (embedding vector_cosine_ops) WITH (lists = 10)"
        )
        conn.commit()


def _embed(text: str) -> list[float] | None:
    """Embed text using the MiniLM model singleton."""
    try:
        from warden.brain.semantic import SemanticGuard  # noqa: PLC0415
        guard = SemanticGuard()
        emb = guard._embed(text)
        return emb.tolist() if emb is not None else None
    except Exception:
        return None


def store_message_embedding(session_id: str, role: str, content: str) -> None:
    """
    Store a message embedding in pgvector for semantic search.
    No-op when pgvector is unavailable.  GDPR-safe: only assistant messages
    are stored (no user content, which may contain PII).
    """
    if role != "assistant":
        return   # GDPR: only store assistant messages

    conn = _pgvector_conn()
    if not conn:
        return

    emb = _embed(content)
    if not emb:
        return

    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sova_memory (session_id, role, content, embedding) "
                "VALUES (%s, %s, %s, %s)",
                (session_id, role, content[:2000], emb),
            )
            conn.commit()
    except Exception as exc:
        log.debug("pgvector: store_message_embedding error: %s", exc)


def semantic_search(query: str, limit: int = 5) -> list[dict]:
    """
    Search past SOVA responses semantically.
    Returns list of {session_id, content, similarity, created_at}.
    Falls back to empty list when pgvector unavailable.
    """
    conn = _pgvector_conn()
    if not conn:
        return []

    emb = _embed(query)
    if not emb:
        return []

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT session_id, content, 1 - (embedding <=> %s::vector) AS similarity,
                       created_at
                FROM sova_memory
                ORDER BY embedding <=> %s::vector
                LIMIT %s
                """,
                (emb, emb, limit),
            )
            rows = cur.fetchall()
            return [
                {
                    "session_id": r[0],
                    "content":    r[1],
                    "similarity": round(float(r[2]), 4),
                    "created_at": r[3].isoformat() if r[3] else None,
                }
                for r in rows
            ]
    except Exception as exc:
        log.debug("pgvector: semantic_search error: %s", exc)
        return []


def pgvector_status() -> dict:
    conn = _pgvector_conn()
    if not conn:
        return {"enabled": False, "reason": "PGVECTOR_URL not set or connection failed"}
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM sova_memory")
            count = cur.fetchone()[0]
        return {"enabled": True, "rows": count, "pg_url": _PG_URL[:30] + "..."}
    except Exception as exc:
        return {"enabled": False, "error": str(exc)}
