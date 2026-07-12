"""
GSAM agent quarantine.

When an agent's EWMA drift crosses `gsam_drift_quarantine_threshold`, the rollup
sink calls :func:`quarantine_agent`, which records the event in
`gsam_quarantine_log` and raises a Redis flag `gsam:quarantine:{agent_id}` (TTL
`gsam_quarantine_ttl_s`). Enforcement is **additive**: dispatchers call
:func:`is_quarantined` as an *extra* gate after their existing boundary/velocity
checks, so STAFF-01/02 can only be strengthened, never bypassed.

Redis is preferred; an in-process TTL dict is the fail-open fallback so the gate
still works with no Redis (single-worker dev / tests).
"""
from __future__ import annotations

import logging
import sqlite3
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime

from warden.config import settings

log = logging.getLogger("warden.gsam.quarantine")

_REDIS_PREFIX = "gsam:quarantine:"
_db_lock = threading.RLock()

# In-process fallback: agent_id -> unix expiry.
_local: dict[str, float] = {}
_local_lock = threading.RLock()

_QUARANTINE_DDL = """
    CREATE TABLE IF NOT EXISTS gsam_quarantine_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id    TEXT NOT NULL,
        reason      TEXT NOT NULL DEFAULT '',
        drift_score REAL NOT NULL DEFAULT 0.0,
        ts          TEXT NOT NULL,
        released_at TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_gsam_quarantine_agent ON gsam_quarantine_log(agent_id, ts);
"""


@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    with suppress(ImportError):
        from warden.db.turso import get_connection, is_turso_enabled  # noqa: PLC0415
        if is_turso_enabled("gsam"):
            with get_connection("gsam", fallback_path=settings.gsam_db_path) as con:
                with suppress(Exception):
                    con.executescript(_QUARANTINE_DDL)
                yield con  # type: ignore[misc]
            return
    con = sqlite3.connect(settings.gsam_db_path, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(_QUARANTINE_DDL)
    try:
        yield con
        con.commit()
    finally:
        con.close()


def quarantine_agent(agent_id: str, drift_score: float, reason: str = "drift", redis=None) -> None:
    """Record + flag an agent as quarantined. Fail-open."""
    if not agent_id:
        return
    ttl = max(1, int(settings.gsam_quarantine_ttl_s))
    with _db_lock, _conn() as con:
        con.execute(
            "INSERT INTO gsam_quarantine_log (agent_id,reason,drift_score,ts) VALUES(?,?,?,?)",
            (agent_id, reason, float(drift_score), datetime.now(UTC).isoformat()),
        )
    if redis is not None:
        with suppress(Exception):
            redis.set(f"{_REDIS_PREFIX}{agent_id}", str(round(drift_score, 4)), ex=ttl)
            log.warning("GSAM: agent %s quarantined (drift=%.3f)", agent_id, drift_score)
            return
    with _local_lock:
        _local[agent_id] = time.time() + ttl
    log.warning("GSAM: agent %s quarantined (drift=%.3f, in-process)", agent_id, drift_score)


def is_quarantined(agent_id: str, redis=None) -> bool:
    """True if the agent currently holds an active quarantine flag. Fail-open →
    returns False on any error (availability over a hard stop)."""
    if not agent_id or not settings.gsam_enabled:
        return False
    if redis is not None:
        with suppress(Exception):
            return bool(redis.exists(f"{_REDIS_PREFIX}{agent_id}"))
    with _local_lock:
        exp = _local.get(agent_id)
        if exp is None:
            return False
        if exp < time.time():
            _local.pop(agent_id, None)
            return False
        return True


def release_agent(agent_id: str, redis=None) -> bool:
    """Manually clear a quarantine (admin action). Returns True if it was set."""
    cleared = False
    if redis is not None:
        with suppress(Exception):
            cleared = bool(redis.delete(f"{_REDIS_PREFIX}{agent_id}"))
    with _local_lock:
        cleared = _local.pop(agent_id, None) is not None or cleared
    with _db_lock, _conn() as con:
        con.execute(
            "UPDATE gsam_quarantine_log SET released_at=? WHERE agent_id=? AND released_at=''",
            (datetime.now(UTC).isoformat(), agent_id),
        )
    return cleared
