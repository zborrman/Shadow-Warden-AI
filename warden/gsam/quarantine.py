"""
GSAM agent quarantine.

A quarantined agent is denied at the marketplace dispatcher and the Digital
Staff dispatcher until the flag expires or an admin releases it. The flag lives
in Redis (``gsam:quarantine:{agent_id}``, SETEX TTL) with an in-process dict
fallback so it also works in tests / when Redis is down. Every state change is
journalled to ``gsam_quarantine_log`` (SQLite ``gsam`` DB) and emitted as a
metadata-only observation.

Fail-open on read: any Redis/DB error in ``is_quarantined()`` returns False —
an infrastructure problem must never wedge the marketplace or staff pipeline.
Quarantine is triggered from ``drift.update_drift`` when EWMA drift crosses
``settings.gsam_drift_quarantine_threshold``.
"""
from __future__ import annotations

import contextlib
import logging
import threading
import time
from datetime import UTC, datetime

from warden.config import settings

log = logging.getLogger("warden.gsam.quarantine")

_REDIS_PREFIX = "gsam:quarantine:"

_DDL = """
    CREATE TABLE IF NOT EXISTS gsam_quarantine_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id    TEXT NOT NULL,
        reason      TEXT NOT NULL DEFAULT '',
        drift_score REAL NOT NULL DEFAULT 0.0,
        ts          TEXT NOT NULL,
        released_at TEXT NOT NULL DEFAULT ''
    );
"""

# In-process fallback when Redis is unavailable: agent_id -> expiry epoch.
_mem: dict[str, float] = {}
_mem_lock = threading.RLock()


def _redis():
    try:
        from warden.cache import _get_client  # noqa: PLC0415
        return _get_client()
    except Exception:  # noqa: BLE001
        return None


# ── Public API ───────────────────────────────────────────────────────────────────

def quarantine(
    agent_id: str,
    reason: str = "",
    drift_score: float = 0.0,
    ttl_s: int | None = None,
) -> bool:
    """Flag an agent as quarantined. Returns True once the flag is set."""
    if not agent_id:
        return False
    ttl = int(ttl_s if ttl_s is not None else settings.gsam_quarantine_ttl_s)
    key = _REDIS_PREFIX + agent_id
    set_in_redis = False
    r = _redis()
    if r is not None:
        try:
            r.setex(key, ttl, reason or "quarantined")
            set_in_redis = True
        except Exception:  # noqa: BLE001
            set_in_redis = False
    if not set_in_redis:
        with _mem_lock:
            _mem[agent_id] = time.time() + ttl
    _log_event(agent_id, reason, drift_score)
    _emit(agent_id, drift_score)
    log.info("gsam: quarantined agent=%s reason=%s drift=%.3f", agent_id, reason, drift_score)
    return True


def is_quarantined(agent_id: str) -> bool:
    """True if the agent is currently quarantined. Fail-open (errors → False)."""
    if not agent_id:
        return False
    key = _REDIS_PREFIX + agent_id
    r = _redis()
    if r is not None:
        try:
            return bool(r.exists(key))
        except Exception:  # noqa: BLE001
            pass  # fall through to the in-process fallback
    with _mem_lock:
        expiry = _mem.get(agent_id)
        if expiry is None:
            return False
        if expiry <= time.time():
            _mem.pop(agent_id, None)
            return False
        return True


def release(agent_id: str) -> bool:
    """Clear an agent's quarantine flag and mark the log row released."""
    if not agent_id:
        return False
    key = _REDIS_PREFIX + agent_id
    r = _redis()
    if r is not None:
        with contextlib.suppress(Exception):
            r.delete(key)
    with _mem_lock:
        _mem.pop(agent_id, None)
    _mark_released(agent_id)
    log.info("gsam: released agent=%s", agent_id)
    return True


def list_active() -> list[dict]:
    """Return open quarantine log rows whose flag is still live."""
    rows: list[dict] = []
    try:
        from warden.db.turso import get_connection  # noqa: PLC0415

        with get_connection("gsam", fallback_path=settings.gsam_db_path) as con:
            with contextlib.suppress(Exception):
                con.executescript(_DDL)
            cur = con.execute(
                "SELECT agent_id, reason, drift_score, ts FROM gsam_quarantine_log "
                "WHERE released_at = '' ORDER BY ts DESC LIMIT 500"
            )
            for row in cur.fetchall():
                agent_id = str(row[0])
                if is_quarantined(agent_id):
                    rows.append({
                        "agent_id":    agent_id,
                        "reason":      str(row[1]),
                        "drift_score": float(row[2]),
                        "ts":          str(row[3]),
                    })
    except Exception as exc:  # noqa: BLE001
        log.debug("gsam: list_active fell through (fail-open): %s", exc)
    return rows


# ── Persistence helpers ──────────────────────────────────────────────────────────

def _log_event(agent_id: str, reason: str, drift_score: float) -> None:
    now = datetime.now(UTC).isoformat()
    try:
        from warden.db.turso import get_connection  # noqa: PLC0415

        with get_connection("gsam", fallback_path=settings.gsam_db_path) as con:
            with contextlib.suppress(Exception):
                con.executescript(_DDL)
            con.execute(
                "INSERT INTO gsam_quarantine_log (agent_id, reason, drift_score, ts) "
                "VALUES (?,?,?,?)",
                (agent_id, reason, float(drift_score), now),
            )
            with contextlib.suppress(Exception):
                con.commit()
    except Exception as exc:  # noqa: BLE001
        log.debug("gsam: quarantine log write skipped (fail-open): %s", exc)


def _mark_released(agent_id: str) -> None:
    now = datetime.now(UTC).isoformat()
    try:
        from warden.db.turso import get_connection  # noqa: PLC0415

        with get_connection("gsam", fallback_path=settings.gsam_db_path) as con:
            with contextlib.suppress(Exception):
                con.executescript(_DDL)
            con.execute(
                "UPDATE gsam_quarantine_log SET released_at = ? "
                "WHERE agent_id = ? AND released_at = ''",
                (now, agent_id),
            )
            with contextlib.suppress(Exception):
                con.commit()
    except Exception as exc:  # noqa: BLE001
        log.debug("gsam: quarantine release write skipped (fail-open): %s", exc)


def _emit(agent_id: str, drift_score: float) -> None:
    with contextlib.suppress(Exception):
        from warden.gsam.collector import gsam_emit  # noqa: PLC0415
        from warden.gsam.schema import Observation  # noqa: PLC0415

        gsam_emit(Observation(
            agent_id=agent_id,
            event="quarantine",
            payload_kind="quarantine",
            drift_score=float(drift_score),
            scan_verdict="COMPROMISED",
        ).to_row())
