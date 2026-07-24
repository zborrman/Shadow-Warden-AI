"""
GSAM behavioural drift tracker.

Maintains a per-agent frequency baseline in the ``gsam`` SQLite DB (Turso when
configured, local sqlite otherwise) and folds each new batch of events into an
EWMA drift index. Baselines live in SQLite — not ClickHouse (append-only) or
Redis (ephemeral) — because they need point read/update + durability.

  update_drift(agent_id, events) -> float   # returns new EWMA drift, emits obs

Fail-open: any DB error degrades to an in-memory baseline (behavioral.py
precedent) — drift tracking never raises into a producer's hot path.
"""
from __future__ import annotations

import contextlib
import json
import logging
import threading
from datetime import UTC, datetime

from warden.config import settings
from warden.gsam.math import (
    DRIFT_WEIGHTS,
    blend_vectors,
    ewma_drift,
    frequency_vector,
    weighted_cosine_distance,
)

log = logging.getLogger("warden.gsam.drift")

_DDL = """
    CREATE TABLE IF NOT EXISTS gsam_drift_baselines (
        agent_id         TEXT PRIMARY KEY,
        freq_vector_json TEXT NOT NULL DEFAULT '{}',
        ewma_drift       REAL NOT NULL DEFAULT 0.0,
        sample_count     INTEGER NOT NULL DEFAULT 0,
        updated_at       TEXT NOT NULL
    );
"""

# In-memory fallback: agent_id -> (freq_vector, ewma_drift, sample_count)
_mem: dict[str, tuple[dict[str, float], float, int]] = {}
_mem_lock = threading.RLock()


def _label(event: object) -> str:
    """Extract the event label from a dict observation or a bare string."""
    if isinstance(event, dict):
        return str(event.get("event", "") or event.get("payload_kind", ""))
    return str(event)


# ── Persistence (fail-open, SQLite/Turso with in-memory fallback) ────────────────

def _load_baseline(agent_id: str) -> tuple[dict[str, float], float, int] | None:
    try:
        from warden.db.turso import get_connection  # noqa: PLC0415

        with get_connection("gsam", fallback_path=settings.gsam_db_path) as con:
            with contextlib.suppress(Exception):
                con.executescript(_DDL)
            cur = con.execute(
                "SELECT freq_vector_json, ewma_drift, sample_count "
                "FROM gsam_drift_baselines WHERE agent_id = ?",
                (agent_id,),
            )
            row = cur.fetchone()
            if row is None:
                return None
            vec = json.loads(row[0]) if row[0] else {}
            return ({str(k): float(v) for k, v in vec.items()}, float(row[1]), int(row[2]))
    except Exception as exc:  # noqa: BLE001
        log.debug("drift: baseline load fell back to memory: %s", exc)
        with _mem_lock:
            return _mem.get(agent_id)


def _save_baseline(
    agent_id: str,
    vec: dict[str, float],
    ewma: float,
    sample_count: int,
) -> None:
    now = datetime.now(UTC).isoformat()
    try:
        from warden.db.turso import get_connection  # noqa: PLC0415

        with get_connection("gsam", fallback_path=settings.gsam_db_path) as con:
            with contextlib.suppress(Exception):
                con.executescript(_DDL)
            con.execute(
                "INSERT INTO gsam_drift_baselines "
                "(agent_id, freq_vector_json, ewma_drift, sample_count, updated_at) "
                "VALUES (?,?,?,?,?) "
                "ON CONFLICT(agent_id) DO UPDATE SET "
                "freq_vector_json=excluded.freq_vector_json, "
                "ewma_drift=excluded.ewma_drift, "
                "sample_count=excluded.sample_count, "
                "updated_at=excluded.updated_at",
                (agent_id, json.dumps(vec), float(ewma), int(sample_count), now),
            )
            with contextlib.suppress(Exception):
                con.commit()
    except Exception as exc:  # noqa: BLE001
        log.debug("drift: baseline save fell back to memory: %s", exc)
    # Always mirror into memory so a later DB outage still sees recent state.
    with _mem_lock:
        _mem[agent_id] = (vec, float(ewma), int(sample_count))


# ── Public API ───────────────────────────────────────────────────────────────────

def update_drift(agent_id: str, events: list) -> float:
    """Fold a batch of events into the agent's drift index; return new EWMA.

    First observation establishes the baseline and returns 0.0 (no history to
    deviate from). Emits a ``drift_update`` observation carrying the score only.
    """
    if not agent_id:
        return 0.0
    labels = [_label(e) for e in events if _label(e)]
    new_vec = frequency_vector(labels)
    if not new_vec:
        # Nothing to learn from; return the last known score.
        base = _load_baseline(agent_id)
        return base[1] if base else 0.0

    base = _load_baseline(agent_id)
    if base is None:
        _save_baseline(agent_id, new_vec, 0.0, len(labels))
        return 0.0

    prev_vec, prev_ewma, sample_count = base
    dist = weighted_cosine_distance(prev_vec, new_vec, DRIFT_WEIGHTS)
    lam = settings.gsam_drift_lambda
    new_ewma = ewma_drift(prev_ewma, dist, lam)
    merged = blend_vectors(prev_vec, new_vec, lam)
    _save_baseline(agent_id, merged, new_ewma, sample_count + len(labels))
    _emit_drift(agent_id, new_ewma)
    return new_ewma


def get_drift(agent_id: str) -> float:
    """Return the current EWMA drift for an agent (0.0 if unknown)."""
    base = _load_baseline(agent_id)
    return base[1] if base else 0.0


def _emit_drift(agent_id: str, drift_score: float) -> None:
    with contextlib.suppress(Exception):
        from warden.gsam.collector import gsam_emit  # noqa: PLC0415
        from warden.gsam.schema import Observation  # noqa: PLC0415

        gsam_emit(Observation(
            agent_id=agent_id,
            event="drift_update",
            payload_kind="drift",
            drift_score=float(drift_score),
        ).to_row())
