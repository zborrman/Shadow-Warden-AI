"""
GSAM hourly rollup sink.

Registered with the collector via ``install()`` so every flushed batch is folded
into the ``gsam_agent_stats`` hourly rollup (SQLite ``gsam`` DB). This is what
makes GSAM read APIs work even when ClickHouse is disabled or down — the rollup
is computed on the collector thread's normal flush ticks, no new scheduler.

Fail-open: a rollup error is logged and swallowed; it never affects the batch's
ClickHouse shipping or the producer hot path.
"""
from __future__ import annotations

import contextlib
import json
import logging
import threading

from warden.config import settings

log = logging.getLogger("warden.gsam.rollup")

_DDL = """
    CREATE TABLE IF NOT EXISTS gsam_agent_stats (
        agent_id      TEXT NOT NULL,
        tenant_id     TEXT NOT NULL DEFAULT '',
        hour_bucket   TEXT NOT NULL,
        events        INTEGER NOT NULL DEFAULT 0,
        tokens_in     INTEGER NOT NULL DEFAULT 0,
        tokens_out    INTEGER NOT NULL DEFAULT 0,
        cost_usd      REAL NOT NULL DEFAULT 0.0,
        roi           REAL NOT NULL DEFAULT 0.0,
        drift         REAL NOT NULL DEFAULT 0.0,
        trust         REAL NOT NULL DEFAULT 0.0,
        verdicts_json TEXT NOT NULL DEFAULT '{}',
        PRIMARY KEY (agent_id, hour_bucket)
    );
"""

_installed = False
_install_lock = threading.Lock()


def install() -> None:
    """Register the rollup as a collector sink (idempotent, fail-open)."""
    global _installed
    with _install_lock:
        if _installed:
            return
        with contextlib.suppress(Exception):
            from warden.gsam.collector import register_sink  # noqa: PLC0415
            register_sink(rollup_sink)
            _installed = True


def _hour_bucket(ts: str) -> str:
    """Truncate an ISO timestamp to the hour (e.g. '2026-07-09T12')."""
    return str(ts)[:13] if ts else ""


def _int(v: object) -> int:
    try:
        return int(v)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return 0


def _float(v: object) -> float:
    try:
        return float(v)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0


def _aggregate(batch: list[dict]) -> dict[tuple[str, str], dict]:
    """Fold a batch into per-(agent_id, hour_bucket) accumulators.

    Malformed rows are skipped individually — one bad row never loses the batch.
    """
    acc: dict[tuple[str, str], dict] = {}
    for row in batch:
        if not isinstance(row, dict):
            continue
        agent_id = str(row.get("agent_id", ""))
        if not agent_id:
            continue
        hour = _hour_bucket(str(row.get("ts", "") or ""))
        if not hour:
            continue
        key = (agent_id, hour)
        cell = acc.get(key)
        if cell is None:
            cell = {
                "tenant_id":  str(row.get("tenant_id", "")),
                "events":     0,
                "tokens_in":  0,
                "tokens_out": 0,
                "cost_usd":   0.0,
                "drift":      0.0,
                "trust":      0.0,
                "verdicts":   {},
            }
            acc[key] = cell
        cell["events"] += 1
        cell["tokens_in"] += _int(row.get("input_tokens", 0))
        cell["tokens_out"] += _int(row.get("output_tokens", 0))
        cell["cost_usd"] += _float(row.get("execution_cost", 0.0))
        if row.get("tenant_id"):
            cell["tenant_id"] = str(row["tenant_id"])
        # Gauges: keep the latest non-zero reading in the batch.
        drift = _float(row.get("drift_score", 0.0))
        if drift:
            cell["drift"] = drift
        trust = _float(row.get("trust_score", 0.0))
        if trust:
            cell["trust"] = trust
        verdict = str(row.get("scan_verdict", "") or "")
        if verdict:
            cell["verdicts"][verdict] = cell["verdicts"].get(verdict, 0) + 1
    return acc


def rollup_sink(batch: list[dict]) -> None:
    """Collector sink — accumulate a flushed batch into the hourly rollup."""
    acc = _aggregate(batch)
    if not acc:
        return
    try:
        from warden.db.turso import get_connection  # noqa: PLC0415

        with get_connection("gsam", fallback_path=settings.gsam_db_path) as con:
            with contextlib.suppress(Exception):
                con.executescript(_DDL)
            for (agent_id, hour), cell in acc.items():
                _upsert(con, agent_id, hour, cell)
            with contextlib.suppress(Exception):
                con.commit()
    except Exception as exc:  # noqa: BLE001
        log.debug("rollup: fold skipped (fail-open): %s", exc)


def _upsert(con, agent_id: str, hour: str, cell: dict) -> None:
    """Read-modify-write one rollup row (accumulates counters + verdict map)."""
    cur = con.execute(
        "SELECT events, tokens_in, tokens_out, cost_usd, verdicts_json "
        "FROM gsam_agent_stats WHERE agent_id = ? AND hour_bucket = ?",
        (agent_id, hour),
    )
    existing = cur.fetchone()
    verdicts = dict(cell["verdicts"])
    if existing is None:
        events, t_in, t_out, cost = 0, 0, 0, 0.0
    else:
        events, t_in, t_out, cost = int(existing[0]), int(existing[1]), int(existing[2]), float(existing[3])
        with contextlib.suppress(Exception):
            for k, v in json.loads(existing[4] or "{}").items():
                verdicts[k] = verdicts.get(k, 0) + int(v)

    con.execute(
        "INSERT INTO gsam_agent_stats "
        "(agent_id, tenant_id, hour_bucket, events, tokens_in, tokens_out, "
        " cost_usd, roi, drift, trust, verdicts_json) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(agent_id, hour_bucket) DO UPDATE SET "
        "tenant_id=excluded.tenant_id, events=excluded.events, "
        "tokens_in=excluded.tokens_in, tokens_out=excluded.tokens_out, "
        "cost_usd=excluded.cost_usd, drift=excluded.drift, "
        "trust=excluded.trust, verdicts_json=excluded.verdicts_json",
        (
            agent_id, cell["tenant_id"], hour,
            events + cell["events"],
            t_in + cell["tokens_in"],
            t_out + cell["tokens_out"],
            cost + cell["cost_usd"],
            0.0,                       # roi computed at read time from mp_trades
            cell["drift"],
            cell["trust"],
            json.dumps(verdicts),
        ),
    )
