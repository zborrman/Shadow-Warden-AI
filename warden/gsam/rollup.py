"""
GSAM rollup sink — folds observation batches into `gsam_agent_stats` and
updates per-agent drift baselines.

Registered with `collector.register_sink()` at startup, so every flushed batch
is aggregated into the hourly rollup (the read APIs and the `gsam_agent_stats`
semantic model read this table — **never ClickHouse**). Pure aggregation math
lives in `fold_batch`; `drift.py` owns the EWMA/total-variation math. All DB
work is fail-open (the collector already suppresses sink exceptions).
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
from collections import defaultdict
from collections.abc import Generator, Iterable
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field

from warden.config import settings
from warden.db.connect import open_db
from warden.db.ddl_registry import register
from warden.gsam import drift as _drift

log = logging.getLogger("warden.gsam.rollup")

_db_lock = threading.RLock()

_ROLLUP_DDL = """
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
    CREATE INDEX IF NOT EXISTS idx_gsam_stats_tenant ON gsam_agent_stats(tenant_id, hour_bucket);
    CREATE TABLE IF NOT EXISTS gsam_drift_baselines (
        agent_id         TEXT PRIMARY KEY,
        freq_vector_json TEXT NOT NULL DEFAULT '{}',
        ewma_drift       REAL NOT NULL DEFAULT 0.0,
        sample_count     INTEGER NOT NULL DEFAULT 0,
        updated_at       TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS gsam_quarantine_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id    TEXT NOT NULL,
        reason      TEXT NOT NULL DEFAULT '',
        drift_score REAL NOT NULL DEFAULT 0.0,
        ts          TEXT NOT NULL,
        released_at TEXT NOT NULL DEFAULT ''
    );
"""
register("gsam", "warden.gsam.rollup", _ROLLUP_DDL)


@dataclass
class StatDelta:
    """Aggregated stats for one (agent_id, tenant_id, hour_bucket) key."""

    events: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    verdicts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    freq: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def trust(self) -> float:
        """Per-hour trust proxy ∈ [0,1]: 1 − (compromised + ½·warning)/events."""
        if self.events <= 0:
            return 1.0
        bad = self.verdicts.get("COMPROMISED", 0) + 0.5 * self.verdicts.get("WARNING", 0)
        return max(0.0, min(1.0, 1.0 - bad / self.events))


def _hour_bucket(ts: str) -> str:
    """Truncate an ISO timestamp to the hour ('YYYY-MM-DDTHH:00:00')."""
    if not ts:
        return ""
    # ts is 'YYYY-MM-DDTHH:MM:SS[.ffffff][+00:00]' — slice to the hour.
    head = ts.replace(" ", "T")[:13]  # 'YYYY-MM-DDTHH'
    return f"{head}:00:00" if len(head) == 13 else ""


def fold_batch(batch: Iterable[dict]) -> dict[tuple[str, str, str], StatDelta]:
    """Pure aggregation: group observations by (agent_id, tenant_id, hour)."""
    out: dict[tuple[str, str, str], StatDelta] = defaultdict(StatDelta)
    for obs in batch:
        agent_id = str(obs.get("agent_id", "") or "")
        if not agent_id:
            continue
        key = (agent_id, str(obs.get("tenant_id", "") or ""), _hour_bucket(str(obs.get("ts", ""))))
        d = out[key]
        d.events += 1
        d.tokens_in += int(obs.get("input_tokens", 0) or 0)
        d.tokens_out += int(obs.get("output_tokens", 0) or 0)
        d.cost_usd += float(obs.get("execution_cost", 0.0) or 0.0)
        d.verdicts[str(obs.get("scan_verdict", "CLEAN") or "CLEAN")] += 1
        kind = str(obs.get("payload_kind", "") or "")
        if kind:
            d.freq[kind] += 1
    return out


@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    with open_db(
        "gsam", settings.gsam_db_path, turso_name="gsam", module_default_path=settings.gsam_db_path
    ) as con:
        yield con


def _update_drift(con: sqlite3.Connection, agent_id: str, freq: dict[str, int]) -> float:
    """Update the agent's EWMA drift baseline; return the new drift score."""
    row = con.execute(
        "SELECT freq_vector_json, ewma_drift, sample_count FROM gsam_drift_baselines WHERE agent_id=?",
        (agent_id,),
    ).fetchone()
    prev_mu = json.loads(row["freq_vector_json"]) if row else {}
    prev_drift = float(row["ewma_drift"]) if row else 0.0
    samples = int(row["sample_count"]) if row else 0

    lam = settings.gsam_drift_lambda
    threshold = settings.gsam_drift_quarantine_threshold
    tv = _drift.total_variation(freq, prev_mu)
    new_drift = _drift.ewma_drift(prev_drift, tv, lam) if samples > 0 else 0.0
    new_mu = _drift.update_baseline(prev_mu, freq, lam, new_drift, threshold)

    from datetime import UTC, datetime  # noqa: PLC0415
    con.execute(
        "INSERT INTO gsam_drift_baselines (agent_id,freq_vector_json,ewma_drift,sample_count,updated_at) "
        "VALUES(?,?,?,?,?) ON CONFLICT(agent_id) DO UPDATE SET "
        "freq_vector_json=excluded.freq_vector_json, ewma_drift=excluded.ewma_drift, "
        "sample_count=excluded.sample_count, updated_at=excluded.updated_at",
        (agent_id, json.dumps(new_mu), new_drift, samples + 1, datetime.now(UTC).isoformat()),
    )
    return new_drift


def rollup_sink(batch: list[dict], redis=None) -> None:
    """Collector sink: fold a batch into gsam_agent_stats + update drift.

    Fail-open — any exception is logged and swallowed (the collector also
    suppresses, this is belt-and-braces so drift errors can't lose the stats).
    """
    if not batch:
        return
    folded = fold_batch(batch)
    if not folded:
        return

    quarantined: list[tuple[str, float]] = []
    with _db_lock, _conn() as con:
        # Per-agent drift (fold freq across all this agent's hour buckets in the batch).
        agent_freq: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for (agent_id, _tenant, _hour), d in folded.items():
            for k, v in d.freq.items():
                agent_freq[agent_id][k] += v
        agent_drift: dict[str, float] = {}
        for agent_id, freq in agent_freq.items():
            with suppress(Exception):
                agent_drift[agent_id] = _update_drift(con, agent_id, dict(freq))

        for (agent_id, tenant_id, hour), d in folded.items():
            drift_score = agent_drift.get(agent_id, 0.0)
            con.execute(
                "INSERT INTO gsam_agent_stats "
                "(agent_id,tenant_id,hour_bucket,events,tokens_in,tokens_out,cost_usd,roi,drift,trust,verdicts_json) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(agent_id,hour_bucket) DO UPDATE SET "
                "events=events+excluded.events, tokens_in=tokens_in+excluded.tokens_in, "
                "tokens_out=tokens_out+excluded.tokens_out, cost_usd=cost_usd+excluded.cost_usd, "
                "drift=excluded.drift, trust=excluded.trust, "
                "verdicts_json=excluded.verdicts_json",
                (agent_id, tenant_id, hour, d.events, d.tokens_in, d.tokens_out,
                 d.cost_usd, 0.0, drift_score, d.trust(), json.dumps(dict(d.verdicts))),
            )
            if drift_score >= settings.gsam_drift_quarantine_threshold:
                quarantined.append((agent_id, drift_score))

    # Quarantine outside the stats transaction (fail-open, own store).
    for agent_id, score in quarantined:
        with suppress(Exception):
            from warden.gsam.quarantine import quarantine_agent  # noqa: PLC0415
            quarantine_agent(agent_id, score, redis=redis)


# ── Read helpers (rollup-backed — never ClickHouse) ─────────────────────────

def read_agent_stats(agent_id: str, hours: int = 24) -> dict:
    """Hourly rows + current drift for one agent over the last *hours*."""
    with _db_lock, _conn() as con:
        rows = con.execute(
            "SELECT hour_bucket,events,tokens_in,tokens_out,cost_usd,drift,trust,verdicts_json "
            "FROM gsam_agent_stats WHERE agent_id=? ORDER BY hour_bucket DESC LIMIT ?",
            (agent_id, max(1, hours)),
        ).fetchall()
        base = con.execute(
            "SELECT ewma_drift,sample_count,updated_at FROM gsam_drift_baselines WHERE agent_id=?",
            (agent_id,),
        ).fetchone()
    return {
        "agent_id": agent_id,
        "current_drift": float(base["ewma_drift"]) if base else 0.0,
        "sample_count": int(base["sample_count"]) if base else 0,
        "updated_at": base["updated_at"] if base else "",
        "hours": [
            {
                "hour": r["hour_bucket"], "events": r["events"],
                "tokens_in": r["tokens_in"], "tokens_out": r["tokens_out"],
                "cost_usd": round(r["cost_usd"], 6), "drift": round(r["drift"], 4),
                "trust": round(r["trust"], 4), "verdicts": json.loads(r["verdicts_json"] or "{}"),
            }
            for r in rows
        ],
    }


def read_heatmap(tenant_id: str = "", hours: int = 24) -> dict:
    """Per-agent latest drift/trust grid over the recent window."""
    where = "WHERE tenant_id=? " if tenant_id else ""
    params: tuple = (tenant_id,) if tenant_id else ()
    with _db_lock, _conn() as con:
        rows = con.execute(
            "SELECT agent_id, MAX(hour_bucket) AS hour, "
            "SUM(events) AS events, AVG(drift) AS drift, AVG(trust) AS trust "
            f"FROM gsam_agent_stats {where}"
            "GROUP BY agent_id ORDER BY drift DESC LIMIT 200",
            params,
        ).fetchall()
    return {
        "tenant_id": tenant_id,
        "agents": [
            {"agent_id": r["agent_id"], "latest_hour": r["hour"], "events": int(r["events"] or 0),
             "drift": round(float(r["drift"] or 0.0), 4), "trust": round(float(r["trust"] or 0.0), 4)}
            for r in rows
        ],
    }


def compliance_score(tenant_id: str = "", hours: int = 168) -> dict:
    """Aggregate 0–100 posture from the rollup: mean trust, discounted by the
    fraction of agents currently drift-quarantined."""
    where = "WHERE tenant_id=? " if tenant_id else ""
    params: tuple = (tenant_id,) if tenant_id else ()
    with _db_lock, _conn() as con:
        agg = con.execute(
            "SELECT COUNT(DISTINCT agent_id) AS agents, AVG(trust) AS trust, "
            "SUM(events) AS events FROM gsam_agent_stats " + where,
            params,
        ).fetchone()
        quarantined = con.execute(
            "SELECT COUNT(DISTINCT agent_id) AS n FROM gsam_quarantine_log WHERE released_at=''"
        ).fetchone()
    agents = int(agg["agents"] or 0)
    mean_trust = float(agg["trust"] or 1.0)
    q = int(quarantined["n"] or 0)
    q_frac = (q / agents) if agents else 0.0
    score = round(100.0 * mean_trust * (1.0 - q_frac), 1)
    return {
        "tenant_id": tenant_id, "score": max(0.0, min(100.0, score)),
        "agents": agents, "events": int(agg["events"] or 0),
        "mean_trust": round(mean_trust, 4), "quarantined_agents": q,
    }
