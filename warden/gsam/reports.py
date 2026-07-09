"""
GSAM read models — heatmap, per-agent stats, anti-inflation compliance score.

All reads come from the SQLite ``gsam_agent_stats`` hourly rollup so the APIs
work with ClickHouse disabled/down. When ClickHouse IS enabled the heatmap
prefers a per-``payload_kind`` GROUP BY over the raw observation stream, falling
back to the rollup on any error.

Every function is fail-open: an error returns an empty/neutral result rather
than raising into the request handler.
"""
from __future__ import annotations

import contextlib
import json
import logging

from warden.config import settings
from warden.gsam.math import anti_inflation_score, roi

log = logging.getLogger("warden.gsam.reports")

# Above this hourly event count an agent counts as "elevated frequency" (weak
# anti-inflation signal).
_ELEVATED_EVENTS = 10_000


def _conn():
    from warden.db.turso import get_connection  # noqa: PLC0415
    return get_connection("gsam", fallback_path=settings.gsam_db_path)


# ── Heatmap ──────────────────────────────────────────────────────────────────────

def heatmap(hours: int = 24) -> dict:
    """Demand buckets over the recent window.

    ClickHouse (when enabled): demand per service category (payload_kind).
    Otherwise: demand per hour bucket from the rollup.
    """
    hours = max(1, min(int(hours), 168))
    if settings.gsam_clickhouse_enabled:
        ch = _heatmap_clickhouse(hours)
        if ch is not None:
            return ch
    return _heatmap_rollup(hours)


def _heatmap_clickhouse(hours: int) -> dict | None:
    try:
        from warden.gsam.clickhouse import get_clickhouse  # noqa: PLC0415

        ch = get_clickhouse()
        if not (ch.is_enabled() and ch.ping()):
            return None
        rows = ch.query(
            "SELECT payload_kind AS category, count() AS events, "
            "sum(execution_cost) AS cost_usd "
            "FROM gsam.gsam_observations "
            "WHERE ts >= now() - INTERVAL %(h)s HOUR "
            "GROUP BY payload_kind ORDER BY events DESC LIMIT 100",
            {"h": hours},
        )
        buckets = [
            {
                "category": str(r.get("category", "")),
                "events":   int(r.get("events", 0) or 0),
                "cost_usd": float(r.get("cost_usd", 0.0) or 0.0),
            }
            for r in rows
        ]
        return {"source": "clickhouse", "group_by": "payload_kind", "buckets": buckets}
    except Exception as exc:  # noqa: BLE001
        log.debug("gsam heatmap: clickhouse path failed, using rollup: %s", exc)
        return None


def _heatmap_rollup(hours: int) -> dict:
    buckets: list[dict] = []
    try:
        with _conn() as con:
            cur = con.execute(
                "SELECT hour_bucket, SUM(events), SUM(cost_usd) "
                "FROM gsam_agent_stats GROUP BY hour_bucket "
                "ORDER BY hour_bucket DESC LIMIT ?",
                (hours,),
            )
            for row in cur.fetchall():
                buckets.append({
                    "category": str(row[0]),
                    "events":   int(row[1] or 0),
                    "cost_usd": float(row[2] or 0.0),
                })
    except Exception as exc:  # noqa: BLE001
        log.debug("gsam heatmap: rollup read failed (fail-open): %s", exc)
    return {"source": "rollup", "group_by": "hour", "buckets": buckets}


# ── Per-agent stats ──────────────────────────────────────────────────────────────

def agent_stats(agent_id: str) -> dict:
    """Aggregate rollup stats for one agent + live drift / quarantine state."""
    stats = {
        "agent_id":    agent_id,
        "events":      0,
        "tokens_in":   0,
        "tokens_out":  0,
        "cost_usd":    0.0,
        "roi":         0.0,
        "drift":       0.0,
        "trust":       0.0,
        "quarantined": False,
        "verdicts":    {},
    }
    if not agent_id:
        return stats

    cost_usd = 0.0
    try:
        with _conn() as con:
            cur = con.execute(
                "SELECT SUM(events), SUM(tokens_in), SUM(tokens_out), SUM(cost_usd), "
                "MAX(drift), AVG(trust) FROM gsam_agent_stats WHERE agent_id = ?",
                (agent_id,),
            )
            row = cur.fetchone()
            if row and row[0] is not None:
                cost_usd = float(row[3] or 0.0)
                stats["events"] = int(row[0] or 0)
                stats["tokens_in"] = int(row[1] or 0)
                stats["tokens_out"] = int(row[2] or 0)
                stats["cost_usd"] = cost_usd
                stats["drift"] = float(row[4] or 0.0)
                stats["trust"] = float(row[5] or 0.0)
            stats["verdicts"] = _agent_verdicts(con, agent_id)
    except Exception as exc:  # noqa: BLE001
        log.debug("gsam agent_stats: rollup read failed (fail-open): %s", exc)

    # Live drift overrides the rollup snapshot when available.
    with contextlib.suppress(Exception):
        from warden.gsam.drift import get_drift  # noqa: PLC0415
        live = get_drift(agent_id)
        if live:
            stats["drift"] = live
    with contextlib.suppress(Exception):
        from warden.gsam.quarantine import is_quarantined  # noqa: PLC0415
        stats["quarantined"] = is_quarantined(agent_id)

    stats["roi"] = roi(_realised_value_usd(agent_id), cost_usd)
    return stats


def _agent_verdicts(con, agent_id: str) -> dict:
    verdicts: dict[str, int] = {}
    with contextlib.suppress(Exception):
        cur = con.execute(
            "SELECT verdicts_json FROM gsam_agent_stats WHERE agent_id = ?",
            (agent_id,),
        )
        for row in cur.fetchall():
            for k, v in json.loads(row[0] or "{}").items():
                verdicts[k] = verdicts.get(k, 0) + int(v)
    return verdicts


def _realised_value_usd(agent_id: str) -> float:
    """Best-effort realised trade value from the marketplace trade ledger.

    Returns 0.0 when the ledger is unavailable — ROI then degrades to 0.0
    rather than raising.
    """
    with contextlib.suppress(Exception):
        from warden.db.turso import get_connection  # noqa: PLC0415

        mkt_path = settings.marketplace_db_path
        with get_connection("marketplace", fallback_path=mkt_path) as con:
            cur = con.execute(
                "SELECT SUM(amount_usd) FROM mp_trades WHERE seller_agent_id = ?",
                (agent_id,),
            )
            row = cur.fetchone()
            if row and row[0] is not None:
                return float(row[0])
    return 0.0


# ── Anti-inflation compliance score ──────────────────────────────────────────────

def compliance_score() -> dict:
    """Marketplace-wide anti-inflation compliance score from current posture."""
    rows: list[dict] = []
    try:
        with _conn() as con:
            cur = con.execute(
                "SELECT agent_id, SUM(events), MAX(drift), verdicts_json "
                "FROM gsam_agent_stats GROUP BY agent_id"
            )
            for r in cur.fetchall():
                verdicts = {}
                with contextlib.suppress(Exception):
                    verdicts = json.loads(r[3] or "{}")
                rows.append({
                    "agent_id": str(r[0]),
                    "events":   int(r[1] or 0),
                    "drift":    float(r[2] or 0.0),
                    "verdicts": verdicts,
                })
    except Exception as exc:  # noqa: BLE001
        log.debug("gsam compliance_score: rollup read failed (fail-open): %s", exc)

    quarantined = _quarantined_ids()
    patterns = _detect_patterns(rows, quarantined)
    result = anti_inflation_score(patterns)
    result["agents_scanned"] = len(rows)
    result["quarantined_count"] = len(quarantined)
    return result


def _quarantined_ids() -> set[str]:
    with contextlib.suppress(Exception):
        from warden.gsam.quarantine import list_active  # noqa: PLC0415
        return {a["agent_id"] for a in list_active()}
    return set()


def _detect_patterns(rows: list[dict], quarantined: set[str]) -> list[str]:
    """Map observable rollup posture onto anti-inflation pattern labels."""
    patterns: list[str] = []
    threshold = settings.gsam_drift_quarantine_threshold

    # Strong: an agent whose behaviour diverged past the quarantine threshold.
    if any(r["drift"] >= threshold for r in rows):
        patterns.append("cost_spike_no_value")
    # Strong: coordinated quarantine (>=2 agents) reads as collusion-like.
    if len(quarantined) >= 2:
        patterns.append("circular_agent_calls")
    # Strong: any COMPROMISED scan verdict recorded in the window.
    if any("COMPROMISED" in r["verdicts"] for r in rows):
        patterns.append("self_dealing")
    # Weak: unusually high event volume from any single agent.
    if rows and max(r["events"] for r in rows) > _ELEVATED_EVENTS:
        patterns.append("elevated_frequency")
    return patterns
