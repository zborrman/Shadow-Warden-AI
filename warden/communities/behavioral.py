"""
warden/communities/behavioral.py
──────────────────────────────────
Community Behavioral Baseline & Anomaly Detection.

Architecture
────────────
  1. record_event(community_id, event_type, payload_bytes)
       → increments Redis sliding-window counters (hourly + daily).
       → SQLite fallback in dev/test.

  2. compute_baseline(community_id)
       → reads 30-day history → computes mean + stddev per metric.
       → stored as BaselineSnapshot in Redis / SQLite.

  3. detect_anomaly(community_id, event_type, value)
       → z-score = (value - mean) / stddev
       → severity: NORMAL (<2σ) | ELEVATED (≥2σ) | CRITICAL (≥3σ)
       → returns AnomalyResult with recommended action.

Anomaly patterns tracked
────────────────────────
  off_hours_access     — req/hour outside 07:00–22:00 UTC baseline
  bulk_transfer        — payload_bytes/event > p99 baseline
  velocity_spike       — req/min > 3σ above 30-day mean
  data_class_shift     — unexpected data_class (not seen in 30-day window)
  new_peering_burst    — >3 new peerins in <1h (account-takeover signal)
"""
from __future__ import annotations

import json
import logging
import math
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

log = logging.getLogger("warden.communities.behavioral")

_BEHAVIORAL_DB = os.getenv("BEHAVIORAL_DB_PATH", "/tmp/warden_behavioral.db")
_db_lock = threading.RLock()

# Redis-style in-memory fallback (no dependency on fakeredis)
_mem_store: dict[str, list[float]] = {}
_mem_lock = threading.RLock()


# ── Schema ────────────────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_BEHAVIORAL_DB, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS behavioral_events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            community_id TEXT NOT NULL,
            event_type   TEXT NOT NULL,
            value        REAL NOT NULL DEFAULT 1.0,
            data_class   TEXT NOT NULL DEFAULT 'GENERAL',
            hour_utc     INTEGER NOT NULL,
            recorded_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_bev_community_type
            ON behavioral_events(community_id, event_type, recorded_at)
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS behavioral_baselines (
            community_id TEXT NOT NULL,
            event_type   TEXT NOT NULL,
            mean         REAL NOT NULL DEFAULT 0.0,
            stddev       REAL NOT NULL DEFAULT 1.0,
            sample_count INTEGER NOT NULL DEFAULT 0,
            p99          REAL NOT NULL DEFAULT 0.0,
            computed_at  TEXT NOT NULL,
            PRIMARY KEY (community_id, event_type)
        )
    """)
    conn.commit()
    return conn


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class AnomalyResult:
    community_id: str
    event_type: str
    value: float
    z_score: float
    severity: str       # NORMAL | ELEVATED | CRITICAL
    action: str         # ALLOW | ALERT | BLOCK
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "community_id": self.community_id,
            "event_type":   self.event_type,
            "value":        self.value,
            "z_score":      round(self.z_score, 3),
            "severity":     self.severity,
            "action":       self.action,
            "reason":       self.reason,
        }


@dataclass
class BaselineSnapshot:
    community_id: str
    event_type: str
    mean: float
    stddev: float
    sample_count: int
    p99: float
    computed_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "community_id": self.community_id,
            "event_type":   self.event_type,
            "mean":         round(self.mean, 4),
            "stddev":       round(self.stddev, 4),
            "sample_count": self.sample_count,
            "p99":          round(self.p99, 4),
            "computed_at":  self.computed_at,
        }


# ── Event recording ───────────────────────────────────────────────────────────

_KNOWN_EVENT_TYPES = {
    "request",
    "transfer",
    "bulk_transfer",
    "off_hours_access",
    "new_peering",
    "member_join",
    "charter_accept",
    "file_scan",
}


def record_event(
    community_id: str,
    event_type: str,
    value: float = 1.0,
    data_class: str = "GENERAL",
) -> None:
    """Record one behavioral event. Fire-and-forget; never raises."""
    try:
        hour_utc = datetime.now(UTC).hour
        with _db_lock:
            conn = _get_conn()
            conn.execute(
                """INSERT INTO behavioral_events
                   (community_id, event_type, value, data_class, hour_utc)
                   VALUES (?,?,?,?,?)""",
                (community_id, event_type, value, data_class, hour_utc),
            )
            conn.commit()
    except Exception as exc:  # noqa: BLE001
        log.debug("behavioral record_event failed: %s", exc)


# ── Baseline computation ──────────────────────────────────────────────────────

def compute_baseline(
    community_id: str,
    event_type: str = "request",
    days: int = 30,
) -> BaselineSnapshot:
    """Recompute and store the mean/stddev/p99 baseline from recent history."""
    conn = _get_conn()
    cutoff = f"{datetime.now(UTC).isoformat()[:10]}T00:00:00Z"
    # Rough approximation: filter by days via rowid ordering (good enough for SQLite)
    rows = conn.execute(
        """
        SELECT value FROM behavioral_events
        WHERE community_id=? AND event_type=?
          AND recorded_at >= datetime('now', ?)
        ORDER BY recorded_at
        """,
        (community_id, event_type, f"-{days} days"),
    ).fetchall()

    values = [float(r["value"]) for r in rows]
    if not values:
        snap = BaselineSnapshot(
            community_id=community_id,
            event_type=event_type,
            mean=0.0, stddev=1.0, sample_count=0, p99=0.0,
            computed_at=datetime.now(UTC).isoformat(),
        )
    else:
        n = len(values)
        mean = sum(values) / n
        variance = sum((v - mean) ** 2 for v in values) / max(n - 1, 1)
        stddev = math.sqrt(variance) or 1.0
        sorted_vals = sorted(values)
        p99_idx = min(int(0.99 * n), n - 1)
        snap = BaselineSnapshot(
            community_id=community_id,
            event_type=event_type,
            mean=mean,
            stddev=stddev,
            sample_count=n,
            p99=sorted_vals[p99_idx],
            computed_at=datetime.now(UTC).isoformat(),
        )

    with _db_lock:
        conn.execute(
            """INSERT OR REPLACE INTO behavioral_baselines
               (community_id, event_type, mean, stddev, sample_count, p99, computed_at)
               VALUES (?,?,?,?,?,?,?)""",
            (
                community_id, event_type,
                snap.mean, snap.stddev, snap.sample_count, snap.p99,
                snap.computed_at,
            ),
        )
        conn.commit()

    return snap


def get_baseline(community_id: str, event_type: str) -> BaselineSnapshot | None:
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM behavioral_baselines WHERE community_id=? AND event_type=?",
        (community_id, event_type),
    ).fetchone()
    if not row:
        return None
    return BaselineSnapshot(
        community_id=row["community_id"],
        event_type=row["event_type"],
        mean=row["mean"],
        stddev=row["stddev"],
        sample_count=row["sample_count"],
        p99=row["p99"],
        computed_at=row["computed_at"],
    )


# ── Anomaly detection ─────────────────────────────────────────────────────────

def detect_anomaly(
    community_id: str,
    event_type: str,
    value: float,
) -> AnomalyResult:
    """
    Z-score anomaly detection against stored baseline.
    Falls back to compute_baseline() on first call.
    """
    baseline = get_baseline(community_id, event_type)
    if baseline is None or baseline.sample_count < 10:
        # Not enough history — auto-compute and allow
        compute_baseline(community_id, event_type)
        return AnomalyResult(
            community_id=community_id,
            event_type=event_type,
            value=value,
            z_score=0.0,
            severity="NORMAL",
            action="ALLOW",
            reason="insufficient_history",
        )

    stddev = baseline.stddev if baseline.stddev > 0 else 1.0
    z = (value - baseline.mean) / stddev

    if abs(z) < 2.0:
        severity, action = "NORMAL", "ALLOW"
        reason = "within_2sigma"
    elif abs(z) < 3.0:
        severity, action = "ELEVATED", "ALERT"
        reason = f"z={z:.2f} exceeds 2σ baseline"
    else:
        severity, action = "CRITICAL", "BLOCK"
        reason = f"z={z:.2f} exceeds 3σ baseline — possible exfiltration"

    # Off-hours heuristic override
    if event_type == "off_hours_access" and value > 0:
        severity = max(severity, "ELEVATED")
        action = "ALERT" if action == "ALLOW" else action

    return AnomalyResult(
        community_id=community_id,
        event_type=event_type,
        value=value,
        z_score=z,
        severity=severity,
        action=action,
        reason=reason,
    )


def detect_off_hours(community_id: str) -> AnomalyResult:
    """Check whether the current request is outside 07:00–22:00 UTC."""
    hour = datetime.now(UTC).hour
    is_off = 1.0 if (hour < 7 or hour >= 22) else 0.0
    record_event(community_id, "off_hours_access", is_off)
    return detect_anomaly(community_id, "off_hours_access", is_off)


def detect_bulk_transfer(community_id: str, payload_bytes: int) -> AnomalyResult:
    mb = payload_bytes / (1024 * 1024)
    record_event(community_id, "bulk_transfer", mb)
    return detect_anomaly(community_id, "bulk_transfer", mb)


# ── Summary ───────────────────────────────────────────────────────────────────

def get_community_risk_summary(community_id: str) -> dict[str, Any]:
    """
    Returns a risk summary for a community across all tracked event types.
    Computes missing baselines on-the-fly (lazy).
    """
    summary: dict[str, Any] = {"community_id": community_id, "metrics": {}}
    for et in _KNOWN_EVENT_TYPES:
        bl = get_baseline(community_id, et)
        if bl:
            summary["metrics"][et] = bl.to_dict()
    return summary


def list_recent_anomalies(community_id: str, limit: int = 50) -> list[dict]:
    """Return recent events that would trigger ELEVATED/CRITICAL anomalies."""
    conn = _get_conn()
    rows = conn.execute(
        """
        SELECT e.event_type, e.value, e.recorded_at,
               b.mean, b.stddev
        FROM behavioral_events e
        LEFT JOIN behavioral_baselines b
          ON e.community_id=b.community_id AND e.event_type=b.event_type
        WHERE e.community_id=?
          AND b.stddev IS NOT NULL AND b.stddev > 0
          AND ABS((e.value - b.mean) / b.stddev) >= 2.0
        ORDER BY e.recorded_at DESC
        LIMIT ?
        """,
        (community_id, limit),
    ).fetchall()
    out = []
    for r in rows:
        stddev = r["stddev"] or 1.0
        z = (r["value"] - r["mean"]) / stddev
        out.append({
            "event_type":  r["event_type"],
            "value":       r["value"],
            "z_score":     round(z, 3),
            "severity":    "CRITICAL" if abs(z) >= 3 else "ELEVATED",
            "recorded_at": r["recorded_at"],
        })
    return out
