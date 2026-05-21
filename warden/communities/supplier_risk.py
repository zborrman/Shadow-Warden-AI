"""
warden/communities/supplier_risk.py  (CM-36)
─────────────────────────────────────────────
Supplier AI Risk Assessment — 5-criteria weighted scoring for AI vendors
using community peering history, DPA status, and declared capabilities.

Criteria (weighted composite):
  1. data_access       (0.30) — what data the vendor can see
  2. ai_capability     (0.20) — sophistication of AI features (higher = more risk)
  3. compliance_posture(0.25) — DPA coverage and currency
  4. peering_history   (0.15) — transfer rejection rate from STIX chain
  5. disclosure_recency(0.10) — days since last security disclosure

Tiers: Community Business+ (supplier_risk_enabled)
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime

log = logging.getLogger("warden.communities.supplier_risk")

_DB_PATH = os.getenv("SEP_DB_PATH", "/tmp/warden_sep.db")
_db_lock = threading.RLock()

_RISK_LABELS = {(0.0, 0.35): "LOW", (0.35, 0.60): "MEDIUM", (0.60, 0.80): "HIGH", (0.80, 1.01): "CRITICAL"}

_WEIGHTS = {
    "data_access":        0.30,
    "ai_capability":      0.20,
    "compliance_posture": 0.25,
    "peering_history":    0.15,
    "disclosure_recency": 0.10,
}


@contextmanager
def _conn(db_path: str = _DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    con = sqlite3.connect(db_path, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    _ensure_schema(con)
    try:
        yield con
        con.commit()
    finally:
        con.close()


def _ensure_schema(con: sqlite3.Connection) -> None:
    con.executescript("""
        CREATE TABLE IF NOT EXISTS supplier_risk_assessments (
            assessment_id      TEXT PRIMARY KEY,
            community_id       TEXT NOT NULL,
            vendor_id          TEXT NOT NULL,
            data_access        REAL NOT NULL DEFAULT 0.5,
            ai_capability      REAL NOT NULL DEFAULT 0.5,
            compliance_posture REAL NOT NULL DEFAULT 0.5,
            peering_history    REAL NOT NULL DEFAULT 0.5,
            disclosure_recency REAL NOT NULL DEFAULT 0.5,
            composite_score    REAL NOT NULL DEFAULT 0.5,
            risk_label         TEXT NOT NULL DEFAULT 'MEDIUM',
            assessed_at        TEXT NOT NULL,
            notes              TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_sra_community ON supplier_risk_assessments(community_id);
        CREATE INDEX IF NOT EXISTS idx_sra_vendor    ON supplier_risk_assessments(vendor_id);
        CREATE INDEX IF NOT EXISTS idx_sra_risk      ON supplier_risk_assessments(community_id, risk_label);
    """)
    con.commit()


def _score_to_label(score: float) -> str:
    for (lo, hi), label in _RISK_LABELS.items():
        if lo <= score < hi:
            return label
    return "CRITICAL"


def _compute_compliance_posture(vendor_id: str, tenant_id: str, db_path: str) -> float:
    """
    0.0 = perfect compliance (all DPAs active, none expiring)
    1.0 = terrible compliance (no DPAs or all expired)
    """
    try:
        con = sqlite3.connect(db_path, check_same_thread=False)
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT status, expires_at FROM vendor_dpa_records WHERE vendor_id=? AND tenant_id=?",
            (vendor_id, tenant_id),
        ).fetchall()
        con.close()
    except Exception:
        return 0.5  # unknown — neutral

    if not rows:
        return 0.8  # no DPAs is high risk

    now = datetime.now(UTC).isoformat()
    active  = sum(1 for r in rows if r["status"] == "active" and (r["expires_at"] is None or r["expires_at"] > now))
    total   = len(rows)
    coverage = active / total if total else 0
    return round(1.0 - coverage, 3)


def _compute_peering_history(community_id: str, vendor_id: str, db_path: str) -> float:
    """
    0.0 = no rejections (clean)
    1.0 = all transfers rejected (very risky)
    Based on sep_transfers rejection rate.
    """
    try:
        con = sqlite3.connect(db_path, check_same_thread=False)
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT status FROM sep_transfers WHERE source_community_id=? LIMIT 100",
            (community_id,),
        ).fetchall()
        con.close()
    except Exception:
        return 0.3  # unknown — lean clean

    if not rows:
        return 0.2  # no history — assume low risk

    rejected = sum(1 for r in rows if r["status"] == "REJECTED")
    return round(rejected / len(rows), 3)


def assess_supplier(
    community_id: str,
    vendor_id: str,
    tenant_id: str = "",
    context: dict | None = None,
    notes: str = "",
    db_path: str = _DB_PATH,
) -> dict:
    """
    Compute and store a supplier risk assessment.

    context keys (all optional, override auto-computed sub-scores):
      data_access, ai_capability, compliance_posture, peering_history, disclosure_recency
    """
    ctx = context or {}

    data_access        = float(ctx.get("data_access",        0.5))
    ai_capability      = float(ctx.get("ai_capability",      0.5))
    compliance_posture = float(ctx.get("compliance_posture",
                                        _compute_compliance_posture(vendor_id, tenant_id, db_path)))
    peering_history    = float(ctx.get("peering_history",
                                        _compute_peering_history(community_id, vendor_id, db_path)))
    disclosure_recency = float(ctx.get("disclosure_recency", 0.3))

    # Clamp all to [0,1]
    scores = {
        "data_access":        max(0.0, min(1.0, data_access)),
        "ai_capability":      max(0.0, min(1.0, ai_capability)),
        "compliance_posture": max(0.0, min(1.0, compliance_posture)),
        "peering_history":    max(0.0, min(1.0, peering_history)),
        "disclosure_recency": max(0.0, min(1.0, disclosure_recency)),
    }

    composite   = round(sum(scores[k] * _WEIGHTS[k] for k in _WEIGHTS), 4)
    risk_label  = _score_to_label(composite)
    now         = datetime.now(UTC).isoformat()
    assessment_id = str(uuid.uuid4())

    with _db_lock, _conn(db_path) as con:
        con.execute(
            """INSERT OR REPLACE INTO supplier_risk_assessments
               (assessment_id, community_id, vendor_id, data_access, ai_capability,
                compliance_posture, peering_history, disclosure_recency,
                composite_score, risk_label, assessed_at, notes)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (assessment_id, community_id, vendor_id,
             scores["data_access"], scores["ai_capability"],
             scores["compliance_posture"], scores["peering_history"],
             scores["disclosure_recency"], composite, risk_label, now, notes),
        )

    log.info("supplier_risk: %s vendor=%s score=%.3f label=%s", assessment_id, vendor_id, composite, risk_label)
    return {
        "assessment_id":      assessment_id,
        "community_id":       community_id,
        "vendor_id":          vendor_id,
        "scores":             scores,
        "composite_score":    composite,
        "risk_label":         risk_label,
        "assessed_at":        now,
        "notes":              notes,
    }


def list_assessments(
    community_id: str,
    risk_label: str | None = None,
    db_path: str = _DB_PATH,
) -> list[dict]:
    sql    = "SELECT * FROM supplier_risk_assessments WHERE community_id = ?"
    params: list = [community_id]
    if risk_label:
        sql += " AND risk_label = ?"
        params.append(risk_label.upper())
    sql   += " ORDER BY assessed_at DESC LIMIT 200"
    with _conn(db_path) as con:
        rows = con.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def get_community_supplier_report(community_id: str, db_path: str = _DB_PATH) -> dict:
    with _conn(db_path) as con:
        total = con.execute(
            "SELECT COUNT(DISTINCT vendor_id) FROM supplier_risk_assessments WHERE community_id=?",
            (community_id,),
        ).fetchone()[0]
        by_label = con.execute(
            "SELECT risk_label, COUNT(*) as cnt FROM supplier_risk_assessments WHERE community_id=? GROUP BY risk_label",
            (community_id,),
        ).fetchall()
        top_risky = con.execute(
            """SELECT vendor_id, composite_score FROM supplier_risk_assessments
               WHERE community_id=? ORDER BY composite_score DESC LIMIT 5""",
            (community_id,),
        ).fetchall()
    return {
        "community_id":    community_id,
        "total_vendors":   total,
        "by_risk_label":   {r["risk_label"]: r["cnt"] for r in by_label},
        "top_risky_vendors": [{"vendor_id": r["vendor_id"], "score": r["composite_score"]} for r in top_risky],
    }
