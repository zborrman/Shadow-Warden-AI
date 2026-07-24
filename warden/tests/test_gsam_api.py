"""GSAM PR 6 — read APIs + Semantic Layer model (GSAM-06).

Seeds the SQLite rollup directly (ClickHouse off) and exercises heatmap,
per-agent stats, compliance score, tier gating, and the gsam_agent_stats
semantic-model SQL generation.
"""
from __future__ import annotations

import sqlite3

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from warden.config import settings

_PRO = {"X-Tenant-Tier": "pro"}


def _seed(db_path: str, rows: list[dict]) -> None:
    con = sqlite3.connect(db_path)
    con.execute("""
        CREATE TABLE IF NOT EXISTS gsam_agent_stats (
            agent_id TEXT NOT NULL, tenant_id TEXT NOT NULL DEFAULT '',
            hour_bucket TEXT NOT NULL, events INTEGER NOT NULL DEFAULT 0,
            tokens_in INTEGER NOT NULL DEFAULT 0, tokens_out INTEGER NOT NULL DEFAULT 0,
            cost_usd REAL NOT NULL DEFAULT 0.0, roi REAL NOT NULL DEFAULT 0.0,
            drift REAL NOT NULL DEFAULT 0.0, trust REAL NOT NULL DEFAULT 0.0,
            verdicts_json TEXT NOT NULL DEFAULT '{}',
            PRIMARY KEY (agent_id, hour_bucket)
        )
    """)
    for r in rows:
        con.execute(
            "INSERT OR REPLACE INTO gsam_agent_stats "
            "(agent_id, tenant_id, hour_bucket, events, tokens_in, tokens_out, "
            " cost_usd, drift, trust, verdicts_json) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                r["agent_id"], r.get("tenant_id", "t-1"), r["hour_bucket"],
                r.get("events", 0), r.get("tokens_in", 0), r.get("tokens_out", 0),
                r.get("cost_usd", 0.0), r.get("drift", 0.0), r.get("trust", 0.0),
                r.get("verdicts_json", "{}"),
            ),
        )
    con.commit()
    con.close()


@pytest.fixture()
def gsam_env(tmp_path, monkeypatch):
    db = tmp_path / "gsam.db"
    monkeypatch.setattr(settings, "gsam_db_path", str(db))
    monkeypatch.setattr(settings, "gsam_clickhouse_enabled", False)
    monkeypatch.setattr(settings, "gsam_drift_quarantine_threshold", 0.85)
    # Isolate quarantine + drift in-process state between tests.
    from warden.gsam import drift as _d
    from warden.gsam import quarantine as _q
    _q._mem.clear()
    _d._mem.clear()
    yield str(db)
    _q._mem.clear()
    _d._mem.clear()


@pytest.fixture()
def client() -> TestClient:
    from warden.gsam.api import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


# ── heatmap ──────────────────────────────────────────────────────────────────────

def test_heatmap_rollup_fallback(gsam_env, client) -> None:
    _seed(gsam_env, [
        {"agent_id": "a1", "hour_bucket": "2026-07-09T12", "events": 5, "cost_usd": 0.01},
        {"agent_id": "a2", "hour_bucket": "2026-07-09T13", "events": 3, "cost_usd": 0.02},
    ])
    resp = client.get("/gsam/heatmap", headers=_PRO)
    assert resp.status_code == 200
    data = resp.json()
    assert data["source"] == "rollup"
    assert data["group_by"] == "hour"
    assert len(data["buckets"]) == 2


def test_heatmap_empty(gsam_env, client) -> None:
    resp = client.get("/gsam/heatmap", headers=_PRO)
    assert resp.status_code == 200
    assert resp.json()["buckets"] == []


# ── agent stats ──────────────────────────────────────────────────────────────────

def test_agent_stats_aggregates(gsam_env, client) -> None:
    _seed(gsam_env, [
        {"agent_id": "a1", "hour_bucket": "2026-07-09T12", "events": 5,
         "tokens_in": 100, "tokens_out": 40, "cost_usd": 0.01, "drift": 0.3, "trust": 0.7},
        {"agent_id": "a1", "hour_bucket": "2026-07-09T13", "events": 7,
         "tokens_in": 200, "tokens_out": 60, "cost_usd": 0.02, "drift": 0.5, "trust": 0.8},
    ])
    resp = client.get("/gsam/agents/a1/stats", headers=_PRO)
    assert resp.status_code == 200
    data = resp.json()
    assert data["agent_id"] == "a1"
    assert data["events"] == 12
    assert data["tokens_in"] == 300
    assert data["cost_usd"] == pytest.approx(0.03)
    assert data["drift"] == pytest.approx(0.5)  # MAX(drift)
    assert data["quarantined"] is False


def test_agent_stats_unknown_agent(gsam_env, client) -> None:
    resp = client.get("/gsam/agents/nobody/stats", headers=_PRO)
    assert resp.status_code == 200
    data = resp.json()
    assert data["events"] == 0
    assert data["roi"] == 0.0


def test_agent_stats_reflects_quarantine(gsam_env, client) -> None:
    from warden.gsam import quarantine as _q
    _seed(gsam_env, [{"agent_id": "bad", "hour_bucket": "2026-07-09T12", "events": 1}])
    _q.quarantine("bad", reason="test")
    resp = client.get("/gsam/agents/bad/stats", headers=_PRO)
    assert resp.json()["quarantined"] is True


# ── compliance score ─────────────────────────────────────────────────────────────

def test_compliance_score_clean(gsam_env, client) -> None:
    _seed(gsam_env, [
        {"agent_id": "a1", "hour_bucket": "2026-07-09T12", "events": 5, "drift": 0.1},
    ])
    resp = client.get("/gsam/compliance/score", headers=_PRO)
    assert resp.status_code == 200
    data = resp.json()
    assert data["score"] == 1.0
    assert data["critical"] is False
    assert data["agents_scanned"] == 1


def test_compliance_score_high_drift_penalised(gsam_env, client) -> None:
    _seed(gsam_env, [
        {"agent_id": "a1", "hour_bucket": "2026-07-09T12", "events": 5, "drift": 0.9},
    ])
    resp = client.get("/gsam/compliance/score", headers=_PRO)
    data = resp.json()
    # one strong pattern (cost_spike_no_value) → penalised but not critical
    assert data["score"] < 1.0
    assert data["critical"] is False
    assert "cost_spike_no_value" in data["strong_patterns"]


def test_compliance_score_critical_on_cooccurrence(gsam_env, client) -> None:
    from warden.gsam import quarantine as _q
    _seed(gsam_env, [
        {"agent_id": "a1", "hour_bucket": "2026-07-09T12", "events": 5, "drift": 0.9},
    ])
    # >=2 quarantined agents → second strong pattern co-occurs → critical trips
    _q.quarantine("q1", reason="test")
    _q.quarantine("q2", reason="test")
    resp = client.get("/gsam/compliance/score", headers=_PRO)
    data = resp.json()
    assert data["critical"] is True
    assert data["score"] <= 0.4


# ── tier gating ──────────────────────────────────────────────────────────────────

def test_read_apis_gated_below_pro(gsam_env, client) -> None:
    for path in ("/gsam/heatmap", "/gsam/agents/a1/stats", "/gsam/compliance/score"):
        resp = client.get(path)  # no tier header → starter
        assert resp.status_code == 403, path


# ── Semantic Layer model ─────────────────────────────────────────────────────────

def test_gsam_semantic_model_registered() -> None:
    from warden.semantic_layer.engine import SemanticEngine
    eng = SemanticEngine()
    model = eng.get_model("gsam_agent_stats")
    assert model.source_table == "gsam_agent_stats"


def test_gsam_semantic_sql_generation() -> None:
    from warden.semantic_layer.engine import SemanticEngine
    from warden.semantic_layer.models import QueryObject

    eng = SemanticEngine()
    result = eng.generate(QueryObject(
        model_id="gsam_agent_stats",
        metrics=["total_events", "cost_usd"],
        dimensions=["agent_id"],
    ))
    assert "gsam_agent_stats" in result.sql
    assert "SUM(events)" in result.sql
    assert "GROUP BY" in result.sql
    # Rollup table, never the ClickHouse observations table
    assert "gsam_observations" not in result.sql
