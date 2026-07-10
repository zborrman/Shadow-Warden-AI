"""
GSAM rollup + quarantine tests.

Covers: batch fold, hourly upsert into gsam_agent_stats, drift-baseline update,
read helpers (agent stats / heatmap / compliance score), and drift-triggered
quarantine (with the additive staff_dispatch gate).
"""
from __future__ import annotations

import pytest

from warden.gsam import quarantine as q
from warden.gsam import rollup as r


@pytest.fixture
def _db(tmp_path, monkeypatch):
    db = str(tmp_path / "gsam.db")
    for mod in (r, q):
        monkeypatch.setattr(mod.settings, "gsam_db_path", db)
        monkeypatch.setattr(mod.settings, "gsam_enabled", True)
    # Clear any in-process quarantine state from a prior test.
    q._local.clear()
    yield db


def _obs(agent="ag", tenant="t", hour="2026-07-10T05", kind="get_health", verdict="CLEAN", **kw):
    base = {"agent_id": agent, "tenant_id": tenant, "ts": f"{hour}:30:00",
            "payload_kind": kind, "scan_verdict": verdict}
    base.update(kw)
    return base


def test_fold_batch_aggregates_by_agent_hour():
    folded = r.fold_batch([
        _obs(input_tokens=10, output_tokens=5, execution_cost=0.01),
        _obs(input_tokens=20, output_tokens=7, execution_cost=0.02),
        _obs(agent="other"),
    ])
    key = ("ag", "t", "2026-07-10T05:00:00")
    assert folded[key].events == 2
    assert folded[key].tokens_in == 30
    assert folded[key].cost_usd == pytest.approx(0.03)
    assert ("other", "t", "2026-07-10T05:00:00") in folded


def test_trust_proxy():
    d = r.StatDelta(events=4)
    d.verdicts["COMPROMISED"] = 1
    d.verdicts["WARNING"] = 2
    # 1 - (1 + 0.5*2)/4 = 1 - 0.5 = 0.5
    assert d.trust() == pytest.approx(0.5)


def test_rollup_persists_and_upserts(_db):
    r.rollup_sink([_obs(input_tokens=10, output_tokens=5, execution_cost=0.01)])
    r.rollup_sink([_obs(input_tokens=10, output_tokens=5, execution_cost=0.01)])
    stats = r.read_agent_stats("ag")
    assert stats["hours"], "no hourly rows persisted"
    hour0 = stats["hours"][0]
    assert hour0["events"] == 2  # upserted, not duplicated
    assert hour0["tokens_in"] == 20


def test_heatmap_and_compliance(_db):
    r.rollup_sink([_obs()])
    hm = r.read_heatmap("t")
    assert any(a["agent_id"] == "ag" for a in hm["agents"])
    score = r.compliance_score("t")
    assert 0.0 <= score["score"] <= 100.0
    assert score["agents"] >= 1


def test_drift_triggers_quarantine(_db, monkeypatch):
    # Low threshold so a single behavioural shift trips it deterministically.
    for mod in (r, q):
        monkeypatch.setattr(mod.settings, "gsam_drift_quarantine_threshold", 0.15)
    # Seed a stable baseline over several buckets.
    for h in range(3):
        r.rollup_sink([_obs(hour=f"2026-07-10T0{h}", kind="get_health")])
    assert not q.is_quarantined("ag")
    # Sudden switch to a new action distribution → drift jumps above 0.15.
    r.rollup_sink([_obs(hour="2026-07-10T09", kind="exfiltrate", verdict="COMPROMISED")])
    assert q.is_quarantined("ag"), "expected drift quarantine"
    # Manual release clears it.
    assert q.release_agent("ag") is True
    assert not q.is_quarantined("ag")


def test_empty_batch_is_noop(_db):
    r.rollup_sink([])
    assert r.read_heatmap("t")["agents"] == []
