"""GSAM PR 3 — drift baselines + hourly rollup (GSAM-03).

No Docker/ClickHouse/Redis: drift persists to a tmp_path SQLite ``gsam`` DB and
the rollup sink folds batches into gsam_agent_stats in the same DB.
"""
from __future__ import annotations

import json
import sqlite3

import pytest

from warden.config import settings
from warden.gsam import drift as _drift
from warden.gsam import rollup as _rollup


@pytest.fixture()
def gsam_db(tmp_path, monkeypatch):
    """Point the gsam DB at a per-test SQLite file; clear in-memory baselines."""
    db = tmp_path / "gsam.db"
    monkeypatch.setattr(settings, "gsam_db_path", str(db))
    monkeypatch.setattr(settings, "gsam_drift_lambda", 0.2)
    _drift._mem.clear()
    yield str(db)
    _drift._mem.clear()


# ── drift ────────────────────────────────────────────────────────────────────────

def test_first_observation_establishes_baseline(gsam_db) -> None:
    score = _drift.update_drift("agent-1", [{"event": "mcp_call"}, {"event": "mcp_call"}])
    assert score == 0.0
    # Baseline persisted
    assert _drift.get_drift("agent-1") == 0.0


def test_drift_rises_on_behaviour_change(gsam_db) -> None:
    # Establish a baseline dominated by mcp_call
    _drift.update_drift("agent-2", [{"event": "mcp_call"}] * 10)
    # Then a batch dominated by a different event
    score = _drift.update_drift("agent-2", [{"event": "billing_event"}] * 10)
    assert score > 0.0


def test_drift_stays_low_on_stable_behaviour(gsam_db) -> None:
    _drift.update_drift("agent-3", [{"event": "agent_span"}] * 10)
    score = _drift.update_drift("agent-3", [{"event": "agent_span"}] * 10)
    assert score == pytest.approx(0.0, abs=1e-6)


def test_drift_persists_round_trip(gsam_db) -> None:
    _drift.update_drift("agent-4", [{"event": "mcp_call"}] * 5)
    _drift.update_drift("agent-4", [{"event": "billing_event"}] * 5)
    persisted = _drift.get_drift("agent-4")
    # Re-read straight from the SQLite file to prove durability (not just memory)
    _drift._mem.clear()
    con = sqlite3.connect(gsam_db)
    row = con.execute(
        "SELECT ewma_drift, sample_count FROM gsam_drift_baselines WHERE agent_id = ?",
        ("agent-4",),
    ).fetchone()
    con.close()
    assert row is not None
    assert row[0] == pytest.approx(persisted)
    assert row[1] == 10  # 5 + 5 samples


def test_drift_empty_events_noop(gsam_db) -> None:
    assert _drift.update_drift("agent-5", []) == 0.0
    assert _drift.update_drift("", [{"event": "mcp_call"}]) == 0.0


def test_drift_string_events_accepted(gsam_db) -> None:
    _drift.update_drift("agent-6", ["mcp_call", "mcp_call"])
    assert _drift.get_drift("agent-6") == 0.0  # first batch → baseline


# ── rollup ───────────────────────────────────────────────────────────────────────

def _obs(agent_id: str, **over) -> dict:
    row = {
        "agent_id":       agent_id,
        "tenant_id":      "t-1",
        "ts":             "2026-07-09T12:30:00+00:00",
        "input_tokens":   100,
        "output_tokens":  50,
        "execution_cost": 0.001,
        "scan_verdict":   "CLEAN",
        "drift_score":    0.0,
        "trust_score":    0.0,
    }
    row.update(over)
    return row


def test_rollup_folds_batch(gsam_db) -> None:
    batch = [_obs("agent-r1"), _obs("agent-r1"), _obs("agent-r2")]
    _rollup.rollup_sink(batch)

    con = sqlite3.connect(gsam_db)
    rows = con.execute(
        "SELECT agent_id, events, tokens_in, tokens_out, cost_usd "
        "FROM gsam_agent_stats ORDER BY agent_id"
    ).fetchall()
    con.close()
    assert len(rows) == 2
    r1 = rows[0]
    assert r1[0] == "agent-r1"
    assert r1[1] == 2               # 2 events
    assert r1[2] == 200            # tokens_in
    assert r1[3] == 100            # tokens_out
    assert r1[4] == pytest.approx(0.002)


def test_rollup_accumulates_across_batches(gsam_db) -> None:
    _rollup.rollup_sink([_obs("agent-r3")])
    _rollup.rollup_sink([_obs("agent-r3")])

    con = sqlite3.connect(gsam_db)
    row = con.execute(
        "SELECT events, verdicts_json FROM gsam_agent_stats WHERE agent_id = ?",
        ("agent-r3",),
    ).fetchone()
    con.close()
    assert row[0] == 2
    assert json.loads(row[1]) == {"CLEAN": 2}


def test_rollup_separate_hour_buckets(gsam_db) -> None:
    _rollup.rollup_sink([_obs("agent-r4", ts="2026-07-09T12:00:00+00:00")])
    _rollup.rollup_sink([_obs("agent-r4", ts="2026-07-09T13:00:00+00:00")])

    con = sqlite3.connect(gsam_db)
    count = con.execute(
        "SELECT COUNT(*) FROM gsam_agent_stats WHERE agent_id = ?", ("agent-r4",)
    ).fetchone()[0]
    con.close()
    assert count == 2  # two distinct hour buckets


def test_rollup_captures_drift_gauge(gsam_db) -> None:
    _rollup.rollup_sink([_obs("agent-r5", drift_score=0.9)])
    con = sqlite3.connect(gsam_db)
    row = con.execute(
        "SELECT drift FROM gsam_agent_stats WHERE agent_id = ?", ("agent-r5",)
    ).fetchone()
    con.close()
    assert row[0] == pytest.approx(0.9)


def test_rollup_skips_rows_without_agent(gsam_db) -> None:
    # Seed one valid row so the table exists, then send only skippable rows.
    _rollup.rollup_sink([_obs("agent-seed")])
    _rollup.rollup_sink([_obs(""), {"ts": "2026-07-09T12:00:00+00:00"}])
    con = sqlite3.connect(gsam_db)
    count = con.execute("SELECT COUNT(*) FROM gsam_agent_stats").fetchone()[0]
    con.close()
    assert count == 1  # only the seed row; agent-less rows skipped


def test_rollup_fail_open_on_bad_batch(gsam_db) -> None:
    # Must not raise even if rows are malformed
    _rollup.rollup_sink([{"agent_id": "x", "ts": None, "input_tokens": "bad"}])


def test_rollup_install_idempotent() -> None:
    from warden.gsam import collector
    _rollup._installed = False
    collector._sinks.clear()
    _rollup.install()
    _rollup.install()
    assert collector._sinks.count(_rollup.rollup_sink) == 1
