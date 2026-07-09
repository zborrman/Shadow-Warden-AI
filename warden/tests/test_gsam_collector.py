"""GSAM PR-1 — collector, spool, schema, settings (GSAM-01)."""
from __future__ import annotations

import json
import queue

import pytest

from warden.config import settings
from warden.gsam import collector, schema


@pytest.fixture(autouse=True)
def _clean_collector(tmp_path, monkeypatch):
    """Isolate queue + spool per test; never touch a real ClickHouse."""
    spool = tmp_path / "gsam_spool.ndjson"
    monkeypatch.setattr(settings, "gsam_spool_path", str(spool))
    monkeypatch.setattr(settings, "gsam_clickhouse_enabled", False)
    monkeypatch.setattr(collector, "_queue", queue.Queue(maxsize=100))
    monkeypatch.setattr(collector, "_drop_count", 0)
    monkeypatch.setattr(collector, "_flushed_count", 0)
    monkeypatch.setattr(collector, "_sinks", [])
    yield


def _obs(**over) -> dict:
    row = schema.Observation(agent_id="agent-x", event="tool_call").to_row()
    row.update(over)
    return row


# ── gsam_emit never raises ────────────────────────────────────────────────────

def test_emit_never_raises_with_clickhouse_disabled():
    for _ in range(10):
        collector.gsam_emit(_obs())
    assert collector._queue.qsize() == 10


def test_emit_swallows_internal_errors(monkeypatch):
    class Boom:
        def put_nowait(self, _):
            raise RuntimeError("boom")

    monkeypatch.setattr(collector, "_queue", Boom())
    collector.gsam_emit(_obs())  # must not raise


def test_queue_overflow_drops_silently(monkeypatch):
    monkeypatch.setattr(collector, "_queue", queue.Queue(maxsize=3))
    for _ in range(10):
        collector.gsam_emit(_obs())
    assert collector._queue.qsize() == 3
    assert collector._drop_count == 7


# ── Spool + replay ────────────────────────────────────────────────────────────

def test_flush_spools_when_clickhouse_down():
    for _ in range(5):
        collector.gsam_emit(_obs())
    handled = collector.flush_once()
    assert handled == 5
    with open(settings.gsam_spool_path, encoding="utf-8") as fh:
        lines = [json.loads(x) for x in fh if x.strip()]
    assert len(lines) == 5
    assert lines[0]["agent_id"] == "agent-x"


def test_spool_replayed_on_healthy_ship(monkeypatch):
    # First flush with CH down → spool
    collector.gsam_emit(_obs())
    collector.flush_once()
    assert collector.stats()["spool_bytes"] > 0

    # Now CH is healthy — replay must drain the spool
    shipped: list[list[dict]] = []
    monkeypatch.setattr(collector, "_ship", lambda batch: shipped.append(batch) or True)
    collector.gsam_emit(_obs(agent_id="agent-y"))
    collector.flush_once()
    assert collector.stats()["spool_bytes"] == 0
    all_ids = [r["agent_id"] for batch in shipped for r in batch]
    assert "agent-x" in all_ids and "agent-y" in all_ids


def test_spool_size_cap(monkeypatch):
    monkeypatch.setattr(settings, "gsam_spool_max_bytes", 1)
    collector.gsam_emit(_obs())
    collector.flush_once()
    size_after_first = collector.stats()["spool_bytes"]
    collector.gsam_emit(_obs())
    collector.flush_once()
    assert collector.stats()["spool_bytes"] == size_after_first  # capped, no growth


def test_sink_receives_batches_and_failures_are_isolated(monkeypatch):
    seen: list[dict] = []

    def bad_sink(batch):
        raise RuntimeError("sink boom")

    collector.register_sink(bad_sink)
    collector.register_sink(lambda batch: seen.extend(batch))
    collector.gsam_emit(_obs())
    collector.flush_once()
    assert len(seen) == 1


def test_stats_shape():
    s = collector.stats()
    for key in ("queue_depth", "dropped", "flushed", "spool_bytes",
                "clickhouse_enabled", "clickhouse_reachable"):
        assert key in s
    assert s["clickhouse_enabled"] is False
    assert s["clickhouse_reachable"] is False


# ── Observation schema (GDPR: metadata only) ─────────────────────────────────

def test_observation_has_no_content_fields():
    fields = set(schema.Observation.model_fields)
    for hint in schema.FORBIDDEN_FIELD_HINTS:
        assert not any(hint in f for f in fields), f"content-like field: {hint}"


def test_observation_validators_coerce_bad_enums():
    obs = schema.Observation(role="HACKER", scan_verdict="NUKED")
    assert obs.role == "SERVICE"
    assert obs.scan_verdict == "CLEAN"


def test_observation_domains_capped_and_stripped():
    obs = schema.Observation(resolved_domains=[f"d{i}.com/path?q=1" for i in range(80)])
    assert len(obs.resolved_domains) == 50
    assert obs.resolved_domains[0] == "d0.com"  # no path/query survives


def test_to_row_matches_clickhouse_columns():
    row = schema.Observation().to_row()
    missing = [c for c in schema.CLICKHOUSE_COLUMNS if c not in row]
    assert missing == []
    assert isinstance(row["unauthorized_commands_flag"], int)


def test_ddl_strings_sane():
    assert "gsam_observations" in schema.CLICKHOUSE_TABLE_DDL
    assert "MergeTree" in schema.CLICKHOUSE_TABLE_DDL
    assert "TTL date + INTERVAL 30 DAY" in schema.CLICKHOUSE_TABLE_DDL
    assert schema.CLICKHOUSE_DATABASE_DDL.startswith("CREATE DATABASE IF NOT EXISTS")


# ── Settings defaults ─────────────────────────────────────────────────────────

def test_settings_defaults():
    assert settings.gsam_enabled is True
    assert settings.gsam_clickhouse_enabled is False  # conftest forces off
    assert 0.0 < settings.gsam_drift_lambda <= 1.0
    assert 0.0 < settings.gsam_drift_quarantine_threshold <= 1.0
    assert settings.gsam_queue_max > 0
    assert settings.gsam_batch_size > 0


def test_clickhouse_wrapper_fail_open(monkeypatch):
    from warden.gsam.clickhouse import GsamClickHouse
    ch = GsamClickHouse()
    assert ch.is_enabled() is False       # disabled via conftest
    assert ch.insert_rows([_obs()]) is False
    assert ch.query("SELECT 1") == []
    assert ch.ping() is False


def test_lazy_package_emit_never_raises(monkeypatch):
    import warden.gsam as gsam_pkg
    # Even with a broken collector import, the package-level proxy is silent.
    monkeypatch.setattr(collector, "gsam_emit", lambda obs: (_ for _ in ()).throw(RuntimeError))
    gsam_pkg.gsam_emit({"agent_id": "x"})
