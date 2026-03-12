"""
warden/tests/test_billing.py
──────────────────────────────
Unit tests for BillingStore — cost aggregation, quota enforcement,
and the daily breakdown query.
"""
from __future__ import annotations

import json
import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from warden.billing import BillingStore

# ── Fixtures & helpers ─────────────────────────────────────────────────────────

@pytest.fixture
def store(tmp_path: Path) -> Generator[BillingStore, None, None]:
    bs = BillingStore(
        db_path   = tmp_path / "test_billing.db",
        logs_path = tmp_path / "test_logs.json",
    )
    yield bs
    bs.close()


def _log_entry(
    *,
    ts: str | None = None,
    tenant_id: str = "default",
    allowed: bool = True,
    cost_usd: float = 0.001,
    tokens: int = 100,
) -> dict:
    return {
        "ts":              ts or datetime.now(UTC).isoformat(),
        "request_id":      str(uuid.uuid4()),
        "tenant_id":       tenant_id,
        "allowed":         allowed,
        "attack_cost_usd": cost_usd,
        "payload_tokens":  tokens,
        "risk_level":      "low",
        "flags":           [],
    }


def _write_logs(path: Path, entries: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


# ── aggregate_from_logs ────────────────────────────────────────────────────────

class TestAggregate:
    def test_returns_zero_when_no_log_file(self, store: BillingStore) -> None:
        assert store.aggregate_from_logs() == 0

    def test_processes_single_entry(self, store: BillingStore, tmp_path: Path) -> None:
        logs = tmp_path / "test_logs.json"
        _write_logs(logs, [_log_entry()])
        count = store.aggregate_from_logs(logs)
        assert count == 1

    def test_aggregates_multiple_entries(self, store: BillingStore, tmp_path: Path) -> None:
        logs = tmp_path / "test_logs.json"
        entries = [_log_entry(cost_usd=0.001) for _ in range(5)]
        _write_logs(logs, entries)
        count = store.aggregate_from_logs(logs)
        assert count == 5

    def test_cost_is_summed_per_tenant(self, store: BillingStore, tmp_path: Path) -> None:
        logs = tmp_path / "test_logs.json"
        _write_logs(logs, [
            _log_entry(tenant_id="t1", cost_usd=0.01),
            _log_entry(tenant_id="t1", cost_usd=0.02),
            _log_entry(tenant_id="t2", cost_usd=0.05),
        ])
        store.aggregate_from_logs(logs)
        usage_t1 = store.get_usage("t1")
        usage_t2 = store.get_usage("t2")
        assert abs(usage_t1["cost_usd"] - 0.03) < 1e-6
        assert abs(usage_t2["cost_usd"] - 0.05) < 1e-6

    def test_blocked_count_tracked(self, store: BillingStore, tmp_path: Path) -> None:
        logs = tmp_path / "test_logs.json"
        _write_logs(logs, [
            _log_entry(allowed=True),
            _log_entry(allowed=False),
            _log_entry(allowed=False),
        ])
        store.aggregate_from_logs(logs)
        usage = store.get_usage("default")
        assert usage["requests"] == 3
        assert usage["blocked"] == 2

    def test_idempotent_on_second_call(self, store: BillingStore, tmp_path: Path) -> None:
        """Second call with no new log lines must not double-count."""
        logs = tmp_path / "test_logs.json"
        _write_logs(logs, [_log_entry(cost_usd=0.01)])
        store.aggregate_from_logs(logs)
        store.aggregate_from_logs(logs)  # second call — watermark prevents re-processing
        usage = store.get_usage("default")
        assert usage["requests"] == 1
        assert abs(usage["cost_usd"] - 0.01) < 1e-6

    def test_new_lines_after_watermark_are_processed(
        self, store: BillingStore, tmp_path: Path
    ) -> None:
        logs = tmp_path / "test_logs.json"
        old_ts = (datetime.now(UTC) - timedelta(seconds=10)).isoformat()
        new_ts = datetime.now(UTC).isoformat()
        _write_logs(logs, [_log_entry(ts=old_ts, cost_usd=0.01)])
        store.aggregate_from_logs(logs)
        # Append a new entry
        with logs.open("a") as f:
            f.write(json.dumps(_log_entry(ts=new_ts, cost_usd=0.02)) + "\n")
        count = store.aggregate_from_logs(logs)
        assert count == 1   # only the new line
        usage = store.get_usage("default")
        assert usage["requests"] == 2

    def test_malformed_json_lines_skipped(self, store: BillingStore, tmp_path: Path) -> None:
        logs = tmp_path / "test_logs.json"
        logs.write_text('{"bad": \n{"ts": "2026-01-01T00:00:00+00:00", "tenant_id": "default", '
                        '"attack_cost_usd": 0.001, "payload_tokens": 10, "allowed": true}\n')
        count = store.aggregate_from_logs(logs)
        assert count >= 0   # must not raise; bad line skipped


# ── quota management ───────────────────────────────────────────────────────────

class TestQuota:
    def test_no_quota_returns_none(self, store: BillingStore) -> None:
        assert store.get_quota("unset-tenant") is None

    def test_set_and_get_quota(self, store: BillingStore) -> None:
        store.set_quota("t1", 5.0)
        assert store.get_quota("t1") == 5.0

    def test_update_quota(self, store: BillingStore) -> None:
        store.set_quota("t1", 5.0)
        store.set_quota("t1", 10.0)
        assert store.get_quota("t1") == 10.0

    def test_is_quota_exceeded_uncapped(self, store: BillingStore) -> None:
        assert not store.is_quota_exceeded("uncapped")

    def test_is_quota_not_exceeded_below_cap(
        self, store: BillingStore, tmp_path: Path
    ) -> None:
        logs = tmp_path / "test_logs.json"
        _write_logs(logs, [_log_entry(cost_usd=0.001)])
        store.aggregate_from_logs(logs)
        store.set_quota("default", 1.0)
        assert not store.is_quota_exceeded("default")

    def test_is_quota_exceeded_at_cap(
        self, store: BillingStore, tmp_path: Path
    ) -> None:
        logs = tmp_path / "test_logs.json"
        _write_logs(logs, [_log_entry(cost_usd=5.0)])
        store.aggregate_from_logs(logs)
        store.set_quota("default", 5.0)
        assert store.is_quota_exceeded("default")

    def test_is_quota_exceeded_over_cap(
        self, store: BillingStore, tmp_path: Path
    ) -> None:
        logs = tmp_path / "test_logs.json"
        _write_logs(logs, [_log_entry(cost_usd=6.0)])
        store.aggregate_from_logs(logs)
        store.set_quota("default", 5.0)
        assert store.is_quota_exceeded("default")


# ── get_usage ──────────────────────────────────────────────────────────────────

class TestGetUsage:
    def test_empty_returns_zeros(self, store: BillingStore) -> None:
        usage = store.get_usage("nobody")
        assert usage["requests"] == 0
        assert usage["blocked"] == 0
        assert usage["cost_usd"] == 0.0
        assert usage["quota_usd"] is None
        assert usage["quota_remaining"] is None

    def test_date_range_filter(self, store: BillingStore, tmp_path: Path) -> None:
        logs = tmp_path / "test_logs.json"
        _write_logs(logs, [
            _log_entry(ts="2026-01-15T00:00:00+00:00", cost_usd=1.0),
            _log_entry(ts="2026-02-15T00:00:00+00:00", cost_usd=2.0),
            _log_entry(ts="2026-03-15T00:00:00+00:00", cost_usd=3.0),
        ])
        store.aggregate_from_logs(logs)
        usage = store.get_usage("default", from_date="2026-01-01", to_date="2026-02-28")
        assert usage["requests"] == 2
        assert abs(usage["cost_usd"] - 3.0) < 1e-6

    def test_quota_remaining_is_calculated(
        self, store: BillingStore, tmp_path: Path
    ) -> None:
        logs = tmp_path / "test_logs.json"
        _write_logs(logs, [_log_entry(cost_usd=1.0)])
        store.aggregate_from_logs(logs)
        store.set_quota("default", 10.0)
        usage = store.get_usage("default")
        # quota_remaining is 10.0 - current month cost (1.0)
        assert usage["quota_remaining"] is not None
        assert abs(usage["quota_remaining"] - 9.0) < 0.01


# ── get_daily_breakdown ────────────────────────────────────────────────────────

class TestDailyBreakdown:
    def test_returns_one_row_per_day(self, store: BillingStore, tmp_path: Path) -> None:
        logs = tmp_path / "test_logs.json"
        _write_logs(logs, [
            _log_entry(ts="2026-01-01T00:00:00+00:00"),
            _log_entry(ts="2026-01-02T00:00:00+00:00"),
            _log_entry(ts="2026-01-02T00:00:01+00:00"),
        ])
        store.aggregate_from_logs(logs)
        rows = store.get_daily_breakdown("default")
        assert len(rows) == 2
        # Newest first
        assert rows[0]["date"] == "2026-01-02"
        assert rows[0]["requests"] == 2

    def test_limit_respected(self, store: BillingStore, tmp_path: Path) -> None:
        logs = tmp_path / "test_logs.json"
        entries = [
            _log_entry(ts=f"2026-01-{i:02d}T00:00:00+00:00")
            for i in range(1, 11)
        ]
        _write_logs(logs, entries)
        store.aggregate_from_logs(logs)
        rows = store.get_daily_breakdown("default", limit=5)
        assert len(rows) == 5

    def test_empty_returns_empty(self, store: BillingStore) -> None:
        assert store.get_daily_breakdown("nobody") == []
