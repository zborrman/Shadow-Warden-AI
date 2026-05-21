"""
Tests for the Business Intelligence module (CM-39).
All tests use isolated temp DBs and patch environment paths.
"""
from __future__ import annotations

import contextlib
import os
import tempfile
import uuid
from unittest import mock

import pytest


def _tid() -> str:
    return f"tenant_{uuid.uuid4().hex[:8]}"


def _cid() -> str:
    return f"community_{uuid.uuid4().hex[:8]}"


# ── Predictive ────────────────────────────────────────────────────────────────

class TestPredictive:
    def test_moving_average_basic(self):
        from warden.business_intelligence.predictive import moving_average
        result = moving_average([1, 2, 3, 4, 5], window=3)
        assert len(result) == 5
        assert result[-1] == pytest.approx(4.0, abs=0.01)

    def test_moving_average_empty(self):
        from warden.business_intelligence.predictive import moving_average
        assert moving_average([], window=3) == []

    def test_linear_trend_rising(self):
        from warden.business_intelligence.predictive import linear_trend
        slope, intercept = linear_trend([1, 2, 3, 4, 5])
        assert slope > 0

    def test_linear_trend_flat(self):
        from warden.business_intelligence.predictive import linear_trend
        slope, _ = linear_trend([5, 5, 5, 5])
        assert abs(slope) < 0.01

    def test_predict_next_length(self):
        from warden.business_intelligence.predictive import predict_next
        result = predict_next([1, 2, 3], steps=7)
        assert len(result) == 7

    def test_predict_next_non_negative(self):
        from warden.business_intelligence.predictive import predict_next
        result = predict_next([0, 0, 0, 0], steps=10)
        assert all(v >= 0 for v in result)

    def test_trend_direction_rising(self):
        from warden.business_intelligence.predictive import trend_direction
        assert trend_direction([1, 2, 3, 4, 5]) == "rising"

    def test_trend_direction_falling(self):
        from warden.business_intelligence.predictive import trend_direction
        assert trend_direction([5, 4, 3, 2, 1]) == "falling"

    def test_trend_direction_stable(self):
        from warden.business_intelligence.predictive import trend_direction
        assert trend_direction([3, 3, 3, 3]) == "stable"

    def test_predict_incidents_empty(self):
        from warden.business_intelligence.predictive import predict_incidents
        result = predict_incidents([])
        assert result["predicted_count"] == 0

    def test_predict_incidents_returns_keys(self):
        from warden.business_intelligence.predictive import predict_incidents
        result = predict_incidents([1, 2, 1, 3, 2], horizon_days=14)
        assert "predicted_count" in result
        assert "confidence" in result
        assert "trend_direction" in result

    def test_r_squared_perfect_fit(self):
        from warden.business_intelligence.predictive import r_squared
        assert r_squared([1, 2, 3, 4, 5]) >= 0.99


# ── Benchmarking ──────────────────────────────────────────────────────────────

class TestBenchmarking:
    def test_percentile_median(self):
        from warden.business_intelligence.benchmarking import percentile
        assert percentile([1, 2, 3, 4, 5], 50) == pytest.approx(3.0)

    def test_percentile_empty(self):
        from warden.business_intelligence.benchmarking import percentile
        assert percentile([], 50) == 0.0

    def test_percentile_rank_all_below(self):
        from warden.business_intelligence.benchmarking import percentile_rank
        assert percentile_rank(10.0, [1, 2, 3]) == 100.0

    def test_benchmark_metric_above(self):
        from warden.business_intelligence.benchmarking import benchmark_metric
        result = benchmark_metric(0.9, [0.3, 0.4, 0.5], "score", "t1")
        assert result["status"] == "above"

    def test_benchmark_metric_below(self):
        from warden.business_intelligence.benchmarking import benchmark_metric
        result = benchmark_metric(0.1, [0.5, 0.6, 0.7, 0.8], "score", "t1")
        assert result["status"] == "below"

    def test_build_benchmarks_length(self):
        from warden.business_intelligence.benchmarking import build_benchmarks
        results = build_benchmarks(
            "t1",
            {"metric_a": 0.5, "metric_b": 0.7},
            [{"metric_a": 0.4, "metric_b": 0.6}] * 5,
        )
        assert len(results) == 2


# ── Repository ────────────────────────────────────────────────────────────────

class TestRepository:
    def _patch_db(self):
        tmp = tempfile.mkstemp(suffix=".db")[1]
        return mock.patch("warden.business_intelligence.repository._DB_PATH", tmp), tmp

    def test_cache_miss(self):
        patch, tmp = self._patch_db()
        with patch:
            import importlib

            import warden.business_intelligence.repository as repo
            importlib.reload(repo)
            result = repo.cache_get("nonexistent_key")
        assert result is None
        with contextlib.suppress(OSError):
            os.unlink(tmp)

    def test_cache_set_and_get(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            tmp = f.name
        with mock.patch("warden.business_intelligence.repository._DB_PATH", tmp):
            import importlib

            import warden.business_intelligence.repository as repo
            importlib.reload(repo)
            repo.cache_set("key1", "t1", "test", {"hello": "world"})
            result = repo.cache_get("key1")
        assert result == {"hello": "world"}
        with contextlib.suppress(OSError):
            os.unlink(tmp)

    def test_cache_stats(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            tmp = f.name
        with mock.patch("warden.business_intelligence.repository._DB_PATH", tmp):
            import importlib

            import warden.business_intelligence.repository as repo
            importlib.reload(repo)
            repo.cache_set("k1", "t2", "usage", {"x": 1})
            stats = repo.cache_stats("t2")
        assert stats["total_entries"] >= 1
        with contextlib.suppress(OSError):
            os.unlink(tmp)


# ── Service ───────────────────────────────────────────────────────────────────

class TestService:
    def _env(self):
        sep  = tempfile.mkstemp(suffix=".db")[1]
        vend = tempfile.mkstemp(suffix=".db")[1]
        cost = tempfile.mkstemp(suffix=".db")[1]
        bi   = tempfile.mkstemp(suffix=".db")[1]
        logs = tempfile.mkstemp(suffix=".jsonl")[1]
        return {
            "SEP_DB_PATH":           sep,
            "VENDOR_GOV_DB_PATH":    vend,
            "COST_ALLOC_DB_PATH":    cost,
            "BI_DB_PATH":            bi,
            "LOGS_PATH":             logs,
        }, [sep, vend, cost, bi, logs]

    def test_usage_summary_empty_logs(self):
        env, files = self._env()
        with mock.patch.dict(os.environ, env):
            import importlib

            import warden.business_intelligence.repository as repo
            import warden.business_intelligence.service as svc
            importlib.reload(repo)
            importlib.reload(svc)
            result = svc.get_usage_summary(_tid())
        assert "total_requests" in result
        assert result["total_requests"] == 0
        for f in files:
            with contextlib.suppress(OSError):
                os.unlink(f)

    def test_threat_summary_empty_db(self):
        env, files = self._env()
        with mock.patch.dict(os.environ, env):
            import importlib

            import warden.business_intelligence.repository as repo
            import warden.business_intelligence.service as svc
            importlib.reload(repo)
            importlib.reload(svc)
            result = svc.get_threat_summary(_tid())
        assert result["total_threats"] == 0
        for f in files:
            with contextlib.suppress(OSError):
                os.unlink(f)

    def test_compliance_score_returns_grade(self):
        env, files = self._env()
        with mock.patch.dict(os.environ, env):
            import importlib

            import warden.business_intelligence.repository as repo
            import warden.business_intelligence.service as svc
            importlib.reload(repo)
            importlib.reload(svc)
            result = svc.get_compliance_score(_tid(), _cid())
        assert "grade" in result
        assert result["grade"] in ("A", "B", "C", "D", "F")
        for f in files:
            with contextlib.suppress(OSError):
                os.unlink(f)

    def test_vendor_scorecards_empty(self):
        env, files = self._env()
        with mock.patch.dict(os.environ, env):
            import importlib

            import warden.business_intelligence.repository as repo
            import warden.business_intelligence.service as svc
            importlib.reload(repo)
            importlib.reload(svc)
            result = svc.get_vendor_scorecards(_tid())
        assert isinstance(result, list)
        for f in files:
            with contextlib.suppress(OSError):
                os.unlink(f)

    def test_cost_insights_empty(self):
        env, files = self._env()
        with mock.patch.dict(os.environ, env):
            import importlib

            import warden.business_intelligence.repository as repo
            import warden.business_intelligence.service as svc
            importlib.reload(repo)
            importlib.reload(svc)
            result = svc.get_cost_insights(_tid())
        assert result["total_spend_usd"] == 0.0
        for f in files:
            with contextlib.suppress(OSError):
                os.unlink(f)

    def test_incident_prediction_empty(self):
        env, files = self._env()
        with mock.patch.dict(os.environ, env):
            import importlib

            import warden.business_intelligence.repository as repo
            import warden.business_intelligence.service as svc
            importlib.reload(repo)
            importlib.reload(svc)
            result = svc.get_incident_prediction(_tid())
        assert "predicted_count" in result
        assert result["trend_direction"] in ("rising", "stable", "falling")
        for f in files:
            with contextlib.suppress(OSError):
                os.unlink(f)

    def test_build_report_full(self):
        env, files = self._env()
        with mock.patch.dict(os.environ, env):
            import importlib

            import warden.business_intelligence.repository as repo
            import warden.business_intelligence.service as svc
            importlib.reload(repo)
            importlib.reload(svc)
            result = svc.build_report(_tid(), report_type="full")
        assert "sections" in result
        assert "usage" in result["sections"]
        assert "compliance" in result["sections"]
        for f in files:
            with contextlib.suppress(OSError):
                os.unlink(f)

    def test_build_report_executive(self):
        env, files = self._env()
        with mock.patch.dict(os.environ, env):
            import importlib

            import warden.business_intelligence.repository as repo
            import warden.business_intelligence.service as svc
            importlib.reload(repo)
            importlib.reload(svc)
            result = svc.build_report(_tid(), report_type="executive")
        assert "sections" in result
        for f in files:
            with contextlib.suppress(OSError):
                os.unlink(f)

    def test_benchmarks_returns_list(self):
        env, files = self._env()
        with mock.patch.dict(os.environ, env):
            import importlib

            import warden.business_intelligence.repository as repo
            import warden.business_intelligence.service as svc
            importlib.reload(repo)
            importlib.reload(svc)
            result = svc.get_benchmarks(_tid(), _cid())
        assert isinstance(result, list)
        for f in files:
            with contextlib.suppress(OSError):
                os.unlink(f)
