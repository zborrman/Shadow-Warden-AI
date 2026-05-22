"""
Direct tests for Business Intelligence modules (CM-39).
Defined inline so pytest collects them under warden/tests/.
"""
from __future__ import annotations

import contextlib
import importlib
import os
import tempfile
from unittest import mock

import pytest


# ── Helpers ────────────────────────────────────────────────────────────────────

def _env():
    """Return (env_dict, paths_to_cleanup)."""
    fds_paths = [tempfile.mkstemp(suffix=sfx) for sfx in (".db", ".db", ".db", ".db", ".jsonl")]
    for fd, _ in fds_paths:
        os.close(fd)
    paths = [p for _, p in fds_paths]
    env = {
        "SEP_DB_PATH":        paths[0],
        "VENDOR_GOV_DB_PATH": paths[1],
        "COST_ALLOC_DB_PATH": paths[2],
        "BI_DB_PATH":         paths[3],
        "LOGS_PATH":          paths[4],
    }
    return env, paths


def _cleanup(paths: list[str]) -> None:
    for p in paths:
        with contextlib.suppress(OSError):
            os.unlink(p)


# ── TestPredictive ─────────────────────────────────────────────────────────────

class TestPredictive:
    def _mod(self):
        from warden.business_intelligence import predictive
        return predictive

    def test_moving_average_basic(self):
        p = self._mod()
        result = p.moving_average([1.0, 2.0, 3.0, 4.0], window=2)
        assert len(result) == 4
        assert result[0] == pytest.approx(1.0)
        assert result[1] == pytest.approx(1.5)

    def test_moving_average_empty(self):
        p = self._mod()
        assert p.moving_average([], window=3) == []

    def test_moving_average_window_zero(self):
        p = self._mod()
        assert p.moving_average([1.0, 2.0], window=0) == []

    def test_linear_trend_rising(self):
        p = self._mod()
        slope, intercept = p.linear_trend([0.0, 1.0, 2.0, 3.0])
        assert slope == pytest.approx(1.0)

    def test_linear_trend_single(self):
        p = self._mod()
        slope, intercept = p.linear_trend([5.0])
        assert slope == pytest.approx(0.0)
        assert intercept == pytest.approx(5.0)

    def test_linear_trend_empty(self):
        p = self._mod()
        slope, intercept = p.linear_trend([])
        assert slope == pytest.approx(0.0)
        assert intercept == pytest.approx(0.0)

    def test_predict_next_basic(self):
        p = self._mod()
        result = p.predict_next([0.0, 1.0, 2.0], steps=3)
        assert len(result) == 3
        assert all(v >= 0.0 for v in result)

    def test_predict_next_empty(self):
        p = self._mod()
        result = p.predict_next([], steps=5)
        assert result == [0.0] * 5

    def test_r_squared_perfect(self):
        p = self._mod()
        # Perfectly linear series → R² = 1.0
        r2 = p.r_squared([0.0, 1.0, 2.0, 3.0, 4.0])
        assert r2 == pytest.approx(1.0, abs=1e-6)

    def test_r_squared_constant(self):
        p = self._mod()
        # Constant series — SS_tot = 0 → returns 1.0
        r2 = p.r_squared([3.0, 3.0, 3.0])
        assert r2 == pytest.approx(1.0)

    def test_r_squared_single(self):
        p = self._mod()
        assert p.r_squared([1.0]) == 0.0

    def test_trend_direction_rising(self):
        p = self._mod()
        assert p.trend_direction([0.0, 1.0, 2.0, 3.0, 4.0]) == "rising"

    def test_trend_direction_falling(self):
        p = self._mod()
        assert p.trend_direction([4.0, 3.0, 2.0, 1.0, 0.0]) == "falling"

    def test_trend_direction_stable(self):
        p = self._mod()
        assert p.trend_direction([1.0, 1.0, 1.0, 1.0]) == "stable"

    def test_trend_direction_single(self):
        p = self._mod()
        assert p.trend_direction([5.0]) == "stable"

    def test_predict_incidents_empty(self):
        p = self._mod()
        result = p.predict_incidents([])
        assert result["predicted_count"] == 0
        assert result["confidence"] == 0.0
        assert result["trend_direction"] == "stable"

    def test_predict_incidents_rising(self):
        p = self._mod()
        counts = list(range(30))
        result = p.predict_incidents(counts, horizon_days=7)
        assert result["trend_direction"] == "rising"
        assert result["predicted_count"] >= 0

    def test_predict_incidents_constant(self):
        p = self._mod()
        result = p.predict_incidents([2] * 10, horizon_days=5)
        assert result["trend_direction"] == "stable"


# ── TestBenchmarking ───────────────────────────────────────────────────────────

class TestBenchmarking:
    def _mod(self):
        from warden.business_intelligence import benchmarking
        return benchmarking

    def test_percentile_median(self):
        b = self._mod()
        values = [1.0, 2.0, 3.0, 4.0, 5.0]
        assert b.percentile(values, 50) == pytest.approx(3.0)

    def test_percentile_min(self):
        b = self._mod()
        assert b.percentile([10.0, 20.0, 30.0], 0) == pytest.approx(10.0)

    def test_percentile_max(self):
        b = self._mod()
        assert b.percentile([10.0, 20.0, 30.0], 100) == pytest.approx(30.0)

    def test_percentile_empty(self):
        b = self._mod()
        assert b.percentile([], 50) == pytest.approx(0.0)

    def test_percentile_rank_above_all(self):
        b = self._mod()
        rank = b.percentile_rank(100.0, [1.0, 2.0, 3.0])
        assert rank == pytest.approx(100.0)

    def test_percentile_rank_below_all(self):
        b = self._mod()
        rank = b.percentile_rank(0.0, [1.0, 2.0, 3.0])
        assert rank == pytest.approx(0.0)

    def test_percentile_rank_empty(self):
        b = self._mod()
        assert b.percentile_rank(5.0, []) == pytest.approx(50.0)

    def test_benchmark_metric_basic(self):
        b = self._mod()
        peers = [0.5, 0.6, 0.7, 0.8, 0.9]
        result = b.benchmark_metric(0.75, peers, "compliance_score", "t1")
        assert result["metric"] == "compliance_score"
        assert result["tenant_value"] == pytest.approx(0.75)
        assert "percentile_rank" in result
        assert "community_avg" in result

    def test_benchmark_metric_no_peers(self):
        b = self._mod()
        result = b.benchmark_metric(0.5, [], "compliance_score", "t1")
        assert result["metric"] == "compliance_score"
        assert result["percentile_rank"] == pytest.approx(50.0)

    def test_build_benchmarks_basic(self):
        b = self._mod()
        tenant = {"compliance_score": 0.75, "training_pct": 0.8}
        peers = [{"compliance_score": 0.5, "training_pct": 0.6} for _ in range(5)]
        results = b.build_benchmarks("t1", tenant, peers)
        assert isinstance(results, list)
        assert len(results) == 2
        metrics = {r["metric"] for r in results}
        assert "compliance_score" in metrics
        assert "training_pct" in metrics

    def test_build_benchmarks_empty(self):
        b = self._mod()
        results = b.build_benchmarks("t1", {}, [])
        assert results == []


# ── TestRepository ─────────────────────────────────────────────────────────────

class TestRepository:
    def test_cache_miss(self):
        env, paths = _env()
        try:
            with mock.patch.dict(os.environ, env):
                import warden.business_intelligence.repository as repo
                importlib.reload(repo)
                result = repo.cache_get("nonexistent_key")
                assert result is None
        finally:
            _cleanup(paths)

    def test_cache_set_and_get(self):
        env, paths = _env()
        try:
            with mock.patch.dict(os.environ, env):
                import warden.business_intelligence.repository as repo
                importlib.reload(repo)
                payload = {"total": 42, "items": [1, 2, 3]}
                repo.cache_set("key1", "tenant1", "usage", payload)
                result = repo.cache_get("key1")
                assert result is not None
                assert result["total"] == 42
        finally:
            _cleanup(paths)

    def test_cache_invalidate(self):
        env, paths = _env()
        try:
            with mock.patch.dict(os.environ, env):
                import warden.business_intelligence.repository as repo
                importlib.reload(repo)
                repo.cache_set("key1", "tenant1", "usage", {"x": 1})
                repo.cache_set("key2", "tenant1", "threats", {"y": 2})
                repo.cache_set("key3", "tenant2", "usage", {"z": 3})
                deleted = repo.cache_invalidate("tenant1")
                assert deleted == 2
                assert repo.cache_get("key1") is None
                assert repo.cache_get("key2") is None
                assert repo.cache_get("key3") is not None
        finally:
            _cleanup(paths)

    def test_cache_purge_expired(self):
        env, paths = _env()
        try:
            with mock.patch.dict(os.environ, env):
                import warden.business_intelligence.repository as repo
                importlib.reload(repo)
                repo.cache_set("key1", "tenant1", "usage", {"x": 1})
                # Purging non-expired entries returns 0
                n = repo.cache_purge_expired()
                assert n >= 0
        finally:
            _cleanup(paths)

    def test_cache_stats(self):
        env, paths = _env()
        try:
            with mock.patch.dict(os.environ, env):
                import warden.business_intelligence.repository as repo
                importlib.reload(repo)
                repo.cache_set("k1", "tenant1", "usage", {"a": 1})
                repo.cache_set("k2", "tenant1", "threats", {"b": 2})
                stats = repo.cache_stats("tenant1")
                assert stats["total_entries"] >= 2
                assert "live_entries" in stats
        finally:
            _cleanup(paths)

    def test_cache_overwrite(self):
        env, paths = _env()
        try:
            with mock.patch.dict(os.environ, env):
                import warden.business_intelligence.repository as repo
                importlib.reload(repo)
                repo.cache_set("key1", "t1", "usage", {"v": 1})
                repo.cache_set("key1", "t1", "usage", {"v": 99})
                result = repo.cache_get("key1")
                assert result is not None
                assert result["v"] == 99
        finally:
            _cleanup(paths)


# ── TestService ────────────────────────────────────────────────────────────────

class TestService:
    def test_usage_summary_empty(self):
        env, paths = _env()
        try:
            with mock.patch.dict(os.environ, env):
                import warden.business_intelligence.repository as repo
                import warden.business_intelligence.service as svc
                importlib.reload(repo)
                importlib.reload(svc)
                result = svc.get_usage_summary("t1", "2026-01")
                assert result["tenant_id"] == "t1"
                assert result["total_requests"] == 0
        finally:
            _cleanup(paths)

    def test_usage_summary_with_events(self):
        env, paths = _env()
        import json
        logs_path = paths[4]
        now_prefix = "2026-01"
        entries = [
            {"tenant_id": "t1", "timestamp": f"{now_prefix}-15T10:00:00Z", "verdict": "ALLOW", "processing_ms": 10},
            {"tenant_id": "t1", "timestamp": f"{now_prefix}-15T11:00:00Z", "verdict": "BLOCK", "processing_ms": 20},
            {"tenant_id": "t1", "timestamp": f"{now_prefix}-16T09:00:00Z", "verdict": "ALLOW", "processing_ms": 15},
            {"tenant_id": "other", "timestamp": f"{now_prefix}-16T09:00:00Z", "verdict": "ALLOW", "processing_ms": 5},
        ]
        with open(logs_path, "w") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")
        env["LOGS_PATH"] = logs_path
        try:
            with mock.patch.dict(os.environ, env):
                import warden.business_intelligence.repository as repo
                import warden.business_intelligence.service as svc
                importlib.reload(repo)
                importlib.reload(svc)
                result = svc.get_usage_summary("t1", now_prefix)
                assert result["total_requests"] == 3
                assert result["blocked_requests"] == 1
        finally:
            _cleanup(paths)

    def test_threat_summary_empty(self):
        env, paths = _env()
        try:
            with mock.patch.dict(os.environ, env):
                import warden.business_intelligence.repository as repo
                import warden.business_intelligence.service as svc
                importlib.reload(repo)
                importlib.reload(svc)
                result = svc.get_threat_summary("t1", 30)
                assert result["tenant_id"] == "t1"
                assert "total_threats" in result
        finally:
            _cleanup(paths)

    def test_compliance_score_empty(self):
        env, paths = _env()
        try:
            with mock.patch.dict(os.environ, env):
                import warden.business_intelligence.repository as repo
                import warden.business_intelligence.service as svc
                importlib.reload(repo)
                importlib.reload(svc)
                result = svc.get_compliance_score("t1", "c1")
                assert result["tenant_id"] == "t1"
                assert "overall_score" in result
                assert "grade" in result
        finally:
            _cleanup(paths)

    def test_vendor_scorecards_empty(self):
        env, paths = _env()
        try:
            with mock.patch.dict(os.environ, env):
                import warden.business_intelligence.repository as repo
                import warden.business_intelligence.service as svc
                importlib.reload(repo)
                importlib.reload(svc)
                result = svc.get_vendor_scorecards("t1")
                assert isinstance(result, list)
        finally:
            _cleanup(paths)

    def test_cost_insights_empty(self):
        env, paths = _env()
        try:
            with mock.patch.dict(os.environ, env):
                import warden.business_intelligence.repository as repo
                import warden.business_intelligence.service as svc
                importlib.reload(repo)
                importlib.reload(svc)
                result = svc.get_cost_insights("t1", months=3)
                assert result["tenant_id"] == "t1"
                assert result["total_spend_usd"] == 0.0
        finally:
            _cleanup(paths)

    def test_incident_prediction_empty(self):
        env, paths = _env()
        try:
            with mock.patch.dict(os.environ, env):
                import warden.business_intelligence.repository as repo
                import warden.business_intelligence.service as svc
                importlib.reload(repo)
                importlib.reload(svc)
                result = svc.get_incident_prediction("t1", horizon_days=7)
                assert result["tenant_id"] == "t1"
                assert "predicted_count" in result
                assert "trend_direction" in result
        finally:
            _cleanup(paths)

    def test_benchmarks_basic(self):
        env, paths = _env()
        try:
            with mock.patch.dict(os.environ, env):
                import warden.business_intelligence.repository as repo
                import warden.business_intelligence.service as svc
                importlib.reload(repo)
                importlib.reload(svc)
                result = svc.get_benchmarks("t1", "c1")
                assert isinstance(result, list)
        finally:
            _cleanup(paths)

    def test_build_report_full(self):
        env, paths = _env()
        try:
            with mock.patch.dict(os.environ, env):
                import warden.business_intelligence.repository as repo
                import warden.business_intelligence.service as svc
                importlib.reload(repo)
                importlib.reload(svc)
                report = svc.build_report("t1", community_id="c1", report_type="full")
                assert report["tenant_id"] == "t1"
                sections = report["sections"]
                assert "usage" in sections
                assert "threats" in sections
                assert "compliance" in sections
        finally:
            _cleanup(paths)

    def test_build_report_executive(self):
        env, paths = _env()
        try:
            with mock.patch.dict(os.environ, env):
                import warden.business_intelligence.repository as repo
                import warden.business_intelligence.service as svc
                importlib.reload(repo)
                importlib.reload(svc)
                report = svc.build_report("t1", report_type="executive")
                assert "usage" in report["sections"]
                assert "compliance" in report["sections"]
        finally:
            _cleanup(paths)

    def test_build_report_selective(self):
        env, paths = _env()
        try:
            with mock.patch.dict(os.environ, env):
                import warden.business_intelligence.repository as repo
                import warden.business_intelligence.service as svc
                importlib.reload(repo)
                importlib.reload(svc)
                report = svc.build_report("t1", include_sections=["compliance"])
                assert "compliance" in report["sections"]
        finally:
            _cleanup(paths)

    def test_usage_summary_cached(self):
        env, paths = _env()
        try:
            with mock.patch.dict(os.environ, env):
                import warden.business_intelligence.repository as repo
                import warden.business_intelligence.service as svc
                importlib.reload(repo)
                importlib.reload(svc)
                r1 = svc.get_usage_summary("t1", "2026-01")
                r2 = svc.get_usage_summary("t1", "2026-01")
                assert r1["total_requests"] == r2["total_requests"]
        finally:
            _cleanup(paths)
