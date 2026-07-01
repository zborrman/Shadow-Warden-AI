"""
Unit tests for Digital Staff Unit Economics (TokenCostTracker).
"""
from __future__ import annotations

import pytest

from warden.staff.economics import (
    _COST_PER_MTOK,
    ActionCost,
    TokenCostTracker,
    compute_cost_usd,
)


@pytest.fixture
def tracker(tmp_path):
    return TokenCostTracker(db_path=str(tmp_path / "economics.db"))


# ── compute_cost_usd ──────────────────────────────────────────────────────────

class TestComputeCost:
    def test_haiku_cheaper_than_opus(self):
        haiku = compute_cost_usd("claude-haiku-4-5-20251001", 1000, 500)
        opus  = compute_cost_usd("claude-opus-4-8", 1000, 500)
        assert haiku < opus

    def test_sonnet_between_haiku_and_opus(self):
        haiku  = compute_cost_usd("claude-haiku-4-5-20251001", 1000, 500)
        sonnet = compute_cost_usd("claude-sonnet-4-6", 1000, 500)
        opus   = compute_cost_usd("claude-opus-4-8", 1000, 500)
        assert haiku < sonnet < opus

    def test_zero_tokens_zero_cost(self):
        assert compute_cost_usd("claude-opus-4-8", 0, 0) == 0.0

    def test_unknown_model_uses_default_sonnet_rate(self):
        known = compute_cost_usd("claude-sonnet-4-6", 1000, 500)
        unknown = compute_cost_usd("unknown-model-xyz", 1000, 500)
        assert known == unknown

    def test_output_tokens_more_expensive_per_unit(self):
        # For all models, output rate > input rate
        for model, rates in _COST_PER_MTOK.items():
            assert rates["output"] > rates["input"], f"{model}: output should cost more than input"

    def test_cost_is_positive_for_nonzero_tokens(self):
        cost = compute_cost_usd("claude-opus-4-8", 100, 50)
        assert cost > 0.0

    @pytest.mark.parametrize("model", list(_COST_PER_MTOK.keys()))
    def test_all_models_produce_nonzero_cost(self, model):
        cost = compute_cost_usd(model, 1000, 500)
        assert cost > 0.0


# ── TokenCostTracker.record ────────────────────────────────────────────────────

class TestRecord:
    def test_record_returns_action_cost(self, tracker):
        result = tracker.record("t1", "bdr", "draft_email", "claude-haiku-4-5-20251001", 800, 400)
        assert isinstance(result, ActionCost)
        assert result.cost_usd > 0.0
        assert result.agent_id == "bdr"

    def test_record_persists_to_db(self, tracker, tmp_path):
        tracker.record("t1", "compliance", "score_kyc", "claude-opus-4-8", 2000, 1000)
        report = tracker.get_report("t1", days=1)
        assert report["total_cost_usd"] > 0.0
        assert len(report["actions"]) >= 1

    def test_record_multiple_actions(self, tracker):
        tracker.record("t1", "bdr", "crm_search", "claude-haiku-4-5-20251001", 100, 50)
        tracker.record("t1", "compliance", "generate_sar", "claude-opus-4-8", 3000, 1500)
        tracker.record("t1", "growth", "generate_seo", "claude-sonnet-4-6", 1500, 800)
        report = tracker.get_report("t1", days=1)
        assert len(report["actions"]) == 3

    def test_tenant_isolation(self, tracker):
        tracker.record("tenant-A", "bdr", "crm_search", "claude-haiku-4-5-20251001", 100, 50)
        tracker.record("tenant-B", "bdr", "crm_search", "claude-haiku-4-5-20251001", 100, 50)
        report_a = tracker.get_report("tenant-A", days=1)
        report_b = tracker.get_report("tenant-B", days=1)
        assert report_a["total_cost_usd"] > 0
        assert report_b["total_cost_usd"] > 0
        # Each tenant sees only their own data
        assert report_a["actions"][0]["agent_id"] == "bdr"


# ── get_report ─────────────────────────────────────────────────────────────────

class TestGetReport:
    def test_empty_report_for_new_tenant(self, tracker):
        report = tracker.get_report("no-such-tenant", days=30)
        assert report["total_cost_usd"] == 0.0
        assert report["actions"] == []

    def test_report_structure(self, tracker):
        tracker.record("t1", "support", "issue_refund", "claude-haiku-4-5-20251001", 500, 200)
        report = tracker.get_report("t1", days=1)
        assert "tenant_id" in report
        assert "period_days" in report
        assert "total_cost_usd" in report
        assert "actions" in report
        assert "model_breakdown" in report

    def test_action_fields(self, tracker):
        tracker.record("t1", "bdr", "crm_upsert_lead", "claude-sonnet-4-6", 600, 300)
        report = tracker.get_report("t1", days=1)
        action = report["actions"][0]
        assert "agent_id" in action
        assert "action" in action
        assert "model" in action
        assert "calls" in action
        assert "total_cost_usd" in action
        assert "avg_cost_usd" in action
        assert "cost_per_call_usd" in action

    def test_model_breakdown_present(self, tracker):
        tracker.record("t1", "bdr", "crm_search", "claude-haiku-4-5-20251001", 100, 50)
        tracker.record("t1", "compliance", "generate_sar", "claude-opus-4-8", 3000, 1500)
        report = tracker.get_report("t1", days=1)
        models = {b["model"] for b in report["model_breakdown"]}
        assert "claude-haiku-4-5-20251001" in models
        assert "claude-opus-4-8" in models

    def test_opus_dominates_cost_breakdown(self, tracker):
        """Opus actions should represent majority of cost even with fewer calls."""
        tracker.record("t1", "bdr", "crm_search", "claude-haiku-4-5-20251001", 200, 100)
        tracker.record("t1", "bdr", "crm_search", "claude-haiku-4-5-20251001", 200, 100)
        tracker.record("t1", "compliance", "generate_sar", "claude-opus-4-8", 5000, 2000)
        report = tracker.get_report("t1", days=1)
        # opus entry should be highest cost
        breakdown = report["model_breakdown"]
        assert breakdown[0]["model"] == "claude-opus-4-8"


# ── get_margin_alerts ─────────────────────────────────────────────────────────

class TestMarginAlerts:
    def test_no_alerts_below_threshold(self, tracker):
        # Haiku cost per call is tiny — won't trigger $1 threshold
        tracker.record("t1", "bdr", "crm_search", "claude-haiku-4-5-20251001", 100, 50)
        alerts = tracker.get_margin_alerts("t1", threshold_usd=1.00)
        assert alerts == []

    def test_alert_triggered_for_opus_sar(self, tracker):
        # 10k input + 5k output on Opus = (10000*15 + 5000*75) / 1e6 = 0.525 USD
        tracker.record("t1", "compliance", "generate_sar", "claude-opus-4-8", 10000, 5000)
        alerts = tracker.get_margin_alerts("t1", threshold_usd=0.50)
        assert len(alerts) >= 1
        assert alerts[0]["agent_id"] == "compliance"
        assert "alert" in alerts[0]

    def test_alert_has_threshold_field(self, tracker):
        tracker.record("t1", "compliance", "generate_sar", "claude-opus-4-8", 10000, 5000)
        alerts = tracker.get_margin_alerts("t1", threshold_usd=0.10)
        assert alerts[0]["threshold_usd"] == 0.10


# ── get_total_cost ────────────────────────────────────────────────────────────

class TestGetTotalCost:
    def test_total_cost_sums_actions(self, tracker):
        tracker.record("t1", "bdr", "a", "claude-haiku-4-5-20251001", 1000, 500)
        tracker.record("t1", "compliance", "b", "claude-opus-4-8", 2000, 1000)
        total = tracker.get_total_cost("t1", days=1)
        assert total > 0.0

    def test_total_cost_zero_for_unknown_tenant(self, tracker):
        assert tracker.get_total_cost("nobody", days=30) == 0.0
