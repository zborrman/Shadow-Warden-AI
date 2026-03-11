"""
warden/tests/test_data_policy.py
──────────────────────────────────
Unit tests for DataPolicyEngine — data classification traffic light.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from warden.data_policy import DataClass, DataPolicyEngine, PolicyDecision, classify_provider


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def engine(tmp_path: Path) -> DataPolicyEngine:
    e = DataPolicyEngine(db_path=tmp_path / "test_policy.db")
    yield e
    e.close()


# ── classify_provider ─────────────────────────────────────────────────────────

class TestClassifyProvider:
    def test_openai_is_cloud(self) -> None:
        assert classify_provider("openai") == "cloud"

    def test_anthropic_is_cloud(self) -> None:
        assert classify_provider("api.anthropic.com") == "cloud"

    def test_ollama_is_local(self) -> None:
        assert classify_provider("ollama") == "local"

    def test_localhost_is_local(self) -> None:
        assert classify_provider("http://localhost:11434") == "local"

    def test_unknown_defaults_to_cloud(self) -> None:
        assert classify_provider("some-unknown-provider") == "cloud"


# ── Built-in category detection ───────────────────────────────────────────────

class TestBuiltinCategories:
    def test_financial_is_red(self, engine: DataPolicyEngine) -> None:
        decision = engine.classify("Please analyze this invoice from Q1 revenue report.")
        assert decision.data_class == DataClass.RED
        assert not decision.allowed
        assert "financial" in decision.triggered_rule

    def test_legal_nda_is_red(self, engine: DataPolicyEngine) -> None:
        decision = engine.classify("This non-disclosure agreement between parties...")
        assert decision.data_class == DataClass.RED
        assert not decision.allowed

    def test_hr_salary_is_red(self, engine: DataPolicyEngine) -> None:
        decision = engine.classify("Performance review indicates bonus structure for Q4.")
        assert decision.data_class == DataClass.RED
        assert not decision.allowed

    def test_medical_hipaa_is_red(self, engine: DataPolicyEngine) -> None:
        decision = engine.classify("Patient record: diagnosis code ICD-10 Z00.00")
        assert decision.data_class == DataClass.RED
        assert not decision.allowed

    def test_customer_list_is_yellow(self, engine: DataPolicyEngine) -> None:
        decision = engine.classify(
            "Summarize our customer list export from CRM.",
            provider="openai",
            tenant_id="default",
        )
        assert decision.data_class == DataClass.YELLOW

    def test_internal_memo_is_yellow(self, engine: DataPolicyEngine) -> None:
        decision = engine.classify("Internal memo: Q4 company strategy roadmap Q4 planning.")
        assert decision.data_class == DataClass.YELLOW

    def test_public_text_is_green(self, engine: DataPolicyEngine) -> None:
        decision = engine.classify("Write a marketing email about our new product launch.")
        assert decision.data_class == DataClass.GREEN
        assert decision.allowed


# ── Yellow + cloud blocking ───────────────────────────────────────────────────

class TestYellowCloudPolicy:
    def test_yellow_blocked_with_cloud_when_setting_on(
        self, engine: DataPolicyEngine
    ) -> None:
        # Default: block_cloud_yellow=True
        decision = engine.classify(
            "Summarize our customer list export from CRM.",
            provider="openai",
            tenant_id="default",
        )
        assert not decision.allowed
        assert decision.suggestion != ""

    def test_yellow_allowed_with_local(self, engine: DataPolicyEngine) -> None:
        decision = engine.classify(
            "Summarize our customer list export from CRM.",
            provider="ollama",
            tenant_id="default",
        )
        assert decision.allowed
        assert decision.data_class == DataClass.YELLOW

    def test_yellow_allowed_with_cloud_when_setting_off(
        self, engine: DataPolicyEngine
    ) -> None:
        engine.update_settings("t1", block_cloud_yellow=False)
        decision = engine.classify(
            "Summarize our customer list export from CRM.",
            provider="openai",
            tenant_id="t1",
        )
        assert decision.allowed
        assert decision.data_class == DataClass.YELLOW

    def test_red_always_blocked_regardless_of_settings(
        self, engine: DataPolicyEngine
    ) -> None:
        engine.update_settings("t1", block_cloud_yellow=False)
        decision = engine.classify(
            "NDA between company and vendor",
            provider="ollama",
            tenant_id="t1",
        )
        assert not decision.allowed
        assert decision.data_class == DataClass.RED


# ── Custom rules ──────────────────────────────────────────────────────────────

class TestCustomRules:
    def test_add_pattern_rule(self, engine: DataPolicyEngine) -> None:
        rule_id = engine.add_rule(
            tenant_id    = "acme",
            data_class   = DataClass.RED,
            trigger_type = "pattern",
            value        = r"(?i)\bACME-SECRET\b",
            description  = "Internal product code",
        )
        assert rule_id is not None
        decision = engine.classify("Order ACME-SECRET to production", tenant_id="acme")
        assert not decision.allowed
        assert decision.data_class == DataClass.RED
        assert rule_id in decision.triggered_rule

    def test_add_keyword_rule(self, engine: DataPolicyEngine) -> None:
        engine.add_rule(
            tenant_id    = "acme",
            data_class   = DataClass.YELLOW,
            trigger_type = "keyword",
            value        = "proprietary algorithm, trade formula",
        )
        decision = engine.classify(
            "Explain our proprietary algorithm",
            provider="openai",
            tenant_id="acme",
        )
        assert decision.data_class == DataClass.YELLOW

    def test_red_custom_rule_takes_priority_over_yellow_builtin(
        self, engine: DataPolicyEngine
    ) -> None:
        engine.add_rule(
            tenant_id    = "acme",
            data_class   = DataClass.RED,
            trigger_type = "keyword",
            value        = "customer list",
        )
        # "customer list" would normally be YELLOW (built-in), now RED by custom rule
        decision = engine.classify(
            "Export our customer list to Excel",
            provider="ollama",
            tenant_id="acme",
        )
        assert decision.data_class == DataClass.RED
        assert not decision.allowed

    def test_invalid_data_class_raises(self, engine: DataPolicyEngine) -> None:
        with pytest.raises(ValueError, match="data_class"):
            engine.add_rule("t1", "purple", "pattern", r"\btest\b")

    def test_invalid_trigger_type_raises(self, engine: DataPolicyEngine) -> None:
        with pytest.raises(ValueError, match="trigger_type"):
            engine.add_rule("t1", DataClass.RED, "regex", r"\btest\b")

    def test_invalid_regex_raises(self, engine: DataPolicyEngine) -> None:
        with pytest.raises(Exception):
            engine.add_rule("t1", DataClass.RED, "pattern", r"[invalid")

    def test_empty_keyword_list_raises(self, engine: DataPolicyEngine) -> None:
        with pytest.raises(ValueError, match="empty"):
            engine.add_rule("t1", DataClass.RED, "keyword", "   ,  ,  ")

    def test_delete_rule(self, engine: DataPolicyEngine) -> None:
        rule_id = engine.add_rule("t1", DataClass.RED, "keyword", "secret code")
        assert engine.delete_rule(rule_id, "t1") is True
        # After deletion, text should pass through (green by default)
        decision = engine.classify("mention secret code here", tenant_id="t1")
        assert rule_id not in decision.triggered_rule

    def test_delete_nonexistent_returns_false(self, engine: DataPolicyEngine) -> None:
        assert engine.delete_rule("no-such-rule", "t1") is False

    def test_delete_wrong_tenant_returns_false(self, engine: DataPolicyEngine) -> None:
        rule_id = engine.add_rule("t1", DataClass.RED, "keyword", "xyz")
        assert engine.delete_rule(rule_id, "t2") is False

    def test_rules_are_tenant_isolated(self, engine: DataPolicyEngine) -> None:
        engine.add_rule("acme", DataClass.RED, "keyword", "top secret")
        # Same text for a different tenant should be green
        decision = engine.classify("top secret project", tenant_id="other-corp")
        # No custom rule for other-corp — might match built-in or pass green
        assert decision.data_class != DataClass.RED or "builtin" in decision.triggered_rule

    def test_get_rules_returns_list(self, engine: DataPolicyEngine) -> None:
        engine.add_rule("t1", DataClass.RED, "keyword", "alpha")
        engine.add_rule("t1", DataClass.YELLOW, "keyword", "beta")
        rules = engine.get_rules("t1")
        assert len(rules) == 2
        # RED should come first
        assert rules[0]["data_class"] == DataClass.RED

    def test_pattern_cache_invalidated_after_add(self, engine: DataPolicyEngine) -> None:
        """Ensure classify() picks up newly-added rules (cache must be invalidated)."""
        # First call: no rule, green
        d1 = engine.classify("super confidential stuff", tenant_id="t1")
        # Add a red rule
        engine.add_rule("t1", DataClass.RED, "keyword", "super confidential")
        # Second call: should now fire the new rule
        d2 = engine.classify("super confidential stuff", tenant_id="t1")
        assert d2.data_class == DataClass.RED


# ── Settings ──────────────────────────────────────────────────────────────────

class TestSettings:
    def test_default_settings(self, engine: DataPolicyEngine) -> None:
        s = engine.get_settings("new-tenant")
        assert s["default_class"] == DataClass.GREEN
        assert s["block_cloud_yellow"] is True

    def test_update_settings(self, engine: DataPolicyEngine) -> None:
        engine.update_settings("t1", default_class="yellow", block_cloud_yellow=False)
        s = engine.get_settings("t1")
        assert s["default_class"] == "yellow"
        assert s["block_cloud_yellow"] is False

    def test_invalid_default_class_raises(self, engine: DataPolicyEngine) -> None:
        with pytest.raises(ValueError):
            engine.update_settings("t1", default_class="purple")


# ── get_full_policy ────────────────────────────────────────────────────────────

class TestGetFullPolicy:
    def test_structure(self, engine: DataPolicyEngine) -> None:
        engine.add_rule("acme", DataClass.RED, "keyword", "secret")
        policy = engine.get_full_policy("acme")
        assert "tenant_id" in policy
        assert "settings" in policy
        assert "rules" in policy
        assert "builtin_categories" in policy

    def test_builtin_categories_present(self, engine: DataPolicyEngine) -> None:
        policy = engine.get_full_policy("acme")
        cats = policy["builtin_categories"]
        assert "financial" in cats
        assert "medical" in cats
        assert "hr" in cats

    def test_custom_rules_in_policy(self, engine: DataPolicyEngine) -> None:
        rid = engine.add_rule("acme", DataClass.RED, "keyword", "xyz123")
        policy = engine.get_full_policy("acme")
        rule_ids = [r["rule_id"] for r in policy["rules"]]
        assert rid in rule_ids
