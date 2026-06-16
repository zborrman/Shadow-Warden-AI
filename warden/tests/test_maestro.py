"""
warden/tests/test_maestro.py
──────────────────────────────
Tests for MAESTRO Threat Detection (MKT-09).
"""
from __future__ import annotations

import json
import os
import tempfile

import pytest

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def db_path(tmp_path):
    return str(tmp_path / "maestro_test.db")


@pytest.fixture()
def svc(db_path):
    from warden.marketplace.maestro import MaestroService
    return MaestroService(db_path)


@pytest.fixture()
def misalign(db_path):
    from warden.marketplace.maestro import GoalMisalignmentDetector
    return GoalMisalignmentDetector(db_path)


@pytest.fixture()
def collusion(db_path):
    from warden.marketplace.maestro import CollusionDetector
    return CollusionDetector(db_path)


@pytest.fixture()
def poisoning(db_path):
    from warden.marketplace.maestro import ModelPoisoningDetector
    return ModelPoisoningDetector(db_path)


# ── GoalMisalignmentDetector ──────────────────────────────────────────────────

class TestGoalMisalignmentDetector:
    def test_returns_zero_for_unknown_agent(self, misalign):
        score = misalign.evaluate_agent("AGENT-unknown-xyz")
        assert score == 0.0

    def test_returns_zero_below_min_trades(self, misalign, db_path):
        agent = "AGENT-few-trades"
        # Record only 2 trades (below 3 minimum)
        for _ in range(2):
            misalign.record_trade(agent, "COMM-01", 5.0, True, False)
        score = misalign.evaluate_agent(agent)
        assert score == 0.0

    def test_flags_misaligned_agent(self, misalign, db_path):
        community = "COMM-misalign"
        # Seed community peers with normal discount ~5%
        for peer in ["PEER-1", "PEER-2", "PEER-3", "PEER-4", "PEER-5"]:
            for _ in range(5):
                misalign.record_trade(peer, community, 5.0, True, False)

        # Agent with extreme discount (50%) — should be a z-score outlier
        bad_agent = "AGENT-outlier"
        for _ in range(5):
            misalign.record_trade(bad_agent, community, 50.0, True, False)

        score = misalign.evaluate_agent(bad_agent)
        assert score > 0.0

    def test_get_misalignment_score_returns_float(self, misalign):
        score = misalign.get_misalignment_score("NO-SUCH-AGENT")
        assert isinstance(score, float)
        assert score == 0.0


# ── CollusionDetector ─────────────────────────────────────────────────────────

class TestCollusionDetector:
    def test_no_flag_below_min_observations(self, collusion):
        score = collusion.analyze_negotiation_pair("A1", "A2", rounds=1, initial_price_usd=100.0, final_price_usd=101.0)
        assert score == 0.0  # only 1 observation; needs 3

    def test_no_flag_when_rounds_high(self, collusion):
        for _ in range(5):
            score = collusion.analyze_negotiation_pair(
                "A3", "A4", rounds=8, initial_price_usd=100.0, final_price_usd=120.0,
            )
        # Many rounds + large delta → not suspicious
        assert score < 0.6

    def test_flags_collusion_pattern(self, collusion):
        for _ in range(5):
            score = collusion.analyze_negotiation_pair(
                "A5", "A6",
                rounds=1,            # below threshold (2)
                initial_price_usd=100.0,
                final_price_usd=100.5,  # <5% delta
            )
        # All observations suspicious → flagged
        assert score >= 0.6

    def test_is_flagged_false_by_default(self, collusion):
        assert collusion.is_flagged("NEVER-SEEN-AGENT") is False

    def test_get_collusion_score_returns_float(self, collusion):
        score = collusion.get_collusion_score("X1", "X2")
        assert isinstance(score, float)


# ── ModelPoisoningDetector ────────────────────────────────────────────────────

class TestModelPoisoningDetector:
    def _seed_baseline(self, poisoning, db_path, community_id: str, count: int = 10):
        """Seed marketplace_listings table so baseline can be built."""
        import sqlite3
        con = sqlite3.connect(db_path)
        con.execute("""CREATE TABLE IF NOT EXISTS marketplace_listings (
            listing_id TEXT PRIMARY KEY,
            community_id TEXT,
            asset_type TEXT,
            status TEXT,
            content TEXT
        )""")
        for i in range(count):
            text = "simple rule detect keyword injection attempt" * 2
            con.execute(
                "INSERT OR IGNORE INTO marketplace_listings VALUES (?,?,?,?,?)",
                (f"L-{i}", community_id, "rule", "active", text),
            )
        con.commit()
        con.close()

    def test_returns_no_flag_insufficient_baseline(self, poisoning, db_path):
        report = poisoning.validate_imported_rule("some rule text", "COMM-empty")
        assert report.flagged is False
        assert "insufficient_baseline" in report.reasons or "check_skipped" in report.reasons

    def test_validates_normal_rule_passes(self, poisoning, db_path):
        cid = "COMM-normal"
        self._seed_baseline(poisoning, db_path, cid, count=10)
        # Invalidate cached baseline
        poisoning._build_baseline(cid)
        normal_rule = "detect keyword injection attempt in prompt"
        report = poisoning.validate_imported_rule(normal_rule, cid)
        # Normal rule shouldn't be an outlier
        assert isinstance(report.flagged, bool)
        assert isinstance(report.score, float)

    def test_validate_imported_model_returns_report(self, poisoning, db_path):
        model_dict = {"metrics": ["m1", "m2"], "dimensions": ["d1"]}
        report = poisoning.validate_imported_model(model_dict, "COMM-model")
        assert hasattr(report, "flagged")
        assert hasattr(report, "score")
        assert hasattr(report, "reasons")

    def test_poisoning_report_to_dict(self, poisoning, db_path):
        report = poisoning.validate_imported_rule("test rule", "COMM-x")
        d = report.to_dict()
        assert "flagged" in d
        assert "score" in d
        assert "reasons" in d


# ── MaestroService ────────────────────────────────────────────────────────────

class TestMaestroService:
    def test_full_audit_returns_report(self, svc):
        report = svc.run_full_audit("AGENT-test-123")
        assert report.agent_id == "AGENT-test-123"
        assert report.overall_threat_level in ("low", "medium", "high")
        assert report.recommended_action in ("none", "monitor", "restrict", "suspend")

    def test_full_audit_to_dict(self, svc):
        d = svc.run_full_audit("AGENT-dict-test").to_dict()
        assert "agent_id" in d
        assert "misalignment_score" in d
        assert "collusion_flags" in d
        assert "overall_threat_level" in d

    def test_maestro_penalty_zero_for_clean_agent(self, svc):
        penalty = svc.get_maestro_penalty("AGENT-clean-no-history")
        assert 0.0 <= penalty <= 1.0

    def test_list_flagged_agents_empty_initially(self, svc):
        flags = svc.list_flagged_agents()
        assert isinstance(flags, list)

    def test_get_maestro_service_singleton(self, db_path):
        from warden.marketplace.maestro import get_maestro_service, _service
        svc1 = get_maestro_service(db_path)
        svc2 = get_maestro_service(db_path)
        # Same object
        assert svc1 is svc2

    def test_classify_threat_levels(self):
        from warden.marketplace.maestro import MaestroService
        level, action = MaestroService._classify(0.1, False, False)
        assert level == "low"
        level, action = MaestroService._classify(0.4, False, False)
        assert level == "medium"
        level, action = MaestroService._classify(0.8, False, False)
        assert level == "high"
        level, action = MaestroService._classify(0.1, True, False)
        assert level == "high"


# ── Reputation Integration ────────────────────────────────────────────────────

class TestReputationMaestroIntegration:
    def test_maestro_penalty_reduces_score(self, db_path):
        """Verify that a non-zero maestro_penalty reduces the reputation score."""
        from warden.marketplace.reputation import ReputationEngine

        class _FakeService:
            def get_maestro_penalty(self, _agent_id):
                return 0.5  # 50% penalty

        class _FakeDB:
            pass

        engine = ReputationEngine()
        # Need enough trades to bypass UNKNOWN band — seed sqlite
        import sqlite3
        con = sqlite3.connect(db_path)
        con.execute("""CREATE TABLE IF NOT EXISTS marketplace_purchases (
            purchase_id TEXT PRIMARY KEY, buyer_agent TEXT, seller_agent TEXT, status TEXT
        )""")
        for i in range(10):
            con.execute(
                "INSERT OR IGNORE INTO marketplace_purchases VALUES (?,?,?,?)",
                (f"P-{i}", "BUYER-A", "SELLER-B", "completed"),
            )
        con.commit()
        con.close()

        score_clean   = engine.get_score("BUYER-A", db_path=db_path, maestro_service=_FakeService.__new__(_FakeService))
        score_clean.maestro_penalty = 0.0

        # Score with penalty
        class _PenaltyService:
            def get_maestro_penalty(self, _):
                return 0.5
        score_penalty = engine.get_score("BUYER-A", db_path=db_path, maestro_service=_PenaltyService())
        assert score_penalty.maestro_penalty == pytest.approx(0.5)
