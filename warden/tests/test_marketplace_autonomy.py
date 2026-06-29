"""Tests for warden/marketplace/autonomy.py — Progressive Autonomy L1/L2/L3."""
import os
import pytest


@pytest.fixture(autouse=True)
def _isolate_autonomy(tmp_path):
    os.environ["MARKETPLACE_DB_PATH"] = str(tmp_path / "autonomy_test.db")
    os.environ["REDIS_URL"] = "memory://"
    yield
    os.environ.pop("MARKETPLACE_DB_PATH", None)
    os.environ.pop("REDIS_URL", None)


def _make_policy(agent_id, level, *, max_spend=10.0, daily=100.0,
                  allowed=None, require_above=0.01, expires=None, creator="tenant-X"):
    from warden.marketplace.autonomy import AutonomyPolicy, set_policy
    policy = AutonomyPolicy(
        agent_id=agent_id,
        level=level,
        max_spend_usd=max_spend,
        daily_spend_usd=daily,
        allowed_actions=allowed or ["search", "negotiate", "clear"],
        require_approval_above_usd=require_above,
        expires_at=expires,
        created_by=creator,
    )
    set_policy(policy)
    return policy


class TestL1ShadowMode:
    def test_l1_all_actions_require_approval(self):
        from warden.marketplace.autonomy import check_action
        _make_policy("agent-l1", level=1)
        for action in ["search", "negotiate", "clear", "transfer"]:
            result = check_action("agent-l1", action, 0.0)
            assert result == "REQUIRE_APPROVAL", f"L1 {action} should be REQUIRE_APPROVAL"

    def test_l1_large_amount_still_require_approval(self):
        from warden.marketplace.autonomy import check_action
        _make_policy("agent-l1-big", level=1, max_spend=1000.0)
        assert check_action("agent-l1-big", "search", 999.0) == "REQUIRE_APPROVAL"

    def test_no_policy_defaults_to_require_approval(self):
        """No registered policy → safe default = REQUIRE_APPROVAL (treated as L1)."""
        from warden.marketplace.autonomy import check_action
        result = check_action("agent-no-policy", "search", 0.001)
        assert result == "REQUIRE_APPROVAL"


class TestL2SupervisedMode:
    def test_l2_small_amount_in_allowed_actions_allows(self):
        from warden.marketplace.autonomy import check_action
        _make_policy("agent-l2", level=2, require_above=0.01)
        result = check_action("agent-l2", "search", 0.001)
        assert result == "ALLOW"

    def test_l2_amount_equal_threshold_requires_approval(self):
        from warden.marketplace.autonomy import check_action
        _make_policy("agent-l2-thresh", level=2, require_above=0.01)
        result = check_action("agent-l2-thresh", "search", 0.01)
        assert result == "REQUIRE_APPROVAL"

    def test_l2_amount_above_threshold_requires_approval(self):
        from warden.marketplace.autonomy import check_action
        _make_policy("agent-l2-over", level=2, require_above=0.01)
        result = check_action("agent-l2-over", "search", 1.00)
        assert result == "REQUIRE_APPROVAL"

    def test_l2_disallowed_action_requires_approval(self):
        from warden.marketplace.autonomy import check_action
        _make_policy("agent-l2-deny", level=2, allowed=["search"], require_above=0.01)
        result = check_action("agent-l2-deny", "clear", 0.001)
        assert result == "REQUIRE_APPROVAL"

    def test_l2_zero_amount_in_allowed_actions_allows(self):
        from warden.marketplace.autonomy import check_action
        _make_policy("agent-l2-zero", level=2, require_above=0.01)
        assert check_action("agent-l2-zero", "search", 0.0) == "ALLOW"


class TestL3AutonomousMode:
    def test_l3_under_limit_in_allowed_allows(self):
        from warden.marketplace.autonomy import check_action
        _make_policy("agent-l3", level=3, max_spend=10.0)
        assert check_action("agent-l3", "search", 5.0) == "ALLOW"

    def test_l3_exactly_at_limit_allows(self):
        from warden.marketplace.autonomy import check_action
        _make_policy("agent-l3-exact", level=3, max_spend=10.0)
        assert check_action("agent-l3-exact", "search", 10.0) == "ALLOW"

    def test_l3_over_limit_blocks(self):
        from warden.marketplace.autonomy import check_action
        _make_policy("agent-l3-over", level=3, max_spend=10.0)
        result = check_action("agent-l3-over", "search", 10.01)
        assert result == "BLOCK"

    def test_l3_disallowed_action_blocks(self):
        from warden.marketplace.autonomy import check_action
        _make_policy("agent-l3-deny", level=3, allowed=["search"], max_spend=100.0)
        result = check_action("agent-l3-deny", "nuclear_launch", 0.001)
        assert result == "BLOCK"

    def test_l3_zero_amount_allows(self):
        from warden.marketplace.autonomy import check_action
        _make_policy("agent-l3-zero", level=3, max_spend=1.0)
        assert check_action("agent-l3-zero", "search", 0.0) == "ALLOW"


class TestPolicyPersistence:
    def test_get_policy_returns_stored_policy(self):
        from warden.marketplace.autonomy import get_policy
        _make_policy("agent-persist", level=2, max_spend=5.0)
        pol = get_policy("agent-persist")
        assert pol is not None
        assert pol.level == 2
        assert pol.max_spend_usd == 5.0

    def test_get_policy_unknown_agent_returns_none(self):
        from warden.marketplace.autonomy import get_policy
        assert get_policy("agent-ghost") is None

    def test_delete_policy_removes_it(self):
        from warden.marketplace.autonomy import check_action, delete_policy, get_policy
        _make_policy("agent-delete", level=3, max_spend=100.0)
        delete_policy("agent-delete")
        assert get_policy("agent-delete") is None
        assert check_action("agent-delete", "search", 0.001) == "REQUIRE_APPROVAL"

    def test_overwrite_policy_updates_level(self):
        from warden.marketplace.autonomy import check_action
        _make_policy("agent-overwrite", level=3, max_spend=100.0)
        _make_policy("agent-overwrite", level=1, max_spend=100.0)
        assert check_action("agent-overwrite", "search", 0.001) == "REQUIRE_APPROVAL"


class TestCheckActionFailOpen:
    def test_check_action_no_policy_is_failopen(self):
        """No policy → check_action must not raise and must return REQUIRE_APPROVAL."""
        from warden.marketplace.autonomy import check_action
        result = check_action("agent-absolutely-no-policy-xyz", "search", 9999.0)
        assert result == "REQUIRE_APPROVAL"

    def test_set_policy_rejects_invalid_level(self):
        """set_policy enforces level must be 1, 2, or 3."""
        from warden.marketplace.autonomy import AutonomyPolicy, set_policy
        pol = AutonomyPolicy(
            agent_id="agent-bad-level",
            level=99,
            max_spend_usd=10.0,
            daily_spend_usd=100.0,
            allowed_actions=["search"],
            require_approval_above_usd=0.01,
            expires_at=None,
            created_by="test",
        )
        with pytest.raises(ValueError):
            set_policy(pol)
