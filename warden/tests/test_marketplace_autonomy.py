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


# ── Expiry semantics ────────────────────────────────────────────────────────────

class TestExpiry:
    def test_is_expired_false_when_no_expiry(self):
        from warden.marketplace.autonomy import AutonomyPolicy
        pol = AutonomyPolicy("a", 2, 1.0, 1.0, expires_at=None)
        assert pol.is_expired() is False

    def test_is_expired_true_for_past_timestamp(self):
        from warden.marketplace.autonomy import AutonomyPolicy
        pol = AutonomyPolicy("a", 2, 1.0, 1.0, expires_at="2000-01-01T00:00:00Z")
        assert pol.is_expired() is True

    def test_is_expired_false_for_far_future(self):
        from warden.marketplace.autonomy import AutonomyPolicy
        pol = AutonomyPolicy("a", 2, 1.0, 1.0, expires_at="2999-01-01T00:00:00Z")
        assert pol.is_expired() is False

    def test_get_policy_ignores_expired_stored_policy(self):
        """A persisted-but-expired policy must resolve to None (agent falls back to L1)."""
        from warden.marketplace.autonomy import check_action, get_policy
        _make_policy("agent-expired", level=3, max_spend=100.0,
                     expires="2000-01-01T00:00:00Z")
        assert get_policy("agent-expired") is None
        assert check_action("agent-expired", "search", 50.0) == "REQUIRE_APPROVAL"


# ── Redis cache path (fake redis) ───────────────────────────────────────────────

class _FakeRedis:
    def __init__(self):
        self.store: dict[str, str] = {}

    def setex(self, key, ttl, val):
        self.store[key] = val

    def get(self, key):
        return self.store.get(key)

    def delete(self, key):
        self.store.pop(key, None)


class TestRedisCachePath:
    def test_set_get_roundtrip_through_cache(self, monkeypatch):
        """With a live cache, set_policy writes it and get_policy reads it back
        (exercising to_dict / _dict_to_policy serialization)."""
        import warden.marketplace.autonomy as a
        fake = _FakeRedis()
        monkeypatch.setattr(a, "_redis", lambda: fake)
        _make_policy("agent-cached", level=2, max_spend=7.5, allowed=["search"])
        assert fake.store, "policy should have been cached"
        pol = a.get_policy("agent-cached")
        assert pol is not None and pol.level == 2 and pol.max_spend_usd == 7.5

    def test_delete_clears_cache_entry(self, monkeypatch):
        import warden.marketplace.autonomy as a
        fake = _FakeRedis()
        monkeypatch.setattr(a, "_redis", lambda: fake)
        _make_policy("agent-cache-del", level=3, max_spend=1.0)
        assert fake.store
        a.delete_policy("agent-cache-del")
        assert fake.store == {}

    def test_expired_cache_hit_returns_none(self, monkeypatch):
        """A cached-but-expired policy resolves to None without touching SQLite."""
        import warden.marketplace.autonomy as a
        fake = _FakeRedis()
        monkeypatch.setattr(a, "_redis", lambda: fake)
        fake.store["marketplace:autonomy:agent-stale"] = a.json.dumps({
            "agent_id": "agent-stale", "level": 3, "max_spend_usd": 100.0,
            "daily_spend_usd": 0.0, "allowed_actions": ["search"],
            "require_approval_above_usd": 0.01,
            "expires_at": "2000-01-01T00:00:00Z", "created_by": "t",
        })
        assert a.get_policy("agent-stale") is None

    def test_redis_errors_are_swallowed(self, monkeypatch):
        """Cache get/set/del must never raise into the caller (fail-open)."""
        import warden.marketplace.autonomy as a

        class _Boom:
            def setex(self, *a):  # noqa: ANN002
                raise RuntimeError("redis down")

            def get(self, *a):  # noqa: ANN002
                raise RuntimeError("redis down")

            def delete(self, *a):  # noqa: ANN002
                raise RuntimeError("redis down")

        monkeypatch.setattr(a, "_redis", lambda: _Boom())
        # None of these should raise despite the failing backend.
        _make_policy("agent-redis-boom", level=2)
        assert a.get_policy("agent-redis-boom") is not None   # SQLite fallback
        assert a.delete_policy("agent-redis-boom") is True


# ── Malformed persistence + error fallbacks ─────────────────────────────────────

class TestErrorFallbacks:
    def test_row_with_bad_allowed_actions_json_falls_back_to_default(self, monkeypatch):
        """A corrupt allowed_actions column must not crash — falls back to defaults."""
        import sqlite3

        import warden.marketplace.autonomy as a
        monkeypatch.setattr(a, "_redis", lambda: None)   # force SQLite read
        _make_policy("agent-badjson", level=3, max_spend=100.0)
        con = sqlite3.connect(a._DB_PATH)
        con.execute(
            "UPDATE marketplace_autonomy_policies SET allowed_actions=? WHERE agent_id=?",
            ("{not valid json", "agent-badjson"),
        )
        con.commit()
        con.close()
        pol = a.get_policy("agent-badjson")
        assert pol is not None
        assert pol.allowed_actions == ["search", "negotiate", "clear"]

    def test_get_policy_sqlite_error_returns_none(self, monkeypatch):
        """A SQLite failure in get_policy must fail-safe to None, not raise."""
        import sqlite3

        import warden.marketplace.autonomy as a
        monkeypatch.setattr(a, "_redis", lambda: None)

        def _boom():
            raise sqlite3.OperationalError("db locked")

        monkeypatch.setattr(a, "_conn", _boom)
        assert a.get_policy("anything") is None

    def test_check_action_unknown_level_is_require_approval(self, monkeypatch):
        """A policy with a corrupt level (bypassing set_policy validation) → safe default."""
        import warden.marketplace.autonomy as a
        pol = a.AutonomyPolicy("agent-weird", 7, 1.0, 1.0, allowed_actions=["search"])
        monkeypatch.setattr(a, "get_policy", lambda _id: pol)
        assert a.check_action("agent-weird", "search", 0.0) == "REQUIRE_APPROVAL"

    def test_check_action_fails_open_on_exception(self, monkeypatch):
        """If get_policy raises, check_action must fail-open to REQUIRE_APPROVAL."""
        import warden.marketplace.autonomy as a

        def _boom(_id):
            raise RuntimeError("store exploded")

        monkeypatch.setattr(a, "get_policy", _boom)
        assert a.check_action("agent-x", "search", 0.0) == "REQUIRE_APPROVAL"
