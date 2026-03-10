"""
warden/tests/test_tenant_policy.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Unit tests for warden/tenant_policy.py and the per-tenant threshold
integration in AgentMonitor.

Covers:
  • TenantPolicy dataclass field defaults mirror env var values
  • TenantPolicyStore.get() returns DEFAULT_POLICY when no file exists
  • TenantPolicyStore.get() returns per-tenant config from JSON file
  • TenantPolicyStore.get() falls back to "default" for unknown tenants
  • TenantPolicyStore.reload() picks up changes written to disk
  • AgentMonitor._check_rapid_block uses policy.rapid_block_threshold
  • AgentMonitor._check_tool_velocity uses policy.velocity_threshold / velocity_window
  • Redis TTL is set from policy.session_ttl (via _r_set_meta / _r_touch_ttl)
  • get_policy() convenience function returns correct policy
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _write_policies(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# TenantPolicy defaults
# ─────────────────────────────────────────────────────────────────────────────

class TestTenantPolicyDefaults:
    def test_defaults_match_env_vars(self, monkeypatch) -> None:
        """TenantPolicy() fields must equal the env-var values so upgrades are safe."""
        monkeypatch.setenv("VELOCITY_THRESHOLD",    "10")
        monkeypatch.setenv("RAPID_BLOCK_THRESHOLD", "3")
        monkeypatch.setenv("AGENT_SESSION_TTL",     "1800")
        monkeypatch.setenv("VELOCITY_WINDOW_SECS",  "60")

        # Re-import to pick up the monkeypatched env
        import importlib

        import warden.tenant_policy as tp
        importlib.reload(tp)

        policy = tp.TenantPolicy()
        assert policy.velocity_threshold    == 10
        assert policy.rapid_block_threshold == 3
        assert policy.session_ttl           == 1800
        assert policy.velocity_window       == 60

    def test_policy_is_frozen(self) -> None:
        """TenantPolicy must be immutable (frozen=True)."""
        from warden.tenant_policy import TenantPolicy
        p = TenantPolicy()
        with pytest.raises((AttributeError, TypeError)):
            p.velocity_threshold = 99  # type: ignore[misc]


# ─────────────────────────────────────────────────────────────────────────────
# TenantPolicyStore — no file
# ─────────────────────────────────────────────────────────────────────────────

class TestTenantPolicyStoreNoFile:
    def test_get_returns_default_policy_when_no_file(self, tmp_path) -> None:
        from warden.tenant_policy import DEFAULT_POLICY, TenantPolicyStore
        store = TenantPolicyStore(path=tmp_path / "nonexistent.json")
        assert store.get("any-tenant") == DEFAULT_POLICY

    def test_get_unknown_tenant_returns_default_policy(self, tmp_path) -> None:
        from warden.tenant_policy import DEFAULT_POLICY, TenantPolicyStore
        store = TenantPolicyStore(path=tmp_path / "nonexistent.json")
        assert store.get("tenant-that-does-not-exist") == DEFAULT_POLICY


# ─────────────────────────────────────────────────────────────────────────────
# TenantPolicyStore — with file
# ─────────────────────────────────────────────────────────────────────────────

class TestTenantPolicyStoreWithFile:
    def test_get_returns_per_tenant_policy(self, tmp_path) -> None:
        """Explicit tenant entry in JSON overrides defaults."""
        p = tmp_path / "policies.json"
        _write_policies(p, {
            "tenant-strict": {
                "velocity_threshold":    5,
                "rapid_block_threshold": 1,
                "session_ttl":           600,
                "velocity_window":       30,
            }
        })
        from warden.tenant_policy import TenantPolicyStore
        store = TenantPolicyStore(path=p)
        policy = store.get("tenant-strict")
        assert policy.velocity_threshold    == 5
        assert policy.rapid_block_threshold == 1
        assert policy.session_ttl           == 600
        assert policy.velocity_window       == 30

    def test_get_falls_back_to_default_entry(self, tmp_path) -> None:
        """Unknown tenant falls back to the 'default' entry in the file."""
        p = tmp_path / "policies.json"
        _write_policies(p, {
            "default": {"rapid_block_threshold": 7},
        })
        from warden.tenant_policy import TenantPolicyStore
        store = TenantPolicyStore(path=p)
        policy = store.get("unknown-tenant")
        assert policy.rapid_block_threshold == 7

    def test_partial_override_merges_with_defaults(self, tmp_path) -> None:
        """Tenant entry with only one key must not wipe out the other defaults."""
        from warden.tenant_policy import DEFAULT_POLICY, TenantPolicyStore
        p = tmp_path / "policies.json"
        _write_policies(p, {
            "tenant-partial": {"rapid_block_threshold": 2},
        })
        store = TenantPolicyStore(path=p)
        policy = store.get("tenant-partial")
        assert policy.rapid_block_threshold == 2
        # All other fields must match defaults
        assert policy.velocity_threshold == DEFAULT_POLICY.velocity_threshold
        assert policy.session_ttl        == DEFAULT_POLICY.session_ttl
        assert policy.velocity_window    == DEFAULT_POLICY.velocity_window

    def test_reload_picks_up_new_values(self, tmp_path) -> None:
        """reload() must update the cache without restarting the store."""
        p = tmp_path / "policies.json"
        _write_policies(p, {"tenant-x": {"rapid_block_threshold": 5}})

        from warden.tenant_policy import TenantPolicyStore
        store = TenantPolicyStore(path=p)
        assert store.get("tenant-x").rapid_block_threshold == 5

        # Update the file and reload
        _write_policies(p, {"tenant-x": {"rapid_block_threshold": 99}})
        store.reload()

        assert store.get("tenant-x").rapid_block_threshold == 99

    def test_invalid_file_keeps_empty_cache(self, tmp_path) -> None:
        """Corrupt JSON must log a warning and not crash; defaults still work."""
        p = tmp_path / "policies.json"
        p.write_text("NOT VALID JSON", encoding="utf-8")

        from warden.tenant_policy import DEFAULT_POLICY, TenantPolicyStore
        store = TenantPolicyStore(path=p)
        # Fallback to DEFAULT_POLICY — no crash
        assert store.get("any") == DEFAULT_POLICY


# ─────────────────────────────────────────────────────────────────────────────
# get_policy() convenience function
# ─────────────────────────────────────────────────────────────────────────────

def test_get_policy_returns_policy_object(tmp_path) -> None:
    from warden.tenant_policy import TenantPolicy, get_policy
    result = get_policy("some-tenant")
    assert isinstance(result, TenantPolicy)


# ─────────────────────────────────────────────────────────────────────────────
# AgentMonitor integration — per-tenant thresholds applied in pattern checks
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def monitor_no_redis(monkeypatch, tmp_path):
    """AgentMonitor with in-memory fallback only."""
    monkeypatch.setenv("ANALYTICS_DATA_PATH", str(tmp_path))
    import warden.agent_monitor as am
    monkeypatch.setattr(am, "SESSIONS_PATH", tmp_path / "sessions.json")
    from warden.agent_monitor import AgentMonitor
    m = AgentMonitor()
    m._redis = None
    return m


class TestAgentMonitorPolicyIntegration:
    def test_rapid_block_respects_custom_threshold(self, monitor_no_redis) -> None:
        """rapid_block_threshold=1 ⇒ first block triggers RAPID_BLOCK threat."""
        from warden.agent_monitor import PATTERN_RAPID_BLOCK
        from warden.tenant_policy import TenantPolicy

        low_policy = TenantPolicy(rapid_block_threshold=1)
        meta  = {"block_count": 1, "threats_detected": []}
        threat = monitor_no_redis._check_rapid_block(meta, [], low_policy)
        assert threat is not None
        assert threat.pattern == PATTERN_RAPID_BLOCK

    def test_rapid_block_no_trigger_below_custom_threshold(self, monitor_no_redis) -> None:
        """block_count below threshold must not fire RAPID_BLOCK."""
        from warden.tenant_policy import TenantPolicy

        high_policy = TenantPolicy(rapid_block_threshold=10)
        meta  = {"block_count": 3, "threats_detected": []}
        threat = monitor_no_redis._check_rapid_block(meta, [], high_policy)
        assert threat is None

    def test_tool_velocity_respects_custom_threshold(self, monitor_no_redis) -> None:
        """velocity_threshold=2 ⇒ 3 tool calls within the window fires TOOL_VELOCITY."""
        from warden.agent_monitor import PATTERN_TOOL_VELOCITY
        from warden.tenant_policy import TenantPolicy

        # 3 tool-call events, all right now
        now_iso = datetime.now(UTC).isoformat()
        events = [
            {"event_type": "tool", "direction": "call", "ts": now_iso}
            for _ in range(3)
        ]
        policy = TenantPolicy(velocity_threshold=2, velocity_window=60)
        threat = monitor_no_redis._check_tool_velocity({}, events, policy)
        assert threat is not None
        assert threat.pattern == PATTERN_TOOL_VELOCITY

    def test_tool_velocity_no_trigger_below_custom_threshold(self, monitor_no_redis) -> None:
        """3 tool calls with threshold=5 must not fire."""
        from warden.tenant_policy import TenantPolicy

        now_iso = datetime.now(UTC).isoformat()
        events = [
            {"event_type": "tool", "direction": "call", "ts": now_iso}
            for _ in range(3)
        ]
        policy = TenantPolicy(velocity_threshold=5, velocity_window=60)
        threat = monitor_no_redis._check_tool_velocity({}, events, policy)
        assert threat is None

    def test_record_request_uses_policy_ttl_for_redis(self, tmp_path, monkeypatch) -> None:
        """record_request must pass policy.session_ttl to _r_set_meta."""
        import warden.agent_monitor as am
        monkeypatch.setenv("ANALYTICS_DATA_PATH", str(tmp_path))
        monkeypatch.setattr(am, "SESSIONS_PATH", tmp_path / "sessions.json")

        from warden.agent_monitor import AgentMonitor
        from warden.tenant_policy import TenantPolicy

        m = AgentMonitor()
        m._redis = None  # force in-memory fallback

        custom_policy = TenantPolicy(session_ttl=300)

        # Patch get_policy to return our custom policy
        monkeypatch.setattr(am, "get_policy", lambda _tid: custom_policy)

        # Spy on _r_set_meta to capture the ttl argument
        calls: list[int] = []
        original = m._r_set_meta
        def spy_set_meta(session_id, meta, ttl=am.SESSION_TTL_SECONDS):
            calls.append(ttl)
            return original(session_id, meta, ttl)
        m._r_set_meta = spy_set_meta  # type: ignore[method-assign]

        m.record_request("sess-ttl", "req-1", True, "low", [], "tenant-ttl")

        assert calls, "expected _r_set_meta to be called"
        assert calls[0] == 300, f"expected ttl=300 but got {calls[0]}"
