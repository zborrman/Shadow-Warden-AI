"""
warden/tests/test_agent_sandbox.py
───────────────────────────────────
Unit tests for Zero-Trust Agent Sandbox (v1.7 Step 1).

Covers:
  - No manifest → skip (non-strict) or deny (strict)
  - Unknown agent_id → deny
  - Tool not in capabilities → deny
  - Disallowed param → deny
  - Session quota exceeded → deny
  - Network egress blocked → deny
  - Happy path → allow
  - required_approval flag passes through
  - ToolCallGuard integration (sandbox check before regex)
"""
from __future__ import annotations

import os
import pytest

from warden.agent_sandbox import (
    AgentManifest,
    SandboxRegistry,
    ToolCapability,
    get_registry,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_registry(*caps: ToolCapability, egress: bool = False) -> SandboxRegistry:
    reg = SandboxRegistry()
    reg.register(AgentManifest(
        agent_id="test-agent",
        description="test",
        capabilities=list(caps),
        network_egress_allowed=egress,
    ))
    return reg


# ── No manifest configured ────────────────────────────────────────────────────

def test_no_manifests_non_strict_allows():
    reg = SandboxRegistry()
    dec = reg.authorize_tool_call("any-agent", "any_tool", {}, "sess1")
    assert dec.allowed
    assert dec.reason == "sandbox_not_configured"


def test_no_manifests_strict_denies(monkeypatch):
    monkeypatch.setattr("warden.agent_sandbox._STRICT", True)
    reg = SandboxRegistry()
    dec = reg.authorize_tool_call("any-agent", "any_tool", {}, "sess1")
    assert not dec.allowed
    assert dec.reason == "no_manifest_file_strict"


# ── Unknown agent ─────────────────────────────────────────────────────────────

def test_unknown_agent_denied():
    reg = _make_registry(ToolCapability(tool_name="query_db"))
    dec = reg.authorize_tool_call("ghost-agent", "query_db", {}, "sess1")
    assert not dec.allowed
    assert dec.reason == "no_manifest"


# ── Tool not in capabilities ──────────────────────────────────────────────────

def test_unlisted_tool_denied():
    reg = _make_registry(ToolCapability(tool_name="query_db"))
    dec = reg.authorize_tool_call("test-agent", "send_email", {}, "sess1")
    assert not dec.allowed
    assert dec.reason == "tool_not_allowed"


# ── Parameter allow-list ──────────────────────────────────────────────────────

def test_allowed_params_pass():
    cap = ToolCapability(tool_name="query_db", allowed_params=["query", "database"])
    reg = _make_registry(cap)
    dec = reg.authorize_tool_call("test-agent", "query_db", {"query": "SELECT 1", "database": "prod"}, "sess1")
    assert dec.allowed


def test_disallowed_param_denied():
    cap = ToolCapability(tool_name="query_db", allowed_params=["query"])
    reg = _make_registry(cap)
    dec = reg.authorize_tool_call("test-agent", "query_db", {"query": "SELECT 1", "execute": True}, "sess1")
    assert not dec.allowed
    assert "param_not_allowed" in dec.reason
    assert "execute" in dec.reason


def test_empty_allowed_params_permits_any():
    cap = ToolCapability(tool_name="query_db", allowed_params=[])
    reg = _make_registry(cap)
    dec = reg.authorize_tool_call("test-agent", "query_db", {"anything": "goes"}, "sess1")
    assert dec.allowed


# ── Session quota (Redis-free — Redis unavailable returns 0, so quota check
#    relies on _get_call_count returning 0 when Redis is down) ─────────────────

def test_quota_zero_means_unlimited():
    cap = ToolCapability(tool_name="query_db", max_calls_per_session=0)
    reg = _make_registry(cap)
    # Should allow even without Redis (quota=0 → unlimited branch)
    dec = reg.authorize_tool_call("test-agent", "query_db", {}, "sess1")
    assert dec.allowed
    assert dec.calls_remaining == -1


def test_quota_exceeded_denied(monkeypatch):
    cap = ToolCapability(tool_name="query_db", max_calls_per_session=3)
    reg = _make_registry(cap)

    # Mock _get_call_count to simulate 3 previous calls
    monkeypatch.setattr(reg, "_get_call_count", lambda *_: 3)
    monkeypatch.setattr(reg, "_incr_call_count", lambda *_: None)

    dec = reg.authorize_tool_call("test-agent", "query_db", {}, "sess-x")
    assert not dec.allowed
    assert "quota_exceeded" in dec.reason


def test_quota_not_reached_allows(monkeypatch):
    cap = ToolCapability(tool_name="query_db", max_calls_per_session=5)
    reg = _make_registry(cap)

    monkeypatch.setattr(reg, "_get_call_count", lambda *_: 2)
    monkeypatch.setattr(reg, "_incr_call_count", lambda *_: None)

    dec = reg.authorize_tool_call("test-agent", "query_db", {}, "sess-y")
    assert dec.allowed
    assert dec.calls_remaining == 3


# ── Network egress check ──────────────────────────────────────────────────────

def test_network_egress_blocked():
    cap = ToolCapability(tool_name="http_post")
    reg = _make_registry(cap, egress=False)
    dec = reg.authorize_tool_call("test-agent", "http_post", {}, "sess1")
    assert not dec.allowed
    assert dec.reason == "network_egress_denied"


def test_network_egress_allowed_when_flag_set():
    cap = ToolCapability(tool_name="http_post")
    reg = _make_registry(cap, egress=True)
    dec = reg.authorize_tool_call("test-agent", "http_post", {}, "sess1")
    assert dec.allowed


def test_non_network_tool_passes_without_egress():
    cap = ToolCapability(tool_name="query_db")
    reg = _make_registry(cap, egress=False)
    dec = reg.authorize_tool_call("test-agent", "query_db", {}, "sess1")
    assert dec.allowed


# ── required_approval flag ────────────────────────────────────────────────────

def test_required_approval_still_allows():
    cap = ToolCapability(tool_name="delete_record", required_approval=True)
    reg = _make_registry(cap)
    dec = reg.authorize_tool_call("test-agent", "delete_record", {}, "sess1")
    assert dec.allowed
    assert dec.requires_approval is True


# ── list_agents / get_manifest ────────────────────────────────────────────────

def test_list_agents():
    reg = _make_registry(ToolCapability(tool_name="query_db"))
    agents = reg.list_agents()
    assert len(agents) == 1
    assert agents[0]["agent_id"] == "test-agent"
    assert "query_db" in agents[0]["tools"]


def test_get_manifest_returns_none_for_unknown():
    reg = _make_registry(ToolCapability(tool_name="query_db"))
    assert reg.get_manifest("no-such-agent") is None


def test_get_manifest_returns_for_known():
    reg = _make_registry(ToolCapability(tool_name="query_db"))
    m = reg.get_manifest("test-agent")
    assert m is not None
    assert m.agent_id == "test-agent"


# ── JSON file loader ──────────────────────────────────────────────────────────

def test_load_from_file(tmp_path):
    manifest_file = tmp_path / "manifests.json"
    manifest_file.write_text("""{
        "manifests": [
            {
                "agent_id": "loader-agent",
                "description": "loaded from file",
                "capabilities": [
                    {"tool_name": "read_file", "allowed_params": ["path"], "max_calls_per_session": 10}
                ],
                "network_egress_allowed": false
            }
        ]
    }""")
    reg = SandboxRegistry()
    count = reg.load_from_file(str(manifest_file))
    assert count == 1
    m = reg.get_manifest("loader-agent")
    assert m is not None
    assert m.capabilities[0].tool_name == "read_file"
    assert m.capabilities[0].max_calls_per_session == 10


def test_load_from_missing_file_non_strict():
    reg = SandboxRegistry()
    count = reg.load_from_file("/tmp/nonexistent_manifests_12345.json")
    assert count == 0
    # non-strict: no manifest → sandbox_not_configured
    dec = reg.authorize_tool_call("x", "y", {}, "s")
    assert dec.allowed


# ── ToolCallGuard integration ─────────────────────────────────────────────────

def test_tool_guard_sandbox_deny_before_regex():
    from warden.tool_guard import ToolCallGuard

    cap = ToolCapability(tool_name="query_db", allowed_params=["query"])
    reg = _make_registry(cap)

    guard = ToolCallGuard(sandbox=reg)
    # Disallowed param — should be caught by sandbox, not regex
    result = guard.inspect_call(
        "query_db",
        {"query": "SELECT 1", "evil_param": "rm -rf /"},
        agent_id="test-agent",
        session_id="sess1",
    )
    assert result.blocked
    assert result.threats[0].kind == "sandbox_violation"


def test_tool_guard_sandbox_allow_then_regex_catches():
    from warden.tool_guard import ToolCallGuard

    cap = ToolCapability(tool_name="bash_exec", allowed_params=["command"])
    reg = _make_registry(cap)

    guard = ToolCallGuard(sandbox=reg)
    # Sandbox allows (param in allow-list), but regex catches shell destruction
    result = guard.inspect_call(
        "bash_exec",
        {"command": "rm -rf /tmp/workdir"},
        agent_id="test-agent",
        session_id="sess1",
    )
    assert result.blocked
    assert result.threats[0].kind == "shell_destruction"


def test_tool_guard_no_agent_id_skips_sandbox():
    from warden.tool_guard import ToolCallGuard

    reg = _make_registry(ToolCapability(tool_name="query_db"))
    guard = ToolCallGuard(sandbox=reg)

    # No agent_id → sandbox skipped, clean args → allowed
    result = guard.inspect_call("query_db", {"query": "SELECT 1"})
    assert result.allowed


def test_tool_guard_no_sandbox_still_works():
    from warden.tool_guard import ToolCallGuard

    guard = ToolCallGuard()
    result = guard.inspect_call("query_db", {"query": "SELECT 1"}, agent_id="x")
    assert result.allowed
