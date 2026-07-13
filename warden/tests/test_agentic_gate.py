"""
Phase 7 — one boundary + velocity + quarantine gate for every agentic tool call.

Before this, only Digital Staff passed BoundaryRegistry/VelocityGuard/quarantine.
SOVA reached traced_dispatch with only the SAC guard, and MasterAgent bypassed
traced_dispatch entirely (calling TOOL_HANDLERS directly) — so its sub-agents had no
SSRF screen, no boundary, no velocity limit and no quarantine. `_AGENT_TOOLS` only
filtered which tools were *offered* to the model, so a sub-agent that named a tool
outside its own subset still executed it. These tests pin that shut.
"""
from __future__ import annotations

import pytest

from warden.agent.gate import (
    SOVA_AGENT_ID,
    _reset_for_tests,
    agentic_gate,
    ensure_agentic_boundaries,
    master_agent_id,
)
from warden.staff.boundaries import get_registry


@pytest.fixture(autouse=True)
def _seeded():
    _reset_for_tests()
    ensure_agentic_boundaries()
    yield
    _reset_for_tests()


class TestSeeding:
    def test_sova_boundary_covers_all_tools(self):
        from warden.agent import tools as t
        b = get_registry().get(SOVA_AGENT_ID)
        assert b is not None
        assert b.allowed_tools == frozenset(t.TOOL_HANDLERS.keys())

    def test_each_sub_agent_gets_exactly_its_subset(self):
        from warden.agent.master import _AGENT_TOOLS
        reg = get_registry()
        for sub, tool_list in _AGENT_TOOLS.items():
            b = reg.get(master_agent_id(str(sub.value)))
            assert b is not None, f"no boundary for {sub}"
            assert b.allowed_tools == frozenset(tool_list)

    def test_seeding_is_idempotent(self):
        ensure_agentic_boundaries()
        ensure_agentic_boundaries()
        assert get_registry().get(SOVA_AGENT_ID) is not None


class TestBoundaryEnforcement:
    def test_sub_agent_denied_tool_outside_its_subset(self):
        """THE escalation: _AGENT_TOOLS was advisory; the boundary now enforces it."""
        from warden.agent import tools as t
        from warden.agent.master import _AGENT_TOOLS, SubAgent

        hunter = master_agent_id(str(SubAgent.THREAT_HUNTER.value))
        own = set(_AGENT_TOOLS[SubAgent.THREAT_HUNTER])
        foreign = next(name for name in t.TOOL_HANDLERS if name not in own)

        denied = agentic_gate(hunter, foreign, {"tenant_id": "t1"})
        assert denied is not None
        assert denied["error"] == "boundary_violation"

    def test_sub_agent_allowed_its_own_tool(self):
        from warden.agent.master import _AGENT_TOOLS, SubAgent

        hunter = master_agent_id(str(SubAgent.THREAT_HUNTER.value))
        own = _AGENT_TOOLS[SubAgent.THREAT_HUNTER][0]
        assert agentic_gate(hunter, own, {"tenant_id": "t1"}) is None

    def test_sova_allowed_any_registered_tool(self):
        from warden.agent import tools as t
        any_tool = next(iter(t.TOOL_HANDLERS))
        assert agentic_gate(SOVA_AGENT_ID, any_tool, {"tenant_id": "t1"}) is None

    def test_unknown_agent_is_denied_fail_closed(self):
        denied = agentic_gate("not-a-real-agent", "get_health", {"tenant_id": "t1"})
        assert denied is not None
        assert denied["error"] == "boundary_violation"

    def test_suspended_agent_is_denied(self):
        reg = get_registry()
        reg.suspend(SOVA_AGENT_ID)
        try:
            denied = agentic_gate(SOVA_AGENT_ID, "get_health", {"tenant_id": "t1"})
            assert denied is not None
            assert denied["error"] == "boundary_violation"
        finally:
            _reset_for_tests()
            reg._local.pop(SOVA_AGENT_ID, None)
            ensure_agentic_boundaries()


class TestQuarantineIsAdditive:
    def test_quarantined_agent_blocked_after_boundary_pass(self, monkeypatch):
        """Quarantine runs AFTER the boundary, so it can only strengthen the verdict."""
        monkeypatch.setattr(
            "warden.gsam.quarantine.is_quarantined", lambda agent_id, redis=None: True
        )
        denied = agentic_gate(SOVA_AGENT_ID, "get_health", {"tenant_id": "t1"})
        assert denied is not None
        assert denied["error"] == "agent_quarantined"

    def test_quarantine_failure_is_fail_open(self, monkeypatch):
        def _boom(agent_id, redis=None):
            raise RuntimeError("redis down")
        monkeypatch.setattr("warden.gsam.quarantine.is_quarantined", _boom)
        # Quarantine backend down must not brick a legitimate call.
        assert agentic_gate(SOVA_AGENT_ID, "get_health", {"tenant_id": "t1"}) is None


class TestStaffNotDoubleGated:
    @pytest.mark.asyncio
    async def test_traced_dispatch_skips_gate_when_already_gated(self, monkeypatch):
        """staff_dispatch already ran the checks; re-running would double-count velocity."""
        calls = []
        monkeypatch.setattr(
            "warden.agent.gate.agentic_gate",
            lambda *a, **k: calls.append(a) or None,
        )
        from warden.agent import tools as t

        async def _fake(**kw):
            return {"ok": True}

        monkeypatch.setitem(t.TOOL_HANDLERS, "get_health", _fake)
        await t.traced_dispatch("get_health", {"tenant_id": "t1"}, "bdr", already_gated=True)
        assert calls == []
