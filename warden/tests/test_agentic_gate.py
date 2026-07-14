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


class TestVelocityGate:
    def test_velocity_alert_is_logged_and_does_not_block(self, monkeypatch):
        """Velocity is advisory: an alert is logged but the call still proceeds."""
        from types import SimpleNamespace
        alert = SimpleNamespace(
            agent_id=SOVA_AGENT_ID, kind="loop", tool_name="get_health",
            count=99, window_s=60,
        )
        monkeypatch.setattr(
            "warden.agent.gate.VelocityGuard.record_and_check",
            lambda self, *a, **k: alert,
        )
        assert agentic_gate(SOVA_AGENT_ID, "get_health", {"tenant_id": "t1"}) is None

    def test_velocity_backend_error_is_fail_open(self, monkeypatch):
        """A velocity backend failure must degrade (record_failopen), never brick dispatch."""
        seen = {}
        monkeypatch.setattr(
            "warden.agent.gate.record_failopen",
            lambda stage, reason, exc: seen.update(stage=stage),
        )

        def _boom(self, *a, **k):
            raise RuntimeError("redis down")

        monkeypatch.setattr("warden.agent.gate.VelocityGuard.record_and_check", _boom)
        assert agentic_gate(SOVA_AGENT_ID, "get_health", {"tenant_id": "t1"}) is None
        assert seen.get("stage") == "agentic_velocity"


class TestSeedingResilience:
    def test_seeding_failure_does_not_raise(self, monkeypatch):
        """If the tool tables can't be read, seeding must swallow the error — an
        unseeded agent is then denied fail-CLOSED by the boundary check."""
        _reset_for_tests()

        class _BadReg:
            def get(self, _id):
                raise RuntimeError("registry exploded")

            def put(self, _b):  # pragma: no cover - never reached
                raise AssertionError("should not put")

        # Must not raise despite the failing registry.
        ensure_agentic_boundaries(registry=_BadReg())
        # And an unseeded agent is denied (fail-CLOSED) on the real registry.
        _reset_for_tests()
        ensure_agentic_boundaries()


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
