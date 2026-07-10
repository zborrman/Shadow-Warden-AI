"""
Additive GSAM quarantine gate in staff_dispatch.

The gate runs AFTER the boundary check (so STAFF-01/02 are never weakened) and
blocks a quarantined agent before tool execution. Fail-open on guard error.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from warden.staff import dispatcher


class _FakeRegistry:
    """Minimal stand-in — passes the boundary check for any agent/tool."""

    def check_and_dispatch(self, agent_id, tool_name):
        return SimpleNamespace(
            max_calls_per_hour=1000, loop_detection_window_s=60, loop_detection_max=5,
        )


@pytest.mark.asyncio
async def test_quarantined_agent_blocked(monkeypatch):
    monkeypatch.setattr("warden.gsam.quarantine.is_quarantined", lambda a, redis=None: True)
    out = await dispatcher.staff_dispatch(
        "bdr-agent", "some_tool", {"tenant_id": "t"}, registry=_FakeRegistry(),
    )
    assert out["error"] == "agent_quarantined"


@pytest.mark.asyncio
async def test_healthy_agent_not_blocked_by_gate(monkeypatch):
    monkeypatch.setattr("warden.gsam.quarantine.is_quarantined", lambda a, redis=None: False)

    async def _async_handler(**kw):
        return {"ok": True}

    # Route to a stub staff handler so we confirm the gate passed through.
    monkeypatch.setattr(
        "warden.staff.tools.STAFF_TOOL_HANDLERS", {"some_tool": _async_handler}
    )
    out = await dispatcher.staff_dispatch(
        "bdr-agent", "some_tool", {"tenant_id": "t"}, registry=_FakeRegistry(),
    )
    assert out == {"ok": True}


@pytest.mark.asyncio
async def test_gate_fail_open(monkeypatch):
    def _boom(a, redis=None):
        raise RuntimeError("redis down")

    monkeypatch.setattr("warden.gsam.quarantine.is_quarantined", _boom)

    async def _async_handler(**kw):
        return {"ok": True}

    monkeypatch.setattr(
        "warden.staff.tools.STAFF_TOOL_HANDLERS", {"some_tool": _async_handler}
    )
    # Gate raising must not block dispatch (fail-open).
    out = await dispatcher.staff_dispatch(
        "bdr-agent", "some_tool", {"tenant_id": "t"}, registry=_FakeRegistry(),
    )
    assert out == {"ok": True}
