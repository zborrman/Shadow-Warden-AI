"""
Boundary-aware dispatcher (warden/staff/dispatcher.py) — branch coverage for
the paths not already exercised by test_gsam_quarantine_gate.py:

  * velocity alert logging (does not block dispatch);
  * SAC guard blocked verdict (fail-CLOSED — dispatch short-circuits);
  * SAC guard raising (fail-OPEN — dispatch proceeds);
  * delegation to traced_dispatch() for non-staff (SOVA) tool names.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from warden.staff import dispatcher
from warden.staff.velocity import VelocityAlert


class _FakeRegistry:
    """Minimal stand-in — passes the boundary check for any agent/tool."""

    def check_and_dispatch(self, agent_id, tool_name):
        return SimpleNamespace(
            max_calls_per_hour=1000, loop_detection_window_s=60, loop_detection_max=5,
        )


@pytest.fixture(autouse=True)
def _quarantine_off(monkeypatch):
    monkeypatch.setattr("warden.gsam.quarantine.is_quarantined", lambda a, redis=None: False)


@pytest.mark.asyncio
async def test_velocity_alert_logged_but_does_not_block(monkeypatch, caplog):
    alert = VelocityAlert(
        agent_id="bdr-agent", kind="rate_exceeded", detail="too fast",
        tool_name="some_tool", count=999, window_s=3600,
    )
    monkeypatch.setattr(
        "warden.staff.velocity.VelocityGuard.record_and_check",
        lambda self, *a, **kw: alert,
    )

    async def _async_handler(**kw):
        return {"ok": True}

    monkeypatch.setattr("warden.staff.tools.STAFF_TOOL_HANDLERS", {"some_tool": _async_handler})

    with caplog.at_level("WARNING"):
        out = await dispatcher.staff_dispatch(
            "bdr-agent", "some_tool", {"tenant_id": "t"}, registry=_FakeRegistry(),
        )
    assert out == {"ok": True}
    assert any("velocity alert" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_sac_guard_blocked_short_circuits_dispatch(monkeypatch):
    verdict = SimpleNamespace(blocked=True, reason="ssrf blocked", verdict="COMPROMISED")
    monkeypatch.setattr("warden.sac.guard.screen_and_emit", lambda *a, **kw: verdict)

    called = {"handler_ran": False}

    async def _async_handler(**kw):
        called["handler_ran"] = True
        return {"ok": True}

    monkeypatch.setattr("warden.staff.tools.STAFF_TOOL_HANDLERS", {"some_tool": _async_handler})

    out = await dispatcher.staff_dispatch(
        "bdr-agent", "some_tool", {"tenant_id": "t"}, registry=_FakeRegistry(),
    )
    assert out == {
        "error": "blocked_by_sac_guard", "reason": "ssrf blocked", "sac_verdict": "COMPROMISED",
    }
    assert called["handler_ran"] is False


@pytest.mark.asyncio
async def test_sac_guard_error_fails_open(monkeypatch):
    def _boom(*a, **kw):
        raise RuntimeError("gsam backend down")

    monkeypatch.setattr("warden.sac.guard.screen_and_emit", _boom)

    async def _async_handler(**kw):
        return {"ok": True}

    monkeypatch.setattr("warden.staff.tools.STAFF_TOOL_HANDLERS", {"some_tool": _async_handler})

    # Guard raising must not block dispatch — telemetry/screening is fail-OPEN.
    out = await dispatcher.staff_dispatch(
        "bdr-agent", "some_tool", {"tenant_id": "t"}, registry=_FakeRegistry(),
    )
    assert out == {"ok": True}


@pytest.mark.asyncio
async def test_non_staff_tool_delegates_to_traced_dispatch(monkeypatch):
    # "some_sova_tool" is not in STAFF_TOOL_HANDLERS → falls through to the
    # already_gated traced_dispatch() delegate (line 82).
    captured = {}

    async def _fake_traced_dispatch(tool_name, tool_input, agent_id, already_gated=False):
        captured["tool_name"] = tool_name
        captured["tool_input"] = tool_input
        captured["agent_id"] = agent_id
        captured["already_gated"] = already_gated
        return {"result": "delegated"}

    monkeypatch.setattr("warden.agent.tools.traced_dispatch", _fake_traced_dispatch)
    monkeypatch.setattr("warden.staff.tools.STAFF_TOOL_HANDLERS", {})

    out = await dispatcher.staff_dispatch(
        "sova", "some_sova_tool", {"tenant_id": "t"}, registry=_FakeRegistry(),
    )
    assert out == {"result": "delegated"}
    assert captured == {
        "tool_name": "some_sova_tool", "tool_input": {"tenant_id": "t"},
        "agent_id": "sova", "already_gated": True,
    }
