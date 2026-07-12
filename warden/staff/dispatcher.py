"""
Boundary-aware tool dispatcher — wraps traced_dispatch with STAFF-01 checks.

Call order:
  1. BoundaryRegistry.check_and_dispatch()  → BoundaryViolationError if denied
  2. VelocityGuard.record_and_check()       → VelocityAlert logged, never blocks
  3. traced_dispatch()                       → actual tool execution + OTel span
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from warden.staff.boundaries import BoundaryRegistry, get_registry
from warden.staff.velocity import VelocityGuard

log = logging.getLogger(__name__)


async def staff_dispatch(
    agent_id: str,
    tool_name: str,
    tool_input: dict[str, Any],
    registry: BoundaryRegistry | None = None,
    redis=None,
) -> Any:
    reg = registry or get_registry(redis=redis)
    boundary = reg.check_and_dispatch(agent_id, tool_name)

    vg = VelocityGuard(redis=redis)
    alert = vg.record_and_check(
        agent_id,
        tool_name,
        tool_input,
        max_per_hour=boundary.max_calls_per_hour,
        loop_window_s=boundary.loop_detection_window_s,
        loop_max=boundary.loop_detection_max,
    )
    if alert:
        log.warning(
            "STAFF velocity alert: agent=%s kind=%s tool=%s count=%d window=%ds",
            alert.agent_id, alert.kind, alert.tool_name, alert.count, alert.window_s,
        )

    # GSAM drift quarantine — ADDITIVE gate (runs after the boundary check, so it
    # can only strengthen STAFF-01/02, never bypass them). Fail-open.
    try:
        from warden.gsam.quarantine import is_quarantined  # noqa: PLC0415
        if is_quarantined(agent_id, redis=redis):
            log.warning("STAFF dispatch blocked: agent=%s is GSAM-quarantined (drift)", agent_id)
            return {"error": "agent_quarantined", "reason": "GSAM drift quarantine active",
                    "agent_id": agent_id}
    except Exception as exc:  # noqa: BLE001 — quarantine gate must not brick dispatch
        log.debug("GSAM quarantine gate fail-open: %s", exc)

    # Delegate to the real dispatch (SOVA tools + staff tools)
    from warden.agent.tools import traced_dispatch
    from warden.staff.tools import STAFF_TOOL_HANDLERS

    if tool_name in STAFF_TOOL_HANDLERS:
        # SOVA tools screen inside traced_dispatch; staff-native tools screen
        # here so they too appear in GSAM and are SSRF-checked (fail-CLOSED
        # block, fail-OPEN telemetry).
        try:
            from warden.sac.guard import screen_and_emit
            tenant_id = str(tool_input.get("tenant_id", "default"))
            verdict = screen_and_emit(agent_id, tenant_id, tool_name, tool_input)
            if verdict.blocked:
                return {"error": "blocked_by_sac_guard", "reason": verdict.reason,
                        "sac_verdict": verdict.verdict}
        except Exception as exc:  # guard must not brick dispatch
            from warden.observability import Reason, record_failopen
            record_failopen("sac_guard", Reason.BACKEND_ERROR, exc)

        handler: Callable[..., Any] = STAFF_TOOL_HANDLERS[tool_name]  # type: ignore[assignment]
        return await handler(**tool_input)

    return await traced_dispatch(tool_name, tool_input)
