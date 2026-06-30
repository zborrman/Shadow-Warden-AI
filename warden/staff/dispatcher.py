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

    # Delegate to the real dispatch (SOVA tools + staff tools)
    from warden.agent.tools import traced_dispatch  # noqa: PLC0415
    from warden.staff.tools import STAFF_TOOL_HANDLERS  # noqa: PLC0415

    if tool_name in STAFF_TOOL_HANDLERS:
        handler: Callable[..., Any] = STAFF_TOOL_HANDLERS[tool_name]  # type: ignore[assignment]
        return await handler(**tool_input)

    return await traced_dispatch(tool_name, tool_input)
