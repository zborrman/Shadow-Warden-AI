"""
warden/agent/gate.py
─────────────────────
One gate for every agentic tool call (Phase 7, runtime isolation).

Before this, only Digital Staff went through `BoundaryRegistry` + `VelocityGuard` +
GSAM quarantine (`staff/dispatcher.py`). SOVA reached `traced_dispatch` with only the
SAC guard, and **MasterAgent bypassed `traced_dispatch` entirely** — its sub-agents
called `TOOL_HANDLERS[name]` directly, so they had no SSRF screen, no boundary, no
velocity limit, no quarantine and no span. `_AGENT_TOOLS` only filtered which tools were
*offered* to the model; a sub-agent that named a tool outside its subset still ran it.

This module closes that: `agentic_gate()` applies the same three checks staff get, and
`traced_dispatch` calls it for every non-staff caller.

Order (identical to staff_dispatch, so the guarantees are the same):
  1. BoundaryRegistry.check_and_dispatch()  → deny tools outside the agent's subset
  2. VelocityGuard.record_and_check()       → rate/loop alert (logs, never blocks)
  3. GSAM drift quarantine                  → additive block

The boundary check is fail-CLOSED (an unknown agent or an out-of-subset tool is denied).
The two advisory checks degrade rather than brick dispatch when their backend is down,
and every such degradation emits a ``record_failopen`` counter (FAILOPEN-01).

Boundaries for the agentic operators are seeded from the authoritative sources — SOVA
gets every tool in `TOOL_HANDLERS`, each MasterAgent sub-agent gets exactly its
`_AGENT_TOOLS` subset — so least privilege is *enforced*, not merely advertised.
"""
from __future__ import annotations

import logging
import threading
from decimal import Decimal
from typing import Any

from warden.observability import Reason, record_failopen
from warden.staff.boundaries import (
    AgentRole,
    AuthorizationBoundary,
    BoundaryRegistry,
    BoundaryViolationError,
    get_registry,
)
from warden.staff.velocity import VelocityGuard

log = logging.getLogger("warden.agent.gate")

SOVA_AGENT_ID = "sova"

#: MasterAgent sub-agent id → role. Ids are namespaced so a compromised sub-agent
#: can never be mistaken for a Digital Staff agent (or vice versa).
_MASTER_ROLES: dict[str, AgentRole] = {
    "sova_operator": AgentRole.SOVA_OPERATOR,
    "threat_hunter": AgentRole.THREAT_HUNTER,
    "forensics":     AgentRole.FORENSICS,
    "compliance":    AgentRole.COMPLIANCE,
    "data_privacy":  AgentRole.DATA_PRIVACY,
}

_seed_lock = threading.Lock()
_seeded = False


def master_agent_id(sub_agent: str) -> str:
    """Boundary id for a MasterAgent sub-agent (namespaced, never a staff id)."""
    return f"master:{sub_agent}"


def ensure_agentic_boundaries(registry: BoundaryRegistry | None = None, redis=None) -> None:
    """
    Seed boundaries for SOVA + the MasterAgent sub-agents. Idempotent; safe to call
    on every dispatch (a module-level flag short-circuits after the first run).

    Seeded from the live tool tables, so adding a tool to `_AGENT_TOOLS` automatically
    widens that sub-agent's boundary and nothing else's.
    """
    global _seeded
    if _seeded:
        return
    with _seed_lock:
        if _seeded:
            return
        reg = registry or get_registry(redis=redis)
        try:
            from warden.agent import tools as _tools  # noqa: PLC0415

            all_tools = frozenset(_tools.TOOL_HANDLERS.keys())
            if reg.get(SOVA_AGENT_ID) is None:
                reg.put(AuthorizationBoundary(
                    agent_id=SOVA_AGENT_ID,
                    role=AgentRole.SOVA,
                    allowed_tools=all_tools,
                    autonomy_level=2,
                    refund_cap_usd=Decimal("0"),   # SOVA never issues refunds
                    max_calls_per_hour=500,
                ))

            from warden.agent.master import _AGENT_TOOLS  # noqa: PLC0415

            for sub, tool_list in _AGENT_TOOLS.items():
                sub_id = master_agent_id(str(sub.value))
                if reg.get(sub_id) is not None:
                    continue
                reg.put(AuthorizationBoundary(
                    agent_id=sub_id,
                    role=_MASTER_ROLES.get(str(sub.value), AgentRole.SOVA_OPERATOR),
                    allowed_tools=frozenset(tool_list),   # least privilege, enforced
                    autonomy_level=2,
                    refund_cap_usd=Decimal("0"),
                    max_calls_per_hour=300,
                ))
            _seeded = True
            log.info("agentic boundaries seeded (sova + %d master sub-agents)", len(_AGENT_TOOLS))
        except Exception as exc:  # noqa: BLE001
            # Seeding must not brick the agent. An unseeded agent_id is denied by
            # check_and_dispatch below (fail-CLOSED), which is the safe direction.
            log.warning("agentic boundary seeding failed: %s", exc)


def agentic_gate(
    agent_id: str,
    tool_name: str,
    tool_input: dict[str, Any],
    redis=None,
) -> dict | None:
    """
    Apply boundary + velocity + quarantine to one agentic tool call.

    Returns ``None`` when the call may proceed, or an error dict to return to the
    agent when it is denied. Never raises.
    """
    ensure_agentic_boundaries(redis=redis)
    reg = get_registry(redis=redis)

    # 1 ── Boundary (fail-CLOSED: unknown agent or out-of-subset tool is denied)
    try:
        boundary = reg.check_and_dispatch(agent_id, tool_name)
    except BoundaryViolationError as exc:
        log.warning("agentic boundary DENY: agent=%s tool=%s — %s", agent_id, tool_name, exc)
        return {"error": "boundary_violation", "reason": str(exc),
                "agent_id": agent_id, "tool": tool_name}

    # 2 ── Velocity (alerts, never blocks — matches staff semantics)
    try:
        alert = VelocityGuard(redis=redis).record_and_check(
            agent_id,
            tool_name,
            tool_input,
            max_per_hour=boundary.max_calls_per_hour,
            loop_window_s=boundary.loop_detection_window_s,
            loop_max=boundary.loop_detection_max,
        )
        if alert:
            log.warning(
                "agentic velocity alert: agent=%s kind=%s tool=%s count=%d window=%ds",
                alert.agent_id, alert.kind, alert.tool_name, alert.count, alert.window_s,
            )
    except Exception as exc:  # noqa: BLE001 — velocity is advisory, never bricks dispatch
        log.debug("agentic velocity gate degraded: %s", exc)
        record_failopen("agentic_velocity", Reason.BACKEND_ERROR, exc)

    # 3 ── GSAM drift quarantine (additive: runs AFTER the boundary, so it can only
    #      strengthen the decision, never bypass it).
    try:
        from warden.gsam.quarantine import is_quarantined  # noqa: PLC0415
        if is_quarantined(agent_id, redis=redis):
            log.warning("agentic dispatch blocked: agent=%s is GSAM-quarantined", agent_id)
            return {"error": "agent_quarantined", "reason": "GSAM drift quarantine active",
                    "agent_id": agent_id}
    except Exception as exc:  # noqa: BLE001
        log.debug("GSAM quarantine gate degraded: %s", exc)
        record_failopen("agentic_quarantine", Reason.BACKEND_ERROR, exc)

    return None


def _reset_for_tests() -> None:
    """Clear the seeded flag (tests only)."""
    global _seeded
    _seeded = False
