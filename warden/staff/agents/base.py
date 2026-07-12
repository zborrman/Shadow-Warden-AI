"""
Generic agentic loop for digital staff.

Each role subclasses StaffAgentRunner and supplies:
  - AGENT_ID      — matches BoundaryRegistry key
  - SYSTEM_PROMPT — role-specific instructions
  - TOOLS         — Anthropic tool-schema dicts (subset from staff.tools)

The loop:
  1. check boundary + velocity before every tool dispatch
  2. use Haiku for supervised (L1), Sonnet for L2, Opus for L3
  3. max 8 iterations (half of SOVA) — staff agents are narrowly scoped
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

log = logging.getLogger(__name__)

_MAX_ITER = 8


def _preflight_reserve(tenant_id: str, agent_id: str) -> tuple[str | None, bool]:
    """Reserve the SAC wallet estimate for this run. Returns (hold_id, blocked).

    Fail-open: disabled, unavailable, or erroring wallet never blocks a run —
    only an explicit InsufficientFundsError does. ``hold_id`` is None whenever
    there is nothing to settle later (feature off / reservation skipped).
    """
    try:
        from warden.config import settings  # noqa: PLC0415
        if not settings.sac_preflight_enabled:
            return None, False
        from warden.sac.preflight import InsufficientFundsError, reserve  # noqa: PLC0415
        try:
            hold_id = reserve(tenant_id, settings.sac_preflight_estimate_usd,
                               reason="staff_agent_run", agent_id=agent_id)
            return hold_id, False
        except InsufficientFundsError:
            return None, True
    except Exception as exc:  # noqa: BLE001 — wallet unavailable must not block the run
        from warden.observability import Reason, record_failopen  # noqa: PLC0415
        record_failopen("sac_preflight", Reason.BACKEND_ERROR, exc)
        return None, False


def _preflight_settle(hold_id: str | None, agent_id: str, model: str, input_tokens: int, output_tokens: int) -> None:
    """Commit the actual token cost against the hold. Fail-open, no-op if unheld."""
    if not hold_id:
        return
    try:
        from warden.sac.preflight import commit  # noqa: PLC0415
        from warden.staff.economics import compute_cost_usd  # noqa: PLC0415
        actual = compute_cost_usd(model, input_tokens, output_tokens)
        commit(hold_id, actual, agent_id=agent_id)
    except Exception as exc:  # noqa: BLE001
        from warden.observability import Reason, record_failopen  # noqa: PLC0415
        record_failopen("sac_preflight", Reason.BACKEND_ERROR, exc)


def _record_cost(
    tenant_id: str, agent_id: str, query: str, model: str,
    input_tokens: int, output_tokens: int,
) -> None:
    """Fire-and-forget cost record — fail-open."""
    try:
        from warden.staff.economics import get_tracker  # noqa: PLC0415
        action = query[:64].replace("\n", " ").strip() if query else agent_id
        get_tracker().record(tenant_id, agent_id, action, model, input_tokens, output_tokens)
    except Exception as exc:  # noqa: BLE001
        log.debug("Cost record skip (fail-open): %s", exc)

_MODEL_BY_LEVEL = {
    1: "claude-haiku-4-5-20251001",
    2: "claude-sonnet-4-6",
    3: "claude-opus-4-8",
}


class StaffAgentRunner:
    AGENT_ID: str = "staff"
    SYSTEM_PROMPT: str = "You are a helpful AI assistant."
    TOOLS: list[dict] = []

    async def run(
        self,
        query: str,
        tenant_id: str = "default",
        session_id: str | None = None,
        redis=None,
    ) -> dict[str, Any]:
        api_key = os.getenv("ANTHROPIC_API_KEY", "")
        if not api_key:
            return {
                "response": f"{self.AGENT_ID} agent offline — ANTHROPIC_API_KEY not set.",
                "tools_used": [],
                "input_tokens": 0,
                "output_tokens": 0,
                "latency_ms": 0.0,
            }

        try:
            import anthropic
        except ImportError:
            return {
                "response": f"{self.AGENT_ID} agent offline — anthropic package not installed.",
                "tools_used": [],
                "input_tokens": 0,
                "output_tokens": 0,
                "latency_ms": 0.0,
            }

        from warden.staff.boundaries import get_registry  # noqa: PLC0415
        from warden.staff.dispatcher import staff_dispatch  # noqa: PLC0415
        from warden.staff.structured_log import AgentSpan  # noqa: PLC0415

        reg = get_registry(redis=redis)
        boundary = reg.get(self.AGENT_ID)
        autonomy = boundary.autonomy_level if boundary else 1
        model = _MODEL_BY_LEVEL.get(autonomy, _MODEL_BY_LEVEL[1])

        hold_id, blocked = _preflight_reserve(tenant_id, self.AGENT_ID)
        if blocked:
            return {
                "response": f"{self.AGENT_ID} agent blocked — insufficient SAC wallet balance.",
                "tools_used": [], "input_tokens": 0, "output_tokens": 0, "latency_ms": 0.0,
            }

        client = anthropic.AsyncAnthropic(api_key=api_key)
        history: list[dict] = [{"role": "user", "content": query}]
        tools_used: list[str] = []
        total_input = total_output = 0
        t0 = time.perf_counter()
        span = AgentSpan(self.AGENT_ID, tenant_id, model, query)
        span.start()

        for _iter in range(_MAX_ITER):
            resp = await client.messages.create(
                model=model,
                max_tokens=2048,
                system=[{"type": "text", "text": self.SYSTEM_PROMPT,
                          "cache_control": {"type": "ephemeral"}}],
                tools=self.TOOLS,  # type: ignore[arg-type]
                messages=history,  # type: ignore[arg-type]
            )

            u = resp.usage
            total_input += u.input_tokens
            total_output += u.output_tokens
            span.update_tokens(total_input, total_output)

            if resp.stop_reason == "end_turn":
                final = "".join(b.text for b in resp.content if hasattr(b, "text"))
                history.append({"role": "assistant", "content": final})
                elapsed = round((time.perf_counter() - t0) * 1000, 1)
                _record_cost(tenant_id, self.AGENT_ID, query, model, total_input, total_output)
                _preflight_settle(hold_id, self.AGENT_ID, model, total_input, total_output)
                span.end(total_input, total_output, detail=f"reply_chars={len(final)}")
                return {
                    "response": final,
                    "tools_used": tools_used,
                    "model": model,
                    "autonomy_level": autonomy,
                    "input_tokens": total_input,
                    "output_tokens": total_output,
                    "latency_ms": elapsed,
                }

            if resp.stop_reason != "tool_use":
                break

            history.append({"role": "assistant", "content": resp.content})
            tool_results = []

            for block in resp.content:
                if block.type != "tool_use":
                    continue
                tool_name = block.name
                tool_input = dict(block.input or {})
                tool_input.setdefault("tenant_id", tenant_id)
                tool_input.setdefault("agent_id", self.AGENT_ID)
                tools_used.append(tool_name)
                span.tool_call(tool_name)

                try:
                    result = await staff_dispatch(self.AGENT_ID, tool_name, tool_input, registry=reg, redis=redis)
                    content = json.dumps(result, default=str)
                    is_error = False
                    span.tool_result(tool_name, status="ok")
                except Exception as exc:  # noqa: BLE001
                    content = f"Tool error: {exc}"
                    is_error = True
                    log.warning("%s: tool %s error: %s", self.AGENT_ID, tool_name, exc)
                    span.tool_result(tool_name, status="error", detail=str(exc)[:80])

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": content,
                    "is_error": is_error,
                })

            history.append({"role": "user", "content": tool_results})

        elapsed = round((time.perf_counter() - t0) * 1000, 1)
        _record_cost(tenant_id, self.AGENT_ID, query, model, total_input, total_output)
        _preflight_settle(hold_id, self.AGENT_ID, model, total_input, total_output)
        span.end(total_input, total_output, detail="max_iter")
        return {
            "response": "Max iterations reached without conclusive answer.",
            "tools_used": tools_used,
            "model": model,
            "autonomy_level": autonomy,
            "input_tokens": total_input,
            "output_tokens": total_output,
            "latency_ms": elapsed,
        }


async def run_staff_query(
    agent_id: str,
    query: str,
    tenant_id: str = "default",
    session_id: str | None = None,
    redis=None,
) -> dict[str, Any]:
    """Generic entry-point — dispatches to the right runner by agent_id."""
    from warden.staff.agents.bdr import BDRAgent  # noqa: PLC0415
    from warden.staff.agents.compliance import ComplianceAgent  # noqa: PLC0415
    from warden.staff.agents.growth import GrowthAgent  # noqa: PLC0415
    from warden.staff.agents.support import SupportAgent  # noqa: PLC0415

    runners: dict[str, type[StaffAgentRunner]] = {
        "bdr": BDRAgent,
        "growth": GrowthAgent,
        "compliance": ComplianceAgent,
        "support": SupportAgent,
    }
    cls = runners.get(agent_id)
    if cls is None:
        return {"error": f"Unknown agent_id: {agent_id}", "response": "", "tools_used": []}
    return await cls().run(query, tenant_id=tenant_id, session_id=session_id, redis=redis)
