"""
GSAM ingest taps — the ONLY bridge from event producers to the collector.

GDPR rule: every tap maps its producer payload onto Observation through an
explicit field ALLOWLIST (ids, counters, model names, costs, latencies,
statuses). Free-text fields such as structured_log's `detail` /
`query_preview` carry content fragments and are deliberately never copied.

All taps are fail-open and cost one dict-build + Queue.put_nowait.
"""
from __future__ import annotations

import contextlib

from warden.gsam.collector import gsam_emit
from warden.gsam.schema import Observation


def _emit(obs: Observation) -> None:
    with contextlib.suppress(Exception):
        gsam_emit(obs.to_row())


def tap_agent_span(record: dict) -> None:
    """Tap for warden.staff.structured_log.emit() — strips `detail`/extras."""
    with contextlib.suppress(Exception):
        _emit(Observation(
            event=str(record.get("event", "")),
            payload_kind="agent_span",
            agent_id=str(record.get("agent_id", "")),
            tenant_id=str(record.get("tenant_id", "")),
            model=str(record.get("model", "")),
            provider="anthropic" if record.get("model") else "",
            input_tokens=int(record.get("input_tokens", 0) or 0),
            output_tokens=int(record.get("output_tokens", 0) or 0),
            execution_cost=float(record.get("cost_usd", 0.0) or 0.0),
            latency_ms=float(record.get("latency_ms", 0.0) or 0.0),
            status=str(record.get("status", "")),
            contract_id=str(record.get("tool_name", "")),
        ))


def tap_token_cost(
    tenant_id: str,
    agent_id: str,
    action: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    cost_usd: float,
) -> None:
    """Tap for warden.staff.economics.TokenCostTracker.record()."""
    with contextlib.suppress(Exception):
        _emit(Observation(
            event="token_cost",
            payload_kind=action[:64],
            agent_id=agent_id,
            tenant_id=tenant_id,
            model=model,
            provider="anthropic" if model else "",
            input_tokens=int(input_tokens),
            output_tokens=int(output_tokens),
            execution_cost=float(cost_usd),
        ))


def tap_billing_event(entry: dict) -> None:
    """Tap for warden.billing.audit_chain.append_billing_event()."""
    with contextlib.suppress(Exception):
        _emit(Observation(
            event="billing_event",
            payload_kind=str(entry.get("event_type", "")),
            agent_id=str(entry.get("agent_id", "")),
            tenant_id=str(entry.get("tenant_id", "")),
            model=str(entry.get("model", "")),
            input_tokens=int(entry.get("input_tokens", 0) or 0),
            output_tokens=int(entry.get("output_tokens", 0) or 0),
            execution_cost=float(entry.get("cost_usd", 0.0) or 0.0),
            trace_id=str(entry.get("entry_id", "")),
        ))


def tap_marketplace_action(
    action_type: str,
    agent_id: str,
    tenant_id: str,
    dispatched: bool,
) -> None:
    """Tap for POST /marketplace/action (runs via BackgroundTasks)."""
    with contextlib.suppress(Exception):
        _emit(Observation(
            event="marketplace_action",
            payload_kind=action_type[:64],
            agent_id=agent_id,
            tenant_id=tenant_id,
            role="ASSISTANT",
            status="dispatched" if dispatched else "no_handler",
        ))


def tap_mcp_call(tool_name: str, agent_id: str, price_usd: float) -> None:
    """Tap for the MCP gateway tools/call branch (post-payment)."""
    with contextlib.suppress(Exception):
        _emit(Observation(
            event="mcp_call",
            payload_kind=tool_name[:64],
            agent_id=agent_id,
            execution_cost=float(price_usd),
        ))
