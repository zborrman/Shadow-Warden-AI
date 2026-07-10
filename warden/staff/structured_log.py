"""
Structured JSON logging for Digital Staff agents.

Every agent action emits a single JSON line with a fixed schema so that
Grafana/Loki, SIEM, and the cost tracker can build dashboards without regex.

Schema (all fields always present):
    ts          ISO-8601 UTC timestamp
    event       event type: agent_start | tool_call | tool_result | agent_end | agent_error
    agent_id    staff agent role (bdr, growth, compliance, support)
    tenant_id   tenant scope
    tool_name   tool name for tool_call / tool_result events, else ""
    model       LLM model string
    input_tokens  cumulative input tokens so far
    output_tokens cumulative output tokens so far
    cost_usd    cumulative cost so far (from economics module, fail-open)
    latency_ms  elapsed ms since agent start (0.0 at start)
    status      ok | error | denied
    detail      free-form short string (error message, verdict, etc.)
"""
from __future__ import annotations

import json
import logging
import time
from datetime import UTC, datetime
from typing import Any

_root_log = logging.getLogger("warden.staff")


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat(timespec="milliseconds")


def _cost(model: str, input_tok: int, output_tok: int) -> float:
    try:
        from warden.staff.economics import compute_cost_usd  # noqa: PLC0415
        return round(compute_cost_usd(model, input_tok, output_tok), 6)
    except Exception:  # noqa: BLE001
        return 0.0


def emit(
    event: str,
    *,
    agent_id: str,
    tenant_id: str,
    model: str = "",
    tool_name: str = "",
    input_tokens: int = 0,
    output_tokens: int = 0,
    latency_ms: float = 0.0,
    status: str = "ok",
    detail: str = "",
    extra: dict[str, Any] | None = None,
) -> None:
    """Emit one structured log line."""
    record: dict[str, Any] = {
        "ts":            _now_iso(),
        "event":         event,
        "agent_id":      agent_id,
        "tenant_id":     tenant_id,
        "tool_name":     tool_name,
        "model":         model,
        "input_tokens":  input_tokens,
        "output_tokens": output_tokens,
        "cost_usd":      _cost(model, input_tokens, output_tokens),
        "latency_ms":    round(latency_ms, 1),
        "status":        status,
        "detail":        detail,
    }
    if extra:
        record.update(extra)
    _root_log.info(json.dumps(record))


class AgentSpan:
    """
    Context object passed through a single agent run to emit correlated events.

    Usage (in StaffAgentRunner.run):
        span = AgentSpan(agent_id, tenant_id, model)
        span.start()
        ...
        span.tool_call("crm_search")
        ... await tool ...
        span.tool_result("crm_search", status="ok", detail="5 leads")
        ...
        span.end(input_tokens, output_tokens)
    """

    def __init__(self, agent_id: str, tenant_id: str, model: str, query: str = "") -> None:
        self.agent_id = agent_id
        self.tenant_id = tenant_id
        self.model = model
        # GDPR: never log raw query content — keep only a length metric.
        self.query_len = len(query) if query else 0
        self._t0 = time.perf_counter()
        self._input = 0
        self._output = 0

    def _elapsed(self) -> float:
        return round((time.perf_counter() - self._t0) * 1000, 1)

    def start(self) -> None:
        emit(
            "agent_start",
            agent_id=self.agent_id,
            tenant_id=self.tenant_id,
            model=self.model,
            detail=f"query_chars={self.query_len}",
        )

    def tool_call(self, tool_name: str, input_preview: str = "") -> None:
        emit(
            "tool_call",
            agent_id=self.agent_id,
            tenant_id=self.tenant_id,
            model=self.model,
            tool_name=tool_name,
            input_tokens=self._input,
            output_tokens=self._output,
            latency_ms=self._elapsed(),
            # GDPR: log the input size, never the raw tool input.
            detail=f"input_chars={len(input_preview)}" if input_preview else "",
        )

    def tool_result(
        self, tool_name: str, *, status: str = "ok", detail: str = ""
    ) -> None:
        emit(
            "tool_result",
            agent_id=self.agent_id,
            tenant_id=self.tenant_id,
            model=self.model,
            tool_name=tool_name,
            input_tokens=self._input,
            output_tokens=self._output,
            latency_ms=self._elapsed(),
            status=status,
            detail=detail[:120],
        )

    def update_tokens(self, input_tokens: int, output_tokens: int) -> None:
        self._input = input_tokens
        self._output = output_tokens

    def end(self, input_tokens: int, output_tokens: int, detail: str = "") -> None:
        self._input = input_tokens
        self._output = output_tokens
        emit(
            "agent_end",
            agent_id=self.agent_id,
            tenant_id=self.tenant_id,
            model=self.model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=self._elapsed(),
            detail=detail,
        )

    def error(self, detail: str) -> None:
        emit(
            "agent_error",
            agent_id=self.agent_id,
            tenant_id=self.tenant_id,
            model=self.model,
            input_tokens=self._input,
            output_tokens=self._output,
            latency_ms=self._elapsed(),
            status="error",
            detail=detail[:200],
        )
