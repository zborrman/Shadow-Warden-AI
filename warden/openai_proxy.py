"""
warden/openai_proxy.py
━━━━━━━━━━━━━━━━━━━━━
OpenAI-compatible reverse proxy.

Drop-in replacement: set OPENAI_BASE_URL=https://your-warden.com and
keep your existing OpenAI client code — no SDK changes needed.

Pipeline:
  POST /v1/chat/completions
      → [A] inspect role=tool messages for prompt injection / secret exfil
      → extract last user message
      → POST /filter  (Warden pipeline — redaction + threat analysis)
      → if blocked: HTTP 403
      → replace message content with redacted version
      → forward to real OpenAI (or any OpenAI-compatible upstream)
      → [B] inspect tool_calls in upstream response before returning
      → return upstream response (or HTTP 400 if tool_call blocked)

Environment variables:
  OPENAI_UPSTREAM   Upstream base URL (default: https://api.openai.com)
  WARDEN_FILTER_URL Internal URL for Warden /filter endpoint
                    (default: http://localhost:8001 — works inside Docker)
"""
from __future__ import annotations

import json
import logging
import os

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status

from warden.auth_guard import AuthResult, require_api_key
from warden.metrics import TOOL_BLOCKS
from warden.tool_guard import ToolCallGuard

log = logging.getLogger("warden.openai_proxy")

router = APIRouter(prefix="/v1", tags=["openai-proxy"])

_UPSTREAM = os.getenv("OPENAI_UPSTREAM", "https://api.openai.com")
_FILTER_URL = os.getenv("WARDEN_FILTER_URL", "http://localhost:8001")

# Module-level singleton — no state, safe to share
_tool_guard = ToolCallGuard()

# Injected by main.py lifespan after AgentMonitor is created; None = monitoring disabled
_agent_monitor = None  # type: ignore[assignment]


def _build_tool_name_map(messages: list[dict]) -> dict[str, str]:
    """
    Walk assistant messages to map tool_call_id → tool function name.
    Used when inspecting role=tool result messages (they carry only the id).
    """
    id_to_name: dict[str, str] = {}
    for msg in messages:
        if msg.get("role") != "assistant":
            continue
        for tc in msg.get("tool_calls") or []:
            if tc.get("type") == "function":
                tc_id = tc.get("id", "")
                name = tc.get("function", {}).get("name", "unknown_tool")
                if tc_id:
                    id_to_name[tc_id] = name
    return id_to_name


@router.post("/chat/completions")
async def proxy_chat(
    payload:  dict,
    request:  Request,
    auth: AuthResult = Depends(require_api_key),
):
    """
    OpenAI /v1/chat/completions proxy with Warden security gates.

    Two ToolCallGuard interception points:
      [A] Incoming tool results (role=tool in request messages)
          — blocks prompt injection / secret exfil before it reaches the model
      [B] Outgoing tool calls (tool_calls in upstream response)
          — blocks dangerous commands before the client executes them
    """
    messages = payload.get("messages", [])
    if not messages:
        raise HTTPException(status_code=400, detail="No messages in request.")

    # ── Session ID for agentic monitoring ─────────────────────────────────
    session_id: str | None = (
        request.headers.get("X-Session-ID")
        or payload.get("metadata", {}).get("session_id")
    )

    # ── [A] Inspect role=tool messages (indirect injection / LLM01) ────────
    tool_name_map = _build_tool_name_map(messages)
    for msg in messages:
        if msg.get("role") != "tool":
            continue
        tool_call_id = msg.get("tool_call_id", "")
        tool_name = tool_name_map.get(tool_call_id, "unknown_tool")
        content = msg.get("content") or ""
        if not isinstance(content, str):
            # content may be a list of blocks — flatten to text
            content = " ".join(
                block.get("text", "") if isinstance(block, dict) else str(block)
                for block in content
            )

        result = _tool_guard.inspect_result(tool_name, content)
        if result.blocked:
            log.warning(
                "tool_result_blocked_proxy tool=%r tool_call_id=%r threats=%r",
                tool_name,
                tool_call_id,
                [t.kind for t in result.threats],
            )
            TOOL_BLOCKS.labels(
                direction="result",
                tool_name=tool_name,
                threat=result.threats[0].kind if result.threats else "unknown",
            ).inc()
            if session_id and _agent_monitor is not None:
                try:
                    _agent_monitor.record_tool_event(
                        session_id, tool_name, "result", True,
                        result.threats[0].kind if result.threats else None,
                    )
                except Exception:
                    pass
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "tool_result_blocked",
                    "tool_name": tool_name,
                    "tool_call_id": tool_call_id,
                    "reason": result.reason,
                    "threats": [t.kind for t in result.threats],
                },
            )

    # Record clean tool results for session monitoring
    if session_id and _agent_monitor is not None:
        for msg in messages:
            if msg.get("role") != "tool":
                continue
            tc_id = msg.get("tool_call_id", "")
            tc_name = tool_name_map.get(tc_id, "unknown_tool")
            try:
                _agent_monitor.record_tool_event(session_id, tc_name, "result", False, None)
            except Exception:
                pass

    # ── Find the last user message ─────────────────────────────────────────
    last_user_idx = next(
        (i for i in reversed(range(len(messages)))
         if messages[i].get("role") == "user"),
        None,
    )
    if last_user_idx is None:
        raise HTTPException(status_code=400, detail="No user message found.")

    user_content = messages[last_user_idx].get("content", "")

    # ── Run through Warden /filter ─────────────────────────────────────────
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            filter_resp = await client.post(
                f"{_FILTER_URL}/filter",
                json={"content": user_content},
                headers={"X-API-Key": auth.api_key} if auth.api_key else {},
            )
        filter_data = filter_resp.json()
    except Exception as exc:
        log.error("Warden /filter call failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Warden filter service unavailable.",
        ) from exc

    if not filter_data.get("allowed", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Blocked by Warden: {filter_data.get('reason', 'policy violation')}",
        )

    # Replace user message content with redacted version
    messages_out = list(messages)
    messages_out[last_user_idx] = {
        **messages[last_user_idx],
        "content": filter_data.get("filtered_content", user_content),
    }
    payload_out = {**payload, "messages": messages_out}

    # ── Forward to upstream OpenAI ─────────────────────────────────────────
    auth_header = request.headers.get("Authorization", "")
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            upstream_resp = await client.post(
                f"{_UPSTREAM}/v1/chat/completions",
                json=payload_out,
                headers={
                    "Authorization": auth_header,
                    "Content-Type": "application/json",
                },
            )
        upstream_data = upstream_resp.json()
    except Exception as exc:
        log.error("Upstream OpenAI call failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Upstream model service unavailable.",
        ) from exc

    # ── [B] Inspect tool_calls in upstream response ────────────────────────
    for choice in upstream_data.get("choices") or []:
        msg = choice.get("message") or {}
        for tc in msg.get("tool_calls") or []:
            if tc.get("type") != "function":
                continue
            func = tc.get("function", {})
            tool_name = func.get("name", "unknown_tool")
            arguments = func.get("arguments", "{}")

            result = _tool_guard.inspect_call(tool_name, arguments)
            if result.blocked:
                log.warning(
                    "tool_call_blocked_proxy tool=%r threats=%r args_preview=%r",
                    tool_name,
                    [t.kind for t in result.threats],
                    arguments[:120] if isinstance(arguments, str) else str(arguments)[:120],
                )
                TOOL_BLOCKS.labels(
                    direction="call",
                    tool_name=tool_name,
                    threat=result.threats[0].kind if result.threats else "unknown",
                ).inc()
                if session_id and _agent_monitor is not None:
                    try:
                        _agent_monitor.record_tool_event(
                            session_id, tool_name, "call", True,
                            result.threats[0].kind if result.threats else None,
                        )
                    except Exception:
                        pass
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": "tool_call_blocked",
                        "tool_name": tool_name,
                        "tool_call_id": tc.get("id", ""),
                        "reason": result.reason,
                        "threats": [t.kind for t in result.threats],
                    },
                )

    # Record clean outgoing tool calls for session monitoring
    if session_id and _agent_monitor is not None:
        for choice in upstream_data.get("choices") or []:
            msg = choice.get("message") or {}
            for tc in msg.get("tool_calls") or []:
                if tc.get("type") != "function":
                    continue
                tc_name = tc.get("function", {}).get("name", "unknown_tool")
                try:
                    _agent_monitor.record_tool_event(session_id, tc_name, "call", False, None)
                except Exception:
                    pass

    return upstream_data


@router.get("/models")
async def list_models(
    request:  Request,
    auth: AuthResult = Depends(require_api_key),
):
    """Proxy GET /v1/models to the upstream transparently."""
    auth_header = request.headers.get("Authorization", "")
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{_UPSTREAM}/v1/models",
                headers={"Authorization": auth_header},
            )
        return resp.json()
    except Exception as exc:
        log.error("Upstream /models call failed: %s", exc)
        raise HTTPException(status_code=502, detail="Upstream unavailable.") from exc
