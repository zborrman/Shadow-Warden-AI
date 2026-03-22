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
  OPENAI_UPSTREAM      Upstream base URL (default: https://api.openai.com)
  OPENAI_API_KEY       API key forwarded to OpenAI (optional — client can send Authorization header)
  PERPLEXITY_API_KEY   Perplexity API key (auto-routed for sonar-* / llama-* / pplx-* models)
  GEMINI_API_KEY       Google Gemini API key (auto-routed for gemini-* models)
  WARDEN_FILTER_URL    Internal URL for Warden /filter endpoint
                       (default: http://localhost:8001 — works inside Docker)

Provider auto-routing (based on model name):
  gemini-*                  → https://generativelanguage.googleapis.com/v1beta/openai
  sonar-* / llama-* / pplx  → https://api.perplexity.ai
  everything else           → OPENAI_UPSTREAM (default: https://api.openai.com)
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
from collections.abc import AsyncGenerator

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse

from warden.auth_guard import AuthResult, require_api_key
from warden.masking.engine import get_engine as _get_masking_engine
from warden.metrics import OUTPUT_GUARD_BLOCKS, OUTPUT_GUARD_SANITIZATIONS, TOOL_BLOCKS
from warden.notification_hook import get_notification_hook
from warden.output_guard import get_output_guard
from warden.tool_guard import ToolCallGuard
from warden.wallet_shield import estimate_tokens, get_wallet_shield

log = logging.getLogger("warden.openai_proxy")

router = APIRouter(prefix="/v1", tags=["openai-proxy"])

_UPSTREAM            = os.getenv("OPENAI_UPSTREAM",   "https://api.openai.com")
_FILTER_URL          = os.getenv("WARDEN_FILTER_URL", "http://localhost:8001")

_PERPLEXITY_UPSTREAM = "https://api.perplexity.ai"
_GEMINI_UPSTREAM     = "https://generativelanguage.googleapis.com/v1beta/openai"
_PERPLEXITY_API_KEY  = os.getenv("PERPLEXITY_API_KEY", "")
_GEMINI_API_KEY      = os.getenv("GEMINI_API_KEY", "")


def _resolve_upstream(model: str) -> tuple[str, str]:
    """Return (base_url, provider_api_key) for the requested model."""
    m = model.lower()
    if m.startswith("gemini"):
        return _GEMINI_UPSTREAM, _GEMINI_API_KEY
    if any(m.startswith(p) for p in ("sonar", "llama-", "r1-", "pplx", "mixtral")):
        return _PERPLEXITY_UPSTREAM, _PERPLEXITY_API_KEY
    return _UPSTREAM, ""
# MASKING_MODE=auto  — transparently mask PII in user messages, unmask LLM responses
# MASKING_MODE=off   — standard redact-only behaviour (default)
_MASKING_MODE = os.getenv("MASKING_MODE", "off").lower()

_WALLET_ENABLED       = os.getenv("WALLET_ENABLED",        "true").lower() == "true"
_OUTPUT_GUARD_ENABLED = os.getenv("OUTPUT_GUARDRAILS_ENABLED", "true").lower() == "true"

# Module-level singleton — no state, safe to share
_tool_guard = ToolCallGuard()

# Injected by main.py lifespan after AgentMonitor is created; None = monitoring disabled
try:
    from warden.agent_monitor import AgentMonitor as _AgentMonitor

    _agent_monitor: _AgentMonitor | None = None
except ImportError:
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
                with contextlib.suppress(Exception):
                    _agent_monitor.record_tool_event(
                        session_id, tool_name, "result", True,
                        result.threats[0].kind if result.threats else None,
                    )
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
            with contextlib.suppress(Exception):
                _agent_monitor.record_tool_event(session_id, tc_name, "result", False, None)

    # ── Find the last user message ─────────────────────────────────────────
    last_user_idx = next(
        (i for i in reversed(range(len(messages)))
         if messages[i].get("role") == "user"),
        None,
    )
    if last_user_idx is None:
        raise HTTPException(status_code=400, detail="No user message found.")

    user_content = messages[last_user_idx].get("content", "")

    # ── WalletShield: token budget pre-flight ──────────────────────────────
    # Blocks the request before it reaches the upstream LLM if the user/tenant
    # has exhausted their token budget window.  Fail-open on Redis errors.
    _tenant_id     = auth.tenant_id if hasattr(auth, "tenant_id") and auth.tenant_id else "default"
    _user_id       = (
        request.headers.get("X-User-ID")
        or payload.get("user", "")
        or "anonymous"
    )
    _estimated_tok = 0
    if _WALLET_ENABLED:
        _estimated_tok = estimate_tokens(messages)
        _budget = get_wallet_shield().check_and_consume(
            tenant_id = _tenant_id,
            user_id   = _user_id,
            estimated = _estimated_tok,
        )
        if not _budget.allowed:
            log.warning(
                "wallet_shield_block tenant=%s user=%s used=%d limit=%d",
                _tenant_id, _user_id, _budget.used, _budget.limit,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=_budget.to_dict(),
            )

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

    # ── Yellow Zone: transparent PII masking ──────────────────────────────────
    # Start with the redacted content from /filter (secrets/keys already removed).
    forwarded_content = filter_data.get("filtered_content", user_content)
    _mask_session_id: str | None = None

    if _MASKING_MODE == "auto":
        # Re-use or create a masking session keyed on X-Session-ID so the vault
        # persists across conversational turns.
        engine = _get_masking_engine()
        mask_result = engine.mask(forwarded_content, session_id or None)
        if mask_result.has_entities:
            forwarded_content = mask_result.masked
            _mask_session_id  = mask_result.session_id
            log.info(
                "masking_applied session=%r entities=%r",
                _mask_session_id,
                mask_result.summary(),
            )

    # Replace user message content with (redacted +) masked version
    messages_out = list(messages)
    messages_out[last_user_idx] = {
        **messages[last_user_idx],
        "content": forwarded_content,
    }
    payload_out = {**payload, "messages": messages_out}

    # ── Resolve upstream once (used by both streaming + non-streaming) ────
    model = payload.get("model", "")
    _upstream_url, _provider_key = _resolve_upstream(model)
    auth_header = request.headers.get("Authorization", "")
    if not auth_header and _provider_key:
        auth_header = f"Bearer {_provider_key}"
    _req_headers = {"Authorization": auth_header, "Content-Type": "application/json"}

    # ── Streaming path ─────────────────────────────────────────────────────
    if payload_out.get("stream"):
        async def _stream_gen() -> AsyncGenerator[bytes, None]:
            try:
                async with httpx.AsyncClient(timeout=120.0) as _sc:
                    async with _sc.stream(
                        "POST",
                        f"{_upstream_url}/chat/completions",
                        json=payload_out,
                        headers=_req_headers,
                    ) as up:
                        # ── Collect all SSE chunks from upstream ──────────
                        _chunks: list[dict] = []
                        _parts:  list[str]  = []
                        async for _line in up.aiter_lines():
                            if not _line.startswith("data: "):
                                continue
                            _raw = _line[6:].strip()
                            if _raw == "[DONE]":
                                break
                            try:
                                _c = json.loads(_raw)
                                _chunks.append(_c)
                                for _ch in _c.get("choices") or []:
                                    _d = _ch.get("delta") or {}
                                    if isinstance(_d.get("content"), str):
                                        _parts.append(_d["content"])
                            except json.JSONDecodeError:
                                pass

                # ── Unmask if PII masking was applied ─────────────────────
                _full = "".join(_parts)
                if _mask_session_id:
                    _full = _get_masking_engine().unmask(_full, _mask_session_id)

                # ── OutputGuard on fully assembled content ─────────────────
                _sanitized: str | None = None
                if _OUTPUT_GUARD_ENABLED and _full:
                    _og = get_output_guard()
                    _ogr = _og.scan(_full)
                    if _ogr.risky:
                        _sanitized = _ogr.sanitized
                        for _f in _ogr.findings:
                            with contextlib.suppress(Exception):
                                OUTPUT_GUARD_BLOCKS.labels(
                                    tenant_id=_tenant_id, risk=_f.risk.value
                                ).inc()
                        with contextlib.suppress(Exception):
                            OUTPUT_GUARD_SANITIZATIONS.labels(
                                tenant_id=_tenant_id
                            ).inc()
                        log.warning(
                            "output_guard_sanitized_stream tenant=%r risks=%r",
                            _tenant_id, _ogr.risk_types,
                        )
                        _hook = get_notification_hook()
                        for _f in _ogr.findings:
                            with contextlib.suppress(Exception):
                                asyncio.create_task(_hook.fire(
                                    finding=_f, session_id=session_id,
                                    tenant_id=_tenant_id, user_id=_user_id,
                                ))

                # ── Re-emit as SSE ─────────────────────────────────────────
                _emit = _sanitized if _sanitized is not None else _full

                if _sanitized is None:
                    # Pass through original chunks with unmasked content patched in
                    _pos = 0
                    for _c in _chunks:
                        for _ch in _c.get("choices") or []:
                            _d = _ch.get("delta") or {}
                            if isinstance(_d.get("content"), str):
                                _len = len(_d["content"])
                                _d["content"] = _emit[_pos:_pos + _len]
                                _pos += _len
                        yield (f"data: {json.dumps(_c)}\n\n").encode()
                else:
                    # Re-stream sanitized content as fresh chunks
                    _tmpl = _chunks[0] if _chunks else {}
                    _pieces = [_emit[i:i + 20] for i in range(0, len(_emit), 20)] or [""]
                    for _i, _piece in enumerate(_pieces):
                        _nc = {
                            "id":      _tmpl.get("id", "chatcmpl-warden"),
                            "object":  "chat.completion.chunk",
                            "created": _tmpl.get("created", 0),
                            "model":   _tmpl.get("model", model),
                            "choices": [{
                                "index": 0,
                                "delta": {"content": _piece},
                                "finish_reason": "stop" if _i == len(_pieces) - 1 else None,
                            }],
                        }
                        yield (f"data: {json.dumps(_nc)}\n\n").encode()

                yield b"data: [DONE]\n\n"

                # ── WalletShield reconciliation (no usage in stream) ───────
                if _WALLET_ENABLED and _estimated_tok:
                    get_wallet_shield().record_actual(
                        tenant_id=_tenant_id, user_id=_user_id,
                        actual=_estimated_tok, estimated=_estimated_tok,
                    )

            except Exception as _exc:
                log.error("Upstream stream failed: %s", _exc)
                yield (
                    f"data: {json.dumps({'error': {'message': str(_exc), 'type': 'upstream_error'}})}\n\n"
                ).encode()
                yield b"data: [DONE]\n\n"

        return StreamingResponse(
            _stream_gen(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # ── Non-streaming path ─────────────────────────────────────────────────
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            upstream_resp = await client.post(
                f"{_upstream_url}/chat/completions",
                json=payload_out,
                headers=_req_headers,
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
                    with contextlib.suppress(Exception):
                        _agent_monitor.record_tool_event(
                            session_id, tool_name, "call", True,
                            result.threats[0].kind if result.threats else None,
                        )
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
                with contextlib.suppress(Exception):
                    _agent_monitor.record_tool_event(session_id, tc_name, "call", False, None)

    # ── Yellow Zone: unmask the LLM response before returning to the caller ────
    if _mask_session_id:
        engine = _get_masking_engine()
        for choice in upstream_data.get("choices") or []:
            msg = choice.get("message") or {}
            if isinstance(msg.get("content"), str):
                msg["content"] = engine.unmask(msg["content"], _mask_session_id)

    # ── Stage 4: OutputGuard — business-layer guardrails ───────────────────
    # Scans LLM output for price manipulation, unauthorized commitments,
    # competitor mentions, and policy violations.  Sanitizes in-place;
    # does NOT raise HTTP errors (sanitize > block for business rules).
    if _OUTPUT_GUARD_ENABLED:
        _guard      = get_output_guard()
        _og_tenant  = _tenant_id
        _og_blocked = False
        for choice in upstream_data.get("choices") or []:
            msg     = choice.get("message") or {}
            content = msg.get("content")
            if not isinstance(content, str) or not content:
                continue
            og_result = _guard.scan(content)
            if og_result.risky:
                _og_blocked = True
                msg["content"] = og_result.sanitized
                for finding in og_result.findings:
                    with contextlib.suppress(Exception):
                        OUTPUT_GUARD_BLOCKS.labels(
                            tenant_id=_og_tenant,
                            risk=finding.risk.value,
                        ).inc()
                with contextlib.suppress(Exception):
                    OUTPUT_GUARD_SANITIZATIONS.labels(tenant_id=_og_tenant).inc()
                log.warning(
                    "output_guard_sanitized tenant=%r risks=%r snippet=%r",
                    _og_tenant,
                    og_result.risk_types,
                    og_result.findings[0].snippet if og_result.findings else "",
                )
                # ── Stage 5: Notification Hook ─────────────────────────────
                # Notify the shop manager via Telegram / CRM webhook for
                # high-business-impact violations (price manipulation, commitments).
                _hook = get_notification_hook()
                for _finding in og_result.findings:
                    with contextlib.suppress(Exception):
                        asyncio.create_task(_hook.fire(
                            finding    = _finding,
                            session_id = session_id,
                            tenant_id  = _og_tenant,
                            user_id    = _user_id,
                        ))

    # ── WalletShield: actual token reconciliation ──────────────────────────
    # Correct the budget counter from the heuristic estimate to the real count
    # returned by the upstream API in usage.total_tokens.
    if _WALLET_ENABLED and _estimated_tok:
        _usage      = upstream_data.get("usage") or {}
        _actual_tok = _usage.get("total_tokens", 0)
        if _actual_tok > 0:
            get_wallet_shield().record_actual(
                tenant_id = _tenant_id,
                user_id   = _user_id,
                actual    = _actual_tok,
                estimated = _estimated_tok,
            )

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
