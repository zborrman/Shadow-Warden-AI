"""
warden/api/ws_stream.py
━━━━━━━━━━━━━━━━━━━━━━━
The three WebSocket endpoints — `/ws/stream`, `/ws/monitor/{monitor_id}` and
`/ws/filter` — extracted from `main.py` (platform P-2).

Why they moved
──────────────
They are a self-contained surface: 463 lines sharing nothing with the REST
routes but the pipeline itself, and the one place a handler can be shadowed in
silence. `/ws/events` once ran **unauthenticated** because `main.py` defined an
inline `@app.websocket` for a path a router already owned — Starlette matches in
registration order, so the inline handler simply never ran, and nothing said so
(PR #237). Keeping every socket in a router removes the shape of that bug:
`warden/api/ws_events.py` owns `/ws/events`, this module owns the other three,
and `test_route_inventory.py` fails on any path that appears or vanishes.

How it reaches the pipeline
───────────────────────────
Through `warden.runtime`, never by importing `main` — the seam Phase 1 built so
domain modules stop creating import cycles. `main` publishes the singletons
during lifespan; this module reads them **per request**, because a module-level
read would capture `None` at import time (routers are imported while `main` is
still executing its own module body).

Slots read here: `filter_orchestrator`, `tenant_guard`, `guard`, `redactor`,
`dynamic_regex_rules` — all declared in `Runtime._KNOWN`, so each is `None`
until startup publishes it rather than an `AttributeError`. `None` can only be
true in a process that never booted the app, where no websocket can connect.

The handler bodies are otherwise byte-for-byte what `main.py` served: the only
edits were `@app.websocket` → `@router.websocket` and six reads of a `main`
global rerouted through the seam.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import time
import uuid

from fastapi import APIRouter, BackgroundTasks, HTTPException, WebSocket, WebSocketDisconnect

from warden.auth_guard import require_api_key
from warden.cache import _get_client as _get_redis
from warden.cache import get_cached, set_cached
from warden.metrics import observe_stage_timings as _observe_stage_timings
from warden.obfuscation import decode as decode_obfuscation
from warden.runtime import runtime as _runtime
from warden.schemas import (
    FilterRequest,
    FilterResponse,
    FlagType,
    RiskLevel,
    SemanticFlag,
)
from warden.schemas import max_risk as _max_risk

log = logging.getLogger("warden.api.ws_stream")

router = APIRouter(tags=["websocket"])

# Moved verbatim from main.py rather than converted to typed Settings fields: a
# config change hidden inside a 463-line move is how a move stops being
# reviewable. The P-4 config seam owns that conversion.
_LLM_BASE_URL   = os.getenv("LLM_BASE_URL", "").rstrip("/")  # e.g. https://api.openai.com/v1
_LLM_API_KEY    = os.getenv("LLM_API_KEY", "")
_WS_MAX_PAYLOAD = int(os.getenv("WS_MAX_PAYLOAD_BYTES", "65536"))  # 64 KiB


# ── WebSocket /ws/stream ─────────────────────────────────────────────────────

async def _ws_send(ws: WebSocket, data: dict) -> None:
    """Send a JSON event over the WebSocket."""
    await ws.send_text(json.dumps(data, ensure_ascii=False))


@router.websocket("/ws/stream")
async def ws_stream(websocket: WebSocket):
    """
    WebSocket streaming endpoint — filter + LLM token stream.

    Connect:  ws://host/ws/stream?key=<api_key>

    Client sends once (JSON):
        {"messages": [...], "model": "gpt-4o-mini", "max_tokens": 512,
         "tenant_id": "default"}

    Server sends (JSON events):
        {"type": "filter_result", "allowed": bool, "risk": str,
         "reason": str, "request_id": str}
        {"type": "token",  "content": str}   <- one per LLM streamed token
        {"type": "done",   "request_id": str}
        {"type": "error",  "code": int, "detail": str}

    WebSocket close codes:
        1008 — Policy Violation (content blocked by Warden filter)
        1009 — Message Too Big
        1011 — Internal server error / upstream error
    """
    await websocket.accept()
    rid = str(uuid.uuid4())

    # ── 1. Authenticate via ?key= query param ─────────────────────────────────
    api_key = websocket.query_params.get("key", "") or None
    try:
        auth = require_api_key(api_key)
    except HTTPException as exc:
        await _ws_send(websocket, {"type": "error", "code": exc.status_code, "detail": exc.detail})
        await websocket.close(code=1008)
        return

    # ── 2. Receive initial message ────────────────────────────────────────────
    try:
        raw = await websocket.receive_text()
    except WebSocketDisconnect:
        return

    if len(raw.encode()) > _WS_MAX_PAYLOAD:
        await _ws_send(websocket, {"type": "error", "code": 413, "detail": "Payload too large."})
        await websocket.close(code=1009)
        return

    try:
        body = json.loads(raw)
    except json.JSONDecodeError:
        await _ws_send(websocket, {"type": "error", "code": 400, "detail": "Invalid JSON."})
        await websocket.close(code=1003)
        return

    messages = body.get("messages")
    if not isinstance(messages, list) or not messages:
        await _ws_send(websocket, {
            "type": "error", "code": 400,
            "detail": "messages must be a non-empty list.",
        })
        await websocket.close(code=1003)
        return

    model      = str(body.get("model", "gpt-4o-mini"))
    max_tokens = int(body.get("max_tokens", 512))
    tenant_id  = str(body.get("tenant_id", auth.tenant_id))

    # Flatten message content to plain text for the filter pipeline
    content_parts: list[str] = []
    for msg in messages:
        c = msg.get("content", "")
        if isinstance(c, str):
            content_parts.append(c)
        elif isinstance(c, list):
            for part in c:
                if isinstance(part, dict) and part.get("type") == "text":
                    content_parts.append(part.get("text", ""))
    content = " ".join(content_parts).strip()

    if not content:
        await _ws_send(websocket, {
            "type": "error", "code": 400,
            "detail": "No text content found in messages.",
        })
        await websocket.close(code=1003)
        return

    # ── 3. Run filter pipeline ────────────────────────────────────────────────
    filter_payload = FilterRequest(content=content, tenant_id=tenant_id)
    bg_tasks       = BackgroundTasks()
    try:
        filter_resp = await _runtime.filter_orchestrator(filter_payload, rid, auth, bg_tasks,
                                                 source="ws")
    except Exception as exc:
        log.exception(json.dumps({"event": "ws_filter_error", "request_id": rid, "error": str(exc)}))
        await _ws_send(websocket, {"type": "error", "code": 500, "detail": "Filter pipeline error."})
        await websocket.close(code=1011)
        return

    await _ws_send(websocket, {
        "type":       "filter_result",
        "allowed":    filter_resp.allowed,
        "risk":       filter_resp.risk_level.value,
        "reason":     filter_resp.reason,
        "request_id": rid,
    })

    if not filter_resp.allowed:
        await websocket.close(code=1008)  # Policy Violation
        return

    # ── 4. Stream from LLM backend ────────────────────────────────────────────
    if not _LLM_BASE_URL or not _LLM_API_KEY:
        await _ws_send(websocket, {
            "type": "error", "code": 503,
            "detail": "LLM backend not configured. Set LLM_BASE_URL and LLM_API_KEY.",
        })
        await websocket.close(code=1011)
        return

    try:
        import httpx  # optional dep; only needed for WebSocket LLM streaming

        llm_headers = {
            "Authorization": f"Bearer {_LLM_API_KEY}",
            "Content-Type":  "application/json",
        }
        llm_body = {
            "model":      model,
            "max_tokens": max_tokens,
            "messages":   messages,
            "stream":     True,
        }
        async with httpx.AsyncClient(timeout=120.0) as client, client.stream(
            "POST",
            f"{_LLM_BASE_URL}/chat/completions",
            headers=llm_headers,
            json=llm_body,
        ) as resp:
            if resp.status_code != 200:
                err_body = await resp.aread()
                await _ws_send(websocket, {
                    "type":   "error",
                    "code":   resp.status_code,
                    "detail": f"LLM error: {err_body.decode()[:200]}",
                })
                await websocket.close(code=1011)
                return

            async for line in resp.aiter_lines():
                if not line.startswith("data: "):
                    continue
                chunk = line[6:].strip()
                if chunk == "[DONE]":
                    break
                try:
                    delta      = json.loads(chunk)
                    token_text = (
                        delta.get("choices", [{}])[0]
                        .get("delta", {})
                        .get("content", "")
                    )
                    if token_text:
                        await _ws_send(websocket, {"type": "token", "content": token_text})
                except (json.JSONDecodeError, IndexError, KeyError):
                    continue

    except WebSocketDisconnect:
        log.info(json.dumps({"event": "ws_client_disconnect", "request_id": rid}))
        return
    except Exception as exc:
        log.exception(json.dumps({"event": "ws_llm_error", "request_id": rid, "error": str(exc)}))
        try:
            await _ws_send(websocket, {"type": "error", "code": 502, "detail": "LLM upstream error."})
            await websocket.close(code=1011)
        except Exception as _exc:  # noqa: BLE001
            log.debug("suppressed exception: %r", _exc)
        return

    await _ws_send(websocket, {"type": "done", "request_id": rid})
    await websocket.close()


# ── WebSocket /ws/monitor/{id} — real-time probe results ─────────────────────

@router.websocket("/ws/monitor/{monitor_id}")
async def ws_monitor_stream(websocket: WebSocket, monitor_id: str):
    """
    Subscribe to real-time probe results for a monitor.

    Connect:  ws://host/ws/monitor/<uuid>
    Receives: {"is_up": bool, "latency_ms": float, "status_code": int,
               "error": str|null, "ts": "ISO8601"}

    Uses a queue bridge: sync Redis pubsub runs in a thread executor,
    forwarding messages to an asyncio.Queue consumed by the WebSocket sender.
    """
    await websocket.accept()
    r = _get_redis()
    if r is None:
        await websocket.send_json({"error": "Redis unavailable"})
        await websocket.close()
        return

    queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    channel = f"monitor:{monitor_id}:result"
    loop = asyncio.get_running_loop()

    def _listen() -> None:
        pubsub = r.pubsub()
        pubsub.subscribe(channel)
        try:
            for msg in pubsub.listen():
                if msg["type"] == "message":
                    loop.call_soon_threadsafe(queue.put_nowait, msg["data"])
        except Exception as _exc:  # noqa: BLE001
            log.debug("suppressed exception: %r", _exc)
        finally:
            with contextlib.suppress(Exception):
                pubsub.unsubscribe(channel)

    import threading
    _t = threading.Thread(target=_listen, daemon=True)
    _t.start()

    try:
        while True:
            data = await asyncio.wait_for(queue.get(), timeout=30)
            await websocket.send_text(data)
    except (TimeoutError, WebSocketDisconnect):
        pass
    except Exception as exc:
        log.debug("ws_monitor: error — %s", exc)


# ── WebSocket /ws/filter — per-stage streaming ───────────────────────────────

@router.websocket("/ws/filter")
async def ws_filter_stream(websocket: WebSocket):
    """
    WebSocket endpoint that emits a JSON event after each filter-pipeline stage.

    Connect:  ws://host/ws/filter?key=<api_key>

    Send one JSON message matching FilterRequest:
        {"content": "...", "tenant_id": "acme", "strict": false}

    Receive event stream:
        {"type": "stage", "stage": "cache",       "hit": bool,    "ms": float}
        {"type": "stage", "stage": "obfuscation", "detected": bool, "layers": list, "ms": float}
        {"type": "stage", "stage": "redaction",   "count": int,   "kinds": list,  "ms": float}
        {"type": "stage", "stage": "rules",       "flags": list,  "risk": str,    "ms": float}
        {"type": "stage", "stage": "ml",          "score": float, "is_jailbreak": bool, "ms": float}
        {"type": "result", "request_id": str, ...FilterResponse fields...}
        {"type": "done",   "request_id": str}
    or
        {"type": "error",  "code": int, "detail": str}

    WebSocket close codes:
        1008 — Policy Violation (content blocked)
        1009 — Message Too Big
        1003 — Unsupported data (invalid JSON / validation error)
        1011 — Internal server error
    """
    await websocket.accept()
    rid = str(uuid.uuid4())

    # ── 1. Authenticate ────────────────────────────────────────────────────────
    api_key = websocket.query_params.get("key", "") or None
    try:
        auth = require_api_key(api_key)
    except HTTPException as exc:
        await _ws_send(websocket, {"type": "error", "code": exc.status_code, "detail": exc.detail})
        await websocket.close(code=1008)
        return

    # ── 2. Receive + validate payload ─────────────────────────────────────────
    try:
        raw = await websocket.receive_text()
    except WebSocketDisconnect:
        return

    if len(raw.encode()) > _WS_MAX_PAYLOAD:
        await _ws_send(websocket, {"type": "error", "code": 413, "detail": "Payload too large."})
        await websocket.close(code=1009)
        return

    try:
        body = json.loads(raw)
    except json.JSONDecodeError:
        await _ws_send(websocket, {"type": "error", "code": 400, "detail": "Invalid JSON."})
        await websocket.close(code=1003)
        return

    try:
        payload = FilterRequest(**body)
    except Exception as exc:
        await _ws_send(websocket, {"type": "error", "code": 422, "detail": str(exc)})
        await websocket.close(code=1003)
        return

    tenant_id = auth.tenant_id if auth.tenant_id != "default" else payload.tenant_id
    strict = payload.strict or (_runtime.guard.strict if _runtime.guard else False)
    timings: dict[str, float] = {}

    log.info(json.dumps({"event": "ws_filter_start", "request_id": rid, "tenant_id": tenant_id}))

    # ── Stage 0: Redis cache check ─────────────────────────────────────────────
    t0 = time.perf_counter()
    cached_json = get_cached(payload.content)
    timings["cache_check"] = round((time.perf_counter() - t0) * 1000, 2)
    await _ws_send(websocket, {
        "type": "stage", "stage": "cache",
        "hit": cached_json is not None,
        "ms": timings["cache_check"],
    })

    if cached_json:
        try:
            resp = FilterResponse(**json.loads(cached_json))
            await _ws_send(websocket, {"type": "result", "request_id": rid, **resp.model_dump()})
            await _ws_send(websocket, {"type": "done", "request_id": rid})
            await websocket.close()
            return
        except Exception as _exc:  # noqa: BLE001
            log.debug("suppressed exception: %r", _exc)  # corrupted cache entry → fall through to full pipeline

    # ── Stage 0b: Obfuscation decoding ────────────────────────────────────────
    t0 = time.perf_counter()
    obfuscation_result = decode_obfuscation(payload.content)
    timings["obfuscation"] = round((time.perf_counter() - t0) * 1000, 2)
    analysis_text = obfuscation_result.combined
    if payload.context:
        ctx_blob = " ".join(
            str(v) for v in payload.context.values()
            if isinstance(v, (str, int, float, bool))
        )
        if ctx_blob:
            analysis_text = f"{analysis_text}\n\n[CONTEXT]{ctx_blob}[/CONTEXT]"
    await _ws_send(websocket, {
        "type": "stage", "stage": "obfuscation",
        "detected": obfuscation_result.has_obfuscation,
        "layers": obfuscation_result.layers_found,
        "ms": timings["obfuscation"],
    })

    # ── Stage 1: Secret Redaction ─────────────────────────────────────────────
    t0 = time.perf_counter()
    redact_result = _runtime.redactor.redact(analysis_text, payload.redaction_policy)
    timings["redaction"] = round((time.perf_counter() - t0) * 1000, 2)
    await _ws_send(websocket, {
        "type": "stage", "stage": "redaction",
        "count": len(redact_result.findings),
        "kinds": [f.kind for f in redact_result.findings],
        "ms": timings["redaction"],
    })

    # ── Stage 2: Rule-based Semantic Analysis ─────────────────────────────────
    t0 = time.perf_counter()
    guard_result = _runtime.guard.analyse(redact_result.text)
    timings["rules"] = round((time.perf_counter() - t0) * 1000, 2)

    # Dynamic evolution regex rules
    for dyn_rule in list(_runtime.dynamic_regex_rules or []):
        if dyn_rule.pattern.search(redact_result.text):
            guard_result.flags.append(SemanticFlag(
                flag=FlagType.PROMPT_INJECTION,
                score=0.80,
                detail=f"Dynamic evolution rule matched: {dyn_rule.snippet}",
            ))
            guard_result.risk_level = _max_risk(guard_result.risk_level, RiskLevel.HIGH)

    if redact_result.has_pii:
        guard_result.flags.append(SemanticFlag(
            flag=FlagType.PII_DETECTED,
            score=1.0,
            detail=f"PII detected: {[f.kind for f in redact_result.findings]}",
        ))

    await _ws_send(websocket, {
        "type": "stage", "stage": "rules",
        "flags": [
            {"flag": f.flag.value, "score": f.score, "detail": f.detail}
            for f in guard_result.flags
        ],
        "risk": guard_result.risk_level.value,
        "ms": timings["rules"],
    })

    # ── Stage 3: ML Semantic Brain ────────────────────────────────────────────
    t0 = time.perf_counter()
    brain_guard = _runtime.tenant_guard(tenant_id)
    try:
        brain_result = await brain_guard.check_async(redact_result.text)
    except Exception as exc:
        log.exception(json.dumps({"event": "ws_filter_ml_error", "request_id": rid, "error": str(exc)}))
        await _ws_send(websocket, {"type": "error", "code": 500, "detail": "ML stage error."})
        await websocket.close(code=1011)
        return
    timings["ml"] = round((time.perf_counter() - t0) * 1000, 2)

    if brain_result.is_jailbreak:
        ml_risk = RiskLevel.HIGH if brain_result.score >= 0.85 else RiskLevel.MEDIUM
        guard_result.flags.append(SemanticFlag(
            flag=FlagType.PROMPT_INJECTION,
            score=round(brain_result.score, 4),
            detail=f"ML jailbreak detected (similarity={brain_result.score:.3f})",
        ))
        guard_result.risk_level = _max_risk(guard_result.risk_level, ml_risk)

    await _ws_send(websocket, {
        "type": "stage", "stage": "ml",
        "score": round(brain_result.score, 4),
        "is_jailbreak": brain_result.is_jailbreak,
        "ms": timings["ml"],
    })

    # ── Decision ──────────────────────────────────────────────────────────────
    allowed = guard_result.safe_for(strict)
    reason = ""
    if not allowed:
        top = guard_result.top_flag
        reason = top.detail if top else f"Risk level: {guard_result.risk_level}"

    timings["total"] = round(sum(timings.values()), 2)
    _observe_stage_timings(timings, "ws_filter")

    response = FilterResponse(
        allowed                  = allowed,
        risk_level               = guard_result.risk_level,
        filtered_content         = redact_result.text,
        secrets_found            = redact_result.findings,
        semantic_flags           = guard_result.flags,
        reason                   = reason,
        redaction_policy_applied = payload.redaction_policy,
        processing_ms            = timings,
    )

    if allowed:
        set_cached(payload.content, response.model_dump_json())

    log.info(json.dumps({
        "event":      "ws_filter_done",
        "request_id": rid,
        "allowed":    allowed,
        "risk":       guard_result.risk_level.value,
        "elapsed_ms": timings["total"],
    }))

    await _ws_send(websocket, {"type": "result", "request_id": rid, **response.model_dump()})

    if not allowed:
        await websocket.close(code=1008)
        return

    await _ws_send(websocket, {"type": "done", "request_id": rid})
    await websocket.close()
