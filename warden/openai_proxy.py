"""
warden/openai_proxy.py
━━━━━━━━━━━━━━━━━━━━━
OpenAI-compatible reverse proxy.

Drop-in replacement: set OPENAI_BASE_URL=https://your-warden.com and
keep your existing OpenAI client code — no SDK changes needed.

Pipeline:
  POST /v1/chat/completions
      → extract last user message
      → POST /filter  (Warden pipeline — redaction + threat analysis)
      → if blocked: HTTP 403
      → replace message content with redacted version
      → forward to real OpenAI (or any OpenAI-compatible upstream)
      → return upstream response transparently

Environment variables:
  OPENAI_UPSTREAM   Upstream base URL (default: https://api.openai.com)
  WARDEN_FILTER_URL Internal URL for Warden /filter endpoint
                    (default: http://localhost:8001 — works inside Docker)
"""
from __future__ import annotations

import logging
import os

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status

from warden.auth_guard import require_api_key

log = logging.getLogger("warden.openai_proxy")

router = APIRouter(prefix="/v1", tags=["openai-proxy"])

_UPSTREAM = os.getenv("OPENAI_UPSTREAM", "https://api.openai.com")
_FILTER_URL = os.getenv("WARDEN_FILTER_URL", "http://localhost:8001")


@router.post("/chat/completions")
async def proxy_chat(
    payload:  dict,
    request:  Request,
    _api_key: str = Depends(require_api_key),
):
    """
    OpenAI /v1/chat/completions proxy.

    Filters the last user message through Warden before forwarding.
    Returns a standard OpenAI-format response from the upstream.
    """
    messages = payload.get("messages", [])
    if not messages:
        raise HTTPException(status_code=400, detail="No messages in request.")

    # Find the last user message
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
                headers={"X-API-Key": _api_key} if _api_key else {},
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
        return upstream_resp.json()
    except Exception as exc:
        log.error("Upstream OpenAI call failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Upstream model service unavailable.",
        ) from exc


@router.get("/models")
async def list_models(
    request:  Request,
    _api_key: str = Depends(require_api_key),
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
