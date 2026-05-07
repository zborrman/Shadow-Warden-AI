"""
warden/api/slack_commands.py
─────────────────────────────
Slack slash command handler — /warden integration.

Slash commands registered in your Slack App:
  /warden scan <text>        — run text through Obsidian AI filter
  /warden status             — gateway health snapshot
  /warden approve <token>    — approve a pending MasterAgent action
  /warden help               — command reference

Security: HMAC-SHA256 signature verification (SLACK_SIGNING_SECRET).
Slack expects a response within 3 s — all work is synchronous-fast.

Environment variables:
  SLACK_SIGNING_SECRET   Slack app signing secret (required for sig verification)
  WARDEN_API_KEY         internal API key for localhost:8001 calls
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from urllib.parse import parse_qs

import httpx
from fastapi import APIRouter, HTTPException, Request, Response

router = APIRouter(tags=["slack"])
log = logging.getLogger("warden.api.slack_commands")

_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET", "")
_BASE           = "http://localhost:8001"
_API_KEY        = os.getenv("WARDEN_API_KEY", "")
_TIMEOUT        = 12.0


# ── Signature verification ────────────────────────────────────────────────────

def _verify(body: bytes, timestamp: str, signature: str) -> bool:
    if not _SIGNING_SECRET:
        return True  # dev mode — skip
    try:
        if abs(time.time() - float(timestamp)) > 300:
            return False  # replay-attack window
    except ValueError:
        return False
    sig_base = f"v0:{timestamp}:{body.decode()}"
    expected = "v0=" + hmac.new(
        _SIGNING_SECRET.encode(), sig_base.encode(), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


# ── Slack Block Kit helpers ───────────────────────────────────────────────────

def _resp(text: str, *, ephemeral: bool = True) -> Response:
    payload = {
        "response_type": "ephemeral" if ephemeral else "in_channel",
        "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": text}}],
    }
    return Response(content=json.dumps(payload), media_type="application/json")


# ── Main endpoint ─────────────────────────────────────────────────────────────

@router.post("/slack/command")
async def slack_command(request: Request) -> Response:
    """Handle /warden slash commands dispatched from Slack."""
    body      = await request.body()
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    signature = request.headers.get("X-Slack-Signature", "")

    if not _verify(body, timestamp, signature):
        raise HTTPException(status_code=403, detail="Invalid Slack signature")

    form = {k: v[0] for k, v in parse_qs(body.decode()).items()}
    text = form.get("text", "").strip()
    user = form.get("user_id", "unknown")

    parts = text.split(None, 1)
    cmd   = parts[0].lower() if parts else "help"
    arg   = parts[1].strip() if len(parts) > 1 else ""

    log.info("slack /warden: user=%s cmd=%s", user, cmd)

    if cmd == "scan":
        return await _cmd_scan(arg)
    if cmd == "status":
        return await _cmd_status()
    if cmd == "approve":
        return await _cmd_approve(arg)
    return _help_resp()


# ── Command handlers ──────────────────────────────────────────────────────────

async def _cmd_scan(text: str) -> Response:
    if not text:
        return _resp("Usage: `/warden scan <text to check>`")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.post(
                f"{_BASE}/obsidian/ai-filter",
                json={"prompt": text},
                headers={"X-API-Key": _API_KEY, "X-Tenant-ID": "default"},
            )
            data = r.json()
    except Exception as exc:
        return _resp(f"⚠️ Scan error: {exc}")

    risk    = data.get("risk_level", "UNKNOWN")
    allowed = data.get("allowed", True)
    flags   = ", ".join(data.get("flags", [])) or "none"
    secrets = len(data.get("secrets_found", []))
    emoji   = {"ALLOW": "✅", "LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🔴", "BLOCK": "🚨"}.get(risk, "⚠️")
    return _resp(
        f"{emoji} *Warden Scan Result*\n"
        f"*Risk:* `{risk}` | *Allowed:* `{allowed}`\n"
        f"*Flags:* {flags} | *Secrets:* {secrets}"
    )


async def _cmd_status() -> Response:
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.get(f"{_BASE}/health", headers={"X-API-Key": _API_KEY})
            data = r.json()
    except Exception as exc:
        return _resp(f"⚠️ Health check error: {exc}")

    status = data.get("status", "unknown")
    emoji  = "✅" if status == "ok" else "⚠️"
    corpus = data.get("corpus_size", "?")
    return _resp(
        f"{emoji} *Shadow Warden Status* — `{status}`\n"
        f"*Corpus:* {corpus} examples | *Cache:* {data.get('cache', '?')}\n"
        f"*Redis:* {data.get('redis', '?')} | *Evolution:* {data.get('evolution_engine', '?')}"
    )


async def _cmd_approve(token: str) -> Response:
    if not token:
        return _resp("Usage: `/warden approve <token>`")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.post(
                f"{_BASE}/agent/approve/{token}",
                params={"action": "approve"},
                headers={"X-API-Key": _API_KEY},
            )
            data   = r.json()
            status = data.get("status", "unknown")
        return _resp(f"✅ *Approved* — token `{token[:12]}…`\nStatus: `{status}`")
    except Exception as exc:
        return _resp(f"⚠️ Approval failed: {exc}")


def _help_resp() -> Response:
    return _resp(
        "*Shadow Warden — Slack Commands*\n"
        "• `/warden scan <text>` — scan text through the AI security filter\n"
        "• `/warden status` — gateway health snapshot\n"
        "• `/warden approve <token>` — approve a pending MasterAgent action\n"
        "• `/warden help` — show this message\n\n"
        "_Configure at: Slack App → Slash Commands → `/warden` → "
        "`https://api.shadow-warden-ai.com/slack/command`_"
    )
