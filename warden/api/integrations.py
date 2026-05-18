"""
warden/api/integrations.py  (IN-16/17/18/20)
──────────────────────────────────────────────
FastAPI router for third-party integrations.

Routes
──────
  POST /integrations/jira/issue          — create Jira security issue
  GET  /integrations/jira/health         — Jira credential check
  POST /integrations/teams/notify        — send Teams adaptive card
  GET  /integrations/teams/health        — Teams webhook check
  POST /integrations/notion/page         — create Notion security page
  GET  /integrations/notion/health       — Notion token check
  POST /integrations/zapier/event        — push event to Zapier/Make webhook
  GET  /integrations/zapier/health       — webhook URL check
"""
from __future__ import annotations

import logging
import os
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException

log = logging.getLogger("warden.api.integrations")

router = APIRouter(prefix="/integrations", tags=["integrations"])


# ── Jira (IN-16) ──────────────────────────────────────────────────────────────

@router.post("/jira/issue", summary="Create Jira security issue from filter event (IN-16)")
async def jira_create_issue(body: dict) -> dict:
    from warden.integrations.jira import create_issue
    verdict    = body.get("verdict", "HIGH")
    request_id = body.get("request_id", "unknown")
    flags      = body.get("flags", [])
    priority   = "Critical" if verdict == "BLOCK" else "High"

    result = await create_issue(
        summary     = f"[Warden] {verdict} threat detected — {', '.join(flags[:3]) or 'security event'}",
        description = (
            f"Shadow Warden AI detected a {verdict} threat.\n\n"
            f"Request ID: {request_id}\n"
            f"Flags: {', '.join(flags)}\n"
            f"Risk level: {body.get('risk_level', 'unknown')}\n"
            f"Timestamp: {datetime.now(UTC).isoformat()}\n\n"
            f"Review the SOC dashboard for full details."
        ),
        labels   = [f"verdict-{verdict.lower()}", *[f"flag-{f}" for f in flags[:5]]],
        priority = priority,
    )
    if not result.get("ok"):
        raise HTTPException(502, detail=result)
    return result


@router.get("/jira/health", summary="Check Jira connectivity (IN-16)")
async def jira_health() -> dict:
    from warden.integrations.jira import health_check
    return await health_check()


# ── Microsoft Teams (IN-17) ───────────────────────────────────────────────────

_TEAMS_WEBHOOK = os.getenv("TEAMS_WEBHOOK_URL", "")


async def _post_teams_card(card: dict) -> dict:
    if not _TEAMS_WEBHOOK:
        return {"ok": False, "error": "TEAMS_WEBHOOK_URL not set"}
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(_TEAMS_WEBHOOK, json=card)
        return {"ok": resp.status_code in (200, 202), "status": resp.status_code}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@router.post("/teams/notify", summary="Send Warden alert to Microsoft Teams (IN-17)")
async def teams_notify(body: dict) -> dict:
    verdict    = body.get("verdict", "HIGH")
    flags      = body.get("flags", [])
    request_id = body.get("request_id", "n/a")
    color      = "attention" if verdict == "BLOCK" else "warning"

    card = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {"type": "TextBlock", "size": "Medium", "weight": "Bolder",
                     "text": f"🛡️ Shadow Warden AI — {verdict} Threat Detected",
                     "color": color},
                    {"type": "FactSet", "facts": [
                        {"title": "Request ID", "value": request_id},
                        {"title": "Risk Level", "value": body.get("risk_level", "unknown")},
                        {"title": "Flags",      "value": ", ".join(flags) or "none"},
                        {"title": "Time",       "value": datetime.now(UTC).isoformat()[:19] + " UTC"},
                    ]},
                ],
                "actions": [{
                    "type": "Action.OpenUrl",
                    "title": "Open SOC Dashboard",
                    "url":   os.getenv("DASHBOARD_URL", "https://dash.shadow-warden-ai.com"),
                }],
            },
        }],
    }
    result = await _post_teams_card(card)
    if not result.get("ok"):
        raise HTTPException(502, detail=result)
    return result


@router.get("/teams/health", summary="Check Teams webhook (IN-17)")
async def teams_health() -> dict:
    return {"configured": bool(_TEAMS_WEBHOOK), "webhook_set": bool(_TEAMS_WEBHOOK)}


# ── Notion (IN-18) ────────────────────────────────────────────────────────────

_NOTION_TOKEN    = os.getenv("NOTION_API_TOKEN",    "")
_NOTION_PAGE_ID  = os.getenv("NOTION_PARENT_PAGE_ID", "")


async def _notion_create_page(title: str, content_blocks: list) -> dict:
    if not _NOTION_TOKEN:
        return {"ok": False, "error": "NOTION_API_TOKEN not set"}
    if not _NOTION_PAGE_ID:
        return {"ok": False, "error": "NOTION_PARENT_PAGE_ID not set"}
    try:
        import httpx
        payload = {
            "parent": {"type": "page_id", "page_id": _NOTION_PAGE_ID},
            "properties": {
                "title": {"title": [{"type": "text", "text": {"content": title[:2000]}}]},
            },
            "children": content_blocks,
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                "https://api.notion.com/v1/pages",
                headers={
                    "Authorization": f"Bearer {_NOTION_TOKEN}",
                    "Notion-Version": "2022-06-28",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
        if resp.status_code == 200:
            data = resp.json()
            return {"ok": True, "page_id": data.get("id"), "url": data.get("url")}
        return {"ok": False, "status": resp.status_code, "error": resp.text[:300]}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _text_block(text: str) -> dict:
    return {"object": "block", "type": "paragraph",
            "paragraph": {"rich_text": [{"type": "text", "text": {"content": text}}]}}


@router.post("/notion/page", summary="Create Notion security page from filter event (IN-18)")
async def notion_create_page(body: dict) -> dict:
    verdict    = body.get("verdict", "HIGH")
    flags      = body.get("flags", [])
    request_id = body.get("request_id", "n/a")
    ts         = datetime.now(UTC).isoformat()[:19] + " UTC"

    result = await _notion_create_page(
        title = f"[Warden] {verdict} — {ts}",
        content_blocks = [
            _text_block(f"Verdict: {verdict}  |  Risk: {body.get('risk_level', 'unknown')}"),
            _text_block(f"Request ID: {request_id}"),
            _text_block(f"Flags: {', '.join(flags) or 'none'}"),
            _text_block(f"Timestamp: {ts}"),
            _text_block("Created by Shadow Warden AI automated security scan."),
        ],
    )
    if not result.get("ok"):
        raise HTTPException(502, detail=result)
    return result


@router.get("/notion/health", summary="Check Notion API token (IN-18)")
async def notion_health() -> dict:
    if not _NOTION_TOKEN:
        return {"configured": False, "error": "NOTION_API_TOKEN not set"}
    try:
        import httpx
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(
                "https://api.notion.com/v1/users/me",
                headers={"Authorization": f"Bearer {_NOTION_TOKEN}", "Notion-Version": "2022-06-28"},
            )
        if resp.status_code == 200:
            return {"configured": True, "ok": True, "user": resp.json().get("name")}
        return {"configured": True, "ok": False, "status": resp.status_code}
    except Exception as exc:
        return {"configured": True, "ok": False, "error": str(exc)}


# ── Zapier / Make connector (IN-20) ──────────────────────────────────────────

_ZAPIER_WEBHOOK = os.getenv("ZAPIER_WEBHOOK_URL", "")
_MAKE_WEBHOOK   = os.getenv("MAKE_WEBHOOK_URL",   "")


@router.post("/zapier/event", summary="Push Warden event to Zapier or Make.com webhook (IN-20)")
async def zapier_event(body: dict) -> dict:
    target = _ZAPIER_WEBHOOK or _MAKE_WEBHOOK
    if not target:
        raise HTTPException(503, detail="Neither ZAPIER_WEBHOOK_URL nor MAKE_WEBHOOK_URL is set")

    payload = {
        "source":     "shadow-warden-ai",
        "timestamp":  datetime.now(UTC).isoformat(),
        "verdict":    body.get("verdict"),
        "risk_level": body.get("risk_level"),
        "flags":      body.get("flags", []),
        "request_id": body.get("request_id"),
        "tenant_id":  body.get("tenant_id"),
    }
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(target, json=payload)
        return {"ok": resp.status_code in (200, 201, 202), "status": resp.status_code}
    except Exception as exc:
        raise HTTPException(502, detail=str(exc)) from exc


@router.get("/zapier/health", summary="Check Zapier/Make webhook URL (IN-20)")
async def zapier_health() -> dict:
    return {
        "zapier_configured": bool(_ZAPIER_WEBHOOK),
        "make_configured":   bool(_MAKE_WEBHOOK),
        "active_target":     "zapier" if _ZAPIER_WEBHOOK else ("make" if _MAKE_WEBHOOK else None),
    }
