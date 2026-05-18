"""
warden/integrations/jira.py  (IN-16)
──────────────────────────────────────
Jira integration — push Warden HIGH/BLOCK events to Jira as security issues.

Config (env vars)
─────────────────
  JIRA_BASE_URL    https://yourorg.atlassian.net
  JIRA_EMAIL       bot@yourorg.com
  JIRA_API_TOKEN   <Jira API token>
  JIRA_PROJECT_KEY SECURITY (default)
  JIRA_ISSUE_TYPE  Bug (default)

FastAPI endpoint
────────────────
  POST /integrations/jira/issue   — create Jira issue from a filter event
  GET  /integrations/jira/health  — verify credentials
"""
from __future__ import annotations

import base64
import logging
import os
from typing import Any

log = logging.getLogger("warden.integrations.jira")

_BASE    = os.getenv("JIRA_BASE_URL",    "")
_EMAIL   = os.getenv("JIRA_EMAIL",       "")
_TOKEN   = os.getenv("JIRA_API_TOKEN",   "")
_PROJECT = os.getenv("JIRA_PROJECT_KEY", "SECURITY")
_ITYPE   = os.getenv("JIRA_ISSUE_TYPE",  "Bug")


def _auth_header() -> str:
    creds = base64.b64encode(f"{_EMAIL}:{_TOKEN}".encode()).decode()
    return f"Basic {creds}"


def _available() -> bool:
    return bool(_BASE and _EMAIL and _TOKEN)


async def create_issue(
    summary:     str,
    description: str,
    labels:      list[str] | None = None,
    priority:    str = "High",
) -> dict[str, Any]:
    """Create a Jira issue and return the response dict."""
    if not _available():
        return {"ok": False, "error": "Jira not configured (JIRA_BASE_URL/EMAIL/API_TOKEN missing)"}

    try:
        import httpx

        payload = {
            "fields": {
                "project":     {"key": _PROJECT},
                "summary":     summary[:255],
                "description": {
                    "type": "doc", "version": 1,
                    "content": [{"type": "paragraph", "content": [{"type": "text", "text": description}]}],
                },
                "issuetype": {"name": _ITYPE},
                "priority":  {"name": priority},
                "labels":    (labels or []) + ["shadow-warden-ai", "security"],
            }
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{_BASE.rstrip('/')}/rest/api/3/issue",
                headers={"Authorization": _auth_header(), "Content-Type": "application/json"},
                json=payload,
            )
        if resp.status_code in (200, 201):
            data = resp.json()
            log.info("Jira issue created: %s", data.get("key"))
            return {"ok": True, "key": data.get("key"), "url": f"{_BASE}/browse/{data.get('key')}"}
        return {"ok": False, "status": resp.status_code, "error": resp.text[:300]}
    except Exception as exc:
        log.warning("jira create_issue error: %s", exc)
        return {"ok": False, "error": str(exc)}


async def health_check() -> dict[str, Any]:
    """Check if Jira credentials are valid."""
    if not _available():
        return {"ok": False, "configured": False, "error": "Missing JIRA_BASE_URL / JIRA_EMAIL / JIRA_API_TOKEN"}
    try:
        import httpx
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(
                f"{_BASE.rstrip('/')}/rest/api/3/myself",
                headers={"Authorization": _auth_header()},
            )
        if resp.status_code == 200:
            return {"ok": True, "configured": True, "user": resp.json().get("emailAddress")}
        return {"ok": False, "configured": True, "status": resp.status_code}
    except Exception as exc:
        return {"ok": False, "configured": True, "error": str(exc)}
