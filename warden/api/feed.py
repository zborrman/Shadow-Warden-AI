"""
warden/api/feed.py
━━━━━━━━━━━━━━━━━━━
Threat Intelligence Feed status + manual sync REST API.

Endpoints
─────────
  GET  /feed/status  — opt-in status, last sync, imported/submitted counts
  POST /feed/sync    — trigger an immediate feed sync (admin / debug)

Extracted from ``warden/main.py`` (Phase 3). The ThreatFeedClient singleton is
published to ``warden.runtime`` in the app lifespan and resolved here.
"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException

from warden.auth_guard import AuthResult, require_api_key
from warden.runtime import runtime as _runtime

router = APIRouter(tags=["threat-feed"])


@router.get(
    "/feed/status",
    summary="Threat Intelligence Feed status for this instance",
)
async def feed_status(auth: AuthResult = Depends(require_api_key)) -> dict:
    """
    Returns opt-in status, last sync time, number of imported rules, and
    number of rules this instance has submitted to the central feed.
    """
    feed = _runtime.get("feed")
    if feed is None:
        raise HTTPException(503, "ThreatFeedClient not initialised.")
    s = feed.status()
    return {
        "enabled":         s.enabled,
        "feed_url":        s.feed_url,
        "last_sync":       s.last_sync,
        "next_sync":       s.next_sync,
        "rules_imported":  s.rules_imported,
        "rules_submitted": s.rules_submitted,
        "errors":          s.errors,
    }


@router.post(
    "/feed/sync",
    summary="Trigger an immediate threat feed sync (admin / debug)",
)
async def feed_sync_now(auth: AuthResult = Depends(require_api_key)) -> dict:
    """Force an immediate download and import of the latest feed rules."""
    feed = _runtime.get("feed")
    if feed is None:
        raise HTTPException(503, "ThreatFeedClient not initialised.")
    if not feed.is_enabled():
        raise HTTPException(400, "Threat feed is disabled. Set THREAT_FEED_ENABLED=true.")
    loop = asyncio.get_running_loop()
    imported = await loop.run_in_executor(None, feed.sync)
    return {"imported": imported}
