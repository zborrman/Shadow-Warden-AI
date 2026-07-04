"""
warden/api/admin_reports.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Admin-triggered reporting endpoints.

Endpoints
─────────
  POST /admin/weekly-report  — manually trigger the weekly ROI email reports

Extracted from ``warden/main.py`` (Phase 3). Fully self-contained: gated by the
``SUPER_ADMIN_KEY`` header check and delegates to the weekly-report worker via a
lazy import; no runtime singletons required.
"""
from __future__ import annotations

import asyncio
import logging
import os

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

log = logging.getLogger("warden.api.admin_reports")

router = APIRouter()


@router.post("/admin/weekly-report", tags=["Admin"], summary="Trigger weekly ROI email reports now")
async def trigger_weekly_report(request: Request):
    """Manually trigger the weekly ROI report for all active paid tenants."""
    _key = request.headers.get("X-Super-Admin-Key", "")
    _expected = os.getenv("SUPER_ADMIN_KEY", "")
    if not _expected or _key != _expected:
        return JSONResponse({"detail": "Forbidden"}, status_code=403)

    loop = asyncio.get_event_loop()
    try:
        from warden.workers.weekly_report import send_weekly_reports as _swr  # noqa: PLC0415
        result = await loop.run_in_executor(None, lambda: asyncio.run(_swr({})))
    except Exception as exc:
        log.error("admin/weekly-report: failed: %s", exc)
        return JSONResponse({"detail": str(exc)}, status_code=500)

    return result
