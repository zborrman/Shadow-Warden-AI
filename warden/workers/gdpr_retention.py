"""
warden/workers/gdpr_retention.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ARQ background task: automatic GDPR data retention enforcement.

Runs daily at 02:00 UTC (configured in workers/settings.py).
Removes log entries older than GDPR_LOG_RETENTION_DAYS (default 30).
"""
from __future__ import annotations

import logging

log = logging.getLogger("warden.workers.gdpr_retention")


async def run_gdpr_retention(ctx: dict) -> dict:
    """ARQ task entrypoint for daily GDPR log retention enforcement."""
    try:
        from warden.api.gdpr import run_retention_purge  # noqa: PLC0415
        removed = await run_retention_purge()
        log.info("GDPR retention: removed %d expired log entries", removed)
        return {"ok": True, "removed": removed}
    except Exception as exc:
        log.error("GDPR retention failed: %s", exc)
        return {"ok": False, "error": str(exc)}
