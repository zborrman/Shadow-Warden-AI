"""
warden/workers/settings.py
──────────────────────────
ARQ WorkerSettings — registers all background tasks and cron jobs.

Run the worker with:
    arq warden.workers.settings.WorkerSettings

Or via the Helm chart (arq-worker Deployment), which sets:
    command: ["arq", "warden.workers.settings.WorkerSettings"]

Cron schedule
─────────────
  weekly_reports  — every Friday at 08:00 UTC
    Sends the Weekly ROI Impact Report email to all active paid tenants.

Environment variables
─────────────────────
  REDIS_URL  — Redis connection string (default redis://localhost:6379/0)
               ARQ uses Redis as its job queue backend.
"""
from __future__ import annotations

import logging
import os

from arq import cron
from arq.connections import RedisSettings

from warden.workers.weekly_report import send_weekly_reports

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

_REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")


async def startup(ctx: dict) -> None:
    logging.getLogger("warden.workers").setLevel(logging.INFO)
    logging.getLogger("arq").setLevel(logging.INFO)


class WorkerSettings:
    """ARQ worker configuration for Shadow Warden background tasks."""

    redis_settings = RedisSettings.from_dsn(_REDIS_URL)

    functions = [send_weekly_reports]

    cron_jobs = [
        # Every Friday at 08:00 UTC
        cron(send_weekly_reports, weekday=4, hour=8, minute=0, timeout=600),
    ]

    on_startup  = startup
    max_jobs    = 10
    job_timeout = 600   # 10 minutes max per job
    keep_result = 3600  # keep result in Redis for 1 hour
