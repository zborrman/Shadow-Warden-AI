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
  weekly_reports              — every Friday at 08:00 UTC
    Sends the Weekly ROI Impact Report email to all active paid tenants.

  reap_expired_tunnels        — every 5 minutes
    Crypto-shreds AES keys for expired Syndicate tunnels and marks them
    EXPIRED in Postgres (double safety — Redis EXPIRE also fires at TTL).

  notify_impending_expiration — every 15 minutes
    Sends Slack warnings for tunnels expiring within the next hour.

Environment variables
─────────────────────
  REDIS_URL          — Redis connection string (default redis://localhost:6379/0)
  DATABASE_URL       — PostgreSQL for reaper DB queries
  SLACK_WEBHOOK_URL  — optional; reaper expiration alerts

  scan_cves                   — every 6 hours (00:10, 06:10, 12:10, 18:10)
    OSV API dependency CVE scan → data/cve_report.json → Slack on new CRITICALs.

  sova_community_watchdog     — every hour at :20
    Auto-blocks WARN-scored posts ≥ 0.85; alerts Slack on any BLOCK verdicts.
"""
from __future__ import annotations

import logging
import os

from arq import cron
from arq.connections import RedisSettings

from warden.agent.scheduler import (
    sova_community_watchdog,
    sova_corpus_watchdog,
    sova_error_budget_alert,
    sova_marketplace_state_sync,
    sova_morning_brief,
    sova_nightly_backup,
    sova_obsidian_watchdog,
    sova_overage_billing,
    sova_rotation_check,
    sova_sla_report,
    sova_soc2_daily_collect,
    sova_threat_sync,
    sova_tunnel_health_check,
    sova_upgrade_scan,
    sova_visual_patrol,
)
from warden.brain.online_learner import online_learning_job
from warden.workers.clearing_outbox_relay import relay_clearing_outbox
from warden.workers.content_filter import moderate_post
from warden.workers.cve_scanner import scan_cves
from warden.workers.dunning import process_dunning
from warden.workers.gdpr_retention import run_gdpr_retention
from warden.workers.ledger_recon_job import nightly_ledger_recon
from warden.workers.reaper import (
    notify_impending_expiration,
    reap_expired_tunnels,
)
from warden.workers.settings_watcher import watch_config_drift
from warden.workers.weekly_report import send_weekly_reports
from warden.workers.x402_settlement import settle_x402_deductions

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

_REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")


async def startup(ctx: dict) -> None:
    logging.getLogger("warden.workers").setLevel(logging.INFO)
    logging.getLogger("arq").setLevel(logging.INFO)
    logging.getLogger("warden.workers.reaper").setLevel(logging.INFO)


class WorkerSettings:
    """ARQ worker configuration for Shadow Warden background tasks."""

    redis_settings = RedisSettings.from_dsn(_REDIS_URL)

    functions = [
        send_weekly_reports,
        process_dunning,
        reap_expired_tunnels,
        notify_impending_expiration,
        # SOVA Agent jobs
        sova_morning_brief,
        sova_threat_sync,
        sova_rotation_check,
        sova_sla_report,
        sova_upgrade_scan,
        sova_corpus_watchdog,
        sova_tunnel_health_check,
        sova_error_budget_alert,     # FM-5 — SLA burn-rate alerts
        sova_visual_patrol,
        sova_community_watchdog,
        sova_obsidian_watchdog,
        sova_overage_billing,        # BL-19
        sova_marketplace_state_sync, # M2M loop state
        sova_nightly_backup,         # Phase 6 — encrypted DB backup
        # Online learning pipeline
        online_learning_job,          # AR-09
        # Community moderation
        moderate_post,
        # Cyber Security Hub
        scan_cves,
        # Settings watcher
        watch_config_drift,
        # GDPR retention
        run_gdpr_retention,
        # x402 settlement (FT-4 slice 1)
        settle_x402_deductions,
        # Ledger reconciliation (FT-4 slice 2)
        nightly_ledger_recon,
        # Clearing outbox relay (FT-4 slice 3)
        relay_clearing_outbox,
    ]

    cron_jobs = [
        # ── Weekly ROI email — every Friday 08:00 UTC ─────────────────────────
        cron(send_weekly_reports, weekday=4, hour=8, minute=0, timeout=600),

        # ── Dunning — every 12 hours (06:00 + 18:00 UTC) ─────────────────────
        cron(process_dunning, hour={6, 18}, minute=0, timeout=120),

        # ── Syndicate Reaper — every 5 minutes ───────────────────────────────
        cron(
            reap_expired_tunnels,
            minute={0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55},
            timeout=120,
        ),

        # ── Expiration warnings — every 15 minutes ────────────────────────────
        cron(
            notify_impending_expiration,
            minute={0, 15, 30, 45},
            timeout=60,
        ),

        # ── SOVA Agent — daily morning brief 08:00 UTC ────────────────────────
        cron(sova_morning_brief, hour=8, minute=0, timeout=300),

        # ── SOVA Agent — threat intel sync every 6 hours ──────────────────────
        cron(sova_threat_sync, hour={0, 6, 12, 18}, minute=5, timeout=300),

        # ── SOVA Agent — key rotation check 02:00 UTC daily ──────────────────
        cron(sova_rotation_check, hour=2, minute=0, timeout=180),

        # ── SOVA Agent — SLA report every Monday 09:00 UTC ───────────────────
        cron(sova_sla_report, weekday=0, hour=9, minute=0, timeout=300),

        # ── SOVA Agent — upgrade scan every Sunday 10:00 UTC ─────────────────
        cron(sova_upgrade_scan, weekday=6, hour=10, minute=0, timeout=300),

        # ── SOVA Agent — corpus watchdog every 30 minutes ────────────────────
        cron(sova_corpus_watchdog, minute={0, 30}, timeout=30),

        # ── MASQUE tunnel health check — every 5 minutes ──────────────────────
        cron(
            sova_tunnel_health_check,
            minute={0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55},
            timeout=60,
        ),

        # ── SLA error-budget burn-rate alert — every 30 minutes (FM-5) ────────
        cron(sova_error_budget_alert, minute={0, 30}, timeout=60),

        # ── SOVA Agent — visual patrol nightly 03:00 UTC ─────────────────────
        cron(sova_visual_patrol, hour=3, minute=0, timeout=300),

        # ── Cyber Security Hub — CVE scan every 6 hours ───────────────────────
        cron(scan_cves, hour={0, 6, 12, 18}, minute=10, timeout=300),

        # ── Community moderation watchdog — every hour ────────────────────────
        cron(sova_community_watchdog, minute=20, timeout=120),

        # ── Config drift + canary probe — every 15 minutes ───────────────────
        cron(watch_config_drift, minute={0, 15, 30, 45}, timeout=60),

        # ── GDPR auto-retention — daily at 02:00 UTC ─────────────────────────
        cron(run_gdpr_retention, hour=2, minute=0, timeout=120),

        # ── Obsidian vault watchdog — every 4 hours ───────────────────────────
        cron(sova_obsidian_watchdog, hour={0, 4, 8, 12, 16, 20}, minute=45, timeout=60),

        # ── Overage billing — monthly on 1st at 00:05 UTC (BL-19) ─────────────
        cron(sova_overage_billing, day=1, hour=0, minute=5, timeout=300),

        # ── Online learning — nightly at 01:00 UTC (AR-09) ───────────────────
        cron(online_learning_job, hour=1, minute=0, timeout=600),

        # ── M2M marketplace loop state sync — every 15 minutes ───────────────
        cron(sova_marketplace_state_sync, minute={0, 15, 30, 45}, timeout=60),

        # ── SOC 2 Type II evidence collection — daily at 00:00 UTC ───────────
        cron(sova_soc2_daily_collect, hour=0, minute=0, timeout=300),

        # ── Nightly encrypted DB backup — daily at 03:30 UTC (Phase 6) ───────
        cron(sova_nightly_backup, hour=3, minute=30, timeout=600),

        # ── x402 pending-deduction settlement — every 15 minutes (FT-4) ──────
        cron(settle_x402_deductions, minute={0, 15, 30, 45}, timeout=60),

        # ── Ledger reconciliation — daily at 04:00 UTC (FT-4 slice 2) ────────
        cron(nightly_ledger_recon, hour=4, minute=0, timeout=300),

        # ── Clearing outbox relay — every 5 minutes (FT-4 slice 3) ───────────
        cron(
            relay_clearing_outbox,
            minute={0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55},
            timeout=120,
        ),
    ]

    on_startup  = startup
    max_jobs    = 10
    job_timeout = 600   # 10 minutes max per job
    keep_result = 3600  # keep result in Redis for 1 hour
