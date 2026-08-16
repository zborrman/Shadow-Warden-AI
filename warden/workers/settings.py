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

import functools
import logging
import os
import time
from collections.abc import Callable
from typing import Any

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

# Registers the shared metric singletons into the default prometheus_client
# REGISTRY. Imported explicitly rather than relied on transitively, because the
# metrics HTTP server below serves that registry and must not race a lazy import.
from warden.metrics import (
    ARQ_JOB_DURATION_SECONDS,
    ARQ_JOB_LAST_SUCCESS,
    ARQ_JOBS_TOTAL,
)
from warden.workers.aml_monitor_job import nightly_aml_scan
from warden.workers.clearing_outbox_relay import (
    purge_clearing_outbox,
    relay_clearing_outbox,
)
from warden.workers.content_filter import moderate_post
from warden.workers.cve_scanner import scan_cves
from warden.workers.dunning import process_dunning
from warden.workers.gdpr_retention import run_gdpr_retention
from warden.workers.ledger_recon_job import nightly_hold_recon, nightly_ledger_recon
from warden.workers.order_recon_job import nightly_order_mirror_recon
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

# ── OB-4: worker observability ───────────────────────────────────────────────
# This container has no HTTP surface, so until OB-4 nothing here was scrapeable:
# 31 cron jobs — the nightly encrypted backup, overage settlement, ledger and
# hold reconciliation, x402 settlement, the clearing outbox relay, the AML sweep
# — ran with no `up` series, no duration, no failure counter. A cron that stops
# firing looks exactly like a cron that runs and finds nothing to do.
#
# 9110 avoids the exporter ports already in use on this network: node-exporter
# 9100, redis-exporter 9121, postgres-exporter 9187.
_METRICS_PORT = int(os.getenv("ARQ_METRICS_PORT", "9110"))

_log = logging.getLogger("warden.workers.metrics")


def _start_metrics_server() -> None:
    """Expose the default prometheus registry over HTTP.

    Telemetry must never stop the worker from running the money crons, so a
    bind failure is non-fatal — but it is not free either: the worker then runs
    the backup, settlement and reconciliation jobs with no `up` series and no
    failure counter, which is the exact blind spot OB-4 closed. So the
    degradation is counted rather than merely logged, via record_failopen().
    """
    try:
        from prometheus_client import start_http_server

        start_http_server(_METRICS_PORT)
        _log.info("arq metrics server listening on :%d", _METRICS_PORT)
    except Exception as exc:                       # pragma: no cover - defensive
        _log.warning("arq metrics server unavailable (%s) — continuing", exc)
        try:
            from warden.observability import record_failopen

            record_failopen("arq_metrics", "metrics_server_unavailable", exc)
        except Exception:                          # pragma: no cover - defensive
            _log.debug("could not record arq metrics degradation", exc_info=True)


_WRAPPED: dict[Callable[..., Any], Callable[..., Any]] = {}


def _instrument(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap an arq job so every execution is counted, timed and dated.

    ``functools.wraps`` preserves ``__name__``/``__qualname__``, which is how
    arq derives the registered job name — so wrapping changes what is measured,
    never what is scheduled or how it is enqueued. Memoised so a function listed
    in both ``functions`` and ``cron_jobs`` yields one wrapper, not two.
    """
    cached = _WRAPPED.get(fn)
    if cached is not None:
        return cached

    name = getattr(fn, "__name__", repr(fn))

    def _record(status: str, elapsed: float) -> None:
        # Metric bookkeeping is never allowed to turn a successful job into a
        # failed one, nor to mask a real exception on the failure path.
        try:
            ARQ_JOBS_TOTAL.labels(task=name, status=status).inc()
            ARQ_JOB_DURATION_SECONDS.labels(task=name).observe(elapsed)
            if status == "complete":
                ARQ_JOB_LAST_SUCCESS.labels(task=name).set(time.time())
        except Exception:                          # pragma: no cover - defensive
            _log.debug("arq metric update failed for %s", name, exc_info=True)

    @functools.wraps(fn)
    async def _wrapper(*args: Any, **kwargs: Any) -> Any:
        started = time.monotonic()
        try:
            result = await fn(*args, **kwargs)
        except Exception:
            _record("failed", time.monotonic() - started)
            raise
        _record("complete", time.monotonic() - started)
        return result

    _WRAPPED[fn] = _wrapper
    return _wrapper


async def startup(ctx: dict) -> None:
    logging.getLogger("warden.workers").setLevel(logging.INFO)
    logging.getLogger("arq").setLevel(logging.INFO)
    logging.getLogger("warden.workers.reaper").setLevel(logging.INFO)
    _start_metrics_server()


class WorkerSettings:
    """ARQ worker configuration for Shadow Warden background tasks."""

    redis_settings = RedisSettings.from_dsn(_REDIS_URL)

    # Each entry is wrapped by _instrument() — same registered name, same
    # behaviour, plus a run counter, a duration histogram and a last-success
    # timestamp. Add new jobs to the tuple; the wrapping is automatic.
    functions = [_instrument(_fn) for _fn in (
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
        # Ledger hold reconciliation (FT-4 remainder)
        nightly_hold_recon,
        # FT-6 order-mirror reconciliation (Phase C gate)
        nightly_order_mirror_recon,
        # Clearing outbox relay (FT-4 slice 3)
        relay_clearing_outbox,
        # Clearing outbox retention/cleanup (FT-4 remainder)
        purge_clearing_outbox,
        # AML structuring sweep on the journal (FT-5)
        nightly_aml_scan,
    )]

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

        # ── Ledger hold reconciliation — daily at 04:10 UTC (FT-4 remainder) ──
        cron(nightly_hold_recon, hour=4, minute=10, timeout=300),

        # ── FT-6 order-mirror reconciliation — daily at 04:20 UTC ────────────
        # The only thing that produces the evidence Phase C is gated on.
        cron(nightly_order_mirror_recon, hour=4, minute=20, timeout=300),

        # ── Clearing outbox relay — every 5 minutes (FT-4 slice 3) ───────────
        cron(
            relay_clearing_outbox,
            minute={0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55},
            timeout=120,
        ),

        # ── Clearing outbox retention — weekly Sunday 05:00 UTC (FT-4) ───────
        cron(purge_clearing_outbox, weekday=6, hour=5, minute=0, timeout=120),

        # ── AML structuring sweep — daily 04:20 UTC (FT-5) ───────────────────
        cron(nightly_aml_scan, hour=4, minute=20, timeout=300),
    ]

    on_startup  = startup
    max_jobs    = 10
    job_timeout = 600   # 10 minutes max per job
    keep_result = 3600  # keep result in Redis for 1 hour


# Instrument the cron entries in place. `cron()` has already captured the job
# name by the time this runs, and _instrument preserves __name__ anyway, so this
# swaps the callable without touching the schedule. Guarded with getattr because
# CronJob.coroutine is arq-internal (pinned at arq==0.28.0 in constraints.txt):
# if a future arq renames it, the worker keeps running with no metrics rather
# than failing to import.
for _cron_job in WorkerSettings.cron_jobs:
    _coro = getattr(_cron_job, "coroutine", None)
    if _coro is not None:
        _cron_job.coroutine = _instrument(_coro)
    else:                                          # pragma: no cover - defensive
        logging.getLogger("warden.workers.metrics").warning(
            "CronJob has no .coroutine attribute — arq internals changed, "
            "cron metrics are not being recorded"
        )
