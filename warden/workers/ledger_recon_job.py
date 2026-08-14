"""
warden/workers/ledger_recon_job.py
────────────────────────────────────
ARQ worker: nightly ledger reconciliation (FT-4 slice 2).

`warden/finops/ledger_recon.py::credit_drift()` has existed since FT-2 slice
2d as pure computation — its own docstring says "no metrics/cron wiring here
(that is FT-4)." Nothing has ever called it on a schedule, so a real drift
between the ledger and its authoritative counters could sit unnoticed
indefinitely.

This job runs `credit_drift()`, publishes the result as the
`warden_ledger_recon_drift_usd` Prometheus gauge, and fires a Slack alert
when drift is nonzero. The recon itself is fail-soft (never raises) — this
wrapper adds observability on top without changing that posture.

`run_hold_reconciliation()` / `nightly_hold_recon` (FT-4 remainder) does the
same for `hold_drift()` — the last deferred item of FT-4's scope.

Two things are alerted on, not one
──────────────────────────────────
Drift is the obvious failure. The silent one is a reconciliation that could
not run: before the FT-2 evidence work, a run in which the ledger was
unreachable for *every* tenant produced `drifted=0, ok=True`, set the drift
gauge to 0.0, and logged "clean" — indistinguishable from a healthy night, on
the job whose entire purpose is to be the money path's tripwire.

So a run whose subjects could not be reconciled now alerts —
`evidence="not_available"`, or subjects enumerated that failed to reconcile —
and `record_failopen()` inside `ledger_recon` counts the same events onto
`warden_stage_failopen_total{stage="ledger_recon_credits"}` for alert rules.

It deliberately does *not* alert on `evidence="nothing_to_check"`: an empty
credits table or no open holds is a normal quiet night, and paging on it
nightly would train everyone to ignore this alert. That state is still not
reported as agreement — it is logged as what it is, and
`ledger_recon.read_cutover_ready()` (see `scripts/finops_report.py
--ledger-gate`) refuses to call it evidence.

Environment variables
──────────────────────
  SLACK_WEBHOOK_URL — optional; alert destination (warden/alerting.py)
"""
from __future__ import annotations

import logging
from decimal import Decimal

from warden.alerting import send_alert
from warden.finops.ledger_recon import COUNTED, NOT_AVAILABLE, credit_drift, hold_drift
from warden.metrics import LEDGER_RECON_DRIFT_USD, LEDGER_RECON_HOLD_DRIFT_USD

log = logging.getLogger("warden.workers.ledger_recon_job")

_MICROS_PER_USD = Decimal("1000000")


def _publish(report: dict, *, subject: str, count_key: str, gauge) -> dict:
    """Publish the drift gauge + alerts for one reconciliation report. Never raises."""
    drift_usd = Decimal(report["total_abs_drift_micros"]) / _MICROS_PER_USD
    checked = report[count_key]
    blind = report["evidence"] != COUNTED

    try:
        gauge.set(float(drift_usd))
    except Exception as exc:
        log.debug("ledger_recon_job: %s gauge set failed (non-fatal): %s", subject, exc)

    alerts: list[str] = []
    if not report["ok"]:
        alerts.append(
            f"{report['drifted']}/{checked} {subject} drifted, total ${drift_usd} USD"
        )
    # A run that verified nothing *because something broke* is the failure this
    # job used to report as a clean night. "nothing_to_check" is not that.
    if report["evidence"] == NOT_AVAILABLE:
        alerts.append(f"{subject} reconciliation could not run — it verified nothing")
    if report["unreadable"]:
        alerts.append(
            f"{report['unreadable']} {subject} enumerated but could not be reconciled"
        )

    if alerts:
        detail = "; ".join(alerts)
        log.warning("ledger_recon_job: %s — %s", subject, detail)
        try:
            send_alert(
                f":warning: Ledger reconciliation ({subject}) — {detail}. "
                f"See `warden.finops.ledger_recon` details in logs.",
                level="warning",
            )
        except Exception as exc:
            log.debug("ledger_recon_job: %s alert failed (non-fatal): %s", subject, exc)
    elif blind:
        # Quiet, honest, unalarming: nothing to reconcile is a real state. It is
        # logged as that rather than as "clean", so the shadow period cannot be
        # declared over on the strength of a log line.
        log.info("ledger_recon_job: %s — nothing to reconcile (evidence=%s)",
                 subject, report["evidence"])
    else:
        log.info("ledger_recon_job: %s clean — %d checked, no drift", subject, checked)

    return report


def run_ledger_reconciliation() -> dict:
    """Run credit_drift(), publish the gauge, alert on drift or on a failed check.

    Returns the underlying credit_drift() report unchanged, so callers/tests
    can assert on the same shape the pure function already produces.
    """
    return _publish(
        credit_drift(),
        subject="credits",
        count_key="tenants_checked",
        gauge=LEDGER_RECON_DRIFT_USD,
    )


async def nightly_ledger_recon(ctx: dict) -> dict:
    """ARQ cron entry point — see run_ledger_reconciliation() for the logic."""
    return run_ledger_reconciliation()


def run_hold_reconciliation() -> dict:
    """Run hold_drift(), publish the gauge, alert on drift or on a failed check.

    Returns the underlying hold_drift() report unchanged, so callers/tests can
    assert on the same shape the pure function already produces.
    """
    return _publish(
        hold_drift(),
        subject="holds",
        count_key="holds_checked",
        gauge=LEDGER_RECON_HOLD_DRIFT_USD,
    )


async def nightly_hold_recon(ctx: dict) -> dict:
    """ARQ cron entry point — see run_hold_reconciliation() for the logic."""
    return run_hold_reconciliation()
