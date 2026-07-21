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
when drift is nonzero. The recon itself is already fail-soft (never raises,
degrades to an ok-by-vacuity report on any read error) — this wrapper adds
observability on top without changing that posture.

`run_hold_reconciliation()` / `nightly_hold_recon` (FT-4 remainder) does the
same for `hold_drift()` — the last deferred item of FT-4's scope.

Environment variables
──────────────────────
  SLACK_WEBHOOK_URL — optional; alert destination (warden/alerting.py)
"""
from __future__ import annotations

import logging
from decimal import Decimal

from warden.alerting import send_alert
from warden.finops.ledger_recon import credit_drift, hold_drift
from warden.metrics import LEDGER_RECON_DRIFT_USD, LEDGER_RECON_HOLD_DRIFT_USD

log = logging.getLogger("warden.workers.ledger_recon_job")

_MICROS_PER_USD = Decimal("1000000")


def run_ledger_reconciliation() -> dict:
    """Run credit_drift(), publish the gauge, alert on nonzero drift.

    Returns the underlying credit_drift() report unchanged, so callers/tests
    can assert on the same shape the pure function already produces.
    """
    report = credit_drift()

    drift_usd = Decimal(report["total_abs_drift_micros"]) / _MICROS_PER_USD
    try:
        LEDGER_RECON_DRIFT_USD.set(float(drift_usd))
    except Exception as exc:
        log.debug("ledger_recon_job: gauge set failed (non-fatal): %s", exc)

    if not report["ok"]:
        log.warning(
            "ledger_recon_job: drift detected — tenants_checked=%d drifted=%d drift_usd=%s",
            report["tenants_checked"], report["drifted"], drift_usd,
        )
        try:
            send_alert(
                f":warning: Ledger reconciliation drift detected — "
                f"{report['drifted']}/{report['tenants_checked']} tenants drifted, "
                f"total ${drift_usd} USD. See `credit_drift()` details in logs.",
                level="warning",
            )
        except Exception as exc:
            log.debug("ledger_recon_job: alert failed (non-fatal): %s", exc)
    else:
        log.info(
            "ledger_recon_job: clean — tenants_checked=%d, no drift",
            report["tenants_checked"],
        )

    return report


async def nightly_ledger_recon(ctx: dict) -> dict:
    """ARQ cron entry point — see run_ledger_reconciliation() for the logic."""
    return run_ledger_reconciliation()


def run_hold_reconciliation() -> dict:
    """Run hold_drift(), publish the gauge, alert on nonzero drift.

    Returns the underlying hold_drift() report unchanged, so callers/tests can
    assert on the same shape the pure function already produces.
    """
    report = hold_drift()

    drift_usd = Decimal(report["total_abs_drift_micros"]) / _MICROS_PER_USD
    try:
        LEDGER_RECON_HOLD_DRIFT_USD.set(float(drift_usd))
    except Exception as exc:
        log.debug("ledger_recon_job: hold gauge set failed (non-fatal): %s", exc)

    if not report["ok"]:
        log.warning(
            "ledger_recon_job: hold drift detected — holds_checked=%d drifted=%d drift_usd=%s",
            report["holds_checked"], report["drifted"], drift_usd,
        )
        try:
            send_alert(
                f":warning: Ledger hold reconciliation drift detected — "
                f"{report['drifted']}/{report['holds_checked']} holds drifted, "
                f"total ${drift_usd} USD. See `hold_drift()` details in logs.",
                level="warning",
            )
        except Exception as exc:
            log.debug("ledger_recon_job: hold alert failed (non-fatal): %s", exc)
    else:
        log.info(
            "ledger_recon_job: holds clean — holds_checked=%d, no drift",
            report["holds_checked"],
        )

    return report


async def nightly_hold_recon(ctx: dict) -> dict:
    """ARQ cron entry point — see run_hold_reconciliation() for the logic."""
    return run_hold_reconciliation()
