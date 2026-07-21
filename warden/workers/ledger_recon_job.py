"""
warden/workers/ledger_recon_job.py
────────────────────────────────────
ARQ worker: nightly ledger reconciliation (FT-4 slice 2 + holds remainder).

`warden/finops/ledger_recon.py::credit_drift()` has existed since FT-2 slice
2d as pure computation — its own docstring said "no metrics/cron wiring here
(that is FT-4)." Nothing has ever called it on a schedule, so a real drift
between the ledger and its authoritative counters could sit unnoticed
indefinitely.

`run_ledger_reconciliation()` runs `credit_drift()`, publishes the
`warden_ledger_recon_drift_usd` gauge, and alerts on nonzero drift.

`run_holds_reconciliation()` is the two-phase-hold analogue: runs
`holds_drift()`, publishes `warden_ledger_holds_recon_mismatches`, and
alerts on any mismatch. Kept as a separate function/cron (not folded into
`run_ledger_reconciliation()`) so its return shape doesn't change — several
tests and any external consumer already depend on the flat `credit_drift()`
shape. `holds_drift()` is itself a no-op until `LEDGER_HOLDS_RECON_CUTOFF_TS`
is set (see `warden/finops/ledger_recon.py`).

Both recon functions are already fail-soft (never raise, degrade to an
ok-by-vacuity report on any read error) — these wrappers add observability
on top without changing that posture.

Environment variables
──────────────────────
  SLACK_WEBHOOK_URL            — optional; alert destination (warden/alerting.py)
  LEDGER_HOLDS_RECON_CUTOFF_TS — optional; enables holds_drift() (warden/config.py)
"""
from __future__ import annotations

import logging
from decimal import Decimal

from warden.alerting import send_alert
from warden.finops.ledger_recon import credit_drift, holds_drift
from warden.metrics import LEDGER_HOLDS_RECON_MISMATCHES, LEDGER_RECON_DRIFT_USD

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


def run_holds_reconciliation() -> dict:
    """Run holds_drift(), publish the gauge, alert on any mismatch.

    Returns the underlying holds_drift() report unchanged. A no-op
    (holds_checked=0, ok=True) until LEDGER_HOLDS_RECON_CUTOFF_TS is set.
    """
    report = holds_drift()

    try:
        LEDGER_HOLDS_RECON_MISMATCHES.set(report["mismatched"])
    except Exception as exc:
        log.debug("ledger_recon_job: holds gauge set failed (non-fatal): %s", exc)

    if not report["ok"]:
        log.warning(
            "ledger_recon_job: holds drift detected — holds_checked=%d mismatched=%d",
            report["holds_checked"], report["mismatched"],
        )
        try:
            send_alert(
                f":warning: Ledger holds reconciliation drift detected — "
                f"{report['mismatched']}/{report['holds_checked']} holds mismatched. "
                f"See `holds_drift()` details in logs.",
                level="warning",
            )
        except Exception as exc:
            log.debug("ledger_recon_job: holds alert failed (non-fatal): %s", exc)
    elif report["holds_checked"]:
        log.info(
            "ledger_recon_job: holds clean — holds_checked=%d, no mismatch",
            report["holds_checked"],
        )

    return report


async def nightly_ledger_recon(ctx: dict) -> dict:
    """ARQ cron entry point — see run_ledger_reconciliation() for the logic."""
    return run_ledger_reconciliation()


async def nightly_holds_recon(ctx: dict) -> dict:
    """ARQ cron entry point — see run_holds_reconciliation() for the logic."""
    return run_holds_reconciliation()
