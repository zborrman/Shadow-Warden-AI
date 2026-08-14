"""
warden/workers/order_recon_job.py
─────────────────────────────────
ARQ worker: nightly FT-6 order-mirror reconciliation.

`finops/order_recon.py::order_mirror_drift()` compares every source-of-truth
order (`m2m_orders`, `commerce_orders`) to its Phase B mirror row in
`marketplace_purchases`. This wrapper is what makes it a standing measurement
rather than a function somebody could run — `credit_drift()` sat uncalled for
two slices for exactly that reason, and FT-6 Phase C is gated on evidence this
job is the only thing producing.

It alerts on two conditions, mirroring `ledger_recon_job.py`:

* the mirror disagrees with the source (missing / mismatched / orphaned rows),
* the check could not run, or enumerated orders it could not read.

It stays silent when there is simply nothing to reconcile — production has had
zero orders on both sides since Phase B shipped, and a nightly page for that
would train everyone to ignore the alert. Silence is not agreement, and
`order_recon.phase_c_ready()` refuses to treat it as such.

Environment variables
──────────────────────
  SLACK_WEBHOOK_URL — optional; alert destination (warden/alerting.py)
"""
from __future__ import annotations

import logging

from warden.alerting import send_alert
from warden.finops.order_recon import order_mirror_drift
from warden.observability import COUNTED, NOT_AVAILABLE

log = logging.getLogger("warden.workers.order_recon_job")


def run_order_mirror_reconciliation() -> dict:
    """Run order_mirror_drift(), alert on disagreement or on a failed check.

    Returns the underlying report unchanged so callers/tests can assert on the
    same shape the pure function produces.
    """
    report = order_mirror_drift()

    alerts: list[str] = []
    if not report["ok"]:
        alerts.append(
            f"{report['missing']} missing, {report['mismatched']} mismatched, "
            f"{report['orphaned']} orphaned out of {report['orders_checked']} orders"
        )
    if report["evidence"] == NOT_AVAILABLE:
        alerts.append("the order-mirror check could not run — it compared nothing")
    if report["unreadable"]:
        alerts.append(f"{report['unreadable']} order(s) could not be read")

    if alerts:
        detail = "; ".join(alerts)
        log.warning("order_recon_job: %s", detail)
        try:
            send_alert(
                f":warning: FT-6 order mirror — {detail}. "
                f"Phase C stays blocked. See `warden.finops.order_recon` details in logs.",
                level="warning",
            )
        except Exception as exc:
            log.debug("order_recon_job: alert failed (non-fatal): %s", exc)
    elif report["evidence"] != COUNTED:
        log.info("order_recon_job: nothing to reconcile (evidence=%s)", report["evidence"])
    else:
        log.info("order_recon_job: clean — %d orders compared", report["orders_checked"])

    return report


async def nightly_order_mirror_recon(ctx: dict) -> dict:
    """ARQ cron entry point — see run_order_mirror_reconciliation()."""
    return run_order_mirror_reconciliation()
