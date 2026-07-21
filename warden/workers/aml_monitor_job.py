"""
warden/workers/aml_monitor_job.py
──────────────────────────────────
ARQ worker: scheduled AML structuring sweep over the ledger journal (FT-5).

`finops/aml_monitor.py::scan_for_structuring()` is pure and already opens its
own COMPLIANCE incidents on a hit — this wrapper just gives it a schedule.
No-op end to end unless `AML_MONITOR_ENABLED=true`.
"""
from __future__ import annotations

import logging

from warden.finops.aml_monitor import scan_for_structuring

log = logging.getLogger("warden.workers.aml_monitor_job")


def run_aml_scan() -> dict:
    """Run scan_for_structuring(), logging a summary either way.

    Returns the underlying report unchanged, so callers/tests can assert on
    the same shape the pure function already produces.
    """
    report = scan_for_structuring()

    if not report.get("scanned"):
        log.debug("aml_monitor_job: scan disabled or unavailable: %s", report)
        return report

    if report["flagged"]:
        log.warning(
            "aml_monitor_job: structuring pattern(s) detected — accounts_scanned=%d flagged=%d",
            report["accounts_scanned"], report["flagged"],
        )
    else:
        log.info(
            "aml_monitor_job: clean — accounts_scanned=%d, no structuring detected",
            report["accounts_scanned"],
        )

    return report


async def nightly_aml_scan(ctx: dict) -> dict:
    """ARQ cron entry point — see run_aml_scan() for the logic."""
    return run_aml_scan()
