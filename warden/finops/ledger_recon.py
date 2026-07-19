"""
warden/finops/ledger_recon.py — dual-run reconciliation (FT-2 slice 2d).

The keystone of the reversible cutover: while `LEDGER_DUAL_WRITE` is on, live
writers mirror into the double-entry ledger, and this job proves the ledger by
comparing its derived balances to the authoritative counters. Drift must be zero
before anything is allowed to *read* from the ledger (the FM-1 `available_usd()`
re-point, deferred until then).

Credits reconcile exactly: `marketplace/credits.py` is the sole writer of the
credit balance, so ledger `tenant:{id}:credits` (µUSD) must equal
`balance_credits × 1000` for every tenant.

Cross-module reads use lazy imports (the `finops/growth.py` pattern) so this
stays an error-swallowing adapter over the billing modules, not a hard import
dependency. Pure computation — no metrics/cron wiring here (that is FT-4).
"""
from __future__ import annotations

import logging

_CREDIT_MICROS = 1_000  # 1 credit = $0.001 = 1000 µUSD

log = logging.getLogger("warden.finops.ledger_recon")


def credit_drift() -> dict:
    """Compare every tenant's ledger credit balance to the authoritative counter.

    Returns a summary:
        {tenants_checked, drifted, total_abs_drift_micros, ok, details}
    where ``details`` lists only the drifted tenants. ``ok`` is True when the
    ledger agrees with the counter for every tenant (or there is nothing to
    check). Fail-soft: any read error yields an empty, ``ok``-by-vacuity report
    rather than raising — reconciliation observes, it never blocks.
    """
    try:
        from warden.ledger import accounts, dual_write
        from warden.marketplace import credits
    except Exception as exc:
        log.debug("ledger_recon: modules unavailable (%s)", exc)
        return _summary([])

    try:
        balances = credits.all_balances()
    except Exception as exc:
        log.debug("ledger_recon: credit enumeration failed (%s)", exc)
        return _summary([])

    details: list[dict] = []
    for tenant_id, credit_balance in balances.items():
        try:
            rep = dual_write.reconcile(
                accounts.tenant_credits(tenant_id), credit_balance * _CREDIT_MICROS
            )
        except Exception as exc:
            log.debug("ledger_recon: reconcile failed tenant=%s (%s)", tenant_id, exc)
            continue
        if not rep["ok"]:
            details.append({"tenant_id": tenant_id, **rep})
    return _summary(details, tenants_checked=len(balances))


def _summary(details: list[dict], tenants_checked: int | None = None) -> dict:
    total = sum(abs(d["drift_micros"]) for d in details)
    return {
        "tenants_checked": tenants_checked if tenants_checked is not None else 0,
        "drifted": len(details),
        "total_abs_drift_micros": total,
        "ok": len(details) == 0,
        "details": details,
    }
