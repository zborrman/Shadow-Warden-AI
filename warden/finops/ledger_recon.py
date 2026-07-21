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

Holds (`hold_drift`, FT-4 remainder) reconcile differently: `hold:{hold_id}`
is a per-transaction contra account, not a per-tenant running balance, so each
currently-open hold (`sac.preflight.open_holds()`, status='HELD') is checked
individually against its own ledger account. A hold that predates dual-write
being enabled has no mirrored ledger entry yet and reads as drift — but
because holds are short-lived (reserve → commit/release within one agent
run), that hold drops out of the open-hold set the moment it resolves, so the
false positive self-clears quickly instead of persisting like an unbackfilled
credit balance would.

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


def hold_drift() -> dict:
    """Compare every currently-open hold's ledger balance to its live amount.

    Returns a summary:
        {holds_checked, drifted, total_abs_drift_micros, ok, details}
    where ``details`` lists only the drifted holds. Fail-soft: any read error
    yields an empty, ``ok``-by-vacuity report rather than raising.
    """
    try:
        from warden.ledger import accounts, dual_write
        from warden.sac import preflight
    except Exception as exc:
        log.debug("ledger_recon: modules unavailable (%s)", exc)
        return _hold_summary([])

    try:
        holds = preflight.open_holds()
    except Exception as exc:
        log.debug("ledger_recon: hold enumeration failed (%s)", exc)
        return _hold_summary([])

    details: list[dict] = []
    for h in holds:
        try:
            rep = dual_write.reconcile(accounts.hold(h["hold_id"]), h["amount_micros"])
        except Exception as exc:
            log.debug("ledger_recon: reconcile failed hold=%s (%s)", h["hold_id"], exc)
            continue
        if not rep["ok"]:
            details.append({"hold_id": h["hold_id"], "tenant_id": h["tenant_id"], **rep})
    return _hold_summary(details, holds_checked=len(holds))


def _hold_summary(details: list[dict], holds_checked: int | None = None) -> dict:
    total = sum(abs(d["drift_micros"]) for d in details)
    return {
        "holds_checked": holds_checked if holds_checked is not None else 0,
        "drifted": len(details),
        "total_abs_drift_micros": total,
        "ok": len(details) == 0,
        "details": details,
    }
