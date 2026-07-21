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
dependency. Pure computation — metrics/cron wiring lives in
`warden/workers/ledger_recon_job.py` (FT-4).

`holds_drift()` (FT-4 remainder) is the two-phase-hold analogue of
`credit_drift()`: it compares `sac/preflight.py`'s live `sac_holds` state
machine to its `ledger/holds.py` mirror, scoped to holds created after the
`ledger_holds_recon_cutoff_ts` cutover point (holds predating dual-write
have no mirror by design, not by bug).
"""
from __future__ import annotations

import logging

from warden.config import settings

_CREDIT_MICROS = 1_000  # 1 credit = $0.001 = 1000 µUSD

# Maps sac_holds.status (live, warden/sac/preflight.py) to the corresponding
# warden/ledger/holds.py status. A hold's ledger mirror should always be in
# the matching state if dual-write mirroring kept up.
_HOLD_STATUS_MAP = {"HELD": "HELD", "COMMITTED": "CAPTURED", "RELEASED": "VOIDED"}

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


def holds_drift() -> dict:
    """Compare post-cutover sac_holds to their FT-2 ledger mirror.

    Only holds created at/after `settings.ledger_holds_recon_cutoff_ts` are
    checked. Holds created before dual-write was enabled never got a ledger
    mirror by design — that's expected history, not drift — so including
    them would just be permanent false-positive noise. The cutoff is unset
    ("") by default, making this a no-op until an operator records the
    dual-write enable time.

    For each in-scope hold, flags either a missing ledger-side row or a
    status mismatch (e.g. live released but the ledger mirror never caught
    up — a silently-swallowed `dual_write.mirror()` failure). Fail-soft:
    any read error yields an empty, ok-by-vacuity report rather than raising.
    """
    cutoff = settings.ledger_holds_recon_cutoff_ts
    if not cutoff:
        return _holds_summary([])

    try:
        from warden.ledger import holds as ledger_holds
        from warden.sac import preflight
    except Exception as exc:
        log.debug("ledger_recon: holds modules unavailable (%s)", exc)
        return _holds_summary([])

    try:
        live_holds = preflight.list_holds_since(cutoff)
    except Exception as exc:
        log.debug("ledger_recon: sac_holds enumeration failed (%s)", exc)
        return _holds_summary([])

    details: list[dict] = []
    for h in live_holds:
        try:
            mirrored = ledger_holds.get_hold(h["hold_id"])
        except Exception as exc:
            log.debug("ledger_recon: get_hold failed hold_id=%s (%s)", h["hold_id"], exc)
            continue
        if mirrored is None:
            details.append({
                "hold_id": h["hold_id"], "tenant_id": h["tenant_id"],
                "issue": "missing_in_ledger", "live_status": h["status"],
            })
            continue
        expected = _HOLD_STATUS_MAP.get(h["status"])
        if expected is not None and mirrored.status != expected:
            details.append({
                "hold_id": h["hold_id"], "tenant_id": h["tenant_id"],
                "issue": "status_mismatch", "live_status": h["status"],
                "ledger_status": mirrored.status,
            })
    return _holds_summary(details, holds_checked=len(live_holds))


def _holds_summary(details: list[dict], holds_checked: int | None = None) -> dict:
    return {
        "holds_checked": holds_checked if holds_checked is not None else 0,
        "mismatched": len(details),
        "ok": len(details) == 0,
        "details": details,
    }
