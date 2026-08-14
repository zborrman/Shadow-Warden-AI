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

Why the reports carry an ``evidence`` label
───────────────────────────────────────────
Reconciliation is fail-soft by design: it observes, it never blocks a money
path. The cost of that posture is that ``ok: true`` used to mean three
different things — *checked and agreed*, *there was nothing to check*, and
*the check could not run at all* — and a caller could not tell them apart.

That matters here more than almost anywhere else, because the documented FT-2
read-cutover gate is "``credit_drift()`` clean with ``tenants_checked > 0``",
and both halves were satisfiable without verifying anything: ``tenants_checked``
counted the tenants *enumerated*, while a tenant whose ``reconcile()`` raised
was skipped and still counted. A ledger that was unreachable for every single
tenant therefore reported ``{tenants_checked: 2, drifted: 0, ok: true}`` — the
gate condition exactly — and the read-cutover would have been flipped onto an
unverified ledger. Reproduced against production on 2026-08-14.

So each report now states what it actually observed:

    evidence="counted"          at least one subject was reconciled
    evidence="nothing_to_check" enumeration worked, there were no subjects
    evidence="not_available"    enumeration or the modules themselves failed

``tenants_checked``/``holds_checked`` count only subjects that were genuinely
reconciled; ``unreadable`` counts those that were enumerated and then failed.
``ok`` keeps its narrow meaning — *no drift among what was checked* — so a
quiet production with no credit rows does not page anyone. Use
:func:`read_cutover_ready` for the go/no-go; it is the gate as code rather than
as a sentence in a roadmap table.
"""
from __future__ import annotations

import logging

from warden.observability import COUNTED, NOT_AVAILABLE, NOTHING_TO_CHECK, Reason, record_failopen

_CREDIT_MICROS = 1_000  # 1 credit = $0.001 = 1000 µUSD

# The evidence vocabulary is canonical in warden.observability — re-exported
# here because callers and tests import it from this module, and because
# finops/order_recon.py must speak exactly the same three words.
__all__ = [
    "COUNTED", "NOTHING_TO_CHECK", "NOT_AVAILABLE",
    "credit_drift", "hold_drift", "read_cutover_ready",
]

log = logging.getLogger("warden.finops.ledger_recon")


def credit_drift() -> dict:
    """Compare every tenant's ledger credit balance to the authoritative counter.

    Returns a summary::

        {tenants_checked, tenants_enumerated, unreadable, drifted,
         total_abs_drift_micros, ok, evidence, details}

    ``details`` lists only the drifted tenants. ``ok`` is True when the ledger
    agreed with the counter for every tenant *that could be read* — consult
    ``evidence`` and ``unreadable`` to learn whether that was any tenant at all.
    Fail-soft: any read error yields an unreadable report rather than raising —
    reconciliation observes, it never blocks.
    """
    try:
        from warden.ledger import accounts, dual_write
        from warden.marketplace import credits
    except Exception as exc:
        record_failopen("ledger_recon_credits", Reason.IMPORT_MISSING, exc)
        log.debug("ledger_recon: modules unavailable (%s)", exc)
        return _summary([], evidence=NOT_AVAILABLE)

    try:
        balances = credits.all_balances()
    except Exception as exc:
        record_failopen("ledger_recon_credits", Reason.BACKEND_ERROR, exc)
        log.debug("ledger_recon: credit enumeration failed (%s)", exc)
        return _summary([], evidence=NOT_AVAILABLE)

    details: list[dict] = []
    checked = 0
    unreadable = 0
    for tenant_id, credit_balance in balances.items():
        try:
            rep = dual_write.reconcile(
                accounts.tenant_credits(tenant_id), credit_balance * _CREDIT_MICROS
            )
        except Exception as exc:
            # Enumerated but not verified. Counting this as "checked" is what
            # made the cutover gate forgeable; it is now reported separately.
            unreadable += 1
            record_failopen("ledger_recon_credits", Reason.BACKEND_ERROR, exc)
            log.debug("ledger_recon: reconcile failed tenant=%s (%s)", tenant_id, exc)
            continue
        checked += 1
        if not rep["ok"]:
            details.append({"tenant_id": tenant_id, **rep})
    return _summary(
        details,
        checked=checked,
        enumerated=len(balances),
        unreadable=unreadable,
        evidence=COUNTED if checked else (NOT_AVAILABLE if unreadable else NOTHING_TO_CHECK),
    )


def _summary(
    details: list[dict],
    *,
    checked: int = 0,
    enumerated: int = 0,
    unreadable: int = 0,
    evidence: str,
) -> dict:
    total = sum(abs(d["drift_micros"]) for d in details)
    return {
        "tenants_checked": checked,
        "tenants_enumerated": enumerated,
        "unreadable": unreadable,
        "drifted": len(details),
        "total_abs_drift_micros": total,
        "ok": len(details) == 0,
        "evidence": evidence,
        "details": details,
    }


def hold_drift() -> dict:
    """Compare every currently-open hold's ledger balance to its live amount.

    Returns a summary::

        {holds_checked, holds_enumerated, unreadable, drifted,
         total_abs_drift_micros, ok, evidence, details}

    ``details`` lists only the drifted holds. Fail-soft: any read error yields
    an unreadable report rather than raising. See the module docstring for what
    ``evidence`` distinguishes.
    """
    try:
        from warden.ledger import accounts, dual_write
        from warden.sac import preflight
    except Exception as exc:
        record_failopen("ledger_recon_holds", Reason.IMPORT_MISSING, exc)
        log.debug("ledger_recon: modules unavailable (%s)", exc)
        return _hold_summary([], evidence=NOT_AVAILABLE)

    try:
        holds = preflight.open_holds()
    except Exception as exc:
        record_failopen("ledger_recon_holds", Reason.BACKEND_ERROR, exc)
        log.debug("ledger_recon: hold enumeration failed (%s)", exc)
        return _hold_summary([], evidence=NOT_AVAILABLE)

    details: list[dict] = []
    checked = 0
    unreadable = 0
    for h in holds:
        try:
            rep = dual_write.reconcile(accounts.hold(h["hold_id"]), h["amount_micros"])
        except Exception as exc:
            unreadable += 1
            record_failopen("ledger_recon_holds", Reason.BACKEND_ERROR, exc)
            log.debug("ledger_recon: reconcile failed hold=%s (%s)", h["hold_id"], exc)
            continue
        checked += 1
        if not rep["ok"]:
            details.append({"hold_id": h["hold_id"], "tenant_id": h["tenant_id"], **rep})
    return _hold_summary(
        details,
        checked=checked,
        enumerated=len(holds),
        unreadable=unreadable,
        evidence=COUNTED if checked else (NOT_AVAILABLE if unreadable else NOTHING_TO_CHECK),
    )


def _hold_summary(
    details: list[dict],
    *,
    checked: int = 0,
    enumerated: int = 0,
    unreadable: int = 0,
    evidence: str,
) -> dict:
    total = sum(abs(d["drift_micros"]) for d in details)
    return {
        "holds_checked": checked,
        "holds_enumerated": enumerated,
        "unreadable": unreadable,
        "drifted": len(details),
        "total_abs_drift_micros": total,
        "ok": len(details) == 0,
        "evidence": evidence,
        "details": details,
    }


def read_cutover_ready() -> dict:
    """The FT-2 read-cutover go/no-go, as code instead of a roadmap sentence.

    The read-cutover (re-pointing FM-1 ``available_usd()`` at the ledger) is a
    human decision, but the evidence it rests on should not be re-derived by
    hand each time somebody asks "is the shadow period done?". Returns::

        {ready: bool, reason: str, credits: <report>, holds: <report>}

    Ready requires **positive** evidence, never absence of bad news:

    * credits were genuinely reconciled (``evidence == "counted"``),
    * nothing was enumerated-but-unverifiable on either side, and
    * neither side reported drift.

    Open holds are permitted to be empty — ``open_holds()`` is an instantaneous
    snapshot and holds are short-lived, so "no holds open right now" is a normal
    state rather than missing evidence. Credits are not: a zero-tenant credits
    report means the shadow period has observed nothing, which is precisely the
    state production has been in since the flag went live on 2026-08-12.
    """
    credits_rep = credit_drift()
    holds_rep = hold_drift()

    blockers: list[str] = []
    if credits_rep["evidence"] != COUNTED:
        blockers.append(
            f"credit reconciliation has no positive evidence "
            f"(evidence={credits_rep['evidence']}, tenants_checked="
            f"{credits_rep['tenants_checked']})"
        )
    if credits_rep["unreadable"]:
        blockers.append(f"{credits_rep['unreadable']} tenant(s) could not be reconciled")
    if credits_rep["drifted"]:
        blockers.append(f"{credits_rep['drifted']} tenant(s) drifted")
    if holds_rep["evidence"] == NOT_AVAILABLE:
        blockers.append("hold reconciliation could not run")
    if holds_rep["unreadable"]:
        blockers.append(f"{holds_rep['unreadable']} hold(s) could not be reconciled")
    if holds_rep["drifted"]:
        blockers.append(f"{holds_rep['drifted']} hold(s) drifted")

    return {
        "ready": not blockers,
        "reason": "; ".join(blockers) if blockers else "ledger agrees with every counter read",
        "credits": credits_rep,
        "holds": holds_rep,
    }
