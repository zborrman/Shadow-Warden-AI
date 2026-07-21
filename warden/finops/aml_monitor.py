"""
warden/finops/aml_monitor.py — AML monitoring on the journal stream (FT-5).

Structuring/smurfing detection: many sub-threshold movements on the same
tenant cash account within a rolling window that sum to (or past) a reporting
threshold — the classic pattern of breaking a large transfer into smaller
pieces to stay under scrutiny.

Additive/observational only, same posture as `marketplace/sanctions.py`: a
flag never blocks or delays anything (there is no real payout mechanism for
it to gate — see `docs/licensing-posture.md`). It opens a COMPLIANCE incident
via `warden.communities.incident_register.log_incident()` (already
STIX-linked) for human follow-up. Opt-in via `AML_MONITOR_ENABLED` (default
false), matching `KYB_ENFORCEMENT_ENABLED` / `SANCTIONS_SCREENING_ENABLED`.

Scan cadence is deliberately periodic (a scheduled batch sweep), not an
inline hook on `journal.post()` — `journal.py` is a leaf module with no
upward imports of compliance code, and reviewing an append-only log for
patterns is naturally a pull-based read, not something the write path needs
to carry.

Env vars
────────
  AML_MONITOR_ENABLED         true/false (default false) — opt-in
  AML_STRUCTURING_WINDOW_HRS  float (default 24.0) — rolling window size
  AML_STRUCTURING_THRESHOLD_USD  float (default 10000.0) — reporting threshold
  AML_STRUCTURING_MIN_POSTINGS   int (default 3) — minimum sub-threshold
                                   postings before a pattern counts as structuring
"""
from __future__ import annotations

import logging
import os
from datetime import UTC, datetime, timedelta

log = logging.getLogger("warden.finops.aml_monitor")


def scan_enabled() -> bool:
    """True when the nightly AML sweep should open incidents on hits."""
    return os.getenv("AML_MONITOR_ENABLED", "false").lower() == "true"


def _window_start(window_hours: float) -> str:
    return (datetime.now(UTC) - timedelta(hours=window_hours)).isoformat()


def assess_structuring_risk(
    account: str,
    *,
    window_hours: float = 24.0,
    threshold_usd: float = 10_000.0,
    min_postings: int = 3,
    db_path: str | None = None,
) -> dict:
    """Pure read: does *account* show a structuring pattern in the last
    *window_hours*?

    Only postings whose absolute value is itself below ``threshold_usd``
    count toward the pattern — a single large legitimate transfer is not
    structuring. Flags when the sub-threshold postings' cumulative absolute
    value reaches ``threshold_usd`` *and* there are at least ``min_postings``
    of them (guards against flagging one or two large-ish postings that
    happen to sum past the threshold).
    """
    from warden.ledger import journal

    since = _window_start(window_hours)
    postings = journal.postings_for_account(account, since_iso=since, db_path=db_path)

    sub_threshold = [p for p in postings if abs(p["amount"].to_usd()) < threshold_usd]
    total_usd = sum(abs(p["amount"].to_usd()) for p in sub_threshold)
    flagged = len(sub_threshold) >= min_postings and total_usd >= threshold_usd

    return {
        "account": account,
        "window_hours": window_hours,
        "threshold_usd": threshold_usd,
        "sub_threshold_count": len(sub_threshold),
        "sub_threshold_total_usd": round(total_usd, 2),
        "risk_level": "HIGH" if flagged else "LOW",
        "flagged": flagged,
    }


def _open_incident(tenant_id: str, account: str, report: dict) -> None:
    try:
        from warden.communities.incident_register import log_incident
        log_incident(
            tenant_id=tenant_id,
            title=f"Possible structuring pattern: {account}",
            severity="HIGH",
            category="COMPLIANCE",
            description=(
                f"{report['sub_threshold_count']} sub-threshold postings totalling "
                f"${report['sub_threshold_total_usd']} within {report['window_hours']}h "
                f"(threshold ${report['threshold_usd']})"
            ),
        )
    except Exception as exc:
        log.warning("aml_monitor: incident_register write failed (non-fatal): %s", exc)


def scan_for_structuring(
    *,
    window_hours: float = 24.0,
    threshold_usd: float = 10_000.0,
    min_postings: int = 3,
    db_path: str | None = None,
) -> dict:
    """Scan every tenant cash account for a structuring pattern.

    No-op (`{"scanned": False}`) unless `AML_MONITOR_ENABLED=true`. Fail-soft:
    any read error yields an empty, ok-by-vacuity report rather than raising —
    monitoring observes, it never blocks.
    """
    if not scan_enabled():
        return {"scanned": False}

    try:
        from warden.ledger import journal
        from warden.ledger.accounts import Namespace
    except Exception as exc:
        log.debug("aml_monitor: ledger modules unavailable (%s)", exc)
        return {"scanned": False, "error": str(exc)}

    try:
        accounts = [
            a for a in journal.distinct_accounts(namespace=Namespace.TENANT, db_path=db_path)
            if a.endswith(":cash")
        ]
    except Exception as exc:
        log.debug("aml_monitor: account enumeration failed (%s)", exc)
        return {"scanned": False, "error": str(exc)}

    details: list[dict] = []
    for account in accounts:
        try:
            report = assess_structuring_risk(
                account, window_hours=window_hours, threshold_usd=threshold_usd,
                min_postings=min_postings, db_path=db_path,
            )
        except Exception as exc:
            log.debug("aml_monitor: assess failed for account=%s: %s", account, exc)
            continue
        if report["flagged"]:
            tenant_id = account.split(":")[1] if ":" in account else account
            _open_incident(tenant_id, account, report)
            details.append({"tenant_id": tenant_id, **report})

    return {
        "scanned": True,
        "accounts_scanned": len(accounts),
        "flagged": len(details),
        "details": details,
    }
