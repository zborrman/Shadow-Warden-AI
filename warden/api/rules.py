"""
warden/api/rules.py
━━━━━━━━━━━━━━━━━━━━
Evolution rule ledger + admin rule-lifecycle + SOC 2 audit-chain REST API.

Endpoints
─────────
  POST   /rules/{rule_id}/report-fp     — report a false positive
  GET    /rules                         — list ledger rules
  POST   /admin/rules/{rule_id}/approve — approve + activate a pending rule
  DELETE /admin/rules/{rule_id}         — retire a rule immediately
  GET    /admin/audit/verify            — verify audit-chain integrity
  GET    /admin/audit/export            — export audit-chain entries

Extracted from ``warden/main.py`` (Phase 3). The RuleLedger, ReviewQueue,
in-memory dynamic-regex list, brain guard and AuditTrail are published to
``warden.runtime`` in the app lifespan and resolved here. The dynamic-regex
list is mutated in place (``lst[:] = ...``) so the change is visible to the
filter hot path, which reads the same object.
"""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from warden.auth_guard import require_api_key
from warden.runtime import runtime as _runtime

log = logging.getLogger("warden.api.rules")

router = APIRouter()


class _FpReportRequest(BaseModel):
    reason: str | None = None


def _require_ledger():
    ledger = _runtime.get("ledger")
    if ledger is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rule ledger not available.",
        )
    return ledger


def _require_audit_trail():
    audit_trail = _runtime.get("audit_trail")
    if audit_trail is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AuditTrail not initialised.",
        )
    return audit_trail


# ── Rule ledger endpoints ─────────────────────────────────────────────────────

@router.post(
    "/rules/{rule_id}/report-fp",
    tags=["rules"],
    summary="Report a false-positive for an evolution-generated rule (increments fp_reports)",
    dependencies=[Depends(require_api_key)],
)
async def report_false_positive(rule_id: str, body: _FpReportRequest):
    ledger = _require_ledger()
    found = ledger.report_fp(rule_id)
    if not found:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule {rule_id!r} not found in ledger.",
        )
    rule = ledger.get_rule(rule_id)
    log.info(
        json.dumps({
            "event":        "fp_reported",
            "rule_id":      rule_id,
            "fp_reports":   rule["fp_reports"],
            "rule_status":  rule["status"],
            "reason":       body.reason,
        })
    )
    return {
        "rule_id":    rule_id,
        "fp_reports": rule["fp_reports"],
        "status":     rule["status"],
    }


@router.get(
    "/rules",
    tags=["rules"],
    summary="List evolution-generated rules from the ledger",
    dependencies=[Depends(require_api_key)],
)
async def list_rules(rule_status: str | None = None, limit: int = 100):
    ledger = _require_ledger()
    return {"rules": ledger.list_rules(status=rule_status, limit=limit)}


# ── Admin rule lifecycle endpoints ────────────────────────────────────────────

@router.post(
    "/admin/rules/{rule_id}/approve",
    tags=["admin"],
    summary="Approve a pending_review rule and activate it (RULE_REVIEW_MODE=manual)",
    dependencies=[Depends(require_api_key)],
)
async def admin_approve_rule(rule_id: str):
    """
    Promote a rule from *pending_review* to *active* and hot-load it into the
    running filter pipeline.

    Only meaningful when ``RULE_REVIEW_MODE=manual``.  Safe to call in auto mode
    (the rule is already active; the ledger update is idempotent).
    """
    ledger = _require_ledger()
    rule = ledger.get_rule(rule_id)
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule {rule_id!r} not found in ledger.",
        )
    if rule["status"] == "retired":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Rule {rule_id!r} is already retired and cannot be approved.",
        )

    # Activate in the running pipeline
    review_queue = _runtime.get("review_queue")
    if review_queue is not None:
        review_queue.activate(
            rule_id    = rule_id,
            rule_type  = rule["rule_type"],
            value      = rule["pattern_snippet"],
            brain_guard= _runtime.get("brain_guard"),
        )

    # Promote in the ledger (approve_rule only changes pending_review → active;
    # already-active rules are unaffected).
    ledger.approve_rule(rule_id)

    log.info(
        json.dumps({
            "event":     "admin_rule_approved",
            "rule_id":   rule_id,
            "rule_type": rule["rule_type"],
        })
    )
    updated = ledger.get_rule(rule_id)
    return {
        "rule_id": rule_id,
        "status":  updated["status"],
        "message": f"Rule {rule_id!r} activated.",
    }


@router.delete(
    "/admin/rules/{rule_id}",
    tags=["admin"],
    summary="Retire an evolution-generated rule immediately",
    dependencies=[Depends(require_api_key)],
)
async def admin_retire_rule(rule_id: str):
    """
    Immediately retire a rule: removes it from the in-memory regex list and sets
    ``status='retired'`` in the ledger so it is not reloaded on restart.
    """
    ledger = _require_ledger()
    found = ledger.retire_rule(rule_id)
    if not found:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule {rule_id!r} not found in ledger.",
        )

    # Remove from the in-memory dynamic regex list (takes effect immediately).
    # Mutate the shared list object in place so the filter hot path sees it.
    dynamic_regex_rules = _runtime.get("dynamic_regex_rules")
    if dynamic_regex_rules is not None:
        dynamic_regex_rules[:] = [r for r in dynamic_regex_rules if r.rule_id != rule_id]

    log.info(
        json.dumps({
            "event":   "admin_rule_retired",
            "rule_id": rule_id,
        })
    )
    return {
        "rule_id": rule_id,
        "status":  "retired",
        "message": f"Rule {rule_id!r} retired and removed from live filter.",
    }


# ── Audit Trail endpoints (SOC 2) ─────────────────────────────────────────────

@router.get(
    "/admin/audit/verify",
    tags=["admin"],
    summary="Verify cryptographic integrity of the audit chain",
    dependencies=[Depends(require_api_key)],
)
async def audit_verify():
    """
    Walk every entry in the audit chain and recompute each SHA-256 hash.

    Returns ``{"valid": true, "entries": N}`` when the chain is intact.
    Returns ``{"valid": false, "broken_at_seq": N}`` if tampering is detected.
    Complexity: O(N) — runs synchronously; suitable for periodic health checks.
    """
    audit_trail = _require_audit_trail()
    valid, count = audit_trail.verify_chain()
    if valid:
        return {"valid": True, "entries": count}
    return {"valid": False, "broken_at_seq": count}


@router.get(
    "/admin/audit/export",
    tags=["admin"],
    summary="Export audit chain entries for SOC 2 auditors",
    dependencies=[Depends(require_api_key)],
)
async def audit_export(
    start: str | None = None,
    end:   str | None = None,
    limit: int        = 10_000,
):
    """
    Export audit entries in ISO-8601 UTC range ``[start, end]``.

    Both *start* and *end* are inclusive recorded_at timestamps.
    Omit both to export the full chain (up to *limit*).

    Also verifies chain integrity and includes ``"valid"`` in the response
    so auditors can confirm the export has not been tampered with.
    """
    audit_trail = _require_audit_trail()
    entries     = audit_trail.export_range(start=start, end=end, limit=limit)
    valid, _cnt = audit_trail.verify_chain()
    return {
        "valid":   valid,
        "count":   len(entries),
        "entries": entries,
    }
