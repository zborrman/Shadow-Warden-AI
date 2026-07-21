"""
warden/marketplace/sanctions.py
────────────────────────────────
Sanctions screening at settlement (FT-5) — reuses the existing staff
`screen_sanctions_list()` tool (STAFF-05) against the buyer party of every
marketplace clearing/settlement run.

Additive/observational only: a HIT never blocks or delays the transaction.
`clearing.py` is money-moving code, and screening here runs against a stub
builtin denylist, not a real OFAC/EU feed — treating a hit as an automatic
hard block would be a compliance decision this code isn't positioned to make.
Instead a HIT opens a COMPLIANCE incident via
`warden.communities.incident_register.log_incident()` (already STIX-linked)
for human follow-up, same "draft/flag, never self-execute" posture as the
rest of the Digital Staff compliance tools.

Subject name resolution: uses the tenant's KYB `business_name` if one exists
(`warden/marketplace/kyb.py`) — a real-world name screens far better than a
tenant_id string — falling back to the raw tenant_id when no KYB record
exists yet.

Scope note: only the buyer party is screened. The seller side needs a
listing→seller_agent_id resolution that `ClearingResult` doesn't carry yet;
tracked as follow-on FT-5 scope rather than added here.

Env vars
────────
  SANCTIONS_SCREENING_ENABLED  true/false (default false) — opt-in, matches
                                every other new compliance gate in this codebase
"""
from __future__ import annotations

import logging
import os

log = logging.getLogger("warden.marketplace.sanctions")


def screening_enabled() -> bool:
    """True when clear_async() should screen the buyer party at settlement."""
    return os.getenv("SANCTIONS_SCREENING_ENABLED", "false").lower() == "true"


def _subject_name(tenant_id: str) -> str:
    try:
        from warden.marketplace import kyb
        record = kyb.get_kyb_record(tenant_id)
        if record and record.business_name:
            return record.business_name
    except Exception as exc:
        log.debug("sanctions: kyb lookup failed for tenant=%s: %s", tenant_id[:32], exc)
    return tenant_id


def _open_incident(tenant_id: str, subject: str, clearing_id: str, result: dict) -> None:
    try:
        from warden.communities.incident_register import log_incident
        log_incident(
            tenant_id=tenant_id,
            title=f"Sanctions list hit at settlement: {subject}",
            severity="HIGH",
            category="COMPLIANCE",
            description=(
                f"screen_sanctions_list hit for clearing_id={clearing_id}, "
                f"list={result.get('list')}, score={result.get('score')}"
            ),
        )
    except Exception as exc:
        log.warning("sanctions: incident_register write failed (non-fatal): %s", exc)


def _resolve_owner_tenant_id(buyer_agent_id: str) -> str:
    """buyer_agent_id is a DID; screening is tenant-scoped (matches KYB).

    Falls back to the raw agent_id when there's no KYA record (unknown
    owner) — still worth screening, just under a less meaningful subject.
    """
    try:
        from warden.marketplace import kya
        record = kya.get_kya_record(buyer_agent_id)
        if record and record.owner_tenant_id:
            return record.owner_tenant_id
    except Exception as exc:
        log.debug("sanctions: kya lookup failed for agent=%s: %s", buyer_agent_id[:32], exc)
    return buyer_agent_id


async def screen_settlement_party(buyer_agent_id: str, clearing_id: str) -> dict:
    """Screen the buyer of a clearing run against the sanctions list.

    No-op (`{"screened": False}`) unless SANCTIONS_SCREENING_ENABLED=true.
    Never raises — any failure degrades to `{"screened": False, "error": ...}`
    so a screening problem can never break a real clearing transaction.
    """
    if not screening_enabled():
        return {"screened": False}
    if not buyer_agent_id:
        return {"screened": False}

    try:
        from warden.staff.tools.compliance_kyc import screen_sanctions_list
        tenant_id = _resolve_owner_tenant_id(buyer_agent_id)
        subject = _subject_name(tenant_id)
        result = await screen_sanctions_list(tenant_id=tenant_id, subject_name=subject)
        if result.get("hit"):
            _open_incident(tenant_id, subject, clearing_id, result)
        return {"screened": True, "result": result}
    except Exception as exc:
        log.warning("sanctions: screen_settlement_party failed (non-fatal): %s", exc)
        return {"screened": False, "error": str(exc)}
