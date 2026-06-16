"""
warden/marketplace/api_maestro.py
───────────────────────────────────
MAESTRO Threat Detection REST endpoints.

Endpoints:
  GET  /marketplace/agents/{agent_id}/maestro-report   — full audit for one agent
  GET  /marketplace/maestro/flags                      — admin: all active flags

Auto-Isolation (Phase 2-3)
──────────────────────────
When a full audit returns overall_threat_level == "high", a non-blocking
background task triggers the isolation pipeline:
  1. Suspend the agent record (status → suspended)
  2. Delist all active listings
  3. Cancel all pending escrows
  4. Freeze WAT token wallet
  5. Append an isolation event to the STIX audit chain
  6. Send Slack/PagerDuty alert

All steps are fail-open — a failure in one step does not block the others.
DAO governance can reverse isolation via a `restore_agent` proposal.
"""
from __future__ import annotations

import logging
import os

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query

from warden.marketplace.maestro import get_maestro_service
from warden.marketplace.rate_limit import marketplace_rate_limit

log = logging.getLogger("warden.marketplace.api_maestro")

_DB_PATH = os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")

router = APIRouter(prefix="/marketplace", tags=["Marketplace MAESTRO"], dependencies=[Depends(marketplace_rate_limit)])

_svc = get_maestro_service(_DB_PATH)


# ── Auto-isolation pipeline ───────────────────────────────────────────────────

def _run_isolation_pipeline(agent_id: str) -> None:
    """
    Isolation pipeline triggered when MAESTRO threat level is HIGH.
    All steps are fail-open — exceptions are logged but do not propagate.
    """
    log.warning("MAESTRO: HIGH threat — triggering isolation for agent=%s", agent_id)

    # 1. Suspend the agent
    try:
        from warden.marketplace.agent import get_agent_service  # type: ignore[attr-defined]
        get_agent_service(_DB_PATH).suspend_agent(agent_id)
        log.info("MAESTRO isolation: agent suspended agent=%s", agent_id)
    except Exception as exc:
        log.warning("MAESTRO isolation: suspend failed agent=%s: %s", agent_id, exc)

    # 2. Delist all active listings
    try:
        from warden.marketplace.listing import get_listing_service  # type: ignore[attr-defined]
        get_listing_service(_DB_PATH).delist_all(agent_id)
        log.info("MAESTRO isolation: listings delisted agent=%s", agent_id)
    except Exception as exc:
        log.warning("MAESTRO isolation: delist_all failed agent=%s: %s", agent_id, exc)

    # 3. Cancel all pending escrows
    try:
        from warden.marketplace.escrow import get_escrow_service  # type: ignore[attr-defined]
        get_escrow_service(_DB_PATH).cancel_all_for_agent(agent_id)
        log.info("MAESTRO isolation: escrows cancelled agent=%s", agent_id)
    except Exception as exc:
        log.warning("MAESTRO isolation: cancel_escrows failed agent=%s: %s", agent_id, exc)

    # 4. Freeze WAT token wallet
    try:
        from warden.tokenomics.agent_token import get_token_service  # type: ignore[attr-defined]
        get_token_service().freeze(agent_id)
        log.info("MAESTRO isolation: WAT wallet frozen agent=%s", agent_id)
    except Exception as exc:
        log.warning("MAESTRO isolation: freeze wallet failed agent=%s: %s", agent_id, exc)

    # 5. STIX audit trail entry
    try:
        from warden.communities.stix_audit import get_stix_audit  # type: ignore[attr-defined]
        get_stix_audit().append_transfer(
            community_id="__system__",
            transfer_id=f"isolation-{agent_id}",
            entity_type="agent_isolation",
            source_community="maestro",
            target_community="isolated",
            data_class="GENERAL",
            proof={
                "action": "auto_isolation",
                "agent_id": agent_id,
                "reason": "maestro_high_threat",
            },
        )
    except Exception as exc:
        log.warning("MAESTRO isolation: STIX audit failed agent=%s: %s", agent_id, exc)

    # 6. Send alert
    try:
        from warden.alerting import send_alert
        send_alert(
            f"MAESTRO auto-isolated agent {agent_id}: suspended, listings delisted, "
            "escrows cancelled, WAT wallet frozen. Use DAO governance to restore.",
            level="HIGH",
        )
    except Exception as exc:
        log.warning("MAESTRO isolation: alert failed agent=%s: %s", agent_id, exc)


# ── REST endpoints ────────────────────────────────────────────────────────────

@router.get("/agents/{agent_id}/maestro-report")
def maestro_report(agent_id: str, background_tasks: BackgroundTasks):
    """Run a full MAESTRO threat audit for a single agent and return the report."""
    try:
        report = _svc.run_full_audit(agent_id)
        if report.overall_threat_level == "high":
            background_tasks.add_task(_run_isolation_pipeline, agent_id)
        return report.to_dict()
    except Exception as exc:
        log.exception("maestro-report: agent=%s", agent_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/maestro/flags")
def maestro_flags(limit: int = Query(100, ge=1, le=1000)):
    """Admin — list all agents with active MAESTRO flags, newest first."""
    try:
        return {"flags": _svc.list_flagged_agents(limit=limit), "count": limit}
    except Exception as exc:
        log.exception("maestro-flags")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
