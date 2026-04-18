"""
warden/api/shadow_ai.py
─────────────────────────
Shadow AI Governance REST API.

Routes
──────
  POST /shadow-ai/scan                 — async subnet probe
  POST /shadow-ai/dns-event            — ingest a DNS telemetry event
  GET  /shadow-ai/findings             — paginated finding list (most recent first)
  DELETE /shadow-ai/findings           — clear all findings for tenant
  GET  /shadow-ai/report               — governance summary report
  GET  /shadow-ai/policy               — get current governance policy
  PUT  /shadow-ai/policy               — update governance policy
  GET  /shadow-ai/providers            — list all known AI providers + signatures

Auth: standard X-API-Key (same as all other warden routes).
Tier: scan + policy requires Pro or above; dns-event + findings available on all tiers.
"""
from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from warden.auth_guard import AuthResult, require_api_key
from warden.billing.addons import require_addon_or_feature

router = APIRouter(prefix="/shadow-ai", tags=["Shadow AI Governance"])

AuthDep = Depends(require_api_key)
_ScanGate = require_addon_or_feature(
    feature="shadow_ai_enabled", addon_key="shadow_ai_discovery", min_tier="pro"
)


# ── Request / Response models ─────────────────────────────────────────────────

class ScanRequest(BaseModel):
    subnet:    str = Field("", description="CIDR subnet (e.g. '10.0.0.0/24'). Omit for DNS-only report.")
    tenant_id: str = Field("default")


class ScanResponse(BaseModel):
    status:       str
    subnet:       str
    hosts_probed: int
    findings:     list[dict]
    summary:      dict[str, int]
    tenant_id:    str
    scanned_at:   str
    latency_ms:   float


class DnsEventRequest(BaseModel):
    domain:    str = Field(..., min_length=1, max_length=253, description="Queried domain name")
    source_ip: str = Field("", description="Source IP of the DNS query")
    tenant_id: str = Field("default")


class PolicyRequest(BaseModel):
    mode:            str | None = Field(None, description="MONITOR | BLOCK_DENYLIST | ALLOWLIST_ONLY")
    allowlist:       list[str] | None = Field(None, description="Provider keys that are approved")
    denylist:        list[str] | None = Field(None, description="Provider keys that are blocked")
    risk_threshold:  str | None = Field(None, description="LOW | MEDIUM | HIGH")
    notify_slack:    bool | None = None


class GovernanceReport(BaseModel):
    tenant_id:         str
    total_findings:    int
    unique_providers:  int
    high_risk:         int
    medium_risk:       int
    low_risk:          int
    blocked:           int
    flagged:           int
    approved:          int
    top_providers:     list[dict]
    policy:            dict
    generated_at:      str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post(
    "/scan",
    response_model=ScanResponse,
    summary="Scan subnet for Shadow AI endpoints",
    dependencies=[_ScanGate],
)
async def scan_subnet(body: ScanRequest, auth: AuthResult = AuthDep) -> ScanResponse:
    """
    Probe a subnet (CIDR /24 or smaller) for unauthorized AI API endpoints.

    Sends async HTTP probes to all hosts on common AI ports (80, 443, 8080,
    11434, 5000, 7860 …) and fingerprints responses against the AI provider
    database (OpenAI, Ollama, Gradio, LocalAI, etc.).

    Omit `subnet` to get a report of DNS-telemetry findings only (no probing).
    """
    from warden.shadow_ai.discovery import ShadowAIDetector

    t0      = time.perf_counter()
    detector = ShadowAIDetector()
    result   = await detector.scan(subnet=body.subnet, tenant_id=body.tenant_id)
    latency  = round((time.perf_counter() - t0) * 1000, 1)

    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result.get("reason", "scan failed"))

    return ScanResponse(
        status       = result["status"],
        subnet       = result["subnet"],
        hosts_probed = result["hosts_probed"],
        findings     = result["findings"],
        summary      = result["summary"],
        tenant_id    = result["tenant_id"],
        scanned_at   = result["scanned_at"],
        latency_ms   = latency,
    )


@router.post("/dns-event", summary="Ingest a DNS telemetry event")
async def ingest_dns_event(body: DnsEventRequest, auth: AuthResult = AuthDep) -> dict:
    """
    Classify a single DNS query against the AI provider domain list.

    Integrate with your DNS RPZ, Zeek, Suricata, or syslog forwarder to
    stream DNS events into the Shadow AI Governance engine.

    Returns:
        `{"match": true, ...finding}` — recognized AI provider domain.
        `{"match": false, "domain": "..."}` — not an AI domain.
    """
    from warden.shadow_ai.discovery import ShadowAIDetector

    detector = ShadowAIDetector()
    return detector.classify_dns_event(
        domain    = body.domain,
        source_ip = body.source_ip,
        tenant_id = body.tenant_id,
    )


@router.get("/findings", summary="List Shadow AI findings")
async def list_findings(
    tenant_id: str = Query("default"),
    limit:     int = Query(100, ge=1, le=1000),
    auth: AuthResult = AuthDep,
) -> list[dict]:
    """
    Return stored Shadow AI findings (most recent first).

    Includes findings from both network probes and DNS telemetry.
    Capped at 1 000 per tenant; use `limit` to reduce the response size.
    """
    from warden.shadow_ai.discovery import get_findings
    return get_findings(tenant_id=tenant_id, limit=limit)


@router.delete("/findings", status_code=204, summary="Clear all findings for a tenant")
async def clear_findings_endpoint(
    tenant_id: str = Query("default"),
    auth: AuthResult = AuthDep,
) -> None:
    """Permanently delete all stored Shadow AI findings for this tenant."""
    from warden.shadow_ai.discovery import clear_findings
    clear_findings(tenant_id)


@router.get(
    "/report",
    response_model=GovernanceReport,
    summary="Shadow AI governance summary report",
)
async def governance_report(
    tenant_id: str = Query("default"),
    limit:     int = Query(1000, ge=1, le=1000),
    auth: AuthResult = AuthDep,
) -> GovernanceReport:
    """
    Generate a Shadow AI Governance summary for a tenant.

    Aggregates findings to produce risk distribution, verdict breakdown,
    and top-5 most-frequently detected providers.

    Use this endpoint for dashboard widgets, compliance reports, or
    SOVA's morning brief query.
    """
    import collections
    from datetime import UTC, datetime

    from warden.shadow_ai.discovery import get_findings
    from warden.shadow_ai.policy import get_policy

    findings = get_findings(tenant_id=tenant_id, limit=limit)
    pol      = get_policy(tenant_id)

    risk_counts: dict[str, int]     = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    verdict_counts: dict[str, int]  = {"BLOCKED": 0, "FLAGGED": 0, "APPROVED": 0}
    provider_counter: collections.Counter = collections.Counter()

    unique_providers: set[str] = set()
    for f in findings:
        rl = f.get("risk_level", "LOW")
        v  = f.get("verdict", "FLAGGED")
        pk = f.get("provider_key", "unknown")

        risk_counts[rl]    = risk_counts.get(rl, 0) + 1
        verdict_counts[v]  = verdict_counts.get(v, 0) + 1
        unique_providers.add(pk)
        provider_counter[pk] += 1

    top_providers = [
        {"provider_key": k, "count": c}
        for k, c in provider_counter.most_common(5)
    ]

    return GovernanceReport(
        tenant_id        = tenant_id,
        total_findings   = len(findings),
        unique_providers = len(unique_providers),
        high_risk        = risk_counts["HIGH"],
        medium_risk      = risk_counts["MEDIUM"],
        low_risk         = risk_counts.get("LOW", 0),
        blocked          = verdict_counts["BLOCKED"],
        flagged          = verdict_counts["FLAGGED"],
        approved         = verdict_counts["APPROVED"],
        top_providers    = top_providers,
        policy           = pol,
        generated_at     = datetime.now(UTC).isoformat(),
    )


@router.get("/policy", summary="Get Shadow AI governance policy")
async def get_policy_endpoint(
    tenant_id: str = Query("default"),
    auth: AuthResult = AuthDep,
) -> dict:
    """Return the current governance policy for a tenant."""
    from warden.shadow_ai.policy import get_policy
    return get_policy(tenant_id)


@router.put("/policy", summary="Update Shadow AI governance policy")
async def update_policy_endpoint(
    body:      PolicyRequest,
    tenant_id: str = Query("default"),
    auth: AuthResult = AuthDep,
) -> dict:
    """
    Update the governance policy for a tenant.

    Unset fields are left unchanged (partial update / patch semantics).

    Mode options:
    - `MONITOR`         — report only, no enforcement
    - `BLOCK_DENYLIST`  — block providers on the denylist
    - `ALLOWLIST_ONLY`  — flag anything not explicitly on the allowlist
    """
    from warden.shadow_ai.policy import update_policy

    patch: dict[str, Any] = {}
    if body.mode           is not None: patch["mode"]           = body.mode
    if body.allowlist      is not None: patch["allowlist"]      = body.allowlist
    if body.denylist       is not None: patch["denylist"]       = body.denylist
    if body.risk_threshold is not None: patch["risk_threshold"] = body.risk_threshold
    if body.notify_slack   is not None: patch["notify_slack"]   = body.notify_slack

    try:
        updated = update_policy(tenant_id, patch)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return updated


@router.get("/providers", summary="List all known AI provider signatures")
async def list_providers(auth: AuthResult = AuthDep) -> list[dict]:
    """
    Return the full AI provider signature database.

    Useful for building allowlist/denylist pickers in the governance UI
    and for verifying which providers Shadow Warden can detect.
    """
    from warden.shadow_ai.signatures import AI_PROVIDERS

    return [
        {
            "provider_key": k,
            "display_name": v["display_name"],
            "category":     v["category"],
            "risk_level":   v["risk_level"],
            "domains":      v["domains"],
            "local_ports":  v["local_ports"],
        }
        for k, v in AI_PROVIDERS.items()
    ]
