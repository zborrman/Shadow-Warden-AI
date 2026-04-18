"""
warden/api/sovereign.py
─────────────────────────
Sovereign AI Cloud REST API.

Routes
──────
  GET    /sovereign/jurisdictions              — list all jurisdictions + frameworks
  GET    /sovereign/jurisdictions/{code}       — jurisdiction detail
  GET    /sovereign/compliance/check           — check cross-border transfer compliance
  GET    /sovereign/policy                     — get tenant's routing policy
  PUT    /sovereign/policy                     — update routing policy
  GET    /sovereign/tunnels                    — list MASQUE tunnels
  POST   /sovereign/tunnels                    — register a new tunnel
  GET    /sovereign/tunnels/{tunnel_id}        — get tunnel detail
  POST   /sovereign/tunnels/{tunnel_id}/probe  — health-check a tunnel
  DELETE /sovereign/tunnels/{tunnel_id}        — deactivate tunnel
  POST   /sovereign/route                      — get routing decision for a request
  POST   /sovereign/attest                     — issue a sovereignty attestation
  GET    /sovereign/attest/{attest_id}         — retrieve attestation
  GET    /sovereign/attest/{attest_id}/verify  — verify attestation signature
  GET    /sovereign/attestations               — list tenant attestations
  GET    /sovereign/report                     — compliance summary report

Auth: standard X-API-Key.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from warden.auth_guard import AuthResult, require_api_key
from warden.billing.feature_gate import require_feature

router = APIRouter(prefix="/sovereign", tags=["Sovereign AI Cloud"])

AuthDep = Depends(require_api_key)
_SovereignGate = require_feature("sovereign_enabled")


# ── Request models ────────────────────────────────────────────────────────────

class PolicyUpdateRequest(BaseModel):
    home_jurisdiction:     str | None  = None
    allowed_jurisdictions: list[str] | None = None
    blocked_jurisdictions: list[str] | None = None
    data_class_overrides:  dict[str, list[str]] | None = None
    require_attestation:   bool | None = None
    fallback_mode:         str | None  = Field(None, description="BLOCK | DIRECT")
    preferred_tunnel_id:   str | None  = None


class RegisterTunnelRequest(BaseModel):
    jurisdiction:    str  = Field(..., description="Jurisdiction code, e.g. 'EU'")
    region:          str  = Field(..., description="Cloud region, e.g. 'eu-west-1'")
    endpoint:        str  = Field(..., description="Proxy endpoint host:port")
    protocol:        str  = Field("MASQUE_H3", description="MASQUE_H3 | MASQUE_H2 | CONNECT_TCP | DIRECT")
    tls_fingerprint: str  = Field("", description="SHA-256 of server leaf cert (TOFU)")
    tenant_id:       str | None = None
    tags:            list[str]  = Field(default_factory=list)


class RouteRequest(BaseModel):
    tenant_id:   str = Field("default")
    data_class:  str = Field("GENERAL", description="GENERAL | PII | PHI | FINANCIAL | CLASSIFIED")
    destination: str = Field("", description="Optional destination AI provider domain hint")


class AttestRequest(BaseModel):
    request_id:   str
    tenant_id:    str  = Field("default")
    data_class:   str  = Field("GENERAL")
    origin_jcode: str  = Field("EU", description="Origin jurisdiction code")
    # Route decision fields (from /sovereign/route response)
    tunnel_id:    str | None = None
    jurisdiction: str        = Field("EU")
    compliant:    bool       = True
    action:       str        = Field("TUNNEL")
    frameworks:   list[str]  = Field(default_factory=list)
    latency_hint_ms: float | None = None


# ── Jurisdiction endpoints ────────────────────────────────────────────────────

@router.get("/jurisdictions", summary="List all supported jurisdictions")
async def list_jurisdictions(auth: AuthResult = AuthDep) -> list[dict]:
    """
    Return all jurisdictions with their compliance frameworks and cloud regions.

    Use this to build jurisdiction selectors in the governance UI and
    to verify which frameworks Shadow Warden enforces per territory.
    """
    from warden.sovereign.jurisdictions import FRAMEWORK_DESCRIPTIONS, JURISDICTIONS

    return [
        {
            "code":                    j.code,
            "name":                    j.name,
            "flag":                    j.flag,
            "frameworks":              list(j.frameworks),
            "ai_regulations":          list(j.ai_regulations),
            "cloud_regions":           list(j.cloud_regions),
            "residency_required":      j.residency_required,
            "cross_border_restricted": j.cross_border_restricted,
            "adequacy_partners":       list(j.adequacy_partners),
            "framework_descriptions":  {
                f: FRAMEWORK_DESCRIPTIONS.get(f, f)
                for f in j.frameworks
            },
        }
        for j in JURISDICTIONS.values()
    ]


@router.get("/jurisdictions/{code}", summary="Get jurisdiction detail")
async def get_jurisdiction_detail(code: str, auth: AuthResult = AuthDep) -> dict:
    from warden.sovereign.jurisdictions import FRAMEWORK_DESCRIPTIONS, get_jurisdiction

    j = get_jurisdiction(code)
    if not j:
        raise HTTPException(status_code=404, detail=f"Jurisdiction {code!r} not found.")
    return {
        "code":                    j.code,
        "name":                    j.name,
        "flag":                    j.flag,
        "frameworks":              list(j.frameworks),
        "ai_regulations":          list(j.ai_regulations),
        "cloud_regions":           list(j.cloud_regions),
        "residency_required":      j.residency_required,
        "cross_border_restricted": j.cross_border_restricted,
        "adequacy_partners":       list(j.adequacy_partners),
        "framework_descriptions":  {
            f: FRAMEWORK_DESCRIPTIONS.get(f, f)
            for f in j.frameworks
        },
    }


@router.get("/compliance/check", summary="Check cross-border data transfer compliance")
async def compliance_check(
    from_jurisdiction: str = Query(..., description="Origin jurisdiction code"),
    to_jurisdiction:   str = Query(..., description="Destination jurisdiction code"),
    data_class:        str = Query("GENERAL"),
    tenant_id:         str = Query("default"),
    auth: AuthResult = AuthDep,
) -> dict:
    """
    Check whether a specific cross-border AI data transfer is compliant.

    Takes into account:
    - Transfer rules matrix (PHI, PII, FINANCIAL, CLASSIFIED, GENERAL)
    - Adequacy decisions between jurisdictions
    - Tenant-specific blocked/allowed jurisdiction policy
    """
    from warden.sovereign.router import check_compliance

    return check_compliance(
        tenant_id         = tenant_id,
        from_jurisdiction = from_jurisdiction,
        to_jurisdiction   = to_jurisdiction,
        data_class        = data_class,
    )


# ── Policy endpoints ──────────────────────────────────────────────────────────

@router.get("/policy", summary="Get tenant routing policy")
async def get_policy(
    tenant_id: str = Query("default"),
    auth: AuthResult = AuthDep,
) -> dict:
    from warden.sovereign.policy import get_policy as _get
    return _get(tenant_id)


@router.put("/policy", summary="Update tenant routing policy", dependencies=[_SovereignGate])
async def update_policy(
    body:      PolicyUpdateRequest,
    tenant_id: str = Query("default"),
    auth: AuthResult = AuthDep,
) -> dict:
    """
    Update the jurisdictional routing policy for a tenant.

    `fallback_mode`:
    - `BLOCK`  — block requests when no compliant tunnel is available (default)
    - `DIRECT` — route directly without a tunnel (logs compliance warning)
    """
    from warden.sovereign.policy import update_policy as _update

    patch: dict[str, Any] = {}
    for field_name in (
        "home_jurisdiction", "allowed_jurisdictions", "blocked_jurisdictions",
        "data_class_overrides", "require_attestation", "fallback_mode",
        "preferred_tunnel_id",
    ):
        val = getattr(body, field_name)
        if val is not None:
            patch[field_name] = val

    try:
        return _update(tenant_id, patch)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


# ── Tunnel endpoints ──────────────────────────────────────────────────────────

@router.get("/tunnels", summary="List MASQUE tunnels")
async def list_tunnels(
    jurisdiction: str | None = Query(None),
    tenant_id:    str | None = Query(None),
    status:       str | None = Query(None, description="PENDING | ACTIVE | DEGRADED | OFFLINE"),
    auth: AuthResult = AuthDep,
) -> list[dict]:
    """List registered MASQUE jurisdictional tunnels with optional filters."""
    from dataclasses import asdict

    from warden.sovereign.tunnel import list_tunnels as _list

    return [asdict(t) for t in _list(jurisdiction=jurisdiction, tenant_id=tenant_id, status=status)]


@router.post("/tunnels", status_code=201, summary="Register a MASQUE tunnel", dependencies=[_SovereignGate])
async def register_tunnel(body: RegisterTunnelRequest, auth: AuthResult = AuthDep) -> dict:
    """
    Register a new MASQUE-over-HTTP/3 proxy tunnel.

    The tunnel is created in `PENDING` status.  Use
    `POST /sovereign/tunnels/{id}/probe` to perform the first health-check
    and transition it to `ACTIVE`.

    `tls_fingerprint` — SHA-256 hex of the server's leaf certificate.
    If omitted, a placeholder is derived from the endpoint string.
    Shadow Warden uses this for Trust-On-First-Use (TOFU) certificate
    pinning to prevent MITM attacks on the sovereign routing path.
    """
    from dataclasses import asdict

    from warden.sovereign.tunnel import register_tunnel as _reg

    try:
        t = _reg(
            jurisdiction    = body.jurisdiction,
            region          = body.region,
            endpoint        = body.endpoint,
            protocol        = body.protocol,   # type: ignore[arg-type]
            tls_fingerprint = body.tls_fingerprint,
            tenant_id       = body.tenant_id,
            tags            = body.tags,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return asdict(t)


@router.get("/tunnels/{tunnel_id}", summary="Get tunnel detail")
async def get_tunnel(tunnel_id: str, auth: AuthResult = AuthDep) -> dict:
    from dataclasses import asdict

    from warden.sovereign.tunnel import get_tunnel as _get

    t = _get(tunnel_id)
    if not t:
        raise HTTPException(status_code=404, detail=f"Tunnel {tunnel_id!r} not found.")
    return asdict(t)


@router.post("/tunnels/{tunnel_id}/probe", summary="Health-check a tunnel")
async def probe_tunnel(tunnel_id: str, auth: AuthResult = AuthDep) -> dict:
    """
    Perform a TCP round-trip health-check on a MASQUE tunnel.

    Updates tunnel `status` and `latency_ms` in Redis.
    Transitions PENDING → ACTIVE on first success.
    """
    from warden.sovereign.tunnel import probe_tunnel as _probe

    return await _probe(tunnel_id)


@router.delete("/tunnels/{tunnel_id}", status_code=204, summary="Deactivate a tunnel", dependencies=[_SovereignGate])
async def deactivate_tunnel(tunnel_id: str, auth: AuthResult = AuthDep) -> None:
    from warden.sovereign.tunnel import deactivate_tunnel as _deact

    if not _deact(tunnel_id):
        raise HTTPException(status_code=404, detail=f"Tunnel {tunnel_id!r} not found.")


# ── Routing endpoints ─────────────────────────────────────────────────────────

@router.post("/route", summary="Get routing decision for a request", dependencies=[_SovereignGate])
async def get_route(body: RouteRequest, auth: AuthResult = AuthDep) -> dict:
    """
    Determine which MASQUE tunnel and jurisdiction to use for a request.

    Returns:
    - `action`:  TUNNEL | DIRECT | BLOCK
    - `tunnel_id`: selected tunnel (null for DIRECT/BLOCK)
    - `jurisdiction`: selected jurisdiction code
    - `compliant`: whether the routing satisfies tenant policy
    - `frameworks`: compliance frameworks satisfied by this route
    - `reason`: plain-English routing explanation
    - `latency_hint_ms`: expected overhead from MASQUE tunneling

    Use the `attest_id` from the subsequent `POST /sovereign/attest` call
    to close the attestation loop after the AI API responds.
    """
    from dataclasses import asdict

    from warden.sovereign.router import route

    decision = route(
        tenant_id   = body.tenant_id,
        data_class  = body.data_class,
        destination = body.destination,
    )
    return asdict(decision)


# ── Attestation endpoints ─────────────────────────────────────────────────────

@router.post("/attest", status_code=201, summary="Issue a sovereignty attestation", dependencies=[_SovereignGate])
async def issue_attestation(body: AttestRequest, auth: AuthResult = AuthDep) -> dict:
    """
    Issue a signed sovereignty attestation for a completed route decision.

    Call this after the AI API response is received to close the audit loop.

    The attestation is:
    - Signed with HMAC-SHA256 (SOVEREIGN_ATTEST_KEY env var)
    - Stored in Redis for 7 years (SOC 2 audit retention)
    - Linked to the filter pipeline via `request_id`
    - Verifiable via `GET /sovereign/attest/{id}/verify`
    """
    from dataclasses import asdict

    from warden.sovereign.attestation import issue_attestation as _issue
    from warden.sovereign.router import RouteDecision

    route_decision = RouteDecision(
        tunnel_id       = body.tunnel_id,
        jurisdiction    = body.jurisdiction,
        compliant       = body.compliant,
        action          = body.action,
        reason          = "",
        frameworks      = body.frameworks,
        latency_hint_ms = body.latency_hint_ms,
    )
    a = _issue(
        request_id   = body.request_id,
        tenant_id    = body.tenant_id,
        route        = route_decision,
        data_class   = body.data_class,
        origin_jcode = body.origin_jcode,
    )
    return asdict(a)


@router.get("/attest/{attest_id}", summary="Retrieve a sovereignty attestation")
async def get_attestation(attest_id: str, auth: AuthResult = AuthDep) -> dict:
    from dataclasses import asdict

    from warden.sovereign.attestation import get_attestation as _get

    a = _get(attest_id)
    if not a:
        raise HTTPException(status_code=404, detail=f"Attestation {attest_id!r} not found.")
    return asdict(a)


@router.get("/attest/{attest_id}/verify", summary="Verify attestation signature")
async def verify_attestation(attest_id: str, auth: AuthResult = AuthDep) -> dict:
    """
    Cryptographically verify that an attestation's HMAC-SHA256 signature is intact.

    Returns `{"valid": true}` when the attestation has not been tampered with.
    Auditors can use this endpoint to validate evidence submitted for SOC 2 /
    GDPR Art.30 / EU AI Act compliance packages.
    """
    from warden.sovereign.attestation import verify_attestation as _verify

    return _verify(attest_id)


@router.get("/attestations", summary="List tenant attestations")
async def list_attestations(
    tenant_id: str = Query("default"),
    limit:     int = Query(100, ge=1, le=1000),
    auth: AuthResult = AuthDep,
) -> list[dict]:
    """Return the most recent attestations for a tenant (newest first)."""
    from dataclasses import asdict

    from warden.sovereign.attestation import list_attestations as _list

    return [asdict(a) for a in _list(tenant_id=tenant_id, limit=limit)]


# ── Report endpoint ───────────────────────────────────────────────────────────

@router.get("/report", summary="Sovereign AI Cloud compliance report")
async def sovereignty_report(
    tenant_id: str = Query("default"),
    limit:     int = Query(500, ge=1, le=5000),
    auth: AuthResult = AuthDep,
) -> dict:
    """
    Generate a Sovereign AI Cloud compliance summary for a tenant.

    Returns:
    - Total attestations + compliance rate
    - Jurisdiction breakdown (how many requests went through each)
    - Framework coverage (which frameworks were satisfied)
    - Non-compliant events (action=DIRECT without policy permission)
    - Tunnel health summary (ACTIVE/DEGRADED/OFFLINE counts)
    - Policy snapshot

    Use this for GDPR Art. 30 / EU AI Act compliance submissions and
    executive sovereignty dashboards.
    """
    import collections
    from dataclasses import asdict
    from datetime import UTC, datetime

    from warden.sovereign.attestation import list_attestations as _list
    from warden.sovereign.policy import get_policy
    from warden.sovereign.tunnel import list_tunnels

    attestations = _list(tenant_id=tenant_id, limit=limit)
    pol          = get_policy(tenant_id)
    tunnels      = list_tunnels()

    total      = len(attestations)
    compliant  = sum(1 for a in attestations if a.compliant)
    juri_count: collections.Counter = collections.Counter()
    fw_count:   collections.Counter = collections.Counter()
    action_count: collections.Counter = collections.Counter()
    non_compliant: list[dict] = []

    for a in attestations:
        juri_count[a.jurisdiction] += 1
        action_count[a.action]     += 1
        for fw in a.frameworks:
            fw_count[fw] += 1
        if not a.compliant:
            non_compliant.append({
                "attest_id":  a.attest_id,
                "request_id": a.request_id,
                "action":     a.action,
                "issued_at":  a.issued_at,
            })

    tunnel_status: collections.Counter = collections.Counter(t.status for t in tunnels)

    return {
        "tenant_id":             tenant_id,
        "total_attestations":    total,
        "compliant":             compliant,
        "non_compliant":         total - compliant,
        "compliance_rate":       round(compliant / max(total, 1), 4),
        "jurisdiction_breakdown": dict(juri_count.most_common()),
        "framework_coverage":    dict(fw_count.most_common()),
        "action_breakdown":      dict(action_count),
        "non_compliant_events":  non_compliant[:50],
        "tunnel_health":         dict(tunnel_status),
        "policy":                pol,
        "generated_at":          datetime.now(UTC).isoformat(),
    }
