"""
Business Threat Neutralizer — FastAPI Router

Endpoints:
  GET  /threat/neutralizer/sectors              — list available sectors
  GET  /threat/neutralizer/matrix               — full threat matrix (all or by sector)
  GET  /threat/neutralizer/families/{threat_id} — single threat family detail
  POST /threat/neutralizer/assess               — standalone threat assessment (no filter pipeline)
  GET  /threat/neutralizer/hierarchy            — risk control hierarchy reference
"""
from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from warden.business_threat_neutralizer import (
    analyze,
    get_threat_by_id,
    get_threat_matrix,
    list_sectors,
)

router = APIRouter(prefix="/threat/neutralizer", tags=["threat-neutralizer"])


# ── Request / Response models ─────────────────────────────────────────────────

class AssessRequest(BaseModel):
    sector:               Literal["B2B", "B2C", "E-Commerce"]
    content:              str  = Field(..., min_length=1, max_length=32_000,
                                       description="Raw text to assess for business threats.")
    risk_level:           str  = Field(default="LOW",
                                       description="Warden risk level: LOW | MEDIUM | HIGH | BLOCK")
    obfuscation_detected: bool = Field(default=False)
    redacted_count:       int  = Field(default=0, ge=0)
    has_pii:              bool = Field(default=False)
    ml_score:             float = Field(default=0.0, ge=0.0, le=1.0)
    vault_matches:        list[dict] = Field(default_factory=list,
                                             description="ThreatVault hits from /filter response.")
    semantic_flags:       list[str]  = Field(default_factory=list,
                                             description="FlagType values from /filter response.")
    poisoning_detected:   bool = Field(default=False)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get(
    "/sectors",
    summary="List available sectors with threat counts",
)
async def sectors_endpoint() -> list[dict]:
    return list_sectors()


@router.get(
    "/matrix",
    summary="Full threat family matrix, optionally filtered by sector",
)
async def threat_matrix(
    sector: Annotated[
        Literal["B2B", "B2C", "E-Commerce"] | None,
        Query(description="Filter by sector: B2B | B2C | E-Commerce"),
    ] = None,
) -> list[dict]:
    return get_threat_matrix(sector)  # type: ignore[arg-type]


@router.get(
    "/families/{threat_id}",
    summary="Get a single threat family by ID",
)
async def threat_family(threat_id: str) -> dict:
    result = get_threat_by_id(threat_id)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat family '{threat_id}' not found.",
        )
    return result


@router.post(
    "/assess",
    summary="Standalone business threat assessment — returns neutralizer report",
)
async def assess(body: AssessRequest) -> dict:
    report = analyze(
        body.sector,
        obfuscation_detected = body.obfuscation_detected,
        redacted_count       = body.redacted_count,
        has_pii              = body.has_pii,
        risk_level           = body.risk_level,
        ml_score             = body.ml_score,
        vault_matches        = body.vault_matches,
        semantic_flags       = body.semantic_flags,
        poisoning_detected   = body.poisoning_detected,
    )
    return report.as_dict()


@router.get(
    "/hierarchy",
    summary="Risk control hierarchy — effectiveness levels and guidance",
)
async def control_hierarchy() -> dict:
    return {
        "description": (
            "The Risk Control Hierarchy defines 6 levels from most to least effective. "
            "Always implement higher levels before lower ones. "
            "Eliminating a risk (Level 1) is more effective and cheaper long-term "
            "than monitoring it (Level 5). Most businesses invest in the wrong order — "
            "spending on SIEM before enforcing MFA."
        ),
        "levels": [
            {
                "level": 1,
                "name": "Elimination",
                "effectiveness_pct": 98,
                "description": "Remove the risk source entirely — no attack surface, no risk",
                "examples": [
                    "Turn off RDP if not needed — eliminates ransomware vector entirely",
                    "Remove Flash/Java plugins from all browsers company-wide",
                    "Delete legacy admin accounts after platform migration",
                    "Disable unneeded protocols: SMBv1, Telnet, FTP",
                    "Remove unused Magento plugins from e-commerce store",
                ],
            },
            {
                "level": 2,
                "name": "Substitution",
                "effectiveness_pct": 90,
                "description": "Replace a high-risk element with a lower-risk alternative",
                "examples": [
                    "Replace Telnet → SSH for server administration",
                    "Replace HTTP → HTTPS / TLS 1.3 on all endpoints",
                    "Replace SMS OTP → authenticator app (TOTP / FIDO2)",
                    "Replace custom checkout → Stripe Elements (hosted payment fields)",
                    "Replace self-hosted email → Microsoft 365 / Google Workspace",
                ],
            },
            {
                "level": 3,
                "name": "Engineering Controls",
                "effectiveness_pct": 80,
                "description": "Technical barriers built into systems — work regardless of human behavior",
                "examples": [
                    "Multi-factor authentication (MFA) — enforced 100%, zero exceptions",
                    "Network segmentation + Zero Trust architecture",
                    "AES-256 encryption at rest + TLS 1.3 in transit",
                    "EDR — behavioral endpoint detection and response",
                    "WAF + DDoS scrubbing protection",
                    "Immutable backups (3-2-1 rule)",
                    "PAM — privileged access management vaults",
                    "CSP + SRI headers on all checkout pages (E-Commerce)",
                ],
            },
            {
                "level": 4,
                "name": "Administrative Controls",
                "effectiveness_pct": 60,
                "description": "Policies, procedures, and training — must be paired with engineering controls",
                "examples": [
                    "Information security policy (master document)",
                    "Patch management SLA: 24h critical / 7d high / 30d medium",
                    "Phishing simulation quarterly (unannounced)",
                    "Role-specific training: developers (OWASP Top 10), finance (BEC)",
                    "Vendor risk assessment and security SLA requirements",
                    "Incident response plan with defined roles and escalation paths",
                ],
            },
            {
                "level": 5,
                "name": "Detective Controls",
                "effectiveness_pct": 45,
                "description": "Identify threats that bypassed preventive layers — reduce dwell time",
                "examples": [
                    "SIEM: Microsoft Sentinel, Splunk, Wazuh (open source)",
                    "EDR behavioral detection (beyond signature-based AV)",
                    "DNS filtering anomaly detection",
                    "Dark web credential and data leak monitoring",
                    "UEBA: user and entity behavior analytics",
                    "Shadow Warden MTTD: <1ms for AI-layer threats",
                ],
            },
            {
                "level": 6,
                "name": "Corrective Controls",
                "effectiveness_pct": 25,
                "description": "Restore operations after incident — last line of defense",
                "examples": [
                    "Isolate affected system (do not power off — preserve forensics)",
                    "Restore from immutable clean backup",
                    "Root cause analysis within 5 days of incident",
                    "Cyber insurance activation with ransomware coverage",
                    "Update controls to prevent recurrence",
                ],
            },
        ],
        "kpis": {
            "MTTD":               "Mean Time to Detect — target <1 hour for critical alerts",
            "MTTR":               "Mean Time to Respond — target <4 hours for full containment",
            "Patch SLA":          ">95% of critical CVEs patched within 24 hours",
            "MFA Adoption":       "100% — zero exceptions across all accounts",
            "Phishing Click Rate": "<5% across all departments",
            "Backup Restore Test": "Quarterly full restore validation",
        },
        "investment_priority": {
            "SMB (<50 staff)":        "Levels 1–3 first. Priority: EDR, MFA, email gateway, tested backups. Skip SIEM until L3 complete.",
            "Mid-market (50–500)":    "Add L3 engineering controls: SIEM, PAM, Zero Trust. Annual pen test. Phishing platform.",
            "Enterprise (500+)":      "Full hierarchy. Dedicated SOC. Threat intelligence. Red team. CISO ownership.",
        },
    }
