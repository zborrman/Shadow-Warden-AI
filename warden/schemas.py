"""
Pydantic schemas for the Warden filter gateway.
"""
from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── Enums ────────────────────────────────────────────────────────────────────

class RiskLevel(StrEnum):
    LOW    = "low"
    MEDIUM = "medium"
    HIGH   = "high"
    BLOCK  = "block"


class FlagType(StrEnum):
    SECRET_DETECTED    = "secret_detected"
    PROMPT_INJECTION   = "prompt_injection"
    HARMFUL_CONTENT    = "harmful_content"
    PII_DETECTED       = "pii_detected"
    POLICY_VIOLATION   = "policy_violation"
    INDIRECT_INJECTION = "indirect_injection"   # LLM01 — indirect prompt injection
    INSECURE_OUTPUT    = "insecure_output"       # LLM05 — XSS, command injection, SSRF, path traversal
    EXCESSIVE_AGENCY   = "excessive_agency"      # LLM06 — unauthorized autonomous actions


class RedactionPolicy(StrEnum):
    FULL   = "full"    # replace entirely with [REDACTED_<KIND>] — default for all tenants
    MASKED = "masked"  # keep last 4 chars: ****-****-****-1234  (admin / audit roles)
    RAW    = "raw"     # detect but do not replace (internal service-to-service, audit logs)


# ── Request ───────────────────────────────────────────────────────────────────

class FilterRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=32_000,
                         description="Raw text payload to be filtered.")
    context: dict[str, Any] = Field(default_factory=dict,
                                    description="Optional metadata (user_id, session_id, source).")
    strict: bool = Field(default=False,
                         description="If True, block on MEDIUM risk (default blocks only HIGH/BLOCK).")
    tenant_id: str = Field(default="default",
                           description="Tenant identifier for multi-tenant rule sets. "
                                       "Each tenant gets an isolated SemanticGuard corpus.")
    redaction_policy: RedactionPolicy = Field(
        default=RedactionPolicy.FULL,
        description=(
            "Controls how matched secrets/PII are rewritten in filtered_content. "
            "'full' replaces entirely (default), 'masked' keeps last 4 chars, "
            "'raw' detects but leaves content unchanged."
        ),
    )


# ── Response pieces ───────────────────────────────────────────────────────────

class SecretFinding(BaseModel):
    kind: str           = Field(..., description="Type of secret (e.g. 'api_key', 'credit_card').")
    start: int          = Field(..., description="Character offset in the original content.")
    end: int            = Field(..., description="Character offset end in the original content.")
    redacted_to: str    = Field(..., description="Replacement token written into filtered_content.")


class SemanticFlag(BaseModel):
    flag: FlagType
    score: float        = Field(..., ge=0.0, le=1.0, description="Confidence score 0–1.")
    detail: str         = Field(default="", description="Human-readable explanation.")


# ── Main response ─────────────────────────────────────────────────────────────

class FilterResponse(BaseModel):
    allowed:                  bool
    risk_level:               RiskLevel
    filtered_content:         str               = Field(..., description="Content after redaction (safe to forward).")
    secrets_found:            list[SecretFinding] = Field(default_factory=list)
    semantic_flags:           list[SemanticFlag]  = Field(default_factory=list)
    reason:                   str               = Field(default="", description="Summary reason if blocked.")
    redaction_policy_applied: RedactionPolicy   = Field(
        default=RedactionPolicy.FULL,
        description="The redaction policy that was applied to filtered_content.",
    )
    processing_ms:            dict[str, float]  = Field(
        default_factory=dict,
        description="Per-stage processing time in milliseconds.",
    )
