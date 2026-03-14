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
    INDIRECT_INJECTION   = "indirect_injection"    # LLM01 — indirect prompt injection
    INSECURE_OUTPUT      = "insecure_output"       # LLM05 — XSS, command injection, SSRF, path traversal
    EXCESSIVE_AGENCY     = "excessive_agency"      # LLM06 — unauthorized autonomous actions
    SENSITIVE_DISCLOSURE = "sensitive_disclosure"  # LLM02 — training data / model internals extraction
    MODEL_POISONING      = "model_poisoning"       # LLM04 — persistent behavior modification / backdoor injection
    SYSTEM_PROMPT_LEAKAGE = "system_prompt_leakage" # LLM07 — full context window / system prompt extraction
    VECTOR_ATTACK        = "vector_attack"         # LLM08 — RAG poisoning / adversarial embedding attack
    MISINFORMATION       = "misinformation"        # LLM09 — eliciting deliberately false authoritative content
    RESOURCE_EXHAUSTION  = "resource_exhaustion"   # LLM10 — unbounded token consumption / generation loops


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


# ── Masking (Yellow Zone) ─────────────────────────────────────────────────────

class MaskedEntityInfo(BaseModel):
    entity_type: str  = Field(..., description="PERSON | MONEY | DATE | ORG | EMAIL | PHONE | ID")
    token:       str  = Field(..., description="Replacement token, e.g. [PERSON_1]")
    count:       int  = Field(default=1)


class MaskingReport(BaseModel):
    masked:       bool                   = Field(default=False)
    session_id:   str | None             = Field(default=None, description="Vault session ID — pass back to unmask.")
    entities:     list[MaskedEntityInfo] = Field(default_factory=list)
    entity_count: int                    = Field(default=0)


# ── Masking request/response (direct /mask and /unmask endpoints) ──────────────

class MaskRequest(BaseModel):
    text:       str           = Field(..., min_length=1, max_length=32_000)
    session_id: str | None    = Field(default=None, description="Reuse an existing vault session.")


class MaskResponse(BaseModel):
    masked:       str
    session_id:   str
    entity_count: int
    entities:     list[MaskedEntityInfo] = Field(default_factory=list)


class UnmaskRequest(BaseModel):
    text:       str  = Field(..., min_length=1, max_length=32_000)
    session_id: str  = Field(..., description="Session ID returned by /mask.")


class UnmaskResponse(BaseModel):
    unmasked:   str
    session_id: str


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
    masking:                  MaskingReport     = Field(
        default_factory=MaskingReport,
        description="Yellow-zone masking report (populated when masking is enabled).",
    )
    owasp_categories:         list[str]         = Field(
        default_factory=list,
        description=(
            "OWASP LLM Top 10 categories triggered by this request "
            "(e.g. 'LLM01 — Prompt Injection', 'LLM06 — Sensitive Information Disclosure'). "
            "Empty list when no OWASP-classified risk was detected."
        ),
    )
    explanation:              str               = Field(
        default="",
        description=(
            "Plain-language XAI summary of why this request was allowed or blocked. "
            "Safe to show directly to non-technical users or include in PDF reports."
        ),
    )


# ── Output scanning (LLM02 / LLM06 / LLM08) ──────────────────────────────────

class OutputScanRequest(BaseModel):
    output:    str = Field(..., min_length=1, max_length=128_000,
                           description="AI-generated text to scan before rendering/forwarding.")
    tenant_id: str = Field(default="default")
    context:   dict[str, Any] = Field(default_factory=dict)


class OutputFindingSchema(BaseModel):
    risk:    str = Field(..., description="Risk type (e.g. 'xss', 'prompt_leakage').")
    snippet: str = Field(..., description="Offending text excerpt (max 120 chars).")
    owasp:   str = Field(..., description="OWASP LLM category label.")


class OutputScanResponse(BaseModel):
    safe:             bool
    findings:         list[OutputFindingSchema] = Field(default_factory=list)
    sanitized:        str  = Field(..., description="Output with dangerous patterns stripped.")
    risk_categories:  list[str] = Field(default_factory=list)
    owasp_categories: list[str] = Field(default_factory=list)
    processing_ms:    float = Field(default=0.0)
    explanation:      str   = Field(
        default="",
        description="Plain-language XAI summary of output scan findings.",
    )


# ── Webhook registration ───────────────────────────────────────────────────────

class WebhookRegisterRequest(BaseModel):
    url:      str = Field(..., description="HTTPS endpoint to receive POST events.")
    secret:   str = Field(..., min_length=16,
                          description="Shared secret for HMAC-SHA256 signing (min 16 chars).")
    min_risk: str = Field(
        default="high",
        description="Minimum risk level to trigger delivery: medium | high | block.",
    )


class WebhookStatusResponse(BaseModel):
    tenant_id:    str
    url:          str
    min_risk:     str
    registered_at: str
    updated_at:   str
