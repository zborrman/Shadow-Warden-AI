"""shadow_warden/models.py — Response models for the Shadow Warden AI client."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SecretFinding:
    kind:    str
    token:   str
    start:   int
    end:     int

    @classmethod
    def from_dict(cls, d: dict) -> SecretFinding:
        return cls(kind=d["kind"], token=d["token"], start=d["start"], end=d["end"])


@dataclass
class SemanticFlag:
    flag:   str
    score:  float
    detail: str

    @classmethod
    def from_dict(cls, d: dict) -> SemanticFlag:
        return cls(flag=d["flag"], score=d["score"], detail=d.get("detail", ""))


@dataclass
class FilterResult:
    """Structured response from ``POST /filter``."""

    allowed:          bool
    risk_level:       str                        # low | medium | high | block
    filtered_content: str                        # content after redaction
    secrets_found:    list[SecretFinding]        = field(default_factory=list)
    semantic_flags:   list[SemanticFlag]         = field(default_factory=list)
    processing_ms:    dict[str, float]           = field(default_factory=dict)

    # Convenience helpers
    @property
    def blocked(self) -> bool:
        return not self.allowed

    @property
    def has_secrets(self) -> bool:
        return bool(self.secrets_found)

    @property
    def has_pii(self) -> bool:
        return any(f.flag == "pii_detected" for f in self.semantic_flags)

    @property
    def flag_names(self) -> list[str]:
        return [f.flag for f in self.semantic_flags]

    @classmethod
    def from_dict(cls, d: dict) -> FilterResult:
        return cls(
            allowed          = d["allowed"],
            risk_level       = d["risk_level"],
            filtered_content = d.get("filtered_content", ""),
            secrets_found    = [SecretFinding.from_dict(s) for s in d.get("secrets_found", [])],
            semantic_flags   = [SemanticFlag.from_dict(f)  for f in d.get("semantic_flags",  [])],
            processing_ms    = d.get("processing_ms", {}),
        )


@dataclass
class ImpactReport:
    """Financial impact report from ``GET /financial/impact`` (v2.3+)."""

    total_annual_value:   float
    inference_savings:    float
    incident_prevention:  float
    compliance_value:     float
    secops_efficiency:    float
    reputational_value:   float
    roi_multiple:         float
    payback_months:       float
    industry:             str
    requests_per_day:     int
    raw:                  dict[str, Any] = field(default_factory=dict)

    @property
    def total_monthly_value(self) -> float:
        return self.total_annual_value / 12

    @classmethod
    def from_dict(cls, d: dict) -> ImpactReport:
        sub = d.get("sub_models", {})
        return cls(
            total_annual_value  = d.get("total_annual_value", 0.0),
            inference_savings   = sub.get("inference_savings", 0.0),
            incident_prevention = sub.get("incident_prevention", 0.0),
            compliance_value    = sub.get("compliance_automation", 0.0),
            secops_efficiency   = sub.get("secops_efficiency", 0.0),
            reputational_value  = sub.get("reputational_value", 0.0),
            roi_multiple        = d.get("roi_multiple", 0.0),
            payback_months      = d.get("payback_months", 0.0),
            industry            = d.get("industry", "technology"),
            requests_per_day    = d.get("requests_per_day", 0),
            raw                 = d,
        )
