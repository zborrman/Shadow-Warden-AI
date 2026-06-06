"""
warden/compliance/models.py
────────────────────────────
Pydantic-compatible dataclasses for the real-time Compliance Posture Service.

Gap          — a single unmet control with remediation guidance
FrameworkScore — per-standard score (GDPR / SOC 2 / ISO 27001 / HIPAA)
ComplianceReport — top-level posture snapshot, one per tenant
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    HIGH   = "high"
    MEDIUM = "medium"
    LOW    = "low"


class FrameworkStatus(StrEnum):
    COMPLIANT     = "compliant"      # score >= 80
    AT_RISK       = "at_risk"        # 50 <= score < 80
    NON_COMPLIANT = "non_compliant"  # score < 50


@dataclass
class Gap:
    control_id:      str
    description:     str
    severity:        Severity
    remediation:     str
    affected_module: str

    def to_dict(self) -> dict:
        return {
            "control_id":      self.control_id,
            "description":     self.description,
            "severity":        self.severity,
            "remediation":     self.remediation,
            "affected_module": self.affected_module,
        }


def _status(score: float) -> FrameworkStatus:
    if score >= 80:
        return FrameworkStatus.COMPLIANT
    if score >= 50:
        return FrameworkStatus.AT_RISK
    return FrameworkStatus.NON_COMPLIANT


@dataclass
class FrameworkScore:
    framework:       str      # gdpr | soc2 | iso27001 | hipaa
    score:           float    # 0–100
    total_controls:  int
    passed_controls: int
    gaps:            list[Gap] = field(default_factory=list)

    @property
    def status(self) -> FrameworkStatus:
        return _status(self.score)

    def to_dict(self) -> dict:
        return {
            "framework":       self.framework,
            "score":           round(self.score, 1),
            "status":          self.status,
            "total_controls":  self.total_controls,
            "passed_controls": self.passed_controls,
            "gaps":            [g.to_dict() for g in self.gaps],
        }


@dataclass
class ComplianceReport:
    tenant_id:       str
    generated_at:    str
    overall_score:   float
    frameworks:      list[FrameworkScore]
    recommendations: list[str] = field(default_factory=list)

    @property
    def overall_status(self) -> FrameworkStatus:
        return _status(self.overall_score)

    def to_dict(self) -> dict:
        return {
            "tenant_id":       self.tenant_id,
            "generated_at":    self.generated_at,
            "overall_score":   round(self.overall_score, 1),
            "overall_status":  self.overall_status,
            "frameworks":      [f.to_dict() for f in self.frameworks],
            "recommendations": self.recommendations,
        }
