"""
warden/business_intelligence/models.py  (CM-39)
────────────────────────────────────────────────
Pydantic models for the Business Intelligence module.
"""
from __future__ import annotations

from pydantic import BaseModel, Field


class UsageSummary(BaseModel):
    tenant_id:          str
    period_month:       str
    total_requests:     int = 0
    blocked_requests:   int = 0
    allowed_requests:   int = 0
    avg_latency_ms:     float = 0.0
    block_rate_pct:     float = 0.0
    top_categories:     list[dict] = Field(default_factory=list)
    daily_trend:        list[dict] = Field(default_factory=list)


class ThreatSummary(BaseModel):
    tenant_id:          str
    period_days:        int = 30
    total_threats:      int = 0
    by_severity:        dict[str, int] = Field(default_factory=dict)
    by_category:        dict[str, int] = Field(default_factory=dict)
    top_attack_vectors: list[str] = Field(default_factory=list)
    incident_trend:     list[dict] = Field(default_factory=list)
    mttr_hours:         float = 0.0


class VendorScorecard(BaseModel):
    vendor_id:          str
    display_name:       str
    risk_tier:          str = "MEDIUM"
    composite_score:    float = 0.5
    compliance_status:  str = "unknown"
    dpa_expiring_soon:  bool = False
    monthly_spend_usd:  float = 0.0
    incident_count:     int = 0
    last_assessed:      str = ""


class ComplianceScore(BaseModel):
    tenant_id:          str
    community_id:       str = ""
    overall_score:      float = 0.0
    grade:              str = "F"
    training_pct:       float = 0.0
    vendor_dpa_pct:     float = 0.0
    incident_closure_pct: float = 0.0
    budget_adherence_pct: float = 0.0
    breakdown:          dict[str, float] = Field(default_factory=dict)


class BenchmarkResult(BaseModel):
    tenant_id:          str
    metric:             str
    tenant_value:       float
    community_avg:      float
    community_p25:      float
    community_p75:      float
    percentile_rank:    float
    status:             str = "average"   # above/average/below


class IncidentPrediction(BaseModel):
    tenant_id:          str
    horizon_days:       int = 30
    predicted_count:    int = 0
    confidence:         float = 0.0
    trend_direction:    str = "stable"   # rising/stable/falling
    risk_factors:       list[str] = Field(default_factory=list)
    recommendations:    list[str] = Field(default_factory=list)


class ReportRequest(BaseModel):
    tenant_id:          str
    community_id:       str = ""
    report_type:        str = "full"   # full/executive/compliance/vendor/cost
    period_months:      int = Field(3, ge=1, le=24)
    include_sections:   list[str] = Field(default_factory=list)
    format:             str = "json"   # json/summary
