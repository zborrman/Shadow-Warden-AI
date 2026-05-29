"""
warden/settings/models.py
──────────────────────────
Pydantic models for each Settings section.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

# ── Agents ────────────────────────────────────────────────────────────────────

class AgentSettings(BaseModel):
    sova_enabled: bool = True
    sova_max_iterations: int = Field(default=10, ge=1, le=30)
    sova_memory_ttl_hours: int = Field(default=6, ge=1, le=72)
    sova_memory_turns: int = Field(default=20, ge=5, le=100)
    master_enabled: bool = True
    master_max_sub_iter: int = Field(default=5, ge=1, le=15)
    master_token_budget: int = Field(default=8192, ge=1024, le=32768)
    healer_bypass_threshold: float = Field(default=0.15, ge=0.0, le=1.0)
    auto_approve_low_risk: bool = False


class AgentSettingsPatch(BaseModel):
    sova_enabled: bool | None = None
    sova_max_iterations: int | None = None
    sova_memory_ttl_hours: int | None = None
    sova_memory_turns: int | None = None
    master_enabled: bool | None = None
    master_max_sub_iter: int | None = None
    master_token_budget: int | None = None
    healer_bypass_threshold: float | None = None
    auto_approve_low_risk: bool | None = None


# ── Notifications ─────────────────────────────────────────────────────────────

class NotificationChannel(BaseModel):
    id: str = ""
    kind: str = Field(..., pattern="^(slack|teams|email|webhook)$")
    label: str = Field(..., max_length=80)
    url: str | None = None          # Slack/Teams/webhook URL
    email: str | None = None        # email channel address
    on_high: bool = True
    on_block: bool = True
    on_healer: bool = False
    active: bool = True


class NotificationChannelPatch(BaseModel):
    label: str | None = None
    on_high: bool | None = None
    on_block: bool | None = None
    on_healer: bool | None = None
    active: bool | None = None


# ── Agentic Commerce ──────────────────────────────────────────────────────────

class CommerceSettings(BaseModel):
    enabled: bool = False
    monthly_budget_usd: float = Field(default=0.0, ge=0.0)
    per_transaction_limit_usd: float = Field(default=50.0, ge=0.0)
    approved_stores: list[str] = Field(default_factory=list)
    require_approval_above_usd: float = Field(default=25.0, ge=0.0)
    audit_all_transactions: bool = True


class CommerceSettingsPatch(BaseModel):
    enabled: bool | None = None
    monthly_budget_usd: float | None = None
    per_transaction_limit_usd: float | None = None
    approved_stores: list[str] | None = None
    require_approval_above_usd: float | None = None
    audit_all_transactions: bool | None = None


# ── Semantic Layer ────────────────────────────────────────────────────────────

class SemanticSettings(BaseModel):
    osi_export_enabled: bool = False
    default_row_limit: int = Field(default=1000, ge=1, le=10_000)
    ai_query_enabled: bool = True


class SemanticSettingsPatch(BaseModel):
    osi_export_enabled: bool | None = None
    default_row_limit: int | None = None
    ai_query_enabled: bool | None = None


# ── Aggregate ─────────────────────────────────────────────────────────────────

class AllSettings(BaseModel):
    tenant_id: str
    agents: AgentSettings = Field(default_factory=AgentSettings)
    notifications: list[NotificationChannel] = Field(default_factory=list)
    commerce: CommerceSettings = Field(default_factory=CommerceSettings)
    semantic: SemanticSettings = Field(default_factory=SemanticSettings)
    meta: dict[str, Any] = Field(default_factory=dict)
