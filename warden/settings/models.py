"""Pydantic models for the Settings service."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, HttpUrl, field_validator


# ── API Keys ──────────────────────────────────────────────────────────────────

class ApiKeyOut(BaseModel):
    id: str
    label: str
    prefix: str          # first 8 chars — never the full key
    created_at: datetime
    last_used_at: datetime | None = None
    request_count: int = 0
    active: bool = True


class ApiKeyCreate(BaseModel):
    label: str = Field(..., min_length=1, max_length=80)


class ApiKeyCreated(BaseModel):
    """Returned ONCE on creation — raw key never stored."""
    id: str
    label: str
    key: str             # full key — shown only once
    prefix: str


# ── Secrets ───────────────────────────────────────────────────────────────────

class SecretOut(BaseModel):
    id: str
    name: str
    description: str = ""
    created_at: datetime
    updated_at: datetime
    expires_at: datetime | None = None


class SecretCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120, pattern=r"^[A-Za-z0-9_\-\.]+$")
    value: str = Field(..., min_length=1)
    description: str = Field("", max_length=255)
    expires_at: datetime | None = None


class SecretUpdate(BaseModel):
    value: str = Field(..., min_length=1)
    description: str | None = None
    expires_at: datetime | None = None


# ── Agent Config ──────────────────────────────────────────────────────────────

class AgentConfig(BaseModel):
    high_risk_threshold: float = Field(0.72, ge=0.0, le=1.0)
    block_threshold: float = Field(0.90, ge=0.0, le=1.0)
    sova_max_iterations: int = Field(10, ge=1, le=25)
    sova_enabled: bool = True
    master_agent_enabled: bool = False
    evolution_engine_enabled: bool = False
    scan_interval_minutes: int = Field(5, ge=1, le=1440)
    causal_arbiter_enabled: bool = True
    phish_guard_enabled: bool = True

    @field_validator("block_threshold")
    @classmethod
    def block_above_high(cls, v: float, info: Any) -> float:
        high = info.data.get("high_risk_threshold", 0.72)
        if v < high:
            raise ValueError("block_threshold must be ≥ high_risk_threshold")
        return v


# ── Notification Channels ─────────────────────────────────────────────────────

class ChannelType(str, Enum):
    slack = "slack"
    teams = "teams"
    email = "email"
    webhook = "webhook"
    telegram = "telegram"
    pagerduty = "pagerduty"


class NotificationChannel(BaseModel):
    id: str
    type: ChannelType
    label: str
    config: dict[str, Any]   # url, email, etc. — values masked in output
    enabled: bool = True
    created_at: datetime
    verified: bool = False


class ChannelCreate(BaseModel):
    type: ChannelType
    label: str = Field(..., min_length=1, max_length=80)
    config: dict[str, Any]   # {"url": "https://..."} or {"email": "..."}

    @field_validator("config")
    @classmethod
    def validate_config(cls, v: dict, info: Any) -> dict:
        ch_type = info.data.get("type")
        if ch_type in (ChannelType.slack, ChannelType.teams, ChannelType.webhook):
            if "url" not in v:
                raise ValueError(f"{ch_type} channel requires 'url' in config")
        elif ch_type == ChannelType.email:
            if "email" not in v:
                raise ValueError("email channel requires 'email' in config")
        elif ch_type == ChannelType.telegram:
            if "bot_token" not in v or "chat_id" not in v:
                raise ValueError("telegram channel requires 'bot_token' and 'chat_id'")
        elif ch_type == ChannelType.pagerduty:
            if "routing_key" not in v:
                raise ValueError("pagerduty channel requires 'routing_key'")
        return v


class TestResult(BaseModel):
    ok: bool
    message: str
    latency_ms: float | None = None


# ── Composite responses ───────────────────────────────────────────────────────

class SettingsSummary(BaseModel):
    api_key_count: int
    secret_count: int
    channel_count: int
    agent_config: AgentConfig
    has_expiring_keys: bool = False
    has_expiring_secrets: bool = False
    unverified_channels: int = 0
