"""
warden/core/ — Core infrastructure facade package.

Canonical import path for schemas, cache, config, metrics,
circuit breaker, and other foundational modules.
"""
from __future__ import annotations

from warden.alerting import send_alert
from warden.audit_trail import AuditEntry, AuditTrail
from warden.cache import check_tenant_rate_limit, get_cached, set_cached
from warden.config import Settings
from warden.metrics import (
    FILTER_BYPASSES_TOTAL,
    FILTER_HONEYTRAP_TOTAL,
    FILTER_UNCERTAIN_TOTAL,
)
from warden.retry import RetryConfig
from warden.schemas import (
    FilterRequest,
    FilterResponse,
    FlagType,
    RiskLevel,
    SemanticFlag,
)
from warden.telemetry import setup_telemetry, trace_stage
from warden.webhook_dispatch import WebhookStore, dispatch_event

__all__ = [
    "AuditEntry",
    "AuditTrail",
    "FILTER_BYPASSES_TOTAL",
    "FILTER_HONEYTRAP_TOTAL",
    "FILTER_UNCERTAIN_TOTAL",
    "FilterRequest",
    "FilterResponse",
    "FlagType",
    "RetryConfig",
    "RiskLevel",
    "SemanticFlag",
    "Settings",
    "WebhookStore",
    "check_tenant_rate_limit",
    "dispatch_event",
    "get_cached",
    "send_alert",
    "set_cached",
    "setup_telemetry",
    "trace_stage",
]
