"""Reliability / SLO accounting (Track C — FM-5).

Pure error-budget + multiwindow burn-rate math over uptime observations.
No I/O — the monitor API feeds it probe-aggregate uptime and it returns
budget state + alert decisions.
"""
from warden.reliability.budget import (
    BURN_MULTIWINDOW,
    DEFAULT_SLA,
    SLA_TARGETS,
    BurnAlert,
    ErrorBudget,
    burn_rate,
    error_budget,
    evaluate_burn_alert,
    sla_for_tier,
)

__all__ = [
    "BURN_MULTIWINDOW",
    "DEFAULT_SLA",
    "SLA_TARGETS",
    "BurnAlert",
    "ErrorBudget",
    "burn_rate",
    "error_budget",
    "evaluate_burn_alert",
    "sla_for_tier",
]
