"""
warden/guards/ — Security guard facade package.

Canonical import path for all detection and blocking modules.
All names are also available at their legacy flat paths
(e.g. ``warden.semantic_guard``) for backward compatibility.
"""
from __future__ import annotations

from warden.agent_monitor import AgentMonitor  # noqa: F401
from warden.auth_guard import (  # noqa: F401
    AuthResult,
    get_rate_limit,
    require_api_key,
    set_default_rate_limit,
)
from warden.causal_arbiter import CausalResult, arbitrate  # noqa: F401
from warden.entity_risk import ERSResult, record_event, score  # noqa: F401
from warden.global_blocklist import is_blocked  # noqa: F401
from warden.honey import HoneyEngine, HoneyResult  # noqa: F401
from warden.output_guard import BusinessScanResult, TenantOutputConfig  # noqa: F401
from warden.output_sanitizer import get_sanitizer  # noqa: F401
from warden.prompt_shield import PromptShield, ShieldResult  # noqa: F401
from warden.rbac import DashboardRole, has_permission  # noqa: F401
from warden.semantic_guard import SemanticGuard  # noqa: F401
from warden.session_guard import SessionGuard, SessionRisk  # noqa: F401
from warden.shadow_ban import fake_filter_response, pick_strategy  # noqa: F401
from warden.taint_tracker import TaintDecision, TaintLevel, TaintState  # noqa: F401
from warden.tool_guard import ToolCallGuard, ToolInspectionResult  # noqa: F401
from warden.topology_guard import scan as topology_scan  # noqa: F401
from warden.worm_guard import WormDetectionResult  # noqa: F401

__all__ = [
    "AgentMonitor",
    "AuthResult",
    "BusinessScanResult",
    "CausalResult",
    "DashboardRole",
    "ERSResult",
    "HoneyEngine",
    "HoneyResult",
    "PromptShield",
    "SemanticGuard",
    "SessionGuard",
    "SessionRisk",
    "ShieldResult",
    "TaintDecision",
    "TaintLevel",
    "TaintState",
    "TenantOutputConfig",
    "ToolCallGuard",
    "ToolInspectionResult",
    "WormDetectionResult",
    "arbitrate",
    "fake_filter_response",
    "get_rate_limit",
    "get_sanitizer",
    "has_permission",
    "is_blocked",
    "pick_strategy",
    "record_event",
    "require_api_key",
    "score",
    "topology_scan",
]
