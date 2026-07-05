"""
warden/guards/ — Security guard facade package.

Canonical import path for all detection and blocking modules.
All names are also available at their legacy flat paths
(e.g. ``warden.semantic_guard``) for backward compatibility.
"""
from __future__ import annotations

from warden.agent_monitor import AgentMonitor
from warden.auth_guard import (  # noqa: F401
    AuthResult,
    get_rate_limit,
    require_api_key,
    set_default_rate_limit,
)
from warden.causal_arbiter import CausalResult, arbitrate
from warden.entity_risk import ERSResult, record_event, score
from warden.global_blocklist import is_blocked
from warden.honey import HoneyEngine, HoneyResult
from warden.output_guard import BusinessScanResult, TenantOutputConfig
from warden.output_sanitizer import get_sanitizer
from warden.prompt_shield import PromptShield, ShieldResult
from warden.rbac import DashboardRole, has_permission
from warden.semantic_guard import SemanticGuard
from warden.session_guard import SessionGuard, SessionRisk
from warden.shadow_ban import fake_filter_response, pick_strategy
from warden.taint_tracker import TaintDecision, TaintLevel, TaintState
from warden.tool_guard import ToolCallGuard, ToolInspectionResult
from warden.topology_guard import scan as topology_scan
from warden.worm_guard import WormDetectionResult

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
