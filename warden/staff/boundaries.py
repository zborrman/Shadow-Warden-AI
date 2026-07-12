"""
Authorization Boundary Registry — STAFF-01.

Each digital employee has a BoundarySpec that is checked before every
tool dispatch. Boundaries live in Redis (key: staff:boundary:{agent_id})
with an in-process fallback dict. Suspension is instant: set the suspended
flag and the next tool call is rejected within the same request.

Rec-3 (payment isolation): issue_refund is never given a payment API key.
Instead it emits a signed RefundIntent that the billing backend countersigns.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from dataclasses import asdict, dataclass
from decimal import Decimal
from enum import StrEnum
from typing import Any

log = logging.getLogger(__name__)

_BOUNDARY_PREFIX = "staff:boundary:"
_REFUND_INTENT_PREFIX = "staff:refund_intent:"


class AgentRole(StrEnum):
    BDR = "BDR"
    GROWTH = "GROWTH"
    COMPLIANCE = "COMPLIANCE"
    QA = "QA"
    SUPPORT = "SUPPORT"


class BoundaryViolationError(RuntimeError):
    """Raised when an agent attempts a tool outside its boundary."""


@dataclass
class AuthorizationBoundary:
    agent_id: str
    role: AgentRole
    allowed_tools: frozenset[str]
    spend_ceiling_usd_daily: Decimal = Decimal("0")
    refund_cap_usd: Decimal = Decimal("10.00")
    autonomy_level: int = 1                 # 1=supervised 2=semi-auto 3=full-auto
    escalation_threshold: str = "MEDIUM"    # risk tier above which → human queue
    veto_role: str = "security_lead"        # human role that can suspend
    suspended: bool = False
    # Velocity limits (Rec-2)
    max_calls_per_hour: int = 200
    loop_detection_window_s: int = 60       # identical tool+hash within window = loop
    loop_detection_max: int = 5

    def to_redis(self) -> str:
        d = asdict(self)
        d["allowed_tools"] = list(self.allowed_tools)
        d["spend_ceiling_usd_daily"] = str(self.spend_ceiling_usd_daily)
        d["refund_cap_usd"] = str(self.refund_cap_usd)
        d["role"] = self.role.value
        return json.dumps(d)

    @classmethod
    def from_redis(cls, raw: str) -> AuthorizationBoundary:
        d = json.loads(raw)
        d["allowed_tools"] = frozenset(d["allowed_tools"])
        d["spend_ceiling_usd_daily"] = Decimal(d["spend_ceiling_usd_daily"])
        d["refund_cap_usd"] = Decimal(d["refund_cap_usd"])
        d["role"] = AgentRole(d["role"])
        return cls(**d)

    def check_tool(self, tool_name: str) -> None:
        if self.suspended:
            raise BoundaryViolationError(
                f"Agent {self.agent_id} is suspended. "
                "Contact your Compliance & Security Lead to restore."
            )
        if tool_name not in self.allowed_tools:
            raise BoundaryViolationError(
                f"Agent {self.agent_id} ({self.role.value}) is not authorized "
                f"to call tool '{tool_name}'. Allowed: {sorted(self.allowed_tools)}"
            )

    def sign_refund_intent(self, tenant_id: str, amount_usd: Decimal, reason: str) -> dict:
        """Rec-3: emit a signed intent, never expose payment credentials."""
        if amount_usd > self.refund_cap_usd:
            raise BoundaryViolationError(
                f"Refund ${amount_usd} exceeds cap ${self.refund_cap_usd} "
                f"for agent {self.agent_id}. Escalating to human approval."
            )
        payload = {
            "agent_id": self.agent_id,
            "tenant_id": tenant_id,
            "amount_usd": str(amount_usd),
            "reason": reason,
            "issued_at": int(time.time()),
        }
        canonical = json.dumps(payload, sort_keys=True)
        # Fail-closed signing key (no hardcoded fallback) — matches the A2A path.
        from warden.secret_keys import resolve_key  # noqa: PLC0415
        _key = resolve_key("STAFF_INTENT_KEY", purpose="staff_refund_intent")
        sig = hmac.new(_key, canonical.encode(), hashlib.sha256).hexdigest()
        return {"intent": payload, "sig": sig, "requires_backend_countersign": True}


# ── Default boundary definitions ──────────────────────────────────────────────

DEFAULT_BOUNDARIES: dict[str, AuthorizationBoundary] = {
    "bdr": AuthorizationBoundary(
        agent_id="bdr",
        role=AgentRole.BDR,
        allowed_tools=frozenset({
            "crm_search", "crm_upsert_lead", "send_email_draft",
            "schedule_meeting_slot", "get_filter_stats",
        }),
        spend_ceiling_usd_daily=Decimal("0"),  # no autonomous spend
        autonomy_level=1,
        escalation_threshold="LOW",    # all commitments → human
        max_calls_per_hour=100,
    ),
    "growth": AuthorizationBoundary(
        agent_id="growth",
        role=AgentRole.GROWTH,
        allowed_tools=frozenset({
            "fetch_market_signals", "generate_seo_content",
            "adjust_ad_budget", "get_filter_stats", "list_semantic_models",
        }),
        spend_ceiling_usd_daily=Decimal("50.00"),
        autonomy_level=2,
        escalation_threshold="HIGH",
        max_calls_per_hour=150,
    ),
    "compliance": AuthorizationBoundary(
        agent_id="compliance",
        role=AgentRole.COMPLIANCE,
        allowed_tools=frozenset({
            "screen_sanctions_list", "score_kyc_profile", "generate_sar",
            "get_compliance_report", "remediate_gap", "get_filter_stats",
            "explain_decision", "scan_document",
        }),
        spend_ceiling_usd_daily=Decimal("0"),
        autonomy_level=2,               # L2: LOW auto-approve, MEDIUM/HIGH → escalate
        escalation_threshold="MEDIUM",
        max_calls_per_hour=300,
    ),
    "qa": AuthorizationBoundary(
        agent_id="qa",
        role=AgentRole.QA,
        allowed_tools=frozenset({
            "visual_assert_page", "visual_diff", "get_filter_stats",
            "get_compliance_report", "explain_decision",
        }),
        spend_ceiling_usd_daily=Decimal("0"),
        autonomy_level=1,
        escalation_threshold="LOW",     # any failure → human review
        max_calls_per_hour=500,
    ),
    "support": AuthorizationBoundary(
        agent_id="support",
        role=AgentRole.SUPPORT,
        allowed_tools=frozenset({
            "get_ticket", "resolve_ticket_kb", "issue_refund",
            "get_billing_status", "get_filter_stats",
        }),
        spend_ceiling_usd_daily=Decimal("0"),
        refund_cap_usd=Decimal("10.00"),
        autonomy_level=2,
        escalation_threshold="MEDIUM",
        max_calls_per_hour=200,
    ),
}


# ── Registry ──────────────────────────────────────────────────────────────────

class BoundaryRegistry:
    """Redis-backed boundary store with in-process fallback."""

    def __init__(self, redis=None) -> None:
        self._redis = redis
        self._local: dict[str, AuthorizationBoundary] = dict(DEFAULT_BOUNDARIES)

    def get(self, agent_id: str) -> AuthorizationBoundary | None:
        if self._redis is not None:
            try:
                raw = self._redis.get(f"{_BOUNDARY_PREFIX}{agent_id}")
                if raw:
                    return AuthorizationBoundary.from_redis(raw)
            except Exception as exc:  # noqa: BLE001
                log.debug("BoundaryRegistry Redis get error: %s", exc)
        return self._local.get(agent_id)

    def put(self, boundary: AuthorizationBoundary, ttl_s: int = 0) -> None:
        self._local[boundary.agent_id] = boundary
        if self._redis is not None:
            try:
                key = f"{_BOUNDARY_PREFIX}{boundary.agent_id}"
                if ttl_s:
                    self._redis.setex(key, ttl_s, boundary.to_redis())
                else:
                    self._redis.set(key, boundary.to_redis())
            except Exception as exc:  # noqa: BLE001
                log.debug("BoundaryRegistry Redis put error: %s", exc)

    def suspend(self, agent_id: str) -> bool:
        b = self.get(agent_id)
        if b is None:
            return False
        import dataclasses
        suspended = dataclasses.replace(b, suspended=True)
        self.put(suspended)
        log.warning("STAFF: agent %s SUSPENDED", agent_id)
        return True

    def restore(self, agent_id: str) -> bool:
        b = self.get(agent_id)
        if b is None:
            return False
        import dataclasses
        restored = dataclasses.replace(b, suspended=False)
        self.put(restored)
        log.info("STAFF: agent %s RESTORED", agent_id)
        return True

    def list_all(self) -> list[dict[str, Any]]:
        ids = set(self._local.keys())
        if self._redis is not None:
            try:
                keys = self._redis.keys(f"{_BOUNDARY_PREFIX}*")
                for k in keys:
                    ids.add(k.decode().removeprefix(_BOUNDARY_PREFIX))
            except Exception:  # noqa: BLE001
                pass
        result = []
        for aid in sorted(ids):
            b = self.get(aid)
            if b:
                result.append({
                    "agent_id": b.agent_id,
                    "role": b.role.value,
                    "suspended": b.suspended,
                    "autonomy_level": b.autonomy_level,
                    "spend_ceiling_usd_daily": str(b.spend_ceiling_usd_daily),
                    "refund_cap_usd": str(b.refund_cap_usd),
                    "allowed_tools": sorted(b.allowed_tools),
                    "escalation_threshold": b.escalation_threshold,
                    "max_calls_per_hour": b.max_calls_per_hour,
                })
        return result

    def check_and_dispatch(self, agent_id: str, tool_name: str) -> AuthorizationBoundary:
        """Validate tool call against boundary; return boundary on success."""
        b = self.get(agent_id)
        if b is None:
            raise BoundaryViolationError(
                f"No boundary registered for agent '{agent_id}'. "
                "Register via POST /staff/boundaries before dispatching."
            )
        b.check_tool(tool_name)
        return b


_registry_instance: BoundaryRegistry | None = None


def get_registry(redis=None) -> BoundaryRegistry:
    global _registry_instance
    if _registry_instance is None:
        _registry_instance = BoundaryRegistry(redis=redis)
    return _registry_instance
