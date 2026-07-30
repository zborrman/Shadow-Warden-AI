"""
warden/business_community/agentic_commerce/mcp_bridge.py  (CM-40)
──────────────────────────────────────────────────────────────────
Model Context Protocol (MCP) bridge for Anthropic-agent commerce intents.

Translates natural-language purchase intents from Anthropic agents into
structured UCP queries. High-value or ambiguous intents are routed through
the human-in-the-loop approval flow via Slack.
"""
from __future__ import annotations

import contextlib
import logging
import os
import re
from typing import Any

from warden.business_community.agentic_commerce.models import MCPIntent

log = logging.getLogger("warden.commerce.mcp")

_APPROVAL_THRESHOLD = float(os.getenv("COMMERCE_APPROVAL_THRESHOLD_USD", "100"))

# Simple keyword → product category mapping
_CATEGORY_HINTS: dict[str, str] = {
    "software": "software_license",
    "licence": "software_license",
    "license": "software_license",
    "subscription": "subscription",
    "cloud": "cloud_service",
    "api": "api_service",
    "domain": "domain",
    "hosting": "hosting",
    "server": "compute",
    "storage": "storage",
    "security": "security_tool",
    "monitoring": "monitoring",
    "analytics": "analytics",
    "ticket": "event_ticket",
    "hotel": "travel",
    "flight": "travel",
    "book": "book",
}


class MCPBridge:
    """
    Bridge between Anthropic MCP agent commands and the UCP/AP2 commerce stack.

    receive_intent → parse → validate → (approval if needed) → execute
    """

    def receive_intent(self, payload: dict[str, Any]) -> MCPIntent:
        """Parse a raw MCP payload into a structured MCPIntent."""
        raw = payload.get("content", payload.get("text", str(payload)))
        max_amount = self._extract_amount(raw)
        keywords = self._extract_keywords(raw)
        requires_approval = (max_amount or 0) >= _APPROVAL_THRESHOLD

        return MCPIntent(
            tenant_id=payload.get("tenant_id", "default"),
            raw=raw,
            max_amount=max_amount,
            currency=payload.get("currency", "USD"),
            keywords=keywords,
            requires_approval=requires_approval,
            metadata=payload.get("metadata", {}),
        )

    def translate_to_ucp(self, intent: MCPIntent) -> dict[str, Any]:
        """Convert MCPIntent to a UCP search/cart request structure."""
        category = "general"
        for kw in intent.keywords:
            if kw.lower() in _CATEGORY_HINTS:
                category = _CATEGORY_HINTS[kw.lower()]
                break

        return {
            "query": " ".join(intent.keywords) if intent.keywords else intent.raw[:100],
            "category": category,
            "max_price": intent.max_amount,
            "currency": intent.currency,
            "limit": 5,
        }

    async def execute_with_approval(
        self,
        intent: MCPIntent,
        tenant_id: str,
        mandate_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Execute a commerce intent, routing to human approval if required.

        Returns {approved, workflow_id, message} synchronously. NOTE: approving
        the resulting workflow records the decision — it does not yet execute the
        purchase. Nothing consumes a resolved workflow, so the execution half of
        this flow is unimplemented. This docstring previously claimed "actual
        purchase happens after approval callback resolves", which was never true.
        """
        if intent.requires_approval:
            workflow_id = await self._request_approval(intent, tenant_id)
            return {
                "approved": False,
                "pending": True,
                "workflow_id": workflow_id,
                "message": f"Purchase intent requires approval (amount ≥ ${_APPROVAL_THRESHOLD:.0f}). "
                           f"Approval request sent to Slack.",
            }

        return {
            "approved": True,
            "pending": False,
            "workflow_id": None,
            "message": "Intent approved automatically (below approval threshold).",
            "ucp_query": self.translate_to_ucp(intent),
        }

    async def _request_approval(self, intent: MCPIntent, tenant_id: str) -> str:
        """
        Open a human-in-the-loop approval request and announce it on Slack.

        The workflow is recorded before the alert goes out. Without that record
        the id was unverifiable: /approve/{workflow_id} accepted any string at
        all and reported it resolved, so the approval gate confirmed decisions
        about workflows that had never existed.
        """
        import uuid as _uuid
        workflow_id = f"mcp-approval-{_uuid.uuid4().hex[:12]}"
        store_pending_workflow(workflow_id, {
            "tenant_id":  tenant_id,
            "max_amount": intent.max_amount,
            "currency":   intent.currency,
            "intent":     intent.raw[:200],
            "status":     "PENDING",
        })

        try:
            from warden.alerting import send_alert as send_slack_alert
            msg = (
                f"*MCP Commerce Approval Required*\n"
                f"Tenant: `{tenant_id}`\n"
                f"Intent: _{intent.raw[:200]}_\n"
                f"Max amount: `{intent.currency} {intent.max_amount:.2f}`\n"
                f"Workflow: `{workflow_id}`\n"
                f"Approve: `POST /business-community/commerce/approve/{workflow_id}`"
            )
            send_slack_alert(msg)
        except Exception as exc:
            log.warning("MCP approval Slack alert failed: %s", exc)

        return workflow_id

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_amount(text: str) -> float | None:
        """Extract the first dollar/euro amount from intent text."""
        patterns = [
            r"\$\s*(\d+(?:\.\d{1,2})?)",
            r"(\d+(?:\.\d{1,2})?)\s*(?:USD|EUR|GBP|dollars?|euros?)",
            r"(?:up to|max|maximum|no more than|under)\s+(\d+(?:\.\d{1,2})?)",
        ]
        for pattern in patterns:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                return float(m.group(1))
        return None

    @staticmethod
    def _extract_keywords(text: str) -> list[str]:
        """Extract meaningful product keywords from intent text."""
        stopwords = {"a", "an", "the", "please", "buy", "purchase", "get", "me",
                     "need", "want", "find", "i", "for", "to", "of", "and", "or"}
        words = re.findall(r"[a-zA-Z]{3,}", text.lower())
        return [w for w in words if w not in stopwords][:10]

# ── Pending approval workflows ───────────────────────────────────────────────
#
# Redis-backed with an in-process fallback, mirroring warden/agent/master.py's
# approval store. Both lookups fail CLOSED: an id that cannot be found is not
# approvable, so losing the store denies rather than waves things through.

_PENDING_TTL_S = 3600
_pending_local: dict[str, dict[str, Any]] = {}


def _redis_client():
    import redis as _redis

    from warden.config import settings
    return _redis.from_url(settings.redis_url, decode_responses=True)


def store_pending_workflow(workflow_id: str, record: dict[str, Any]) -> None:
    """Record a workflow awaiting human approval."""
    import json
    import time
    record = {**record, "created_at": int(time.time())}
    try:
        _redis_client().setex(
            f"commerce:approval:{workflow_id}", _PENDING_TTL_S, json.dumps(record)
        )
    except Exception as exc:
        log.warning("commerce: Redis unavailable for approval storage: %s", exc)
    _pending_local[workflow_id] = record


def get_pending_workflow(workflow_id: str) -> dict[str, Any] | None:
    """Return the pending record, or None if unknown, expired or resolved."""
    import json
    with contextlib.suppress(Exception):
        raw = _redis_client().get(f"commerce:approval:{workflow_id}")
        if raw:
            return json.loads(raw)  # type: ignore[arg-type]
    return _pending_local.get(workflow_id)


def resolve_workflow(
    workflow_id: str, tenant_id: str, approved: bool
) -> dict[str, Any] | None:
    """
    Consume a pending workflow and record the decision.

    Returns the updated record, or None when the id is unknown, already resolved,
    or belongs to a different tenant — the caller turns that into a 404 rather
    than confirming a decision about a workflow that does not exist.
    """
    import json
    record = get_pending_workflow(workflow_id)
    if not record or record.get("status") != "PENDING":
        return None
    if record.get("tenant_id") != tenant_id:
        return None

    record = {**record, "status": "APPROVED" if approved else "REJECTED"}
    with contextlib.suppress(Exception):
        _redis_client().setex(
            f"commerce:approval:{workflow_id}", _PENDING_TTL_S, json.dumps(record)
        )
    _pending_local[workflow_id] = record
    return record
