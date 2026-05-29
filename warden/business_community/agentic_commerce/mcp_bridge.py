"""
warden/business_community/agentic_commerce/mcp_bridge.py  (CM-40)
──────────────────────────────────────────────────────────────────
Model Context Protocol (MCP) bridge for Anthropic-agent commerce intents.

Translates natural-language purchase intents from Anthropic agents into
structured UCP queries. High-value or ambiguous intents are routed through
the human-in-the-loop approval flow via Slack.
"""
from __future__ import annotations

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
        Returns {approved, workflow_id, message} synchronously; actual
        purchase happens after approval callback resolves.
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
        """Send human-in-the-loop approval request via Slack alerting."""
        import uuid as _uuid
        workflow_id = f"mcp-approval-{_uuid.uuid4().hex[:12]}"

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
