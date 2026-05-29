"""
shadow_warden_sdk/agent.py
SecureAgent — mixin/decorator that adds Shadow Warden mandate controls
to any AI agent class.
"""
from __future__ import annotations

from typing import Any


class SecureAgent:
    """
    Mix this into an AI agent class to add mandate-controlled purchasing.

    Usage::

        class MyProcurementAgent(SecureAgent):
            def __init__(self, api_key: str, tenant_id: str):
                super().__init__(api_key=api_key, tenant_id=tenant_id,
                                 base_url="https://api.shadow-warden-ai.com")

            def run(self, task: str):
                # Filter the task through Shadow Warden first
                result = self.filter_prompt(task)
                if result.get("blocked"):
                    raise ValueError(f"Task blocked: {result['risk_score']}")

                # Create a mandate and purchase
                mandate = self.create_mandate(max_amount=100.0)
                order   = self.purchase({
                    "store_url":  "https://shop.example.com",
                    "mandate_id": mandate["id"],
                    "items":      [{"name": "Widget", "qty": 1, "unit_price": 29.99}],
                })
                return order
    """

    def __init__(
        self,
        api_key: str,
        tenant_id: str,
        base_url: str = "https://api.shadow-warden-ai.com",
        max_default_amount: float = 100.0,
    ) -> None:
        from shadow_warden_sdk.client import ShadowWardenClient
        self._sw_client   = ShadowWardenClient(api_key=api_key, base_url=base_url)
        self._tenant_id   = tenant_id
        self._max_default = max_default_amount
        self._active_mandate: dict[str, Any] | None = None

    # ── Security ──────────────────────────────────────────────────────────────

    def filter_prompt(self, content: str) -> dict[str, Any]:
        """Pass any AI prompt through Shadow Warden before processing."""
        return self._sw_client.filter(content, tenant_id=self._tenant_id)

    # ── Commerce ──────────────────────────────────────────────────────────────

    def create_mandate(
        self,
        max_amount: float | None = None,
        currency: str = "USD",
        allowed_merchants: list[str] | None = None,
    ) -> dict[str, Any]:
        mandate = self._sw_client.create_mandate(
            tenant_id=self._tenant_id,
            max_amount=max_amount or self._max_default,
            currency=currency,
            allowed_merchants=allowed_merchants or [],
        )
        self._active_mandate = mandate
        return mandate

    def purchase(self, order: dict[str, Any]) -> dict[str, Any]:
        """
        Execute a purchase. If no mandate_id is provided in order,
        uses the last created mandate or creates a new one.
        """
        if "mandate_id" not in order:
            if not self._active_mandate:
                self.create_mandate()
            order["mandate_id"] = self._active_mandate["id"]

        order.setdefault("tenant_id", self._tenant_id)
        return self._sw_client.create_order(
            tenant_id=order.pop("tenant_id", self._tenant_id),
            store_url=order.pop("store_url", ""),
            mandate_id=order.pop("mandate_id", ""),
            items=order.pop("items", []),
        )

    def get_spend_report(self) -> dict[str, Any]:
        return self._sw_client.get_spend_report(self._tenant_id)

    def submit_purchase_intent(self, natural_language: str) -> dict[str, Any]:
        """Submit a natural-language purchase intent to the MCP bridge."""
        return self._sw_client.submit_intent(self._tenant_id, natural_language)
