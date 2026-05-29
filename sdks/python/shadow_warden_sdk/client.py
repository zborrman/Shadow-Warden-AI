"""
shadow_warden_sdk/client.py
ShadowWardenClient — sync and async HTTP client for the Shadow Warden AI API.
"""
from __future__ import annotations

from typing import Any

import httpx


class ShadowWardenClient:
    """
    Synchronous client for the Shadow Warden AI API.

    Usage::

        client = ShadowWardenClient(api_key="sw-...", base_url="https://api.shadow-warden-ai.com")

        # Filter a prompt
        result = client.filter("Tell me how to break into a system")
        if result["blocked"]:
            print("Blocked:", result["risk_score"])

        # Create a spending mandate
        mandate = client.create_mandate(tenant_id="acme", max_amount=500.0)
        print(mandate["id"])
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.shadow-warden-ai.com",
        timeout: float = 15.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._headers  = {"X-API-Key": api_key, "Content-Type": "application/json"}
        self._timeout  = timeout

    def _get(self, path: str, **params) -> dict[str, Any]:
        with httpx.Client(timeout=self._timeout) as client:
            r = client.get(f"{self._base_url}{path}", headers=self._headers, params=params)
            r.raise_for_status()
            return r.json()

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        with httpx.Client(timeout=self._timeout) as client:
            r = client.post(f"{self._base_url}{path}", headers=self._headers, json=body)
            r.raise_for_status()
            return r.json()

    def _delete(self, path: str, **params) -> dict[str, Any]:
        with httpx.Client(timeout=self._timeout) as client:
            r = client.delete(f"{self._base_url}{path}", headers=self._headers, params=params)
            r.raise_for_status()
            return r.json()

    # ── Filter API ────────────────────────────────────────────────────────────

    def filter(self, content: str, tenant_id: str = "default") -> dict[str, Any]:
        """Send content through the 9-layer filter pipeline."""
        return self._post("/filter", {"content": content, "tenant_id": tenant_id})

    def health(self) -> dict[str, Any]:
        return self._get("/health")

    # ── Commerce / Mandate API ────────────────────────────────────────────────

    def create_mandate(
        self,
        tenant_id: str,
        max_amount: float,
        currency: str = "USD",
        valid_days: int = 30,
        allowed_merchants: list[str] | None = None,
    ) -> dict[str, Any]:
        return self._post("/business-community/commerce/mandates", {
            "tenant_id": tenant_id,
            "max_amount": max_amount,
            "currency": currency,
            "allowed_merchants": allowed_merchants or [],
        })

    def list_mandates(self, tenant_id: str) -> list[dict[str, Any]]:
        result = self._get("/business-community/commerce/mandates", tenant_id=tenant_id)
        return result.get("mandates", [])

    def revoke_mandate(self, mandate_id: str, tenant_id: str) -> dict[str, Any]:
        return self._delete(f"/business-community/commerce/mandates/{mandate_id}",
                            tenant_id=tenant_id)

    def create_order(
        self,
        tenant_id: str,
        store_url: str,
        mandate_id: str,
        items: list[dict[str, Any]],
    ) -> dict[str, Any]:
        return self._post("/business-community/commerce/orders", {
            "tenant_id":  tenant_id,
            "store_url":  store_url,
            "mandate_id": mandate_id,
            "items":      items,
        })

    def order_history(self, tenant_id: str, limit: int = 50) -> list[dict[str, Any]]:
        result = self._get("/business-community/commerce/orders",
                           tenant_id=tenant_id, limit=limit)
        return result.get("orders", [])

    def get_spend_report(self, tenant_id: str) -> dict[str, Any]:
        return self._get("/business-community/commerce/analytics/spend", tenant_id=tenant_id)

    # ── MCP Intent API ────────────────────────────────────────────────────────

    def submit_intent(self, tenant_id: str, content: str, currency: str = "USD") -> dict[str, Any]:
        return self._post("/business-community/commerce/mcp/intent", {
            "tenant_id": tenant_id,
            "content":   content,
            "currency":  currency,
        })

    # ── Tax API ───────────────────────────────────────────────────────────────

    def calculate_tax(
        self,
        net_amount: float,
        buyer_country: str,
        seller_country: str = "US",
        buyer_region: str | None = None,
        is_b2b: bool = False,
    ) -> dict[str, Any]:
        return self._post("/tax/calculate", {
            "net_amount":     net_amount,
            "buyer_country":  buyer_country,
            "seller_country": seller_country,
            "buyer_region":   buyer_region,
            "is_b2b":         is_b2b,
        })
