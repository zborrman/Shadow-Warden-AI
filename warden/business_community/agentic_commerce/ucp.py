"""
warden/business_community/agentic_commerce/ucp.py  (CM-40)
───────────────────────────────────────────────────────────
Universal Commerce Protocol (UCP) client.

Implements store discovery, product search, cart management and
checkout initiation per the Google UCP draft specification.
All network calls are async; fall back gracefully when the store
does not expose a UCP endpoint.
"""
from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

log = logging.getLogger("warden.commerce.ucp")

_DEFAULT_TIMEOUT = 8.0


class UCPCapabilities:
    def __init__(self, data: dict[str, Any]) -> None:
        self.raw = data
        self.search_url: str = data.get("search_url", "")
        self.cart_url: str = data.get("cart_url", "")
        self.checkout_url: str = data.get("checkout_url", "")
        self.supported_protocols: list[str] = data.get("protocols", [])
        self.supports_ap2: bool = "ap2" in [p.lower() for p in self.supported_protocols]


class UCPClient:
    """
    Async client for Universal Commerce Protocol stores.

    All methods are fail-open: on network error they return empty
    structures rather than raising, so the commerce workflow can
    log the failure and continue with alternative stores.
    """

    def __init__(self, timeout: float = _DEFAULT_TIMEOUT) -> None:
        self.timeout = timeout

    async def discover_store(self, domain: str) -> UCPCapabilities | None:
        """
        GET /.well-known/ucp on *domain* and return capability record.
        Returns None when the store does not implement UCP.
        """
        try:
            from warden.net_guard import send_pinned_async
            parsed = urlparse(domain if "://" in domain else f"https://{domain}")
            url = f"{parsed.scheme}://{parsed.netloc}/.well-known/ucp"
            # SSRF guard: caller-supplied store domain — validate AND pin.
            r = await send_pinned_async("GET", url, timeout=self.timeout)
            if r.status_code == 200:
                return UCPCapabilities(r.json())
        except Exception as exc:
            log.debug("UCP discovery failed for %s: %s", domain, exc)
        return None

    async def search_products(
        self,
        store: UCPCapabilities,
        query: str,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Query store product catalog via UCP Search API."""
        if not store.search_url:
            return []
        try:
            from warden.net_guard import send_pinned_async
            # SSRF guard: store-supplied URL — validate AND pin.
            r = await send_pinned_async(
                "GET", store.search_url, params={"q": query, "limit": limit},
                timeout=self.timeout,
            )
            if r.status_code == 200:
                return r.json().get("items", [])
        except Exception as exc:
            log.warning("UCP product search failed: %s", exc)
        return []

    async def add_to_cart(
        self,
        store: UCPCapabilities,
        product_id: str,
        qty: int = 1,
        cart_id: str | None = None,
    ) -> dict[str, Any]:
        """Add a product to cart via UCP Cart API. Returns updated cart state."""
        if not store.cart_url:
            return {"error": "store_does_not_support_cart"}
        try:
            from warden.net_guard import send_pinned_async
            payload: dict[str, Any] = {"product_id": product_id, "qty": qty}
            if cart_id:
                payload["cart_id"] = cart_id
            # SSRF guard: store-supplied URL — validate AND pin.
            r = await send_pinned_async("POST", store.cart_url, json=payload, timeout=self.timeout)
            if r.status_code in (200, 201):
                return r.json()
        except Exception as exc:
            log.warning("UCP add_to_cart failed: %s", exc)
        return {"error": "cart_failed"}

    async def checkout(
        self,
        store: UCPCapabilities,
        cart_id: str,
        mandate_id: str,
        tenant_id: str,
    ) -> dict[str, Any]:
        """
        Initiate checkout via UCP Checkout API, using mandate_id as the
        AP2 payment reference. Returns {order_id, status, total}.
        """
        if not store.checkout_url:
            return {"error": "store_does_not_support_checkout"}
        try:
            from warden.net_guard import send_pinned_async
            payload = {
                "cart_id": cart_id,
                "payment_protocol": "ap2",
                "mandate_id": mandate_id,
                "buyer_ref": tenant_id,
            }
            # SSRF guard: store-supplied URL — validate AND pin.
            r = await send_pinned_async("POST", store.checkout_url, json=payload, timeout=self.timeout)
            if r.status_code in (200, 201):
                return r.json()
        except Exception as exc:
            log.warning("UCP checkout failed: %s", exc)
        return {"error": "checkout_failed"}
