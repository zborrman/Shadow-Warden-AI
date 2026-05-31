"""
warden/m2m_store/catalog.py
────────────────────────────
AICatalog — AI-readable product catalog with semantic search fallback.

Primary search: full-text SQLite (FTS5 if available, else LIKE).
Optional upgrade path: vector embeddings via pgvector / FAISS.
UCP-compatible: exposes list_by_category for UCP discovery endpoint.
"""
from __future__ import annotations

import logging
from typing import Any

from warden.m2m_store.inventory import get_inventory
from warden.m2m_store.models import Product

log = logging.getLogger("warden.m2m_store.catalog")


class AICatalog:
    """AI-readable product catalog backed by InventoryManager."""

    def search(
        self,
        query: str = "",
        filters: dict[str, Any] | None = None,
    ) -> list[Product]:
        """
        Search products by query string and optional filters.

        filters keys:
          category      — exact match (case-insensitive)
          min_price     — float
          max_price     — float
          in_stock_only — bool (default True)
        """
        f = filters or {}
        products = get_inventory().list_products(
            category=f.get("category"),
            query=query or None,
            active_only=True,
        )
        if f.get("in_stock_only", True):
            products = [p for p in products if p.available > 0]
        if "min_price" in f:
            products = [p for p in products if p.price_base >= float(f["min_price"])]
        if "max_price" in f:
            products = [p for p in products if p.price_base <= float(f["max_price"])]
        return products

    def get_product(self, product_id: str) -> Product | None:
        return get_inventory().get_product(product_id)

    def list_by_category(self, category: str) -> list[Product]:
        return get_inventory().list_products(category=category, active_only=True)

    def update_stock(self, product_id: str, delta: int) -> bool:
        return get_inventory().update_stock(product_id, delta)

    def add_product(self, product: Product) -> Product:
        return get_inventory().add_product(product)

    def to_ucp_catalog(self) -> dict[str, Any]:
        """Format catalog as UCP-compatible JSON for external discovery."""
        products = get_inventory().list_products(active_only=True)
        return {
            "version": "1.0",
            "store": "shadow-warden-m2m",
            "products": [
                {
                    "id":          p.id,
                    "name":        p.name,
                    "description": p.description,
                    "category":    p.category,
                    "price":       p.price_base,
                    "currency":    "USD",
                    "available":   p.available,
                    "unit":        p.unit,
                }
                for p in products
                if p.available > 0
            ],
            "count": len(products),
        }


_catalog = AICatalog()


def get_catalog() -> AICatalog:
    return _catalog
