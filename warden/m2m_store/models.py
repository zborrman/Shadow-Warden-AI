"""
warden/m2m_store/models.py
───────────────────────────
Pydantic models for the M2M Commerce Store.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class Product(BaseModel):
    id: str = ""
    name: str
    description: str = ""
    category: str = "general"
    price_base: float = Field(..., ge=0.0)
    stock: int = Field(default=0, ge=0)
    reserved: int = Field(default=0, ge=0)
    unit: str = "unit"
    metadata: dict[str, Any] = Field(default_factory=dict)
    active: bool = True

    @property
    def available(self) -> int:
        return max(0, self.stock - self.reserved)


class Offer(BaseModel):
    id: str = ""
    product_id: str
    agent_id: str
    qty: int = Field(default=1, ge=1)
    price_base: float
    price_final: float
    discount_percent: float = Field(default=0.0, ge=0.0, le=100.0)
    valid_until: int = 0       # Unix timestamp
    reservation_id: str = ""
    explanation: str = ""      # LLM-generated discount explanation (optional)
    tenant_id: str = ""


class Order(BaseModel):
    id: str = ""
    agent_id: str
    offer_id: str
    product_id: str
    mandate_id: str
    qty: int = Field(default=1, ge=1)
    total: float
    status: str = "PENDING"    # PENDING | PAID | SHIPPED | CANCELLED
    payment_token: str = ""
    reservation_id: str = ""
    created_at: str = ""
    shipped_at: str = ""
    tenant_id: str = ""
    stix_chain_id: str = ""


class StoreConfig(BaseModel):
    tenant_id: str
    accepted_mandate_issuers: list[str] = Field(default_factory=list)
    max_discount: float = Field(default=20.0, ge=0.0, le=100.0)
    default_ttl_seconds: int = Field(default=45, ge=10, le=300)
    rate_limit_per_minute: int = Field(default=100, ge=1)
    store_name: str = "M2M Store"
    currency: str = "USD"
    active: bool = True


class OfferRequest(BaseModel):
    product_id: str = Field(..., max_length=120)
    qty: int = Field(default=1, ge=1, le=10_000)
    agent_id: str = Field(..., max_length=120)


class OrderRequest(BaseModel):
    offer_id: str = Field(..., max_length=120)
    mandate_id: str = Field(..., max_length=120)
    payment_token: str = Field(..., max_length=512)
