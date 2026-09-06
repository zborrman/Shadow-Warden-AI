"""
warden/business_community/agentic_commerce/models.py  (CM-40)
──────────────────────────────────────────────────────────────
Pydantic models for Agentic Commerce: Mandate, PurchaseOrder, Receipt.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class Mandate(BaseModel):
    id: str
    tenant_id: str
    max_amount: float
    spent_so_far: float = 0.0
    currency: str = "USD"
    valid_until: str                        # ISO-8601
    allowed_merchants: list[str] = Field(default_factory=list)
    status: str = "ACTIVE"                  # ACTIVE | SUSPENDED | REVOKED | EXPIRED
    created_at: str = ""
    signature: str = ""                     # Ed25519 + HMAC over canonical fields
    ueciid: str = ""                        # SEP UECIID for audit chain

    def remaining(self) -> float:
        return max(0.0, self.max_amount - self.spent_so_far)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()


class OrderItem(BaseModel):
    product_id: str
    name: str
    qty: int = 1
    unit_price: float
    currency: str = "USD"


class PurchaseOrder(BaseModel):
    id: str
    tenant_id: str
    store_url: str
    items: list[OrderItem] = Field(default_factory=list)
    total: float
    currency: str = "USD"
    mandate_id: str
    status: str = "PENDING"               # PENDING | PAID | FAILED | REFUNDED
    created_at: str = ""
    mcp_intent: str = ""                  # original MCP intent string, if agent-initiated
    ueciid: str = ""
    stix_chain_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()


class Receipt(BaseModel):
    id: str
    purchase_order_id: str
    transaction_id: str
    timestamp: str
    amount: float
    currency: str = "USD"
    payment_method: str = "AP2"
    merchant: str = ""

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()


class MCPIntent(BaseModel):
    tenant_id: str
    raw: str                               # natural-language intent from the agent
    max_amount: float | None = None
    currency: str = "USD"
    keywords: list[str] = Field(default_factory=list)
    requires_approval: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)
