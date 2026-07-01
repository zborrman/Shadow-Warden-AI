"""
ACP data models — Shared Payment Tokens, Cart, ACP Receipt, Refund Request.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class SharedPaymentToken(BaseModel):
    """
    Merchant-issued token authorizing an agent to spend up to max_amount
    in a single checkout session. Analogous to a pre-authorized one-time payment link.

    Security properties:
    - HMAC-SHA256 signed (token_id|merchant_id|agent_id|max_amount|expires_at)
    - One-time-use by default (use_limit=1); remaining_uses decrements on checkout
    - Redis-backed (acp:spt:{token_id}) with TTL = expires_at
    - SQLite audit trail on each use
    """
    token_id:        str
    merchant_id:     str
    agent_id:        str                           # DID of the purchasing agent
    max_amount:      float
    currency:        str = "USD"
    scope:           list[str] = Field(default_factory=list)  # e.g. ["checkout", "refund"]
    expires_at:      str                           # ISO-8601
    use_limit:       int = 1
    remaining_uses:  int = 1
    status:          str = "ACTIVE"               # ACTIVE | USED | EXPIRED | REVOKED
    issued_at:       str = ""
    signature:       str = ""


class CartItem(BaseModel):
    product_id:  str
    name:        str
    qty:         int = 1
    unit_price:  float
    currency:    str = "USD"

    @property
    def subtotal(self) -> float:
        return round(self.qty * self.unit_price, 2)


class Cart(BaseModel):
    cart_id:     str
    tenant_id:   str
    agent_id:    str
    merchant_id: str
    mandate_id:  str
    spt_id:      str = ""                         # bound after SPT is presented
    items:       list[CartItem] = Field(default_factory=list)
    currency:    str = "USD"
    status:      str = "OPEN"                     # OPEN | CHECKED_OUT | ABANDONED
    created_at:  str = ""

    @property
    def total(self) -> float:
        return round(sum(i.subtotal for i in self.items), 2)


class ACPReceipt(BaseModel):
    """
    ACP-standard receipt returned after successful checkout.
    Includes both the AP2 transaction reference and the STIX audit chain entry.
    """
    receipt_id:      str
    order_id:        str
    transaction_id:  str                           # AP2 transaction ID
    merchant_id:     str
    agent_id:        str
    tenant_id:       str
    amount:          float
    currency:        str = "USD"
    items:           list[CartItem] = Field(default_factory=list)
    spt_id:          str = ""
    mandate_id:      str = ""
    stix_chain_id:   str = ""
    timestamp:       str = ""
    acp_version:     str = "1.0"


class RefundRequest(BaseModel):
    """
    ACP refund request — always PENDING_REVIEW (draft-only pattern).
    Agents propose refunds; humans approve them.
    """
    refund_id:   str
    order_id:    str
    merchant_id: str
    agent_id:    str
    tenant_id:   str
    amount:      float
    currency:    str = "USD"
    reason:      str = ""
    status:      str = "PENDING_REVIEW"           # PENDING_REVIEW | APPROVED | REJECTED
    created_at:  str = ""
    stix_chain_id: str = ""


class ACPMerchantManifest(BaseModel):
    """
    ACP discovery manifest served at GET /.well-known/acp.json.
    External agents discover this to understand payment capabilities.
    """
    merchant_id:      str
    merchant_name:    str = "Shadow Warden AI"
    acp_version:      str = "1.0"
    token_endpoint:   str
    checkout_endpoint: str
    refund_endpoint:  str
    receipt_endpoint: str
    supported_currencies: list[str] = Field(default_factory=lambda: ["USD", "USDC"])
    supported_scopes: list[str] = Field(default_factory=lambda: ["checkout", "refund"])
    max_token_amount: float = 10_000.0
    require_agent_did: bool = True
    metadata:         dict[str, Any] = Field(default_factory=dict)
