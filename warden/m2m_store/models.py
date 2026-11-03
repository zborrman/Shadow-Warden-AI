"""
warden/m2m_store/models.py
───────────────────────────
Pydantic models for the M2M Commerce Store.

Money is an integer count of the currency's minor unit (cents for USD) next
to its ISO 4217 code. The ``price_base`` / ``price_final`` / ``total`` floats
are display values derived from the integers — never compute with them.
"""
from __future__ import annotations

from decimal import ROUND_HALF_EVEN, Decimal
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

# Currencies the store accepts, with their minor-unit exponent. USD only for
# now: the Budget Guardian and the AP2 mandate both count in USD, and nothing
# converts between currencies. Per-currency prices are plan stage M2.
MINOR_DIGITS: dict[str, int] = {"USD": 2}


def to_minor(amount: float | str | Decimal, currency: str) -> int:
    """Convert a major-unit amount to minor units, rounding half-even."""
    digits = MINOR_DIGITS[currency]
    return int((Decimal(str(amount)) * (10 ** digits)).quantize(Decimal(1), ROUND_HALF_EVEN))


def from_minor(amount_minor: int, currency: str) -> float:
    """Major-unit display value of a minor-unit amount."""
    return float(Decimal(amount_minor) / (10 ** MINOR_DIGITS[currency]))


def _check_currency(value: str) -> str:
    code = (value or "").upper()
    if code not in MINOR_DIGITS:
        raise ValueError(f"unsupported currency {value!r}; supported: {sorted(MINOR_DIGITS)}")
    return code


class Product(BaseModel):
    id: str = ""
    # Seller tenant. Set by the server from the caller's API key, never
    # trusted from the request body.
    tenant_id: str = ""
    name: str
    description: str = ""
    category: str = "general"
    currency: str = "USD"
    price_minor: int | None = Field(default=None, ge=0)
    price_base: float = Field(default=0.0, ge=0.0)
    stock: int = Field(default=0, ge=0)
    reserved: int = Field(default=0, ge=0)
    unit: str = "unit"
    metadata: dict[str, Any] = Field(default_factory=dict)
    active: bool = True

    @field_validator("currency")
    @classmethod
    def _currency(cls, value: str) -> str:
        return _check_currency(value)

    @model_validator(mode="after")
    def _derive_money(self) -> Product:
        # price_minor is authoritative; price_base is accepted from older
        # clients and is always rewritten from the integer.
        if self.price_minor is None:
            self.price_minor = to_minor(self.price_base, self.currency)
        self.price_base = from_minor(self.price_minor, self.currency)
        return self

    @property
    def available(self) -> int:
        return max(0, self.stock - self.reserved)


class Offer(BaseModel):
    id: str = ""
    product_id: str
    agent_id: str
    qty: int = Field(default=1, ge=1)
    currency: str = "USD"
    price_base_minor: int = 0
    price_final_minor: int = 0
    price_base: float = 0.0
    price_final: float = 0.0
    discount_percent: float = Field(default=0.0, ge=0.0, le=100.0)
    valid_until: int = 0       # Unix timestamp
    reservation_id: str = ""
    explanation: str = ""      # LLM-generated discount explanation (optional)
    tenant_id: str = ""        # buyer tenant
    seller_tenant_id: str = ""
    product_name: str = ""


class Order(BaseModel):
    id: str = ""
    agent_id: str
    offer_id: str
    product_id: str
    mandate_id: str
    qty: int = Field(default=1, ge=1)
    # Snapshot at payment time: the order never re-reads the catalog.
    currency: str = "USD"
    unit_price_minor: int = 0
    total_minor: int | None = None
    product_name: str = ""
    total: float = 0.0
    status: str = "PENDING"    # PENDING | PAID | SHIPPED | CANCELLED
    payment_token: str = ""
    reservation_id: str = ""
    created_at: str = ""
    shipped_at: str = ""
    tenant_id: str = ""        # buyer tenant
    seller_tenant_id: str = ""
    stix_chain_id: str = ""

    @model_validator(mode="after")
    def _derive_total(self) -> Order:
        # Rows written before minor units carry only the float total.
        if self.total_minor is None:
            self.total_minor = to_minor(self.total, self.currency)
        self.total = from_minor(self.total_minor, self.currency)
        return self


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
