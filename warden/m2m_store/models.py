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

# Currencies a seller may price in, with their ISO 4217 minor-unit exponent.
# The seller sets each price; nothing converts between currencies.
MINOR_DIGITS: dict[str, int] = {
    "USD": 2, "EUR": 2, "GBP": 2, "CHF": 2, "CAD": 2, "AUD": 2, "JPY": 0,
}

# Currencies an agent order can settle in. The Budget Guardian and the AP2
# mandate both count in USD, so every product carries a USD price and agent
# offers are always made from it.
SETTLEMENT_CURRENCIES: frozenset[str] = frozenset({"USD"})

# Storefront UI locales (owner decision 2026-11-03; CLAUDE.md Language Rule).
STORE_LOCALES: frozenset[str] = frozenset({"en", "fr", "de", "es", "it"})


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


def _check_settlement(value: str) -> str:
    code = _check_currency(value)
    if code not in SETTLEMENT_CURRENCIES:
        raise ValueError(f"a product's base price must be in {sorted(SETTLEMENT_CURRENCIES)}")
    return code


class Product(BaseModel):
    id: str = ""
    # Seller tenant. Set by the server from the caller's API key, never
    # trusted from the request body.
    tenant_id: str = ""
    store_id: str = ""
    category_id: str = ""
    deleted_at: str = ""
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
        return _check_settlement(value)

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
    # A WebAuthn assertion as JSON (see security.validate_fido2_token).
    payment_token: str = Field(..., max_length=8192)


# ── Store builder (plan stage M2) ─────────────────────────────────────────────

_SLUG = r"^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$"


class StoreIn(BaseModel):
    slug: str = Field(..., pattern=_SLUG)
    name: str = Field(..., min_length=1, max_length=120)
    description: str = Field(default="", max_length=2000)
    default_currency: str = "USD"
    currencies: list[str] = Field(default_factory=lambda: ["USD"], max_length=len(MINOR_DIGITS))
    locales: list[str] = Field(default_factory=lambda: ["en"], max_length=len(STORE_LOCALES))

    @field_validator("default_currency")
    @classmethod
    def _default(cls, value: str) -> str:
        return _check_currency(value)

    @field_validator("currencies")
    @classmethod
    def _currencies(cls, value: list[str]) -> list[str]:
        codes = sorted({_check_currency(c) for c in value})
        if not set(codes) >= SETTLEMENT_CURRENCIES:
            raise ValueError(f"currencies must include {sorted(SETTLEMENT_CURRENCIES)}")
        return codes

    @field_validator("locales")
    @classmethod
    def _locales(cls, value: list[str]) -> list[str]:
        codes = sorted({c.lower() for c in value})
        bad = [c for c in codes if c not in STORE_LOCALES]
        if bad or not codes:
            raise ValueError(f"locales must be a non-empty subset of {sorted(STORE_LOCALES)}")
        return codes

    @model_validator(mode="after")
    def _default_listed(self) -> StoreIn:
        if self.default_currency not in self.currencies:
            raise ValueError("default_currency must be one of currencies")
        return self


class StorePatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    active: bool | None = None


class CategoryIn(BaseModel):
    slug: str = Field(..., pattern=_SLUG)
    name: str = Field(..., min_length=1, max_length=120)
    parent_id: str = ""
    position: int = Field(default=0, ge=0, le=10_000)


class CategoryPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    parent_id: str | None = None      # "" moves the category to the root
    position: int | None = Field(default=None, ge=0, le=10_000)


class PriceIn(BaseModel):
    currency: str
    amount_minor: int = Field(..., ge=0, le=10**12)

    @field_validator("currency")
    @classmethod
    def _currency(cls, value: str) -> str:
        return _check_currency(value)


class TranslationIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(default="", max_length=5000)


class ShippingZoneIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    # ISO 3166-1 alpha-2 codes; "*" is the rest of the world.
    countries: list[str] = Field(..., min_length=1, max_length=250)
    currency: str
    rate_minor: int = Field(..., ge=0, le=10**10)
    free_over_minor: int | None = Field(default=None, ge=0, le=10**12)
    # A rate the seller typed in, in basis points. It is shown to buyers as an
    # estimate: nothing here knows a tariff schedule.
    duty_estimate_bps: int = Field(default=0, ge=0, le=10_000)
    min_days: int = Field(default=1, ge=0, le=365)
    max_days: int = Field(default=7, ge=0, le=365)

    @field_validator("currency")
    @classmethod
    def _currency(cls, value: str) -> str:
        return _check_currency(value)

    @field_validator("countries")
    @classmethod
    def _countries(cls, value: list[str]) -> list[str]:
        codes = sorted({c.strip().upper() for c in value})
        bad = [c for c in codes if c != "*" and not (len(c) == 2 and c.isascii() and c.isalpha())]
        if bad:
            raise ValueError(f"not ISO 3166-1 alpha-2 codes: {bad}")
        return codes

    @model_validator(mode="after")
    def _days(self) -> ShippingZoneIn:
        if self.min_days > self.max_days:
            raise ValueError("min_days must not exceed max_days")
        return self
