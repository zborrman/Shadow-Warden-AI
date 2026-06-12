"""Shadow Warden SDK response models."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class FilterResponse:
    """Result of a POST /filter call."""

    request_id: str
    allowed: bool
    blocked: bool
    risk_level: str
    flags: list[str]
    secrets_found: list[str]
    processing_ms: float

    @classmethod
    def _from_dict(cls, d: dict[str, Any]) -> FilterResponse:
        return cls(
            request_id=d.get("request_id", ""),
            allowed=bool(d.get("allowed", True)),
            blocked=bool(d.get("blocked", False)),
            risk_level=str(d.get("risk_level", "LOW")),
            flags=list(d.get("flags", [])),
            secrets_found=list(d.get("secrets_found", [])),
            processing_ms=float(d.get("processing_ms", 0.0)),
        )


@dataclass
class AgentResponse:
    """Result of a POST /agent/sova call."""

    session_id: str
    reply: str
    iterations: int
    tools_used: list[str] = field(default_factory=list)

    @classmethod
    def _from_dict(cls, d: dict[str, Any]) -> AgentResponse:
        return cls(
            session_id=str(d.get("session_id", "")),
            reply=str(d.get("reply", d.get("response", ""))),
            iterations=int(d.get("iterations", 0)),
            tools_used=list(d.get("tools_used", [])),
        )


@dataclass
class MarketplaceListing:
    """A single marketplace listing returned by GET /marketplace/listings."""

    listing_id: str
    title: str
    asset_type: str
    price_usd: float
    pricing_strategy: str
    seller_agent_id: str
    community_id: str
    status: str
    created_at: str

    @classmethod
    def _from_dict(cls, d: dict[str, Any]) -> MarketplaceListing:
        return cls(
            listing_id=str(d.get("listing_id", "")),
            title=str(d.get("title", "")),
            asset_type=str(d.get("asset_type", "")),
            price_usd=float(d.get("price_usd", 0)),
            pricing_strategy=str(d.get("pricing_strategy", "fixed")),
            seller_agent_id=str(d.get("seller_agent_id", "")),
            community_id=str(d.get("community_id", "")),
            status=str(d.get("status", "")),
            created_at=str(d.get("created_at", "")),
        )
