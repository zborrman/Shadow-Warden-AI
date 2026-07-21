"""warden/marketplace/api_listings.py — Listing publication and purchase endpoints."""
from __future__ import annotations

import contextlib
import logging
import os
import time

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel

from warden.config import data_path
from warden.db.connect import open_db
from warden.marketplace.rate_limit import marketplace_rate_limit
from warden.observability import Reason, record_failopen

log = logging.getLogger("warden.marketplace.api_listings")

with contextlib.suppress(Exception):
    from warden.metrics import (
        MARKETPLACE_LISTINGS_TOTAL,
        MARKETPLACE_PURCHASES_TOTAL,
        MARKETPLACE_TRADE_VOLUME_USD,
    )

router = APIRouter(tags=["Marketplace Listings"], dependencies=[Depends(marketplace_rate_limit)])


class ListingCreateRequest(BaseModel):
    asset_id:         str
    seller_agent_id:  str
    community_id:     str
    tenant_id:        str
    asset_type:       str = "rule"
    price_usd:        float
    pricing_strategy: str = "fixed"
    expires_hours:    int | None = None
    chain:            str = "sepolia"


class PurchaseRequest(BaseModel):
    buyer_agent_id: str


@router.post("/listings", status_code=201)
async def create_listing(body: ListingCreateRequest) -> dict:
    from warden.marketplace.listing import publish_listing
    # Sybil gate — flagged agents may not create new listings
    try:
        from warden.marketplace.sybil_guard import SybilGuard
        if SybilGuard().is_flagged(body.seller_agent_id):
            raise HTTPException(
                status_code=403,
                detail="Agent is flagged for suspicious activity and cannot create listings.",
            )
    except HTTPException:
        raise
    except Exception as exc:
        # Rule 4 fail-open by design — but the Sybil gate silently degrading
        # (a flagged agent can now publish) must be alertable, not just logged.
        log.warning("sybil_gate fail-open: %s", exc)
        record_failopen("marketplace_sybil", Reason.BACKEND_ERROR, exc)
    try:
        from warden.web3.chains import VALID_CHAINS  # noqa: PLC0415
        if body.chain not in VALID_CHAINS:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid chain '{body.chain}'. Valid: {sorted(VALID_CHAINS)}.",
            )
    except HTTPException:
        raise
    except Exception as exc:
        log.warning("valid_chains check fail-open: %s", exc)
        record_failopen("marketplace_chain", Reason.BACKEND_ERROR, exc)
    try:
        listing = publish_listing(
            asset_id=body.asset_id,
            seller_agent=body.seller_agent_id,
            community_id=body.community_id,
            tenant_id=body.tenant_id,
            asset_type=body.asset_type,
            price_usd=body.price_usd,
            pricing_strategy=body.pricing_strategy,
            expires_hours=body.expires_hours,
            chain=body.chain,
        )
        with contextlib.suppress(Exception):
            MARKETPLACE_LISTINGS_TOTAL.labels(asset_type=body.asset_type).inc()
        return listing.to_dict()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/listings/{listing_id}")
async def get_listing(listing_id: str) -> dict:
    from warden.marketplace.listing import get_listing as _get
    listing = _get(listing_id)
    if listing is None:
        raise HTTPException(status_code=404, detail=f"Listing '{listing_id}' not found.")
    return listing.to_dict()


@router.get("/listings")
async def search_listings(
    community_id: str | None = Query(default=None),
    asset_type:   str | None = Query(default=None),
    max_price:    float | None = Query(default=None),
    limit:        int         = Query(default=20, le=50),
) -> list[dict]:
    from warden.marketplace.listing import get_listings
    listings = get_listings(
        community_id=community_id,
        asset_type=asset_type,
        max_price=max_price,
        limit=limit,
    )
    return [lst.to_dict() for lst in listings]


@router.post("/listings/{listing_id}/purchase", status_code=201)
async def buy_listing(
    listing_id: str, body: PurchaseRequest,
    idempotency_key: str = Header(default="", alias="Idempotency-Key"),
) -> dict:
    """Buy a listing. Requires an Idempotency-Key header (FT-3): without one, a
    retried call (double-submit, webhook retry) created a second purchase record
    + a second escrow for the same buyer intent — a real double-charge, not just
    a duplicate log row. A replayed key returns the original purchase unchanged."""
    if not idempotency_key.strip():
        raise HTTPException(
            status_code=400,
            detail={"error": "idempotency_key_required",
                    "message": "Send an Idempotency-Key header with every purchase."},
        )
    from warden.marketplace.listing import purchase_listing as _buy
    try:
        result = _buy(listing_id=listing_id, buyer_agent_id=body.buyer_agent_id,
                     idempotency_key=idempotency_key.strip())
        try:
            asset_type = result.get("asset_type", "unknown")
            price = result.get("price_usd", 0.0)
            MARKETPLACE_PURCHASES_TOTAL.labels(asset_type=asset_type).inc()
            MARKETPLACE_TRADE_VOLUME_USD.inc(price)
        except Exception as exc:
            log.debug("prometheus metrics fail-open: %s", exc)
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/purchases")
async def list_purchases(
    buyer_agent:  str | None = Query(default=None),
    seller_agent: str | None = Query(default=None),
    limit:        int        = Query(default=50, le=100),
) -> list[dict]:
    from warden.marketplace.listing import list_purchases as _list
    return [p.to_dict() for p in _list(buyer_agent=buyer_agent, seller_agent=seller_agent, limit=limit)]


class SponsorRequest(BaseModel):
    days: int = 30


@router.post("/listings/{listing_id}/sponsor", status_code=200)
async def sponsor_listing(
    listing_id: str,
    body: SponsorRequest,
    x_admin_key: str | None = Header(default=None, alias="X-Admin-Key"),
) -> dict:
    """Set a listing as sponsored for N days (admin-grant only in v1).

    Requires X-Admin-Key header matching ADMIN_KEY env var.
    """
    admin_key = os.getenv("ADMIN_KEY", "")
    if not admin_key or x_admin_key != admin_key:
        raise HTTPException(status_code=403, detail="X-Admin-Key required.")

    if body.days < 1 or body.days > 365:
        raise HTTPException(status_code=422, detail="days must be 1–365.")

    db_path = data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    until_ts = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ",
        time.gmtime(time.time() + body.days * 86400),
    )
    try:
        with open_db(
            "marketplace", db_path, turso_name="marketplace", module_default_path=db_path
        ) as con:
            result = con.execute(
                "UPDATE marketplace_listings "
                "SET is_sponsored=1, sponsored_until=? "
                "WHERE listing_id=? AND status='active'",
                (until_ts, listing_id),
            )
            updated = result.rowcount
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    if not updated:
        raise HTTPException(status_code=404, detail="Listing not found or not active.")

    log.info("sponsor_listing: %s sponsored for %d days until %s", listing_id[:16], body.days, until_ts)
    return {
        "listing_id":     listing_id,
        "is_sponsored":   True,
        "sponsored_until": until_ts,
        "granted_at":     now,
    }
