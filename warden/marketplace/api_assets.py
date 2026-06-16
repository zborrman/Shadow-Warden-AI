"""warden/marketplace/api_assets.py — Asset tokenization and registry endpoints."""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from warden.marketplace.rate_limit import marketplace_rate_limit

log = logging.getLogger("warden.marketplace.api_assets")

router = APIRouter(tags=["Marketplace Assets"], dependencies=[Depends(marketplace_rate_limit)])


class AssetRegisterRequest(BaseModel):
    tenant_id:       str
    seller_agent_id: str
    asset_type:      str
    raw_data:        Any


def _resolve_keypair(community_id: str):
    """Load community keypair; return ephemeral dev keypair on failure (fail-open)."""
    try:
        from warden.communities.keypair import generate_community_keypair
        return generate_community_keypair(community_id, kid="v1")
    except Exception as exc:
        log.warning("Could not load community keypair for %s: %s", community_id, exc)
        from warden.communities.keypair import generate_community_keypair
        return generate_community_keypair("_ephemeral", kid="v1")


@router.post("/assets", status_code=201)
async def register_asset(body: AssetRegisterRequest) -> dict:
    from warden.marketplace.agent import get_agent as _get_agent
    from warden.marketplace.service import register_asset as _register

    agent = _get_agent(body.seller_agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent '{body.seller_agent_id}' not found.")

    keypair = _resolve_keypair(agent.community_id)

    try:
        asset_id = _register(
            tenant_id=body.tenant_id,
            seller_agent_id=body.seller_agent_id,
            asset_type=body.asset_type,
            raw_data=body.raw_data,
            keypair=keypair,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail={"error": "rule_validation_failed", "details": [str(exc)]},
        ) from exc

    ipfs_hash = ""
    try:
        from warden.marketplace.service import get_asset as _get
        asset = _get(asset_id) or {}
        ipfs_hash = asset.get("ipfs_hash", "")
    except Exception:
        pass

    return {
        "asset_id":       asset_id,
        "asset_type":     body.asset_type,
        "seller_agent_id": body.seller_agent_id,
        "ipfs_hash":      ipfs_hash,
    }


@router.get("/assets/{ueciid}")
async def get_asset(ueciid: str) -> dict:
    from warden.marketplace.service import get_asset as _get
    asset = _get(ueciid)
    if asset is None:
        raise HTTPException(status_code=404, detail=f"Asset '{ueciid}' not found.")
    return asset


@router.get("/assets")
async def search_assets(
    agent_id:     str | None = Query(default=None),
    type:         str | None = Query(default=None),
    community_id: str | None = Query(default=None),
    limit:        int        = Query(default=20, le=50),
) -> list[dict]:
    if agent_id:
        from warden.marketplace.service import list_assets_by_agent
        return list_assets_by_agent(agent_id, asset_type=type, limit=limit)
    if community_id:
        from warden.marketplace.service import search_assets as _search
        return _search(community_id, asset_type=type, limit=limit)
    return []
