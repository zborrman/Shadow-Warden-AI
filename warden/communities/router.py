"""
warden/communities/router.py
──────────────────────────────
Business Communities REST API.

Endpoints
─────────
  POST   /communities
      Create a new community for the authenticated tenant.
      Generates a fresh keypair (kid=v1) and stores it in key_archive.

  GET    /communities
      List all communities for the tenant.

  GET    /communities/{community_id}
      Retrieve community profile + active kid + member count.

  POST   /communities/{community_id}/members
      Invite a member (generates scoped Member_ID).

  GET    /communities/{community_id}/members
      List active members with their clearance levels.

  PATCH  /communities/{community_id}/members/{member_id}/clearance
      Update a member's clearance level.
      Returns rotation_required=true when a Root Key Rollover must be
      triggered (member downgraded from CONFIDENTIAL/RESTRICTED).

  DELETE /communities/{community_id}/members/{member_id}
      Soft-remove a member from the community.

  POST   /communities/{community_id}/rotate
      Initiate Root Key Rollover (generates new kid, enqueues ARQ worker).

  GET    /communities/{community_id}/rotation
      Query rotation progress.

Auth
────
  All endpoints require X-Tenant-API-Key (same portal auth used by
  warden/syndicates/router.py).  Tier is extracted from the key payload;
  community creation is gated to Business+ tier.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from warden.communities.clearance import ClearanceLevel
from warden.communities.registry import (
    CommunityRecord,
    MemberRecord,
    create_community,
    get_community,
    get_member,
    invite_member,
    list_communities,
    list_members,
    remove_member,
    update_clearance,
)
from warden.communities.rotation import get_rotation_progress, initiate_rotation

log = logging.getLogger("warden.communities.router")

router = APIRouter(prefix="/communities", tags=["Communities"])


# ── Auth helper ───────────────────────────────────────────────────────────────

def _get_tenant(request: Request) -> dict:
    """
    Extract tenant context from request state (set by portal auth middleware).
    Falls back to X-Tenant-ID header for backwards compatibility.

    Returns dict with at least {tenant_id, tier}.
    """
    # portal_auth middleware sets request.state.tenant when present
    if hasattr(request.state, "tenant") and request.state.tenant:
        return request.state.tenant

    tenant_id = request.headers.get("X-Tenant-ID", "")
    tier       = request.headers.get("X-Tenant-Tier", "individual")
    if not tenant_id:
        raise HTTPException(status_code=401, detail="Missing tenant authentication.")
    return {"tenant_id": tenant_id, "tier": tier}


def _require_tier(tier: str, minimum: str) -> None:
    """
    Enforce minimum tier.  Hierarchy: individual < business < mcp.

    Raises HTTP 403 if the tenant's tier is below *minimum*.
    """
    order = {"individual": 0, "business": 1, "mcp": 2}
    if order.get(tier.lower(), 0) < order.get(minimum.lower(), 1):
        raise HTTPException(
            status_code=403,
            detail=(
                f"Communities require at least {minimum.upper()} tier. "
                f"Current tier: {tier.upper()}."
            ),
        )


# ── Request / Response schemas ────────────────────────────────────────────────

class CreateCommunityRequest(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=120)
    description:  str = Field("", max_length=500)


class CommunityResponse(BaseModel):
    community_id:  str
    tenant_id:     str
    display_name:  str
    description:   str
    tier:          str
    active_kid:    str
    status:        str
    created_by:    str
    created_at:    str

    @classmethod
    def from_record(cls, r: CommunityRecord) -> "CommunityResponse":
        return cls(
            community_id = r.community_id,
            tenant_id    = r.tenant_id,
            display_name = r.display_name,
            description  = r.description,
            tier         = r.tier,
            active_kid   = r.active_kid,
            status       = r.status,
            created_by   = r.created_by,
            created_at   = r.created_at,
        )


class InviteMemberRequest(BaseModel):
    external_id:  str = Field(..., min_length=1, max_length=256)
    display_name: str = Field("", max_length=120)
    clearance:    str = Field("PUBLIC", description="PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED")
    role:         str = Field("MEMBER", description="MEMBER | MODERATOR | ADMIN")
    invited_by:   Optional[str] = None


class MemberResponse(BaseModel):
    member_id:    str
    community_id: str
    external_id:  str
    display_name: str
    clearance:    str
    role:         str
    status:       str
    joined_at:    str

    @classmethod
    def from_record(cls, r: MemberRecord) -> "MemberResponse":
        return cls(
            member_id    = r.member_id,
            community_id = r.community_id,
            external_id  = r.external_id,
            display_name = r.display_name,
            clearance    = r.clearance,
            role         = r.role,
            status       = r.status,
            joined_at    = r.joined_at,
        )


class UpdateClearanceRequest(BaseModel):
    clearance: str = Field(..., description="PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED")


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("", status_code=201)
async def create_community_endpoint(
    body:    CreateCommunityRequest,
    request: Request,
) -> CommunityResponse:
    """Create a new community (Business+ tier required)."""
    ctx = _get_tenant(request)
    _require_tier(ctx["tier"], "business")

    try:
        record = create_community(
            tenant_id    = ctx["tenant_id"],
            display_name = body.display_name,
            created_by   = ctx.get("user_id", ctx["tenant_id"]),
            description  = body.description,
            tier         = ctx["tier"],
        )
    except Exception as exc:
        log.error("create_community failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return CommunityResponse.from_record(record)


@router.get("")
async def list_communities_endpoint(request: Request) -> list[CommunityResponse]:
    """List all communities for the authenticated tenant."""
    ctx = _get_tenant(request)
    _require_tier(ctx["tier"], "business")
    records = list_communities(ctx["tenant_id"])
    return [CommunityResponse.from_record(r) for r in records]


@router.get("/{community_id}")
async def get_community_endpoint(
    community_id: str,
    request:      Request,
) -> dict:
    """Retrieve community profile with member count and active kid."""
    ctx = _get_tenant(request)
    _require_tier(ctx["tier"], "business")

    record = get_community(community_id)
    if not record or record.tenant_id != ctx["tenant_id"]:
        raise HTTPException(status_code=404, detail="Community not found.")

    members = list_members(community_id)
    return {
        **CommunityResponse.from_record(record).model_dump(),
        "member_count": len(members),
    }


@router.post("/{community_id}/members", status_code=201)
async def invite_member_endpoint(
    community_id: str,
    body:         InviteMemberRequest,
    request:      Request,
) -> MemberResponse:
    """Invite a member to a community (generates scoped Member_ID)."""
    ctx = _get_tenant(request)
    _require_tier(ctx["tier"], "business")

    community = get_community(community_id)
    if not community or community.tenant_id != ctx["tenant_id"]:
        raise HTTPException(status_code=404, detail="Community not found.")

    try:
        clearance_level = ClearanceLevel.from_str(body.clearance)
    except KeyError:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid clearance level: {body.clearance!r}. "
                   "Use PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED.",
        )

    try:
        member = invite_member(
            community_id = community_id,
            tenant_id    = ctx["tenant_id"],
            external_id  = body.external_id,
            display_name = body.display_name,
            clearance    = clearance_level,
            role         = body.role,
            invited_by   = body.invited_by or ctx.get("user_id"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return MemberResponse.from_record(member)


@router.get("/{community_id}/members")
async def list_members_endpoint(
    community_id: str,
    request:      Request,
) -> list[MemberResponse]:
    """List active members of a community."""
    ctx = _get_tenant(request)
    _require_tier(ctx["tier"], "business")

    community = get_community(community_id)
    if not community or community.tenant_id != ctx["tenant_id"]:
        raise HTTPException(status_code=404, detail="Community not found.")

    members = list_members(community_id, active_only=True)
    return [MemberResponse.from_record(m) for m in members]


@router.patch("/{community_id}/members/{member_id}/clearance")
async def update_clearance_endpoint(
    community_id: str,
    member_id:    str,
    body:         UpdateClearanceRequest,
    request:      Request,
) -> dict:
    """
    Update a member's clearance level.

    Returns {member, rotation_required}.  When rotation_required=true the
    caller should POST /communities/{id}/rotate to prevent the demoted member
    from using cached Clearance Level Keys.
    """
    ctx = _get_tenant(request)
    _require_tier(ctx["tier"], "business")

    community = get_community(community_id)
    if not community or community.tenant_id != ctx["tenant_id"]:
        raise HTTPException(status_code=404, detail="Community not found.")

    try:
        new_clearance = ClearanceLevel.from_str(body.clearance)
    except KeyError:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid clearance level: {body.clearance!r}.",
        )

    try:
        updated, rotation_required = update_clearance(community_id, member_id, new_clearance)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return {
        "member":            MemberResponse.from_record(updated).model_dump(),
        "rotation_required": rotation_required,
    }


@router.delete("/{community_id}/members/{member_id}", status_code=204)
async def remove_member_endpoint(
    community_id: str,
    member_id:    str,
    request:      Request,
) -> None:
    """Soft-remove a member from the community."""
    ctx = _get_tenant(request)
    _require_tier(ctx["tier"], "business")

    community = get_community(community_id)
    if not community or community.tenant_id != ctx["tenant_id"]:
        raise HTTPException(status_code=404, detail="Community not found.")

    removed = remove_member(community_id, member_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Member not found or already removed.")


@router.post("/{community_id}/rotate", status_code=202)
async def initiate_rotation_endpoint(
    community_id: str,
    request:      Request,
) -> dict:
    """
    Initiate Root Key Rollover for this community.

    Generates a new keypair (kid increments), demotes the current ACTIVE key
    to ROTATION_ONLY, and enqueues the ARQ background worker to re-wrap all
    entity CEKs.

    Returns {old_kid, new_kid, status}.
    """
    ctx = _get_tenant(request)
    _require_tier(ctx["tier"], "business")

    community = get_community(community_id)
    if not community or community.tenant_id != ctx["tenant_id"]:
        raise HTTPException(status_code=404, detail="Community not found.")

    try:
        result = initiate_rotation(
            community_id = community_id,
            initiated_by = ctx.get("user_id", ctx["tenant_id"]),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return result


@router.get("/{community_id}/rotation")
async def rotation_progress_endpoint(
    community_id: str,
    request:      Request,
) -> dict:
    """Query the current Root Key Rollover progress (if any)."""
    ctx = _get_tenant(request)
    _require_tier(ctx["tier"], "business")

    community = get_community(community_id)
    if not community or community.tenant_id != ctx["tenant_id"]:
        raise HTTPException(status_code=404, detail="Community not found.")

    progress = get_rotation_progress(community_id)
    if not progress:
        return {"status": "IDLE", "community_id": community_id}
    return progress
