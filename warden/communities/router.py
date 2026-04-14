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

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from warden.communities.clearance import ClearanceLevel
from warden.communities.registry import (
    CommunityRecord,
    MemberRecord,
    create_community,
    get_community,
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
    def from_record(cls, r: CommunityRecord) -> CommunityResponse:
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
    invited_by:   str | None = None


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
    def from_record(cls, r: MemberRecord) -> MemberResponse:
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
        ) from None

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
        ) from None

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


# ── Entity schemas ────────────────────────────────────────────────────────────

class UploadEntityRequest(BaseModel):
    content_b64:  str = Field(..., description="Base64-encoded plaintext content")
    clearance:    str = Field("PUBLIC", description="PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED")
    content_type: str = Field("application/octet-stream")
    sender_mid:   str = Field(..., description="Member_ID of the uploader")


class EntityMetaResponse(BaseModel):
    entity_id:    str
    community_id: str
    kid:          str
    clearance:    str
    sender_mid:   str
    byte_size:    int
    content_type: str
    status:       str
    created_at:   str
    expires_at:   str | None


# ── Entity endpoints ──────────────────────────────────────────────────────────

@router.post("/{community_id}/entities", status_code=201)
async def upload_entity_endpoint(
    community_id: str,
    body:         UploadEntityRequest,
    request:      Request,
) -> EntityMetaResponse:
    """Encrypt and store an entity in the community vault."""
    import base64
    import uuid as _uuid

    from warden.communities.clearance import create_envelope as _create_envelope
    from warden.communities.entity_store import store_entity
    from warden.communities.key_archive import get_active_entry, load_keypair_from_entry

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
            detail=f"Invalid clearance: {body.clearance!r}. Use PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED.",
        ) from None

    entry = get_active_entry(community_id)
    if not entry:
        raise HTTPException(status_code=409, detail="Community has no active keypair.")

    try:
        keypair = load_keypair_from_entry(entry)
    except Exception as exc:
        log.error("upload_entity: keypair load failed community=%s: %s", community_id[:8], exc)
        raise HTTPException(status_code=500, detail="Keypair unavailable.") from exc

    try:
        plaintext = base64.b64decode(body.content_b64)
    except Exception:
        raise HTTPException(status_code=422, detail="content_b64 is not valid base64.") from None

    entity_id = str(_uuid.uuid4())
    envelope  = _create_envelope(entity_id, community_id, plaintext, clearance_level, keypair, body.sender_mid)

    try:
        meta = store_entity(envelope, community_id, ctx["tier"], body.content_type)
    except Exception as exc:
        log.error("upload_entity: store failed community=%s: %s", community_id[:8], exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return EntityMetaResponse(
        entity_id    = meta.entity_id,
        community_id = meta.community_id,
        kid          = meta.kid,
        clearance    = meta.clearance,
        sender_mid   = meta.sender_mid,
        byte_size    = meta.byte_size,
        content_type = meta.content_type,
        status       = meta.status,
        created_at   = meta.created_at,
        expires_at   = meta.expires_at,
    )


@router.get("/{community_id}/entities")
async def list_entities_endpoint(
    community_id:     str,
    request:          Request,
    clearance_filter: str | None = None,
    limit:            int = 50,
    offset:           int = 0,
) -> list[EntityMetaResponse]:
    """List encrypted entities in a community (metadata only, no payload)."""
    from warden.communities.entity_store import list_entities

    ctx = _get_tenant(request)
    _require_tier(ctx["tier"], "business")

    community = get_community(community_id)
    if not community or community.tenant_id != ctx["tenant_id"]:
        raise HTTPException(status_code=404, detail="Community not found.")

    entities = list_entities(community_id, clearance_filter=clearance_filter, limit=limit, offset=offset)
    return [
        EntityMetaResponse(
            entity_id    = e.entity_id,
            community_id = e.community_id,
            kid          = e.kid,
            clearance    = e.clearance,
            sender_mid   = e.sender_mid,
            byte_size    = e.byte_size,
            content_type = e.content_type,
            status       = e.status,
            created_at   = e.created_at,
            expires_at   = e.expires_at,
        )
        for e in entities
    ]


@router.get("/{community_id}/entities/{entity_id}")
async def get_entity_endpoint(
    community_id: str,
    entity_id:    str,
    request:      Request,
) -> dict:
    """Get entity metadata and a 1-hour pre-signed download URL."""
    from warden.communities.entity_store import get_entity_meta, get_entity_presigned_url

    ctx = _get_tenant(request)
    _require_tier(ctx["tier"], "business")

    community = get_community(community_id)
    if not community or community.tenant_id != ctx["tenant_id"]:
        raise HTTPException(status_code=404, detail="Community not found.")

    meta = get_entity_meta(entity_id, community_id)
    if not meta or meta.status != "ACTIVE":
        raise HTTPException(status_code=404, detail="Entity not found.")

    download_url = get_entity_presigned_url(entity_id, community_id, expires_in=3600)
    return {
        "entity": EntityMetaResponse(
            entity_id    = meta.entity_id,
            community_id = meta.community_id,
            kid          = meta.kid,
            clearance    = meta.clearance,
            sender_mid   = meta.sender_mid,
            byte_size    = meta.byte_size,
            content_type = meta.content_type,
            status       = meta.status,
            created_at   = meta.created_at,
            expires_at   = meta.expires_at,
        ).model_dump(),
        "download_url": download_url,
    }


@router.delete("/{community_id}/entities/{entity_id}", status_code=204)
async def delete_entity_endpoint(
    community_id: str,
    entity_id:    str,
    request:      Request,
) -> None:
    """Crypto-shred and permanently delete an entity."""
    from warden.communities.entity_store import delete_entity

    ctx = _get_tenant(request)
    _require_tier(ctx["tier"], "business")

    community = get_community(community_id)
    if not community or community.tenant_id != ctx["tenant_id"]:
        raise HTTPException(status_code=404, detail="Community not found.")

    deleted = delete_entity(entity_id, community_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Entity not found or already deleted.")


# ── Break Glass schemas ───────────────────────────────────────────────────────

class InitiateBreakGlassRequest(BaseModel):
    kid:          str = Field(..., description="Key ID (kid) to recover, e.g. 'v1'")
    reason:       str = Field(..., min_length=10, max_length=1000)
    requested_by: str = Field(..., description="User / admin ID initiating the request")


class SignBreakGlassRequest(BaseModel):
    signer_id: str = Field(..., description="Admin user ID of the co-signer")
    sig_b64:   str = Field(..., description="Ed25519 signature over SHA-256(request_id+community_id+kid+reason)")


# ── Break Glass endpoints (MCP tier only) ─────────────────────────────────────

@router.post("/{community_id}/break-glass", status_code=201)
async def initiate_break_glass_endpoint(
    community_id: str,
    body:         InitiateBreakGlassRequest,
    request:      Request,
) -> dict:
    """
    Initiate a Break Glass emergency access procedure (MCP tier only).

    Returns a BreakGlassRequest dict with request_id for co-signers.
    Requires M-of-N signatures (default 3) before activation.
    """
    from warden.communities.break_glass import initiate_break_glass

    ctx = _get_tenant(request)
    _require_tier(ctx["tier"], "mcp")

    community = get_community(community_id)
    if not community or community.tenant_id != ctx["tenant_id"]:
        raise HTTPException(status_code=404, detail="Community not found.")

    try:
        bg_req = initiate_break_glass(
            community_id = community_id,
            kid          = body.kid,
            reason       = body.reason,
            requested_by = body.requested_by,
            tenant_tier  = ctx["tier"],
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return bg_req.__dict__


@router.post("/break-glass/{request_id}/sign")
async def sign_break_glass_endpoint(
    request_id: str,
    body:       SignBreakGlassRequest,
    request:    Request,
) -> dict:
    """
    Add a co-signer's approval to a Break Glass request.

    Returns {status, sigs, required}.
    """
    from warden.communities.break_glass import sign_break_glass

    ctx = _get_tenant(request)
    _require_tier(ctx["tier"], "mcp")

    try:
        return sign_break_glass(request_id, body.signer_id, body.sig_b64)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/break-glass/{request_id}/activate")
async def activate_break_glass_endpoint(
    request_id: str,
    request:    Request,
) -> dict:
    """
    Activate the Break Glass session after M signatures are collected.

    Returns {status, kid, community_id}.  The keypair is accessible
    for BREAK_GLASS_TTL_S seconds (default 3600); it is auto-closed after.
    """
    from warden.communities.break_glass import activate_break_glass

    ctx = _get_tenant(request)
    _require_tier(ctx["tier"], "mcp")

    try:
        kp = activate_break_glass(request_id)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return {"status": "ACTIVE", "kid": kp.kid, "community_id": kp.community_id}


@router.delete("/break-glass/{request_id}", status_code=204)
async def close_break_glass_endpoint(
    request_id: str,
    request:    Request,
) -> None:
    """Manually close a Break Glass session before TTL expires."""
    from warden.communities.break_glass import close_break_glass

    ctx = _get_tenant(request)
    _require_tier(ctx["tier"], "mcp")
    close_break_glass(request_id)


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
