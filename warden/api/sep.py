"""
warden/api/sep.py
──────────────────
Syndicate Exchange Protocol (SEP) REST API.

Document Numbers (UECIID)
──────────────────────────
  GET  /sep/ueciid/{ueciid}                    — resolve a UECIID → entity metadata
  GET  /sep/search                             — search by UECIID prefix or display name
  POST /sep/register                           — register an existing entity in UECIID index
  GET  /sep/list                               — list all UECIIDs for a community
  POST /sep/pod-tag                            — attach a Sovereign Pod Tag to an entity
  GET  /sep/pod-tag/{entity_id}                — retrieve a Sovereign Pod Tag

Inter-Community Peering
────────────────────────
  POST   /sep/peerings                         — initiate a peering request
  GET    /sep/peerings                         — list peerings for a community
  GET    /sep/peerings/{peering_id}            — get peering detail
  POST   /sep/peerings/{peering_id}/accept     — accept a PENDING peering (with token)
  DELETE /sep/peerings/{peering_id}            — revoke a peering
  POST   /sep/peerings/{peering_id}/transfer   — transfer an entity to the peered community
  GET    /sep/peerings/{peering_id}/transfers  — list transfers for a peering
  GET    /sep/transfers/{transfer_id}          — get a specific transfer + causal proof

Knock-and-Verify Invitations
──────────────────────────────
  POST   /sep/knock                            — issue a knock invitation
  POST   /sep/knock/accept                     — accept a knock (claimant proves SW tenancy)
  DELETE /sep/knock/{token}                    — revoke a pending knock
  GET    /sep/knock/pending                    — list pending knocks for a community

Auth: standard X-API-Key (same as all other warden routes).
Tier: Pro+ required for peering; all tiers can use UECIID + knock for their own communities.
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from warden.auth_guard import AuthResult, require_api_key
from warden.billing.feature_gate import require_feature

router  = APIRouter(prefix="/sep", tags=["SEP — Syndicate Exchange Protocol"])
AuthDep = Depends(require_api_key)
_ProGate = require_feature("communities_enabled")


# ── Request / Response models ─────────────────────────────────────────────────

class RegisterUECIIDRequest(BaseModel):
    entity_id:    str
    community_id: str
    display_name: str  = Field("", max_length=200)
    content_type: str  = Field("application/octet-stream")
    byte_size:    int  = Field(0, ge=0)


class PodTagRequest(BaseModel):
    entity_id:    str
    community_id: str
    jurisdiction: str = Field("EU", description="EU|US|UK|CA|SG|AU|JP|CH")
    data_class:   str = Field("GENERAL", description="GENERAL|PII|PHI|FINANCIAL|CLASSIFIED")
    notes:        str = Field("", max_length=500)


class InitiatePeeringRequest(BaseModel):
    initiator_community: str
    target_community:    str
    initiator_mid:       str
    policy:              str = Field("REWRAP_ALLOWED", description="MIRROR_ONLY|REWRAP_ALLOWED|FULL_SYNC")
    notes:               str = Field("", max_length=500)


class AcceptPeeringRequest(BaseModel):
    handshake_token: str
    accepted_by_mid: str


class TransferEntityRequest(BaseModel):
    entity_id:           str
    source_ueciid:       str = Field(..., description="UECIID of the entity in the source community")
    initiator_mid:       str
    purpose:             str = Field("sharing", description="sharing|archive|compliance|legal")
    target_jurisdiction: str | None = Field(None, description="Jurisdiction of the target community")
    display_name:        str = Field("", max_length=200)


class IssueKnockRequest(BaseModel):
    community_id:      str
    inviter_mid:       str
    invitee_tenant_id: str = Field(..., description="tenant_id of the Shadow Warden tenant to invite")
    clearance:         str = Field("PUBLIC", description="Initial clearance level")
    role:              str = Field("MEMBER", description="MEMBER|MODERATOR|ADMIN")
    message:           str = Field("", max_length=500, description="Optional personal note")


class AcceptKnockRequest(BaseModel):
    token:              str
    claiming_tenant_id: str = Field(..., description="Must match invitee_tenant_id on the knock")


# ── UECIID endpoints ──────────────────────────────────────────────────────────

@router.get("/ueciid/{ueciid}", summary="Resolve a UECIID to entity metadata")
async def resolve_ueciid(ueciid: str, auth: AuthResult = AuthDep) -> dict:
    """
    Look up the entity metadata for a UECIID document number.

    Returns community_id, entity_id, display_name, content_type, byte_size,
    and the Snowflake integer (for timestamp extraction).

    Use `GET /communities/{id}/entities/{entity_id}` to retrieve the
    encrypted payload after resolving the UECIID.
    """
    from warden.communities.sep import lookup_ueciid
    entry = lookup_ueciid(ueciid)
    if not entry:
        raise HTTPException(status_code=404, detail=f"UECIID {ueciid!r} not found.")
    return {
        "ueciid":        entry.ueciid,
        "snowflake_id":  entry.snowflake_id,
        "entity_id":     entry.entity_id,
        "community_id":  entry.community_id,
        "display_name":  entry.display_name,
        "content_type":  entry.content_type,
        "byte_size":     entry.byte_size,
        "created_at":    entry.created_at,
    }


@router.get("/search", summary="Search entities by UECIID prefix or display name")
async def search_ueciids(
    community_id: str = Query(...),
    q:            str = Query(..., min_length=1, description="UECIID prefix or display name fragment"),
    limit:        int = Query(20, ge=1, le=100),
    auth: AuthResult = AuthDep,
) -> list[dict]:
    """
    Search the UECIID index for a community.

    Matches on:
    - UECIID prefix (e.g. `SEP-0JM` finds all UECIIDs starting with those chars)
    - display_name substring

    Results are sorted newest-first (Snowflake order).
    """
    from warden.communities.sep import search_ueciids as _search
    entries = _search(community_id=community_id, query=q, limit=limit)
    return [
        {
            "ueciid":       e.ueciid,
            "entity_id":    e.entity_id,
            "display_name": e.display_name,
            "content_type": e.content_type,
            "byte_size":    e.byte_size,
            "created_at":   e.created_at,
        }
        for e in entries
    ]


@router.get("/list", summary="List all UECIIDs for a community")
async def list_ueciids(
    community_id: str = Query(...),
    limit:        int = Query(100, ge=1, le=1000),
    offset:       int = Query(0, ge=0),
    auth: AuthResult = AuthDep,
) -> dict:
    """Return paginated UECIID list for a community, newest first."""
    from warden.communities.sep import list_ueciids as _list
    entries = _list(community_id=community_id, limit=limit, offset=offset)
    return {
        "community_id": community_id,
        "total":        len(entries),
        "offset":       offset,
        "limit":        limit,
        "items": [
            {
                "ueciid":       e.ueciid,
                "entity_id":    e.entity_id,
                "display_name": e.display_name,
                "content_type": e.content_type,
                "byte_size":    e.byte_size,
                "created_at":   e.created_at,
            }
            for e in entries
        ],
    }


@router.post("/register", status_code=201, summary="Register an entity in the UECIID index")
async def register_ueciid(
    body: RegisterUECIIDRequest,
    auth: AuthResult = AuthDep,
) -> dict:
    """
    Register an existing entity_id in the UECIID index and assign it a document number.

    Call this after storing an entity via `POST /communities/{id}/entities`
    to make it searchable by UECIID.

    Returns the assigned UECIID (e.g. `SEP-0JMj9K2WfKE`).
    """
    from warden.communities.sep import register_ueciid as _reg
    entry = _reg(
        entity_id    = body.entity_id,
        community_id = body.community_id,
        display_name = body.display_name,
        content_type = body.content_type,
        byte_size    = body.byte_size,
    )
    return {
        "ueciid":       entry.ueciid,
        "snowflake_id": entry.snowflake_id,
        "entity_id":    entry.entity_id,
        "community_id": entry.community_id,
        "created_at":   entry.created_at,
    }


# ── Sovereign Pod Tag endpoints ────────────────────────────────────────────────

@router.post("/pod-tag", status_code=200, summary="Attach a Sovereign Pod Tag to an entity")
async def set_pod_tag(
    body: PodTagRequest,
    auth: AuthResult = AuthDep,
) -> dict:
    """
    Attach a Sovereign Pod Tag that pins the entity to a jurisdiction
    and data classification.

    This tag is checked before every inter-community transfer:
    - PHI data from EU → transfer to US is blocked
    - CLASSIFIED data → never transferred
    - GENERAL data    → all jurisdictions allowed (with adequacy check)

    Use this to enforce GDPR Chapter V, HIPAA, and EU AI Act data
    residency requirements at the document level.
    """
    from warden.communities.sep import set_pod_tag as _set
    tag = _set(
        entity_id    = body.entity_id,
        community_id = body.community_id,
        jurisdiction = body.jurisdiction,
        data_class   = body.data_class,
        notes        = body.notes,
    )
    return {
        "entity_id":    tag.entity_id,
        "community_id": tag.community_id,
        "jurisdiction": tag.jurisdiction,
        "data_class":   tag.data_class,
        "notes":        tag.notes,
        "created_at":   tag.created_at,
    }


@router.get("/pod-tag/{entity_id}", summary="Get Sovereign Pod Tag for an entity")
async def get_pod_tag(
    entity_id:    str,
    community_id: str = Query(...),
    auth: AuthResult = AuthDep,
) -> dict:
    from warden.communities.sep import get_pod_tag as _get
    tag = _get(entity_id=entity_id, community_id=community_id)
    if not tag:
        raise HTTPException(status_code=404, detail="No pod tag for this entity.")
    return {
        "entity_id":    tag.entity_id,
        "community_id": tag.community_id,
        "jurisdiction": tag.jurisdiction,
        "data_class":   tag.data_class,
        "notes":        tag.notes,
        "created_at":   tag.created_at,
    }


# ── Peering endpoints ─────────────────────────────────────────────────────────

@router.post(
    "/peerings",
    status_code=201,
    summary="Initiate an inter-community peering request",
    dependencies=[_ProGate],
)
async def initiate_peering(
    body: InitiatePeeringRequest,
    auth: AuthResult = AuthDep,
) -> dict:
    """
    Initiate a peering between two communities.

    Returns the PeeringRecord and a one-time `handshake_token`.
    Deliver the token out-of-band to the target community admin.

    Policies:
    - `MIRROR_ONLY`    — target receives read-only copies, no re-export
    - `REWRAP_ALLOWED` — target may re-wrap + share within their community
    - `FULL_SYNC`      — bidirectional; either side may initiate transfers
    """
    from warden.communities.peering import initiate_peering as _init
    try:
        record, token = _init(
            initiator_community = body.initiator_community,
            target_community    = body.target_community,
            initiator_mid       = body.initiator_mid,
            policy              = body.policy,
            notes               = body.notes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {
        "peering":          asdict(record),
        "handshake_token":  token,
        "warning":          "Deliver handshake_token out-of-band. It is one-time use.",
    }


@router.get(
    "/peerings",
    summary="List peerings for a community",
    dependencies=[_ProGate],
)
async def list_peerings(
    community_id:  str = Query(...),
    status_filter: str | None = Query(None, description="PENDING|ACTIVE|REVOKED"),
    auth: AuthResult = AuthDep,
) -> list[dict]:
    """Return all peerings where *community_id* is initiator or target."""
    from warden.communities.peering import list_peerings as _list
    return [asdict(p) for p in _list(community_id=community_id, status_filter=status_filter)]


@router.get(
    "/peerings/{peering_id}",
    summary="Get peering detail",
    dependencies=[_ProGate],
)
async def get_peering(peering_id: str, auth: AuthResult = AuthDep) -> dict:
    from warden.communities.peering import get_peering as _get
    p = _get(peering_id)
    if not p:
        raise HTTPException(status_code=404, detail=f"Peering {peering_id[:8]}… not found.")
    return asdict(p)


@router.post(
    "/peerings/{peering_id}/accept",
    summary="Accept a pending peering request",
    dependencies=[_ProGate],
)
async def accept_peering(
    peering_id: str,
    body:       AcceptPeeringRequest,
    auth: AuthResult = AuthDep,
) -> dict:
    """
    Accept a PENDING peering using the handshake token provided by the initiator.

    After acceptance, both communities can initiate entity transfers through
    this peering link (subject to the agreed policy).
    """
    from warden.communities.peering import accept_peering as _accept
    try:
        record = _accept(
            peering_id      = peering_id,
            handshake_token = body.handshake_token,
            accepted_by_mid = body.accepted_by_mid,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return asdict(record)


@router.delete(
    "/peerings/{peering_id}",
    status_code=204,
    summary="Revoke a peering",
    dependencies=[_ProGate],
)
async def revoke_peering(peering_id: str, auth: AuthResult = AuthDep) -> None:
    from warden.communities.peering import revoke_peering as _revoke
    if not _revoke(peering_id):
        raise HTTPException(status_code=404, detail=f"Peering {peering_id[:8]}… not found.")


@router.post(
    "/peerings/{peering_id}/transfer",
    status_code=201,
    summary="Transfer an entity to the peered community",
    dependencies=[_ProGate],
)
async def transfer_entity(
    peering_id: str,
    body:       TransferEntityRequest,
    auth: AuthResult = AuthDep,
) -> dict:
    """
    Transfer an entity to the target community via an ACTIVE peering.

    What this does:
    1. Checks the entity's Sovereign Pod Tag for cross-jurisdiction compliance.
    2. Issues a Causal Transfer Proof (HMAC-SHA256) — immutable SOC 2 evidence.
    3. Assigns a new UECIID for the document in the target community.
    4. Returns the TransferRecord including the causal proof.

    The caller is responsible for re-encrypting the payload with the target
    community's public X25519 key and uploading the new entity via
    `POST /communities/{target_community_id}/entities`.

    If `sovereign_ok=false` in the response, the transfer is REJECTED —
    do not re-upload the payload.
    """
    from warden.communities.peering import transfer_entity as _transfer
    try:
        record = _transfer(
            peering_id          = peering_id,
            entity_id           = body.entity_id,
            source_ueciid       = body.source_ueciid,
            initiator_mid       = body.initiator_mid,
            purpose             = body.purpose,
            target_jurisdiction = body.target_jurisdiction,
            display_name        = body.display_name,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return asdict(record)


@router.get(
    "/peerings/{peering_id}/transfers",
    summary="List transfers for a peering",
    dependencies=[_ProGate],
)
async def list_peering_transfers(
    peering_id: str,
    limit:      int = Query(100, ge=1, le=1000),
    auth: AuthResult = AuthDep,
) -> list[dict]:
    from warden.communities.peering import list_transfers
    return [asdict(t) for t in list_transfers(peering_id=peering_id, limit=limit)]


@router.get(
    "/transfers/{transfer_id}",
    summary="Get a specific transfer and its Causal Transfer Proof",
)
async def get_transfer(transfer_id: str, auth: AuthResult = AuthDep) -> dict:
    """
    Retrieve a transfer record including the full Causal Transfer Proof.

    The `causal_proof.signature` is a HMAC-SHA256 that auditors can verify
    using `POST /sep/transfers/{id}/verify-proof`.
    """
    from warden.communities.peering import get_transfer as _get
    t = _get(transfer_id)
    if not t:
        raise HTTPException(status_code=404, detail=f"Transfer {transfer_id[:8]}… not found.")
    return asdict(t)


@router.post(
    "/transfers/{transfer_id}/verify-proof",
    summary="Cryptographically verify a Causal Transfer Proof",
)
async def verify_transfer_proof(transfer_id: str, auth: AuthResult = AuthDep) -> dict:
    """
    Verify the HMAC-SHA256 signature on a Causal Transfer Proof.

    Returns `{"valid": true}` when the proof has not been tampered with.
    Use this to produce SOC 2 CC6.3 evidence that a data sharing event was
    authorised and has not been modified after issuance.
    """
    from warden.communities.peering import get_transfer as _get  # noqa: PLC0415
    from warden.communities.sep import CausalTransferProof  # noqa: PLC0415
    from warden.communities.sep import verify_transfer_proof as _verify
    t = _get(transfer_id)
    if not t:
        raise HTTPException(status_code=404, detail=f"Transfer {transfer_id[:8]}… not found.")
    p = t.causal_proof
    proof_obj = CausalTransferProof(
        transfer_id         = p.get("transfer_id", ""),
        source_community_id = p.get("source_community_id", ""),
        target_community_id = p.get("target_community_id", ""),
        entity_ueciid       = p.get("entity_ueciid", ""),
        initiator_mid       = p.get("initiator_mid", ""),
        issued_at           = p.get("issued_at", ""),
        purpose             = p.get("purpose", ""),
        signature           = p.get("signature", ""),
    )
    valid = _verify(proof_obj)
    return {
        "valid":       valid,
        "transfer_id": transfer_id,
        "issued_at":   p.get("issued_at"),
        "reason":      "Signature valid." if valid else "Signature mismatch — proof may have been tampered.",
    }


# ── Knock-and-Verify endpoints ────────────────────────────────────────────────

@router.post("/knock", status_code=201, summary="Issue a Knock-and-Verify invitation")
async def issue_knock(
    body: IssueKnockRequest,
    auth: AuthResult = AuthDep,
) -> dict:
    """
    Invite an existing Shadow Warden tenant to join a community.

    Returns a one-time `knock_token` valid for 72 hours.
    Deliver this token to the invitee (Slack, email, etc.).

    Only the `invitee_tenant_id` can accept this knock — outsiders
    cannot impersonate the invite even if they obtain the token, because
    `verify_and_accept_knock()` asserts the claiming tenant_id matches.
    """
    from warden.communities.knock import issue_knock as _issue
    try:
        record, token = _issue(
            community_id      = body.community_id,
            inviter_mid       = body.inviter_mid,
            invitee_tenant_id = body.invitee_tenant_id,
            clearance         = body.clearance,
            role              = body.role,
            message           = body.message,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {
        "knock_id":          record.knock_id,
        "community_id":      record.community_id,
        "invitee_tenant_id": record.invitee_tenant_id,
        "clearance":         record.clearance,
        "expires_at":        record.expires_at,
        "knock_token":       token,
        "warning":           "Deliver knock_token out-of-band. One-time use, 72h TTL.",
    }


@router.post("/knock/accept", summary="Accept a knock invitation (prove Shadow Warden tenancy)")
async def accept_knock(
    body: AcceptKnockRequest,
    auth: AuthResult = AuthDep,
) -> dict:
    """
    Accept a Knock-and-Verify invitation.

    `claiming_tenant_id` must match the `invitee_tenant_id` that was set
    when the knock was issued.  On success the claimant is added to the
    community with the configured clearance and role.

    Returns the new MemberRecord.
    """
    from warden.communities.knock import verify_and_accept_knock
    try:
        knock_record, member = verify_and_accept_knock(
            token              = body.token,
            claiming_tenant_id = body.claiming_tenant_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    from dataclasses import asdict as _asdict
    return {
        "knock_id":    knock_record.knock_id,
        "status":      knock_record.status,
        "accepted_at": knock_record.accepted_at,
        "member":      _asdict(member),
    }


@router.delete(
    "/knock/{token}",
    status_code=204,
    summary="Revoke a pending knock invitation",
)
async def revoke_knock(token: str, auth: AuthResult = AuthDep) -> None:
    from warden.communities.knock import revoke_knock as _revoke
    if not _revoke(token):
        raise HTTPException(status_code=404, detail="Knock token not found or not PENDING.")


@router.get("/knock/pending", summary="List pending knock invitations for a community")
async def list_pending_knocks(
    community_id: str = Query(...),
    auth: AuthResult = AuthDep,
) -> list[dict]:
    """
    List all PENDING knocks issued by this community.

    Use this to see outstanding invitations and detect tokens that have
    been issued but not yet accepted.
    """
    from warden.communities.knock import list_pending_knocks as _list  # noqa: PLC0415
    return [
        {
            "knock_id":          k.knock_id,
            "invitee_tenant_id": k.invitee_tenant_id,
            "clearance":         k.clearance,
            "role":              k.role,
            "message":           k.message,
            "expires_at":        k.expires_at,
            "created_at":        k.created_at,
        }
        for k in _list(community_id)
    ]


# ── Sovereign Data Pods ───────────────────────────────────────────────────────

class RegisterPodRequest(BaseModel):
    community_id:   str
    jurisdiction:   str  = Field("EU", description="EU|US|UK|CA|SG|AU|JP|CH")
    minio_endpoint: str  = Field(..., description="https://fsn1.your-objectstorage.com")
    minio_region:   str  = Field("eu-central-1")
    access_key:     str  = Field("", description="MinIO / S3 access key")
    secret_key:     str  = Field("", description="MinIO / S3 secret key (encrypted at rest)")
    data_classes:   list[str] = Field(
        default_factory=lambda: ["GENERAL"],
        description="Data classes this pod handles (GENERAL|PII|PHI|FINANCIAL|CLASSIFIED)",
    )
    bucket:         str  = Field("warden-evidence")
    is_primary:     bool = Field(False, description="Designate as primary pod for this jurisdiction")
    notes:          str  = Field("", max_length=500)


@router.post(
    "/pods",
    status_code=201,
    summary="Register a Sovereign Data Pod (MinIO endpoint + jurisdiction)",
    dependencies=[_ProGate],
)
async def register_pod(body: RegisterPodRequest, auth: AuthResult = AuthDep) -> dict:
    """
    Register a jurisdiction-pinned MinIO endpoint as a Sovereign Data Pod.

    Data tagged with the matching jurisdiction will be stored / routed to
    this pod's MinIO endpoint — ensuring data never leaves the legal boundary.
    """
    from warden.communities.data_pod import register_pod as _register
    pod = _register(
        community_id   = body.community_id,
        jurisdiction   = body.jurisdiction,
        minio_endpoint = body.minio_endpoint,
        minio_region   = body.minio_region,
        access_key     = body.access_key,
        secret_key     = body.secret_key,
        data_classes   = body.data_classes,
        bucket         = body.bucket,
        is_primary     = body.is_primary,
        notes          = body.notes,
    )
    return {
        "pod_id":         pod.pod_id,
        "community_id":   pod.community_id,
        "jurisdiction":   pod.jurisdiction,
        "minio_endpoint": pod.minio_endpoint,
        "minio_region":   pod.minio_region,
        "data_classes":   pod.data_classes,
        "bucket":         pod.bucket,
        "is_primary":     pod.is_primary,
        "status":         pod.status,
        "created_at":     pod.created_at,
    }


@router.get("/pods", summary="List Sovereign Data Pods for a community")
async def list_pods(
    community_id: str = Query(...),
    auth: AuthResult = AuthDep,
) -> list[dict]:
    from warden.communities.data_pod import list_pods as _list
    return [
        {
            "pod_id":         p.pod_id,
            "jurisdiction":   p.jurisdiction,
            "minio_endpoint": p.minio_endpoint,
            "minio_region":   p.minio_region,
            "data_classes":   p.data_classes,
            "bucket":         p.bucket,
            "is_primary":     p.is_primary,
            "status":         p.status,
            "created_at":     p.created_at,
        }
        for p in _list(community_id)
    ]


@router.post("/pods/{pod_id}/probe", summary="Test connectivity to a Sovereign Data Pod")
async def probe_pod(pod_id: str, auth: AuthResult = AuthDep) -> dict:
    from warden.communities.data_pod import probe_pod as _probe
    return _probe(pod_id)


@router.delete("/pods/{pod_id}", summary="Decommission a Sovereign Data Pod")
async def decommission_pod(
    pod_id: str,
    auth: AuthResult = AuthDep,
    _gate: Any = _ProGate,
) -> dict:
    from warden.communities.data_pod import decommission_pod as _decommission
    ok = _decommission(pod_id)
    if not ok:
        raise HTTPException(404, "Pod not found")
    return {"pod_id": pod_id, "status": "decommissioned"}


# ── STIX 2.1 Audit Chain ──────────────────────────────────────────────────────

@router.get(
    "/audit-chain/{community_id}",
    summary="List STIX 2.1 audit chain entries for a community",
)
async def get_audit_chain(
    community_id: str,
    limit:  int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    auth: AuthResult = AuthDep,
) -> list[dict]:
    """
    Return STIX 2.1 bundles from the tamper-evident audit chain.

    Each entry is a full STIX 2.1 bundle (identity × 2 + relationship + note).
    The `extensions.x-chain.prev_hash` links the chain.
    """
    from warden.communities.stix_audit import get_chain
    entries = get_chain(community_id, limit=limit, offset=offset)
    return [
        {
            "chain_id":    e.chain_id,
            "transfer_id": e.transfer_id,
            "seq":         e.seq,
            "bundle_hash": e.bundle_hash,
            "prev_hash":   e.prev_hash,
            "created_at":  e.created_at,
            "bundle":      e.bundle,
        }
        for e in entries
    ]


@router.get(
    "/audit-chain/{community_id}/verify",
    summary="Verify STIX audit chain integrity",
)
async def verify_audit_chain(community_id: str, auth: AuthResult = AuthDep) -> dict:
    """
    Re-hash every bundle and verify the prev_hash links.

    Returns `valid=true` if the chain is intact, or `valid=false` with
    `broken_at_seq` identifying where tampering was detected.
    """
    from warden.communities.stix_audit import verify_chain
    return verify_chain(community_id)


@router.get(
    "/audit-chain/{community_id}/export",
    summary="Export audit chain as STIX 2.1 JSONL",
    response_class=None,
)
async def export_audit_chain(community_id: str, auth: AuthResult = AuthDep) -> Any:
    """
    Export the full audit chain as JSONL (one STIX 2.1 bundle per line).

    Suitable for import into SIEM / SOAR platforms that accept STIX format.
    Content-Type: application/x-ndjson
    """
    from fastapi.responses import Response  # noqa: PLC0415

    from warden.communities.stix_audit import export_chain_jsonl  # noqa: PLC0415
    body = export_chain_jsonl(community_id)
    return Response(
        content    = body,
        media_type = "application/x-ndjson",
        headers    = {
            "Content-Disposition": f'attachment; filename="sep-audit-{community_id[:8]}.jsonl"'
        },
    )
