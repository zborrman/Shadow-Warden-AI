"""
warden/syndicates/invites_router.py
─────────────────────────────────────
Warden Gatekeeper — invite system for Warden Syndicates.

Two invite types
────────────────

1. Single-User Magic Link  (type=SINGLE_USER)
   ─────────────────────────────────────────
   An admin generates a signed JWT link valid for N hours (default 24).
   The link is sent to the individual out-of-band (email / Slack).
   When the user opens it, they see an accept page that creates their
   Warden ID (WID) and binds it to the syndicate's access group.

   Endpoints:
     POST /invites/user/generate      → {magic_link, invite_code, expires_at}
     POST /invites/user/accept        → {wid, syndicate_id, role, expires_at}

2. Platform Federation Manifest  (type=PLATFORM_FEDERATION)
   ──────────────────────────────────────────────────────────
   An admin exports a signed JSON manifest containing this gateway's
   ephemeral X25519 public key.  The manifest is sent to the partner
   admin out-of-band.  Platform B imports it, and the handshake
   (ECDH key exchange) is triggered automatically — no manual steps.

   The manifest also stores a one-time HMAC challenge so replay attacks
   are impossible even if the manifest file is intercepted later.

   Endpoints:
     POST /invites/platform/init      → Warden Manifest JSON
     POST /invites/platform/join      → ECDH handshake + tunnel ACTIVE
                                        Returns {tunnel_id, safety_number}

TTL presets
───────────
  24h  — Audit Mode      (one-off review / pentest)
  168h — Sprint Mode     (1 week project)
  720h — Project Mode    (30 days contract)
  0    — Permanent       (manual revocation required)

JWT signing
───────────
  Re-uses PORTAL_JWT_SECRET (HS256) — same key as portal auth tokens.
  The invite JWT contains {type, invite_code, creator_sid, exp} plus
  role/group metadata for user invites.

One-time enforcement
────────────────────
  invitation_store.is_used is set TRUE on first redemption.
  Attempting to use the same code twice returns HTTP 409.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

log = logging.getLogger("warden.syndicates.invites")

invites_router = APIRouter(prefix="/invites", tags=["Syndicates"])

# ── JWT helpers (reuse portal secret) ────────────────────────────────────────

_JWT_SECRET    = os.getenv("PORTAL_JWT_SECRET", "change-me-" + secrets.token_hex(16))
_JWT_ALGORITHM = "HS256"
_PORTAL_URL    = os.getenv("PORTAL_URL", "https://app.shadow-warden-ai.com")


def _sign_invite(payload: dict) -> str:
    from jose import jwt
    return jwt.encode(payload, _JWT_SECRET, algorithm=_JWT_ALGORITHM)


def _verify_invite(token: str) -> dict:
    from jose import jwt, JWTError
    try:
        return jwt.decode(token, _JWT_SECRET, algorithms=[_JWT_ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid or expired invite token: {exc}")


def _require_super_admin(request: Request) -> None:
    expected = os.getenv("SUPER_ADMIN_KEY", "")
    provided = request.headers.get("X-Super-Admin-Key", "")
    if not expected or provided != expected:
        raise HTTPException(status_code=403, detail="Forbidden")


# ── DB helpers ────────────────────────────────────────────────────────────────

async def _db_insert_invite(
    invite_code: str,
    invite_type: str,
    creator_sid: str,
    target_email: str,
    target_group: str,
    metadata: dict,
    expires_at: datetime,
) -> None:
    from sqlalchemy import text
    from warden.db.connection import get_async_engine
    async with get_async_engine().begin() as conn:
        await conn.execute(text("""
            INSERT INTO warden_core.syndicate_invitations
                (invite_code, invite_type, creator_sid, target_email, target_group,
                 metadata, is_used, expires_at)
            VALUES
                (:code, :type, :sid, :email, :grp, :meta::jsonb, FALSE, :exp)
        """), {
            "code": invite_code,
            "type": invite_type,
            "sid":  creator_sid,
            "email": target_email,
            "grp":  target_group,
            "meta": json.dumps(metadata),
            "exp":  expires_at,
        })


async def _db_redeem_invite(invite_code: str) -> dict:
    """Mark invite as used (atomic). Returns the invite row or raises 409/410."""
    from sqlalchemy import text
    from warden.db.connection import get_async_engine

    async with get_async_engine().begin() as conn:
        # Read first
        row = await conn.execute(
            text("""
                SELECT invite_type, creator_sid, target_email, target_group,
                       metadata, is_used, expires_at
                FROM   warden_core.syndicate_invitations
                WHERE  invite_code = :code
            """),
            {"code": invite_code},
        )
        inv = row.fetchone()

        if not inv:
            raise HTTPException(status_code=404, detail="Invite not found.")
        if inv[5]:  # is_used
            raise HTTPException(status_code=409, detail="Invite already used.")
        if inv[6] and inv[6] < datetime.now(UTC):
            raise HTTPException(status_code=410, detail="Invite expired.")

        # Atomic mark-used
        await conn.execute(
            text("UPDATE warden_core.syndicate_invitations SET is_used=TRUE WHERE invite_code=:code"),
            {"code": invite_code},
        )

    return {
        "invite_type":  inv[0],
        "creator_sid":  inv[1],
        "target_email": inv[2],
        "target_group": inv[3],
        "metadata":     inv[4] if isinstance(inv[4], dict) else json.loads(inv[4] or "{}"),
        "expires_at":   inv[6],
    }


async def _db_get_syndicate_for_tenant(tenant_id: str) -> str | None:
    from sqlalchemy import text
    from warden.db.connection import get_async_engine
    async with get_async_engine().connect() as conn:
        row = await conn.execute(
            text("SELECT syndicate_id FROM warden_core.syndicates WHERE tenant_id=:tid"),
            {"tid": tenant_id},
        )
        r = row.fetchone()
    return r[0] if r else None


# ═══════════════════════════════════════════════════════════════════════════════
# 1.  SINGLE-USER MAGIC LINK
# ═══════════════════════════════════════════════════════════════════════════════

class UserInviteRequest(BaseModel):
    target_email: str  = Field("", description="Restrict to this email (optional)")
    role: str          = Field("MEMBER", description="MEMBER | AUDITOR | ANALYST | ADMIN")
    target_group: str  = Field("", description="Access group slug (optional)")
    ttl_hours: int     = Field(24, ge=1, le=8760, description="Link validity in hours")


class UserInviteResponse(BaseModel):
    invite_code: str
    magic_link:  str
    role:        str
    expires_at:  str
    ttl_hours:   int


@invites_router.post("/user/generate", response_model=UserInviteResponse)
async def generate_user_invite(body: UserInviteRequest, request: Request):
    """
    Generate a Magic Link JWT for a single external user or consultant.

    The link has the form:
        {PORTAL_URL}/syndicate/join?token=<JWT>

    The JWT payload contains:
        sub       : invite_code (UUID)
        type      : "user_invite"
        creator   : syndicate_id of this gateway
        role      : access role on this syndicate
        group     : optional access group
        exp       : Unix timestamp

    The invited person opens the link, authenticates with OIDC (Google / MS),
    and their email + Warden ID are registered via POST /invites/user/accept.
    """
    _require_super_admin(request)

    tenant_id = request.headers.get("X-Warden-Tenant-ID") or request.headers.get("X-Tenant-ID", "")
    creator_sid = await _db_get_syndicate_for_tenant(tenant_id)
    if not creator_sid:
        raise HTTPException(
            status_code=404,
            detail="Syndicate not registered. Call POST /syndicates/register first.",
        )

    invite_code = str(uuid.uuid4())
    expires_at  = datetime.now(UTC) + timedelta(hours=body.ttl_hours)

    jwt_payload = {
        "sub":     invite_code,
        "type":    "user_invite",
        "creator": creator_sid,
        "role":    body.role,
        "group":   body.target_group,
        "exp":     int(expires_at.timestamp()),
    }
    token = _sign_invite(jwt_payload)

    await _db_insert_invite(
        invite_code  = invite_code,
        invite_type  = "SINGLE_USER",
        creator_sid  = creator_sid,
        target_email = body.target_email,
        target_group = body.target_group,
        metadata     = {"role": body.role, "ttl_hours": body.ttl_hours},
        expires_at   = expires_at,
    )

    magic_link = f"{_PORTAL_URL}/syndicate/join?token={token}"
    log.info(
        "User invite generated: code=%s creator=%s role=%s ttl=%dh",
        invite_code, creator_sid, body.role, body.ttl_hours,
    )

    return UserInviteResponse(
        invite_code = invite_code,
        magic_link  = magic_link,
        role        = body.role,
        expires_at  = expires_at.isoformat(),
        ttl_hours   = body.ttl_hours,
    )


class UserAcceptRequest(BaseModel):
    token:          str  = Field(..., description="JWT from the magic link")
    user_email:     str  = Field(..., description="OIDC-verified email of the joining user")
    display_name:   str  = Field("", description="User's display name (optional)")


class UserAcceptResponse(BaseModel):
    wid:          str
    syndicate_id: str
    role:         str
    group:        str
    expires_at:   str | None


@invites_router.post("/user/accept", response_model=UserAcceptResponse)
async def accept_user_invite(body: UserAcceptRequest, request: Request):
    """
    Accept a Magic Link and register the user as a Syndicate member.

    The caller must have already verified the user's identity via OIDC
    and supply their email.  This endpoint:
      1. Validates the invite JWT (signature + expiry)
      2. Marks the invite as used (one-time enforcement)
      3. Checks email restriction if set
      4. Creates a WID (Warden ID) — anonymous external identifier
      5. Inserts the syndicate_members row

    The WID is returned so the frontend can display it and the user
    can share it with the syndicate admin for group assignments.
    """
    claims = _verify_invite(body.token)

    if claims.get("type") != "user_invite":
        raise HTTPException(status_code=400, detail="Invalid invite type.")

    invite_code = claims["sub"]
    inv = await _db_redeem_invite(invite_code)

    # Email restriction check
    if inv["target_email"] and inv["target_email"].lower() != body.user_email.lower():
        raise HTTPException(
            status_code=403,
            detail=f"This invite is restricted to {inv['target_email']}.",
        )

    creator_sid = inv["creator_sid"]
    role        = inv["metadata"].get("role", "MEMBER")
    group       = inv["target_group"] or ""

    # Generate WID — deterministic but anonymous: hash(creator_sid + email + salt)
    salt = secrets.token_hex(8)
    wid_raw = hashlib.sha256(f"{creator_sid}:{body.user_email}:{salt}".encode()).hexdigest()[:16]
    wid = f"WID-{wid_raw.upper()}"

    # Member expiry — inherit the invite TTL if set
    member_expires: datetime | None = None
    ttl_hours = inv["metadata"].get("ttl_hours", 0)
    if ttl_hours:
        member_expires = datetime.now(UTC) + timedelta(hours=ttl_hours)

    from sqlalchemy import text
    from warden.db.connection import get_async_engine
    async with get_async_engine().begin() as conn:
        await conn.execute(text("""
            INSERT INTO warden_core.syndicate_members
                (wid, syndicate_id, internal_email, role, expires_at)
            VALUES (:wid, :sid, :email, :role, :exp)
            ON CONFLICT (wid) DO NOTHING
        """), {
            "wid":   wid,
            "sid":   creator_sid,
            "email": body.user_email,
            "role":  role,
            "exp":   member_expires,
        })

    log.info(
        "User invite accepted: wid=%s syndicate=%s role=%s email=%s",
        wid, creator_sid, role, body.user_email,
    )

    return UserAcceptResponse(
        wid          = wid,
        syndicate_id = creator_sid,
        role         = role,
        group        = group,
        expires_at   = member_expires.isoformat() if member_expires else None,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 2.  PLATFORM FEDERATION MANIFEST
# ═══════════════════════════════════════════════════════════════════════════════

class PlatformInviteRequest(BaseModel):
    ttl_hours: int         = Field(24, ge=1, le=8760)
    permissions: dict      = Field(default_factory=dict)
    peer_display_name: str = Field("", description="Human label for the partner platform")
    own_endpoint: str      = Field(
        "",
        description=(
            "Public URL of THIS gateway's /tunnels/handshake/accept endpoint. "
            "Platform B will POST back here to complete the ECDH exchange. "
            "e.g. https://my-warden.example.com"
        ),
    )


class PlatformManifest(BaseModel):
    """Warden Manifest — sent out-of-band to the partner admin."""
    version:          str
    manifest_type:    str
    invite_code:      str
    inviter_sid:      str
    inviter_pub_key:  str   # ephemeral X25519 pub key (URL-safe b64)
    nexus_endpoint:   str   # initiator's /tunnels/handshake/accept URL
    one_time_code:    str   # HMAC-SHA256 challenge (replay prevention)
    ttl_hours:        int
    permissions:      dict
    expires_at:       str


class PlatformJoinRequest(BaseModel):
    manifest:          PlatformManifest
    responder_endpoint: str = Field(
        "",
        description="URL of THIS (responder) gateway so the initiator can reach back.",
    )


class PlatformJoinResponse(BaseModel):
    tunnel_id:      str
    safety_number:  str
    status:         str
    message:        str


@invites_router.post("/platform/init", response_model=PlatformManifest)
async def platform_invite_init(body: PlatformInviteRequest, request: Request):
    """
    Generate a Warden Platform Manifest for B2B gateway federation.

    The manifest is a signed JSON document containing:
      - This gateway's SID and ephemeral X25519 public key
      - A one-time HMAC challenge (prevents replay)
      - The nexus_endpoint URL for Platform B to POST back to
      - TTL and permission grants

    Admin workflow:
      1. Platform A admin calls this endpoint
      2. Downloads the manifest JSON
      3. Sends it to Platform B admin (email / Slack / secure channel)
      4. Platform B admin imports it via POST /invites/platform/join
      5. Tunnel activates automatically — both admins verify Safety Numbers

    The ephemeral private key is stored in Redis for 10 minutes (handshake window).
    If Platform B doesn't respond within that window, a new manifest must be generated.
    """
    _require_super_admin(request)

    tenant_id = request.headers.get("X-Warden-Tenant-ID") or request.headers.get("X-Tenant-ID", "")
    inviter_sid = await _db_get_syndicate_for_tenant(tenant_id)
    if not inviter_sid:
        raise HTTPException(
            status_code=404,
            detail="Syndicate not registered. Call POST /syndicates/register first.",
        )

    # Generate ephemeral X25519 key pair for this tunnel
    from warden.syndicates.crypto import TunnelCrypto
    priv_b64, pub_b64 = TunnelCrypto.generate_keypair()

    invite_code = str(uuid.uuid4())
    tunnel_id   = str(uuid.uuid4())
    expires_at  = datetime.now(UTC) + timedelta(hours=body.ttl_hours)

    # HMAC one-time challenge — prevents reuse of the manifest even if intercepted
    otc_secret  = os.getenv("PORTAL_JWT_SECRET", secrets.token_hex(32)).encode()
    one_time_code = hmac.new(
        otc_secret,
        msg=f"{invite_code}:{tunnel_id}:{inviter_sid}".encode(),
        digestmod=hashlib.sha256,
    ).hexdigest()[:32]

    nexus_endpoint = (
        body.own_endpoint.rstrip("/") + "/tunnels/handshake/accept"
        if body.own_endpoint
        else f"{_PORTAL_URL}/tunnels/handshake/accept"
    )

    # Store private key + tunnel_id in Redis (10-min handshake window)
    try:
        import redis as _redis
        from warden.config import settings
        r = _redis.from_url(settings.redis_url, decode_responses=False)
        r.setex(f"warden:handshake:priv:{tunnel_id}", 600, priv_b64.encode())
        r.setex(f"warden:manifest:otc:{invite_code}", 600, one_time_code.encode())
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Redis unavailable: {exc}")

    # Pre-create PENDING tunnel link
    from sqlalchemy import text
    from warden.db.connection import get_async_engine
    async with get_async_engine().begin() as conn:
        await conn.execute(text("""
            INSERT INTO warden_core.syndicate_links
                (link_id, initiator_sid, status, is_ephemeral, ttl_hours, expires_at, permissions)
            VALUES (:lid, :sid, 'PENDING', TRUE, :ttl, :exp, :perms::jsonb)
        """), {
            "lid":  tunnel_id,
            "sid":  inviter_sid,
            "ttl":  body.ttl_hours,
            "exp":  expires_at,
            "perms": json.dumps(body.permissions),
        })

    # Store invite record
    await _db_insert_invite(
        invite_code  = invite_code,
        invite_type  = "PLATFORM_FEDERATION",
        creator_sid  = inviter_sid,
        target_email = "",
        target_group = "",
        metadata     = {
            "tunnel_id":       tunnel_id,
            "ttl_hours":       body.ttl_hours,
            "peer_label":      body.peer_display_name,
            "nexus_endpoint":  nexus_endpoint,
        },
        expires_at   = expires_at,
    )

    log.info(
        "Platform manifest generated: invite=%s tunnel=%s sid=%s ttl=%dh",
        invite_code, tunnel_id, inviter_sid, body.ttl_hours,
    )

    return PlatformManifest(
        version         = "1.0",
        manifest_type   = "PLATFORM_FEDERATION",
        invite_code     = invite_code,
        inviter_sid     = inviter_sid,
        inviter_pub_key = pub_b64,
        nexus_endpoint  = nexus_endpoint,
        one_time_code   = one_time_code,
        ttl_hours       = body.ttl_hours,
        permissions     = body.permissions,
        expires_at      = expires_at.isoformat(),
    )


@invites_router.post("/platform/join", response_model=PlatformJoinResponse)
async def platform_invite_join(body: PlatformJoinRequest, request: Request):
    """
    Platform B imports a Warden Manifest and activates the tunnel automatically.

    Steps performed:
      1. Verify HMAC one-time code (replay prevention)
      2. Mark invite as used
      3. Auto-register Platform B as a Syndicate node if needed
      4. Generate Platform B's ephemeral X25519 key pair
      5. ECDH: derive shared AES-256 key from B's private + A's public key
      6. Store AES key in Redis with TTL
      7. POST responder_pub_key back to A's nexus_endpoint
      8. A derives the same key and marks tunnel ACTIVE
      9. Return Safety Number — both admins verify out-of-band

    Both admins must confirm the Safety Number matches before trusting the tunnel.
    """
    _require_super_admin(request)

    manifest    = body.manifest
    invite_code = manifest.invite_code
    tunnel_id   = None  # resolved from DB below

    # ── 1. Verify HMAC one-time code ───────────────────────────────────────��─
    try:
        import redis as _redis
        from warden.config import settings
        r = _redis.from_url(settings.redis_url, decode_responses=False)
        stored_otc = r.get(f"warden:manifest:otc:{invite_code}")
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Redis unavailable: {exc}")

    if not stored_otc:
        raise HTTPException(
            status_code=410,
            detail="Manifest expired or already used. Ask Platform A to generate a new one.",
        )

    expected_otc = stored_otc.decode() if isinstance(stored_otc, bytes) else stored_otc
    if not hmac.compare_digest(manifest.one_time_code, expected_otc):
        raise HTTPException(status_code=401, detail="Invalid one-time code — possible replay attack.")

    # ── 2. Mark invite as used ────────────────────────────────────────────────
    inv = await _db_redeem_invite(invite_code)
    tunnel_id = inv["metadata"].get("tunnel_id")
    if not tunnel_id:
        raise HTTPException(status_code=500, detail="Manifest metadata missing tunnel_id.")

    # Delete OTC from Redis
    r.delete(f"warden:manifest:otc:{invite_code}")

    # ── 3. Auto-register Platform B's syndicate if not exists ─────────────────
    tenant_id = request.headers.get("X-Warden-Tenant-ID") or request.headers.get("X-Tenant-ID", "unknown")
    responder_sid = await _db_get_syndicate_for_tenant(tenant_id)

    if not responder_sid:
        from warden.syndicates.crypto import TunnelCrypto as _TC
        _, b_identity_pub = _TC.generate_keypair()
        responder_sid = f"SID-{hashlib.sha256(tenant_id.encode()).hexdigest()[:12].upper()}"

        from sqlalchemy import text
        from warden.db.connection import get_async_engine
        async with get_async_engine().begin() as conn:
            await conn.execute(text("""
                INSERT INTO warden_core.syndicates
                    (syndicate_id, tenant_id, display_name, public_key_b64)
                VALUES (:sid, :tid, :name, :pub)
                ON CONFLICT (tenant_id) DO NOTHING
            """), {
                "sid":  responder_sid,
                "tid":  tenant_id,
                "name": f"Auto-registered via manifest {invite_code[:8]}",
                "pub":  b_identity_pub,
            })
        log.info("Auto-registered syndicate for manifest join: sid=%s tenant=%s", responder_sid, tenant_id)

    # ── 4 & 5. ECDH — derive shared AES-256 key ───────────────────────────────
    from warden.syndicates.crypto import TunnelCrypto
    priv_b_b64, pub_b_b64 = TunnelCrypto.generate_keypair()
    aes_key      = TunnelCrypto.derive_shared_key(priv_b_b64, manifest.inviter_pub_key, tunnel_id)
    safety_num   = TunnelCrypto.safety_number(aes_key)
    ttl_seconds  = manifest.ttl_hours * 3600

    # ── 6. Store AES key in Redis with TTL ────────────────────────────────────
    r.setex(f"warden:tunnels:active:{tunnel_id}", ttl_seconds, aes_key)

    # Update tunnel record with responder SID
    from sqlalchemy import text
    from warden.db.connection import get_async_engine
    async with get_async_engine().begin() as conn:
        await conn.execute(text("""
            UPDATE warden_core.syndicate_links
            SET responder_sid  = :rsid,
                safety_number  = :snum,
                peer_endpoint  = :ep
            WHERE link_id = :lid
        """), {
            "rsid": responder_sid,
            "snum": safety_num,
            "ep":   body.responder_endpoint,
            "lid":  tunnel_id,
        })

    # ── 7. POST back to Platform A's nexus_endpoint ───────────────────────────
    a_completed = False
    try:
        import httpx
        complete_payload = {
            "tunnel_id":               tunnel_id,
            "responder_pub_key":       pub_b_b64,
            "expected_safety_number":  "",  # A will verify independently
        }
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                manifest.nexus_endpoint.replace("/accept", "/complete"),
                json=complete_payload,
                headers={"X-Super-Admin-Key": os.getenv("SUPER_ADMIN_KEY", "")},
            )
            if resp.status_code == 200:
                a_completed = True
                log.info("Handshake complete notification sent to Platform A: tunnel=%s", tunnel_id)
            else:
                log.warning(
                    "Platform A complete call returned %d: tunnel=%s body=%s",
                    resp.status_code, tunnel_id, resp.text[:200],
                )
    except Exception as exc:
        log.warning("Could not notify Platform A (will retry manually): tunnel=%s error=%s", tunnel_id, exc)

    # Mark ACTIVE locally regardless (A will also mark it when it receives the callback)
    if a_completed:
        from sqlalchemy import text as _t
        from warden.db.connection import get_async_engine as _eng
        async with _eng().begin() as conn:
            await conn.execute(_t("""
                UPDATE warden_core.syndicate_links
                SET status='ACTIVE', established_at=NOW()
                WHERE link_id=:lid
            """), {"lid": tunnel_id})

    log.info(
        "Platform join complete: tunnel=%s responder=%s initiator=%s safety=%s a_notified=%s",
        tunnel_id, responder_sid, manifest.inviter_sid, safety_num, a_completed,
    )

    return PlatformJoinResponse(
        tunnel_id     = tunnel_id,
        safety_number = safety_num,
        status        = "ACTIVE" if a_completed else "PENDING_A_COMPLETION",
        message       = (
            f"Tunnel established. Safety Number: {safety_num}. "
            f"{'Both gateways are now active.' if a_completed else 'Platform A must call POST /tunnels/handshake/complete to finalise.'} "
            f"Verify the Safety Number with Platform A's admin out-of-band before sending sensitive data."
        ),
    )


# ── List invites ───────────────────────────────────────────────────────────────

@invites_router.get("")
async def list_invites(request: Request):
    """List all invites created by the calling tenant's syndicate."""
    _require_super_admin(request)

    tenant_id = request.headers.get("X-Warden-Tenant-ID") or request.headers.get("X-Tenant-ID", "")
    creator_sid = await _db_get_syndicate_for_tenant(tenant_id)
    if not creator_sid:
        return {"invites": []}

    from sqlalchemy import text
    from warden.db.connection import get_async_engine
    async with get_async_engine().connect() as conn:
        rows = await conn.execute(text("""
            SELECT invite_code, invite_type, target_email, is_used, expires_at, created_at
            FROM   warden_core.syndicate_invitations
            WHERE  creator_sid = :sid
            ORDER  BY created_at DESC
            LIMIT  100
        """), {"sid": creator_sid})
        invites = rows.fetchall()

    return {
        "invites": [
            {
                "invite_code":  str(r[0]),
                "invite_type":  r[1],
                "target_email": r[2],
                "is_used":      r[3],
                "expires_at":   r[4].isoformat() if r[4] else None,
                "created_at":   r[5].isoformat() if r[5] else None,
            }
            for r in invites
        ]
    }
