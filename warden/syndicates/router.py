"""
warden/syndicates/router.py
───────────────────────────
Warden Syndicates API — Zero-Trust Tunnel handshake endpoints.

Endpoints
─────────
  POST /syndicates/register
      Register this gateway as a Syndicate node.
      Creates a long-term identity (SID + public key) for the tenant.

  POST /tunnels/handshake/init
      Platform A initiates a tunnel.
      Generates an ephemeral X25519 key pair and stores the private key
      in Redis for 10 minutes (handshake window).
      Returns a manifest JSON that the admin forwards to Platform B.

  POST /tunnels/handshake/accept
      Platform B accepts the manifest from Platform A.
      Performs ECDH key exchange, derives the shared AES-256 key,
      stores it in Redis with TTL, inserts the link record in Postgres.
      Returns its own public key + safety number to Platform A.

  POST /tunnels/handshake/complete
      Platform A finalises the tunnel after receiving Platform B's public key.
      Derives the same shared AES-256 key, verifies safety numbers match,
      marks the tunnel ACTIVE in Postgres.

  DELETE /tunnels/{tunnel_id}
      Instant kill-switch: deletes the shared key from Redis (crypto-shredding)
      and marks the link REVOKED in Postgres.

  GET /tunnels
      List all tunnel links for the calling tenant's syndicate.

Auth
────
  All endpoints require the tenant's portal API key via
  X-Tenant-API-Key header (same auth used by the portal router).
"""
from __future__ import annotations

import hashlib
import logging
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from warden.syndicates.crypto import DecryptionError, TunnelCrypto

log = logging.getLogger("warden.syndicates")

router = APIRouter(prefix="/syndicates", tags=["Syndicates"])
tunnels_router = APIRouter(prefix="/tunnels", tags=["Syndicates"])


# ── Auth helper ───────────────────────────────────────────────────────────────

def _get_redis():
    """Lazy Redis client (same pattern as warden.cache)."""
    try:
        import redis as _redis
        from warden.config import settings
        client = _redis.from_url(
            settings.redis_url,
            decode_responses=False,   # keys binary; values may be raw bytes
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        client.ping()
        return client
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Redis unavailable: {exc}") from exc


async def _get_db():
    """Async DB session dependency."""
    from warden.db.connection import get_db
    async for session in get_db():
        yield session


def _require_super_admin(request: Request) -> None:
    """Require X-Super-Admin-Key for syndicate management endpoints."""
    expected = os.getenv("SUPER_ADMIN_KEY", "")
    provided = request.headers.get("X-Super-Admin-Key", "")
    if not expected or provided != expected:
        raise HTTPException(status_code=403, detail="Forbidden")


def _tenant_from_request(request: Request) -> str:
    """Extract tenant_id from X-Warden-Tenant-ID header (set by OIDC guard)."""
    tenant_id = request.headers.get("X-Warden-Tenant-ID", "")
    if not tenant_id:
        # Fall back to API key lookup
        tenant_id = request.headers.get("X-Tenant-ID", "")
    if not tenant_id:
        raise HTTPException(status_code=401, detail="Tenant identification required")
    return tenant_id


# ── Pydantic models ───────────────────────────────────────────────────────────

class RegisterSyndicateRequest(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=120)
    ttl_hours_default: int = Field(24, ge=1, le=8760)  # 1h – 1 year


class RegisterSyndicateResponse(BaseModel):
    syndicate_id: str
    public_key_b64: str
    display_name: str
    created_at: str


class HandshakeInitRequest(BaseModel):
    target_display_name: str = Field("", description="Human-readable name of the target platform")
    ttl_hours: int = Field(24, ge=1, le=8760, description="Tunnel TTL in hours")
    permissions: dict[str, Any] = Field(
        default_factory=dict,
        description='Access grants, e.g. {"allow_rag": true, "allow_documents": false}',
    )


class HandshakeManifest(BaseModel):
    """Manifest that Platform A sends to Platform B (out-of-band)."""
    version: str = "1.0"
    tunnel_id: str
    initiator_sid: str
    initiator_pub_key: str
    ttl_hours: int
    permissions: dict[str, Any]
    expires_at: str


class HandshakeAcceptRequest(BaseModel):
    manifest: HandshakeManifest


class HandshakeAcceptResponse(BaseModel):
    tunnel_id: str
    responder_pub_key: str
    safety_number: str
    message: str


class HandshakeCompleteRequest(BaseModel):
    tunnel_id: str
    responder_pub_key: str
    expected_safety_number: str = Field(
        "", description="Safety number shown by Platform B — verify before completing"
    )


class HandshakeCompleteResponse(BaseModel):
    tunnel_id: str
    status: str
    safety_number: str
    expires_at: str


class TunnelListItem(BaseModel):
    tunnel_id: str
    initiator_sid: str
    responder_sid: str | None
    status: str
    ttl_hours: int
    expires_at: str
    safety_number: str | None


# ── Syndicate Registration ─────────────────────────────────────────────────────

@router.post("/register", response_model=RegisterSyndicateResponse)
async def register_syndicate(
    body: RegisterSyndicateRequest,
    request: Request,
):
    """
    Register this gateway as a named Syndicate node.

    Generates a long-term X25519 identity key pair for the tenant.
    The public key is stored in Postgres; the private key is stored in Redis
    under warden:syndicate:identity:priv:{tenant_id} (persistent, no TTL).

    One syndicate per tenant — calling again updates display_name only.
    """
    _require_super_admin(request)
    tenant_id = request.headers.get("X-Warden-Tenant-ID") or request.headers.get("X-Tenant-ID", "unknown")

    priv_b64, pub_b64 = TunnelCrypto.generate_keypair()
    syndicate_id = f"SID-{hashlib.sha256(tenant_id.encode()).hexdigest()[:12].upper()}"

    redis = _get_redis()

    # Store identity private key persistently (no TTL — this is the long-term identity)
    redis.set(f"warden:syndicate:identity:priv:{tenant_id}", priv_b64.encode())

    # Upsert syndicate record in Postgres
    from sqlalchemy import text
    from warden.db.connection import get_async_engine
    async with get_async_engine().begin() as conn:
        await conn.execute(text("""
            INSERT INTO warden_core.syndicates (syndicate_id, tenant_id, display_name, public_key_b64)
            VALUES (:sid, :tid, :name, :pub)
            ON CONFLICT (tenant_id) DO UPDATE
                SET display_name   = EXCLUDED.display_name,
                    public_key_b64 = EXCLUDED.public_key_b64
        """), {"sid": syndicate_id, "tid": tenant_id, "name": body.display_name, "pub": pub_b64})

    log.info("Syndicate registered: %s (tenant=%s)", syndicate_id, tenant_id)
    return RegisterSyndicateResponse(
        syndicate_id=syndicate_id,
        public_key_b64=pub_b64,
        display_name=body.display_name,
        created_at=datetime.now(UTC).isoformat(),
    )


# ── Handshake: Init (Platform A) ──────────────────────────────────────────────

@tunnels_router.post("/handshake/init", response_model=HandshakeManifest)
async def handshake_init(
    body: HandshakeInitRequest,
    request: Request,
):
    """
    Platform A initiates a tunnel handshake.

    Generates an ephemeral X25519 key pair.  The private key is stored in
    Redis for 10 minutes — if Platform B doesn't respond within that window,
    the handshake expires and a new one must be initiated.

    Returns a HandshakeManifest that the admin sends to Platform B out-of-band
    (email, Slack, etc.).  Platform B feeds it into POST /tunnels/handshake/accept.
    """
    _require_super_admin(request)

    tenant_id = request.headers.get("X-Warden-Tenant-ID") or request.headers.get("X-Tenant-ID", "")

    # Look up initiator SID
    from sqlalchemy import text
    from warden.db.connection import get_async_engine
    async with get_async_engine().connect() as conn:
        row = await conn.execute(
            text("SELECT syndicate_id FROM warden_core.syndicates WHERE tenant_id = :tid"),
            {"tid": tenant_id},
        )
        syndicate = row.fetchone()

    if not syndicate:
        raise HTTPException(
            status_code=404,
            detail="Syndicate not registered. Call POST /syndicates/register first.",
        )

    initiator_sid = syndicate[0]
    tunnel_id = str(uuid.uuid4())
    priv_b64, pub_b64 = TunnelCrypto.generate_keypair()
    expires_at = datetime.now(UTC) + timedelta(hours=body.ttl_hours)

    redis = _get_redis()
    # Private key lives for 10 minutes (handshake window) in Redis
    redis.setex(f"warden:handshake:priv:{tunnel_id}", 600, priv_b64.encode())

    # Pre-create link record in PENDING state
    async with get_async_engine().begin() as conn:
        await conn.execute(text("""
            INSERT INTO warden_core.syndicate_links
                (link_id, initiator_sid, status, is_ephemeral, ttl_hours, expires_at, permissions)
            VALUES
                (:lid, :sid, 'PENDING', TRUE, :ttl, :exp, :perms::jsonb)
        """), {
            "lid": tunnel_id,
            "sid": initiator_sid,
            "ttl": body.ttl_hours,
            "exp": expires_at,
            "perms": __import__("json").dumps(body.permissions),
        })

    log.info("Handshake initiated: tunnel=%s initiator=%s ttl=%dh", tunnel_id, initiator_sid, body.ttl_hours)

    return HandshakeManifest(
        tunnel_id=tunnel_id,
        initiator_sid=initiator_sid,
        initiator_pub_key=pub_b64,
        ttl_hours=body.ttl_hours,
        permissions=body.permissions,
        expires_at=expires_at.isoformat(),
    )


# ── Handshake: Accept (Platform B) ────────────────────────────────────────────

@tunnels_router.post("/handshake/accept", response_model=HandshakeAcceptResponse)
async def handshake_accept(
    body: HandshakeAcceptRequest,
    request: Request,
):
    """
    Platform B accepts the manifest and completes its side of the ECDH exchange.

    Generates Platform B's ephemeral key pair, derives the shared AES-256 key,
    and stores it in Redis with the tunnel TTL.  Returns Platform B's public key
    and the Safety Number to the admin, who relays both to Platform A's admin.
    """
    _require_super_admin(request)

    tenant_id = request.headers.get("X-Warden-Tenant-ID") or request.headers.get("X-Tenant-ID", "")
    manifest = body.manifest
    tunnel_id = manifest.tunnel_id

    # Look up responder SID
    from sqlalchemy import text
    from warden.db.connection import get_async_engine
    async with get_async_engine().connect() as conn:
        row = await conn.execute(
            text("SELECT syndicate_id FROM warden_core.syndicates WHERE tenant_id = :tid"),
            {"tid": tenant_id},
        )
        syndicate = row.fetchone()

    if not syndicate:
        raise HTTPException(
            status_code=404,
            detail="Syndicate not registered on this gateway. Call POST /syndicates/register first.",
        )

    responder_sid = syndicate[0]

    # Generate Platform B's ephemeral key pair
    priv_b_b64, pub_b_b64 = TunnelCrypto.generate_keypair()

    # ECDH: derive shared AES-256 key from B's private key + A's public key
    aes_key = TunnelCrypto.derive_shared_key(priv_b_b64, manifest.initiator_pub_key, tunnel_id)
    safety_num = TunnelCrypto.safety_number(aes_key)

    # Store AES key in Redis with TTL matching the tunnel lifetime
    ttl_seconds = manifest.ttl_hours * 3600
    redis = _get_redis()
    redis.setex(f"warden:tunnels:active:{tunnel_id}", ttl_seconds, aes_key)

    # Store B's private key briefly (10 min) — not needed after A completes
    redis.setex(f"warden:handshake:priv_b:{tunnel_id}", 600, priv_b_b64.encode())

    expires_at = datetime.now(UTC) + timedelta(hours=manifest.ttl_hours)

    # Update link record: set responder + safety number, keep PENDING until A completes
    async with get_async_engine().begin() as conn:
        await conn.execute(text("""
            UPDATE warden_core.syndicate_links
            SET responder_sid  = :rsid,
                safety_number  = :snum,
                expires_at     = :exp
            WHERE link_id = :lid
        """), {
            "rsid": responder_sid,
            "snum": safety_num,
            "exp": expires_at,
            "lid": tunnel_id,
        })

    log.info(
        "Handshake accepted: tunnel=%s responder=%s safety=%s",
        tunnel_id, responder_sid, safety_num,
    )

    return HandshakeAcceptResponse(
        tunnel_id=tunnel_id,
        responder_pub_key=pub_b_b64,
        safety_number=safety_num,
        message=(
            f"Send your responder_pub_key and safety_number to Platform A's admin. "
            f"They must verify the safety number matches before activating the tunnel."
        ),
    )


# ── Handshake: Complete (Platform A) ──────────────────────────────────────────

@tunnels_router.post("/handshake/complete", response_model=HandshakeCompleteResponse)
async def handshake_complete(
    body: HandshakeCompleteRequest,
    request: Request,
):
    """
    Platform A finalises the tunnel.

    Retrieves Platform A's ephemeral private key from Redis, performs ECDH
    with Platform B's public key, derives the same shared AES-256 key,
    verifies the Safety Number, and marks the tunnel ACTIVE.
    """
    _require_super_admin(request)

    tunnel_id = body.tunnel_id
    redis = _get_redis()

    # Retrieve Platform A's ephemeral private key (10-min window)
    priv_a_bytes = redis.get(f"warden:handshake:priv:{tunnel_id}")
    if not priv_a_bytes:
        raise HTTPException(
            status_code=410,
            detail="Handshake expired or tunnel_id not found. Initiate a new handshake.",
        )

    priv_a_b64 = priv_a_bytes.decode("ascii") if isinstance(priv_a_bytes, bytes) else priv_a_bytes

    # ECDH: derive shared key from A's private key + B's public key
    aes_key = TunnelCrypto.derive_shared_key(priv_a_b64, body.responder_pub_key, tunnel_id)
    safety_num = TunnelCrypto.safety_number(aes_key)

    # Optional safety number verification
    if body.expected_safety_number and body.expected_safety_number != safety_num:
        log.warning(
            "Safety number mismatch on tunnel %s — possible MitM attack! "
            "expected=%s computed=%s",
            tunnel_id, body.expected_safety_number, safety_num,
        )
        raise HTTPException(
            status_code=409,
            detail=(
                f"Safety number mismatch — possible Man-in-the-Middle attack! "
                f"Expected: {body.expected_safety_number} | Computed: {safety_num}. "
                f"Do NOT activate this tunnel. Revoke and start over."
            ),
        )

    # Get TTL from Postgres
    from sqlalchemy import text
    from warden.db.connection import get_async_engine
    async with get_async_engine().connect() as conn:
        row = await conn.execute(
            text("SELECT ttl_hours, expires_at FROM warden_core.syndicate_links WHERE link_id = :lid"),
            {"lid": tunnel_id},
        )
        link = row.fetchone()

    if not link:
        raise HTTPException(status_code=404, detail="Tunnel record not found.")

    ttl_seconds = link[0] * 3600
    expires_at = link[1]

    # Store AES key in Redis with full TTL (Platform A's copy)
    redis.setex(f"warden:tunnels:active:{tunnel_id}", ttl_seconds, aes_key)

    # Clean up ephemeral private keys — no longer needed
    redis.delete(f"warden:handshake:priv:{tunnel_id}")
    redis.delete(f"warden:handshake:priv_b:{tunnel_id}")

    # Activate tunnel in Postgres
    async with get_async_engine().begin() as conn:
        await conn.execute(text("""
            UPDATE warden_core.syndicate_links
            SET status          = 'ACTIVE',
                safety_number   = :snum,
                established_at  = NOW()
            WHERE link_id = :lid
        """), {"snum": safety_num, "lid": tunnel_id})

    log.info("Tunnel ACTIVE: %s safety=%s expires=%s", tunnel_id, safety_num, expires_at)

    return HandshakeCompleteResponse(
        tunnel_id=tunnel_id,
        status="ACTIVE",
        safety_number=safety_num,
        expires_at=expires_at.isoformat() if hasattr(expires_at, "isoformat") else str(expires_at),
    )


# ── Kill-switch ────────────────────────────────────────────────────────────────

@tunnels_router.delete("/{tunnel_id}")
async def revoke_tunnel(
    tunnel_id: str,
    request: Request,
):
    """
    Instantly revoke a tunnel (crypto-shredding).

    Deletes the AES key from Redis — all in-flight packets become undecipherable.
    Marks the link REVOKED in Postgres for audit trail.
    """
    _require_super_admin(request)

    redis = _get_redis()
    deleted = redis.delete(f"warden:tunnels:active:{tunnel_id}")

    from sqlalchemy import text
    from warden.db.connection import get_async_engine
    async with get_async_engine().begin() as conn:
        result = await conn.execute(text("""
            UPDATE warden_core.syndicate_links
            SET status = 'REVOKED'
            WHERE link_id = :lid AND status != 'REVOKED'
            RETURNING link_id
        """), {"lid": tunnel_id})
        updated = result.fetchone()

    if not updated and not deleted:
        raise HTTPException(status_code=404, detail="Tunnel not found.")

    log.warning("Tunnel REVOKED: %s (key_deleted=%s)", tunnel_id, bool(deleted))
    return {"tunnel_id": tunnel_id, "status": "REVOKED", "key_deleted": bool(deleted)}


# ── List tunnels ───────────────────────────────────────────────────────────────

@tunnels_router.get("")
async def list_tunnels(request: Request):
    """List all tunnel links for the calling tenant's syndicate."""
    _require_super_admin(request)

    tenant_id = request.headers.get("X-Warden-Tenant-ID") or request.headers.get("X-Tenant-ID", "")

    from sqlalchemy import text
    from warden.db.connection import get_async_engine
    async with get_async_engine().connect() as conn:
        rows = await conn.execute(text("""
            SELECT
                l.link_id, l.initiator_sid, l.responder_sid, l.status,
                l.ttl_hours, l.expires_at, l.safety_number
            FROM warden_core.syndicate_links l
            JOIN warden_core.syndicates s
              ON s.syndicate_id = l.initiator_sid OR s.syndicate_id = l.responder_sid
            WHERE s.tenant_id = :tid
            ORDER BY l.created_at DESC
            LIMIT 100
        """), {"tid": tenant_id})
        links = rows.fetchall()

    return {
        "tunnels": [
            {
                "tunnel_id": str(r[0]),
                "initiator_sid": r[1],
                "responder_sid": r[2],
                "status": r[3],
                "ttl_hours": r[4],
                "expires_at": r[5].isoformat() if r[5] else None,
                "safety_number": r[6],
            }
            for r in links
        ]
    }
