"""
warden/api/kya.py
─────────────────
FastAPI router for Know-Your-Agent (KYA) + DID operations.

Endpoints
─────────
  POST /kya/register          — register DID + pubkey, return AgentProfile
  GET  /kya/profile/{did}     — fetch profile
  GET  /kya/trust/{did}       — trust score (0.0–1.0)
  POST /kya/trust/{did}/adjust — admin: adjust trust delta
  POST /kya/challenge/{did}   — issue a nonce challenge
  POST /kya/verify/{did}      — verify Ed25519 challenge response
  GET  /kya/list              — list profiles (owner-scoped)
  POST /kya/revoke/{did}      — admin: revoke DID

All write endpoints are fail-open (KYA errors never block marketplace flow).
"""
from __future__ import annotations

import logging
import os
import secrets

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel

from warden.kya.did import is_valid_did, sign_trust_assertion, verify_signature
from warden.kya.profile import (
    get_profile,
    get_trust_score,
    list_profiles,
    promote_status,
    register_did,
    update_trust,
)

log = logging.getLogger("warden.api.kya")
router = APIRouter(prefix="/kya", tags=["KYA"])

_ADMIN_KEY = os.getenv("ADMIN_KEY", "")
_redis_challenges: dict[str, str] = {}  # did → nonce (in-process; Redis when available)


def _require_admin(x_admin_key: str = Header("")) -> None:
    if _ADMIN_KEY and x_admin_key != _ADMIN_KEY:
        raise HTTPException(403, "Requires X-Admin-Key")


# ── Models ─────────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    did: str
    pubkey_b64: str
    owner_tenant_id: str = ""


class TrustAdjustRequest(BaseModel):
    delta: float
    reason: str = ""


class VerifyRequest(BaseModel):
    signature_b64: str


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.post("/register", response_model=dict)
async def register(req: RegisterRequest) -> dict:
    """Register or upsert an agent DID."""
    if not is_valid_did(req.did):
        raise HTTPException(422, f"Invalid DID format: {req.did!r}")
    try:
        profile = register_did(req.did, req.pubkey_b64, req.owner_tenant_id)
        return profile.to_dict()
    except Exception as exc:
        log.warning("kya register fail-open: %s", exc)
        return {
            "did": req.did, "owner_tenant_id": req.owner_tenant_id,
            "pubkey_b64": req.pubkey_b64, "trust_score": 0.5, "kya_status": "PENDING",
        }


@router.get("/profile/{did}", response_model=dict)
async def get_agent_profile(did: str) -> dict:
    profile = get_profile(did)
    if profile is None:
        raise HTTPException(404, f"DID not found: {did}")
    return profile.to_dict()


@router.get("/trust/{did}", response_model=dict)
async def trust_score(did: str) -> dict:
    score = get_trust_score(did)
    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()
    sig = sign_trust_assertion(did, score, now)
    return {"did": did, "trust_score": score, "issued_at": now, "assertion_sig": sig}


@router.post("/trust/{did}/adjust", response_model=dict, dependencies=[Depends(_require_admin)])
async def adjust_trust(did: str, req: TrustAdjustRequest) -> dict:
    new_score = update_trust(did, req.delta, req.reason)
    return {"did": did, "trust_score": new_score, "delta": req.delta}


@router.post("/challenge/{did}", response_model=dict)
async def issue_challenge(did: str) -> dict:
    """Issue a random nonce for Ed25519 challenge-response authentication."""
    nonce = secrets.token_hex(32)
    try:
        import redis as redis_lib  # noqa: PLC0415
        r = redis_lib.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))
        r.setex(f"kya:challenge:{did}", 120, nonce)
    except Exception:
        _redis_challenges[did] = nonce
    return {"did": did, "challenge": nonce, "expires_in": 120}


@router.post("/verify/{did}", response_model=dict)
async def verify_challenge(did: str, req: VerifyRequest) -> dict:
    """Verify a signed challenge. Returns verified=True and adjusts trust +0.02."""
    nonce: str | None = None
    try:
        import redis as redis_lib  # noqa: PLC0415
        r = redis_lib.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))
        raw = r.get(f"kya:challenge:{did}")
        nonce = raw.decode() if isinstance(raw, bytes) else None
        if nonce:
            r.delete(f"kya:challenge:{did}")
    except Exception:
        nonce = _redis_challenges.pop(did, None)

    if nonce is None:
        raise HTTPException(400, "No active challenge for this DID")

    profile = get_profile(did)
    if profile is None:
        raise HTTPException(404, "DID not registered")

    ok = verify_signature(profile.pubkey_b64, nonce, req.signature_b64)
    if ok:
        update_trust(did, 0.02, "challenge-verified")
        promote_status(did, "VERIFIED")
    return {"did": did, "verified": ok}


@router.get("/list", response_model=list)
async def list_agents(
    owner: str | None = Query(None),
    min_trust: float = Query(0.0, ge=0.0, le=1.0),
    limit: int = Query(50, le=200),
) -> list:
    return [p.to_dict() for p in list_profiles(owner, min_trust, limit)]


@router.post("/revoke/{did}", dependencies=[Depends(_require_admin)])
async def revoke_did(did: str) -> dict:
    promote_status(did, "REVOKED")
    update_trust(did, -1.0, "admin-revoked")
    return {"did": did, "status": "REVOKED"}
