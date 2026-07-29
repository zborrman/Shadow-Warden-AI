"""
warden/security/api.py
────────────────────────
FastAPI router for ANS Certificate Authority.

Endpoints:
  POST   /marketplace/agents/{id}/certificate   — issue certificate
  DELETE /marketplace/agents/{id}/certificate   — revoke certificate
  GET    /marketplace/agents/{id}/certificate   — download certificate
  POST   /marketplace/certificates/verify       — verify a PEM
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from warden.auth_guard import require_api_key
from warden.marketplace.rate_limit import marketplace_rate_limit
from warden.security.certificate_authority import get_ca

log = logging.getLogger("warden.security.api")
router = APIRouter(prefix="/marketplace", tags=["ANS Certificates"], dependencies=[Depends(marketplace_rate_limit)])

# Issuing and revoking are identity operations on an arbitrary {agent_id}: without
# a key any caller could mint an ANS X.509 certificate for an agent, or revoke a
# live one — a denial-of-service against that agent's ability to transact.
# /certificates/verify stays open; it only checks a PEM the caller already holds,
# which is the same discovery surface the audit kept public.
_WRITE = [Depends(require_api_key)]


# ── Models ────────────────────────────────────────────────────────────────────

class CertIssueRequest(BaseModel):
    community_id:   str
    public_key_pem: str = ""


class CertVerifyRequest(BaseModel):
    cert_pem: str


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/agents/{agent_id}/certificate", status_code=201, dependencies=_WRITE)
def issue_certificate(agent_id: str, body: CertIssueRequest):
    """Issue an ANS X.509 certificate for an agent."""
    try:
        result = get_ca().issue_agent_certificate(
            agent_id=agent_id,
            community_id=body.community_id,
            public_key_pem=body.public_key_pem,
        )
        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.delete("/agents/{agent_id}/certificate", dependencies=_WRITE)
def revoke_certificate(agent_id: str):
    """Revoke the active certificate for an agent."""
    revoked = get_ca().revoke_certificate(agent_id)
    if not revoked:
        raise HTTPException(status_code=404, detail=f"No active certificate for agent {agent_id!r}.")
    return {"revoked": True, "agent_id": agent_id}


@router.get("/agents/{agent_id}/certificate")
def get_certificate(agent_id: str):
    """Download the latest certificate for an agent."""
    cert = get_ca().get_agent_certificate(agent_id)
    if not cert:
        raise HTTPException(status_code=404, detail=f"No certificate found for agent {agent_id!r}.")
    return cert


@router.post("/certificates/verify")
def verify_certificate(body: CertVerifyRequest):
    """Verify a certificate PEM — checks chain, revocation, expiry."""
    return get_ca().verify_certificate(body.cert_pem)
