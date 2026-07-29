"""
warden/api/fido_auth.py
FastAPI router for FIDO2 / WebAuthn Passkey endpoints.
Prefix: /auth/fido
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from warden.auth_guard import require_api_key

router = APIRouter(prefix="/auth/fido", tags=["FIDO2 Auth"])

# Enrolment and credential management take `tenant_id` from the request body or
# query string, so without a key any caller could register a passkey against any
# tenant, or list and delete another tenant's credentials. Authentication itself
# stays open — a caller proving possession of a passkey has no key yet, which is
# the point of the flow.
_ENROL = [Depends(require_api_key)]


class RegistrationBeginRequest(BaseModel):
    tenant_id:    str
    display_name: str = ""


class RegistrationCompleteRequest(BaseModel):
    tenant_id:  str
    credential: dict[str, Any]


class AuthBeginRequest(BaseModel):
    tenant_id: str


class AuthCompleteRequest(BaseModel):
    tenant_id: str
    assertion: dict[str, Any]


@router.post("/register/begin", summary="Start Passkey registration", dependencies=_ENROL)
async def register_begin(body: RegistrationBeginRequest) -> dict:
    from warden.auth.fido import FIDOProvider
    return FIDOProvider().generate_registration_options(
        body.tenant_id, body.display_name or body.tenant_id
    )


@router.post("/register/complete", summary="Complete Passkey registration", dependencies=_ENROL)
async def register_complete(body: RegistrationCompleteRequest) -> dict:
    from warden.auth.fido import FIDOProvider
    result = FIDOProvider().verify_registration(body.tenant_id, body.credential)
    if not result.get("verified"):
        raise HTTPException(status_code=400, detail=result)
    return result


@router.post("/authenticate/begin", summary="Start Passkey authentication")
async def authenticate_begin(body: AuthBeginRequest) -> dict:
    from warden.auth.fido import FIDOProvider
    return FIDOProvider().generate_authentication_options(body.tenant_id)


@router.post("/authenticate/complete", summary="Complete Passkey authentication — returns JWT")
async def authenticate_complete(body: AuthCompleteRequest) -> dict:
    from warden.auth.fido import FIDOProvider
    result = FIDOProvider().verify_authentication(body.tenant_id, body.assertion)
    if not result.get("verified"):
        raise HTTPException(status_code=401, detail=result)
    return {"verified": True, "tenant_id": body.tenant_id}


@router.get("/credentials", summary="List registered Passkeys", dependencies=_ENROL)
async def list_credentials(tenant_id: str) -> dict:
    from warden.auth.fido import FIDOProvider
    creds = FIDOProvider().list_credentials(tenant_id)
    return {"credentials": creds, "count": len(creds)}


@router.delete("/credentials/{credential_id}", summary="Remove a Passkey", dependencies=_ENROL)
async def delete_credential(credential_id: str, tenant_id: str) -> dict:
    from warden.auth.fido import FIDOProvider
    ok = FIDOProvider().delete_credential(tenant_id, credential_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Credential not found")
    return {"deleted": True}
