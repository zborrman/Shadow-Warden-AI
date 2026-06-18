"""warden/api/framework_builder.py  (ENT-03) — /compliance/frameworks/* REST endpoints."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/compliance/frameworks", tags=["Compliance Framework Builder"])


class ControlIn(BaseModel):
    id:          str
    name:        str
    description: str   = ""
    category:    str   = "General"
    status:      str   = "Not Started"
    evidence:    list[str] = []
    weight:      float = 1.0


class FrameworkIn(BaseModel):
    name:        str
    description: str         = ""
    controls:    list[ControlIn] = []


class ControlStatusUpdate(BaseModel):
    status: str


@router.post("/{tenant_id}", status_code=201)
async def create_framework(tenant_id: str, body: FrameworkIn):
    from dataclasses import asdict  # noqa: PLC0415

    from warden.compliance.framework_builder import create_framework  # noqa: PLC0415
    fw = create_framework(
        tenant_id=tenant_id,
        name=body.name,
        description=body.description,
        controls=[c.model_dump() for c in body.controls],
    )
    return {**asdict(fw), "score": fw.score()}


@router.get("/{tenant_id}")
async def list_frameworks(tenant_id: str):
    from dataclasses import asdict  # noqa: PLC0415

    from warden.compliance.framework_builder import list_frameworks  # noqa: PLC0415
    return [{**asdict(fw), "score": fw.score()} for fw in list_frameworks(tenant_id)]


@router.get("/{tenant_id}/{framework_id}")
async def get_framework(tenant_id: str, framework_id: str):
    from dataclasses import asdict  # noqa: PLC0415

    from warden.compliance.framework_builder import get_framework  # noqa: PLC0415
    fw = get_framework(framework_id, tenant_id)
    if not fw:
        raise HTTPException(status_code=404, detail="Framework not found")
    return {**asdict(fw), "score": fw.score()}


@router.put("/{tenant_id}/{framework_id}")
async def update_framework(tenant_id: str, framework_id: str, body: FrameworkIn):
    from dataclasses import asdict  # noqa: PLC0415

    from warden.compliance.framework_builder import update_framework  # noqa: PLC0415
    fw = update_framework(
        framework_id, tenant_id,
        name=body.name, description=body.description,
        controls=[c.model_dump() for c in body.controls],
    )
    if not fw:
        raise HTTPException(status_code=404, detail="Framework not found")
    return {**asdict(fw), "score": fw.score()}


@router.delete("/{tenant_id}/{framework_id}")
async def delete_framework(tenant_id: str, framework_id: str):
    from warden.compliance.framework_builder import delete_framework  # noqa: PLC0415
    ok = delete_framework(framework_id, tenant_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Framework not found")
    return {"deleted": framework_id}


@router.patch("/{tenant_id}/{framework_id}/controls/{control_id}")
async def update_control(tenant_id: str, framework_id: str, control_id: str, body: ControlStatusUpdate):
    from warden.compliance.framework_builder import update_control_status  # noqa: PLC0415
    ok = update_control_status(framework_id, tenant_id, control_id, body.status)
    if not ok:
        raise HTTPException(status_code=404, detail="Framework or control not found")
    return {"updated": control_id, "status": body.status}
