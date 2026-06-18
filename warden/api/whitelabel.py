"""warden/api/whitelabel.py  (ENT-02) — /whitelabel/* REST endpoints."""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/whitelabel", tags=["White-Label"])


class WhitelabelIn(BaseModel):
    domain:          str  = ""
    brand_name:      str  = "Shadow Warden AI"
    logo_url:        str  = "/logo.png"
    primary_color:   str  = "#6366f1"
    secondary_color: str  = "#4f46e5"
    support_email:   str  = ""
    hide_branding:   bool = False
    custom_css:      str  = ""


@router.get("/{tenant_id}")
async def get_whitelabel(tenant_id: str):
    from dataclasses import asdict  # noqa: PLC0415

    from warden.whitelabel.config import get_config  # noqa: PLC0415
    return asdict(get_config(tenant_id))


@router.put("/{tenant_id}")
async def save_whitelabel(tenant_id: str, body: WhitelabelIn):
    from dataclasses import asdict  # noqa: PLC0415

    from warden.whitelabel.config import WhitelabelConfig, save_config  # noqa: PLC0415
    cfg = WhitelabelConfig(tenant_id=tenant_id, **body.model_dump())
    save_config(cfg)
    return asdict(cfg)


@router.delete("/{tenant_id}")
async def delete_whitelabel(tenant_id: str):
    from warden.whitelabel.config import delete_config  # noqa: PLC0415
    delete_config(tenant_id)
    return {"deleted": tenant_id}


@router.get("/{tenant_id}/css")
async def whitelabel_css(tenant_id: str):
    from fastapi.responses import Response  # noqa: PLC0415

    from warden.whitelabel.config import get_config, render_css  # noqa: PLC0415
    css = render_css(get_config(tenant_id))
    return Response(content=css, media_type="text/css")


@router.get("/{tenant_id}/caddy-snippet")
async def caddy_snippet(tenant_id: str):
    from warden.whitelabel.config import caddy_vhost_snippet, get_config  # noqa: PLC0415
    return {"snippet": caddy_vhost_snippet(get_config(tenant_id))}
