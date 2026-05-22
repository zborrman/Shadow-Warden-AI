"""
warden/api/prompt_library.py  (CM-37)
──────────────────────────────────────
FastAPI router for Shared Prompt Library.

Prefix: /prompt-library
Tier:   Community Business+ (prompt_library_enabled)
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from warden.billing.feature_gate import require_feature

router = APIRouter(prefix="/prompt-library", tags=["Prompt Library"])
_Gate  = require_feature("prompt_library_enabled")


class PromptCreateRequest(BaseModel):
    community_id: str
    created_by:   str
    title:        str = Field(..., min_length=1, max_length=200)
    prompt_text:  str = Field(..., min_length=1)
    category:     str = "general"
    tags:         list[str] = Field(default_factory=list)
    visibility:   str = "community"
    description:  str = ""


class VersionRequest(BaseModel):
    new_text:    str = Field(..., min_length=1)
    updated_by:  str


@router.get("", summary="Search/list prompts in a community", dependencies=[_Gate])
async def list_prompts(
    community_id: str,
    query:        str | None = None,
    category:     str | None = None,
    limit:        int = 20,
) -> dict:
    from warden.communities.prompt_library import search_prompts
    items = search_prompts(community_id, query=query or "", category=category, limit=limit)
    return {"prompts": items, "count": len(items)}


@router.post("", summary="Add a prompt to the library", dependencies=[_Gate])
async def create_prompt(body: PromptCreateRequest) -> dict:
    from warden.communities.prompt_library import add_prompt
    try:
        entry = add_prompt(
            community_id=body.community_id,
            created_by=body.created_by,
            title=body.title,
            prompt_text=body.prompt_text,
            category=body.category,
            tags=body.tags,
            visibility=body.visibility,
            description=body.description,
        )
        return entry
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/stats", summary="Prompt library stats for a community", dependencies=[_Gate])
async def get_stats(community_id: str) -> dict:
    from warden.communities.prompt_library import get_library_stats
    return get_library_stats(community_id)


@router.get("/{prompt_id}", summary="Get a specific prompt", dependencies=[_Gate])
async def get_prompt(prompt_id: str) -> dict:
    from warden.communities.prompt_library import get_prompt as _get
    p = _get(prompt_id)
    if not p:
        raise HTTPException(status_code=404, detail=f"Prompt {prompt_id!r} not found")
    return p


@router.post("/{prompt_id}/use", summary="Record a use of a prompt", dependencies=[_Gate])
async def record_use(prompt_id: str) -> dict:
    from warden.communities.prompt_library import get_prompt, increment_use
    if not get_prompt(prompt_id):
        raise HTTPException(status_code=404, detail=f"Prompt {prompt_id!r} not found")
    increment_use(prompt_id)
    return {"recorded": True, "prompt_id": prompt_id}


@router.post("/{prompt_id}/version", summary="Create a new version of a prompt", dependencies=[_Gate])
async def version_prompt(prompt_id: str, body: VersionRequest) -> dict:
    from warden.communities.prompt_library import create_version
    try:
        return create_version(prompt_id, body.new_text, body.updated_by)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
