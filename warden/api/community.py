"""
Business Community REST API — /community/*

Endpoints:
  POST   /community/posts                — create post (queues NIM moderation)
  GET    /community/feed                 — approved posts feed
  GET    /community/posts/{id}           — single post + comments
  POST   /community/posts/{id}/comment  — add comment
  DELETE /community/posts/{id}           — admin: block post
  GET    /community/members             — list members
  POST   /community/members             — register member

Obsidian bridge:
  POST   /community/posts/from-obsidian — share Obsidian note → community post

NVIDIA NIM:
  Moderation runs as an ARQ background job (moderate_post).
  Fallback to SemanticGuard when NVIDIA_API_KEY is absent.
"""
from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Query
from pydantic import BaseModel, Field

from warden.models.community import (
    Comment, Member, Post,
    create_comment, create_post, get_comments,
    get_feed, get_members, get_post,
    init_db, register_member, update_post_status,
)

router = APIRouter(prefix="/community", tags=["community"])

# Ensure tables exist on import
init_db()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _tenant(x_tenant_id: Annotated[str, Header()] = "default") -> str:
    return x_tenant_id


async def _queue_moderation(post_id: str) -> None:
    """Fire-and-forget: enqueue NIM moderation via ARQ or run inline as fallback."""
    try:
        from arq import create_pool
        from arq.connections import RedisSettings
        import os
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
        if redis_url.startswith("memory://"):
            raise RuntimeError("in-memory redis — inline moderation")
        pool = await create_pool(RedisSettings.from_dsn(redis_url))
        await pool.enqueue_job("moderate_post", post_id)
        await pool.aclose()
    except Exception:
        # Inline fallback — runs synchronously in background task
        from warden.workers.content_filter import moderate_post
        await moderate_post({}, post_id)


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class CreatePostRequest(BaseModel):
    author_id: str
    content: str = Field(min_length=1, max_length=10_000)
    source: str = "manual"

class CommentRequest(BaseModel):
    author_id: str
    content: str = Field(min_length=1, max_length=2_000)

class MemberRequest(BaseModel):
    user_id: str
    display_name: str
    role: str = "member"

class ObsidianPostRequest(BaseModel):
    author_id: str
    note_content: str
    filename: str = ""
    obsidian_ueciid: str | None = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/posts", status_code=202)
async def create_community_post(
    req: CreatePostRequest,
    background_tasks: BackgroundTasks,
    tenant_id: str = "default",
):
    """Create a post. NIM moderation runs in background; post starts as 'pending'."""
    post = Post(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        author_id=req.author_id,
        content=req.content,
        source=req.source,
        status="pending",
    )
    create_post(post)
    background_tasks.add_task(_queue_moderation, post.id)
    return {"id": post.id, "status": "pending", "message": "Post queued for moderation"}


@router.post("/posts/from-obsidian", status_code=202)
async def post_from_obsidian(
    req: ObsidianPostRequest,
    background_tasks: BackgroundTasks,
    tenant_id: str = "default",
):
    """
    Obsidian → Community bridge.
    Scans note content first; blocks share if secrets or CLASSIFIED data found.
    On pass: creates community post with source='obsidian'.
    """
    from warden.integrations.obsidian.note_scanner import scan_note

    scan = scan_note(req.note_content, filename=req.filename)

    if scan["secrets_found"]:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "secrets_detected",
                "count": len(scan["secrets_found"]),
                "message": "Note contains secrets — redact before sharing.",
            },
        )
    if scan["data_class"] == "CLASSIFIED":
        raise HTTPException(
            status_code=422,
            detail={"error": "classified_content", "message": "CLASSIFIED notes cannot be shared."},
        )

    post = Post(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        author_id=req.author_id,
        content=scan.get("redacted_body", req.note_content),
        source="obsidian",
        obsidian_ueciid=req.obsidian_ueciid,
        status="pending",
    )
    create_post(post)
    background_tasks.add_task(_queue_moderation, post.id)

    return {
        "id": post.id,
        "status": "pending",
        "data_class": scan["data_class"],
        "obsidian_ueciid": req.obsidian_ueciid,
        "message": "Note queued for moderation",
    }


@router.get("/feed")
def get_community_feed(
    tenant_id: str = "default",
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    posts = get_feed(tenant_id, limit=limit, offset=offset)
    return {"posts": [p.to_dict() for p in posts], "count": len(posts)}


@router.get("/posts/{post_id}")
def get_community_post(post_id: str, tenant_id: str = "default"):
    post = get_post(post_id)
    if not post or post.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Post not found")
    comments = get_comments(post_id)
    return {
        **post.to_dict(),
        "comments": [
            {"id": c.id, "author_id": c.author_id, "content": c.content, "created_at": c.created_at}
            for c in comments
        ],
    }


@router.post("/posts/{post_id}/comment", status_code=201)
def add_comment(post_id: str, req: CommentRequest, tenant_id: str = "default"):
    post = get_post(post_id)
    if not post or post.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Post not found")
    if post.status != "approved":
        raise HTTPException(status_code=403, detail="Cannot comment on unapproved post")
    comment = Comment(
        id=str(uuid.uuid4()),
        post_id=post_id,
        tenant_id=tenant_id,
        author_id=req.author_id,
        content=req.content,
    )
    create_comment(comment)
    return {"id": comment.id, "created_at": comment.created_at}


@router.delete("/posts/{post_id}", status_code=200)
def admin_block_post(
    post_id: str,
    tenant_id: str = "default",
    x_admin_key: Annotated[str | None, Header()] = None,
):
    import os, hmac
    admin_key = os.getenv("ADMIN_KEY", "")
    if not admin_key or not x_admin_key or not hmac.compare_digest(x_admin_key, admin_key):
        raise HTTPException(status_code=403, detail="Admin key required")
    post = get_post(post_id)
    if not post or post.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Post not found")
    update_post_status(post_id, "blocked", "BLOCK", 1.0)
    return {"id": post_id, "status": "blocked"}


@router.get("/members")
def list_members(tenant_id: str = "default"):
    members = get_members(tenant_id)
    return {
        "members": [
            {"id": m.id, "user_id": m.user_id, "display_name": m.display_name,
             "role": m.role, "joined_at": m.joined_at}
            for m in members
        ],
        "count": len(members),
    }


@router.post("/members", status_code=201)
def join_community(req: MemberRequest, tenant_id: str = "default"):
    member = Member(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        user_id=req.user_id,
        display_name=req.display_name,
        role=req.role,
    )
    register_member(member)
    return {"id": member.id, "summary": member.summary()}
