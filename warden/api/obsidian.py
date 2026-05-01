"""Obsidian Business Community Integration — /obsidian/* endpoints."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from warden.integrations.obsidian.note_scanner import scan_note as _scan

router = APIRouter(tags=["obsidian"])

_RISK_ORDER = ("ALLOW", "LOW", "MEDIUM", "HIGH", "BLOCK")


def _get_tenant(x_tenant_id: str = "default") -> str:
    return x_tenant_id


# ── Pydantic models ───────────────────────────────────────────────────────────

class ScanNoteRequest(BaseModel):
    content: str
    filename: str = ""


class ShareNoteRequest(BaseModel):
    content: str
    filename: str = ""
    display_name: str
    community_id: str
    data_class: str | None = None
    tags: dict = Field(default_factory=dict)


class AIFilterRequest(BaseModel):
    prompt: str
    context: str = ""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _risk_from_scan(result: dict) -> tuple[str, list[str]]:
    secrets = result["secrets_found"]
    flags: list[str] = []
    risk = "ALLOW"

    if result["data_class"] == "CLASSIFIED":
        risk = "BLOCK"
        flags.append("classified_content")

    if secrets:
        flags.append("secrets_detected")
        worst = "HIGH" if len(secrets) > 1 else "MEDIUM"
        if _RISK_ORDER.index(worst) > _RISK_ORDER.index(risk):
            risk = worst

    return risk, flags


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/scan")
async def scan_note(
    body: ScanNoteRequest,
    tenant_id: str = Depends(_get_tenant),
):
    result = _scan(body.content)
    risk, flags = _risk_from_scan(result)
    return {
        "allowed": risk not in ("HIGH", "BLOCK"),
        "risk_level": risk,
        "secrets_found": result["secrets_found"],
        "flags": flags,
        "data_class": result["data_class"],
        "word_count": result["word_count"],
        "redacted_content": result["redacted_body"],
        "filename": body.filename,
        "tenant_id": tenant_id,
        "scanned_at": datetime.now(UTC).isoformat(),
    }


@router.post("/share")
async def share_note(
    body: ShareNoteRequest,
    tenant_id: str = Depends(_get_tenant),
):
    result = _scan(body.content)
    if result["secrets_found"]:
        raise HTTPException(
            400,
            f"Cannot share — {len(result['secrets_found'])} secret(s) detected. "
            "Use /obsidian/scan to get the redacted version first.",
        )

    data_class = (body.data_class or result["data_class"]).upper()
    entity_id = str(uuid.uuid4())
    ueciid: str

    try:
        from warden.communities.sep import register_ueciid
        entry = register_ueciid(
            entity_id=entity_id,
            community_id=body.community_id,
            display_name=body.display_name,
            content_type="text/markdown",
            byte_size=len(body.content.encode()),
        )
        ueciid = entry.ueciid
    except Exception:
        ueciid = f"SEP-{uuid.uuid4().hex[:11].upper()}"

    return {
        "ueciid": ueciid,
        "entity_id": entity_id,
        "community_id": body.community_id,
        "display_name": body.display_name,
        "data_class": data_class,
        "filename": body.filename,
        "word_count": result["word_count"],
        "shared_at": datetime.now(UTC).isoformat(),
        "tenant_id": tenant_id,
    }


@router.get("/feed")
async def community_feed(
    community_id: str,
    limit: int = 20,
    tenant_id: str = Depends(_get_tenant),
):
    try:
        from warden.communities.sep import list_ueciids
        entries = list_ueciids(community_id=community_id, limit=limit)
        return [
            {
                "ueciid": e.ueciid,
                "display_name": e.display_name,
                "content_type": e.content_type,
                "byte_size": e.byte_size,
                "shared_at": e.created_at,
            }
            for e in entries
        ]
    except Exception:
        return []


@router.post("/ai-filter")
async def ai_filter(
    body: AIFilterRequest,
    tenant_id: str = Depends(_get_tenant),
):
    """Scan an AI prompt through the full Warden pipeline before sending to an LLM."""
    from warden.secret_redactor import SecretRedactor
    from warden.semantic_guard import SemanticGuard

    redact_result = SecretRedactor().redact(body.prompt)
    secrets = [f.kind for f in redact_result.findings]

    guard = SemanticGuard()
    guard_result = guard.analyse(redact_result.text)

    risk = "ALLOW"
    if secrets:
        risk = "MEDIUM"
    if guard_result.risk_level in ("HIGH", "BLOCK"):
        risk = guard_result.risk_level

    return {
        "allowed": risk not in ("HIGH", "BLOCK"),
        "risk_level": risk,
        "secrets_found": secrets,
        "flags": guard_result.flags,
        "filtered_prompt": redact_result.text,
        "tenant_id": tenant_id,
    }


@router.get("/stats")
async def obsidian_stats(tenant_id: str = Depends(_get_tenant)):
    return {
        "integration": "obsidian",
        "version": "1.0.0",
        "tenant_id": tenant_id,
        "endpoints": ["scan", "share", "feed", "ai-filter", "stats"],
        "status": "active",
    }
