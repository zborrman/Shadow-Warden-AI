"""
warden/api/doc_converter.py
────────────────────────────
FastAPI router — MarkItDown-powered community document conversion.

Prefix: /doc-converter
Tier:   Community Business+ (reuses prompt_library_enabled gate)

Endpoints
─────────
POST /doc-converter/convert        Upload any file → Markdown + scan result
POST /doc-converter/to-prompt      Convert file and add directly to Prompt Library
GET  /doc-converter/formats        List supported file extensions
"""
from __future__ import annotations

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from warden.billing.feature_gate import require_feature

router = APIRouter(prefix="/doc-converter", tags=["Document Converter"])
_Gate = require_feature("prompt_library_enabled")


@router.post("/convert", summary="Convert any file to Markdown with secret redaction", dependencies=[_Gate])
async def convert_file(
    file: UploadFile = File(...),
    community_id: str = Form(...),
) -> dict:
    """Convert an uploaded file to Markdown and run SecretRedactor on the result."""
    from warden.communities.doc_converter import DocConverterUnavailable, convert_to_markdown

    try:
        file_bytes = await file.read()
        result = convert_to_markdown(file_bytes, file.filename or "upload.tmp")
    except DocConverterUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return {**result.to_dict(), "community_id": community_id}


@router.post("/to-prompt", summary="Convert a file and add it to the community Prompt Library", dependencies=[_Gate])
async def convert_to_prompt(
    file: UploadFile = File(...),
    community_id: str = Form(...),
    created_by: str = Form(...),
    title: str = Form(...),
    category: str = Form("general"),
    tags: str = Form(""),
    visibility: str = Form("community"),
    description: str = Form(""),
) -> dict:
    """Convert *file* to Markdown, screen it, and add it to the Prompt Library in one step."""
    from warden.communities.doc_converter import DocConverterUnavailable, convert_to_markdown
    from warden.communities.prompt_library import add_prompt

    try:
        file_bytes = await file.read()
        result = convert_to_markdown(file_bytes, file.filename or "upload.tmp")
    except DocConverterUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if result.data_class == "CLASSIFIED":
        raise HTTPException(status_code=422, detail="CLASSIFIED documents cannot be added to the Prompt Library.")

    tag_list = [t.strip() for t in tags.split(",") if t.strip()]

    try:
        entry = add_prompt(
            community_id=community_id,
            created_by=created_by,
            title=title,
            prompt_text=result.markdown,
            category=category,
            tags=tag_list,
            visibility=visibility,
            description=description or f"Converted from {result.filename}",
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return {
        **entry,
        "conversion": {
            "filename": result.filename,
            "data_class": result.data_class,
            "secrets_found": result.secrets_found,
            "redacted": result.redacted,
            "word_count": result.word_count,
        },
    }


@router.get("/formats", summary="List supported input file formats")
async def supported_formats() -> dict:
    from warden.communities.doc_converter import SUPPORTED_EXTENSIONS
    return {"supported_extensions": sorted(SUPPORTED_EXTENSIONS)}
