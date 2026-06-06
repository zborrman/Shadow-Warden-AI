"""
warden/document_intel/api.py
─────────────────────────────
FastAPI router — Document Intelligence endpoints (FE-50).

Prefix: /document-intel
Tier:   Community Business+ (reuses prompt_library_enabled gate)

Endpoints
─────────
POST /document-intel/convert             File → Markdown + data class + secrets
POST /document-intel/convert-and-scan    File → Markdown + full Warden filter verdict
POST /document-intel/convert-batch       Multiple files → list of results
GET  /document-intel/health              MarkItDown availability check
GET  /document-intel/formats             List supported file extensions
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from warden.billing.feature_gate import require_feature

log = logging.getLogger("warden.document_intel.api")

router = APIRouter(prefix="/document-intel", tags=["Document Intelligence"])
_Gate = require_feature("prompt_library_enabled")


@router.post("/convert", summary="Convert any file to Markdown with secret redaction", dependencies=[_Gate])
async def convert_file(file: UploadFile = File(...)) -> dict:
    """Convert an uploaded file to Markdown and run SecretRedactor on the result."""
    from warden.document_intel.converter import MarkItDownUnavailable, get_converter

    try:
        file_bytes = await file.read()
        result = get_converter().convert_bytes(file_bytes, file.filename or "upload.tmp")
    except MarkItDownUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return result.to_dict()


@router.post("/convert-and-scan", summary="Convert file and run the full Warden filter pipeline", dependencies=[_Gate])
async def convert_and_scan(
    file: UploadFile = File(...),
    tenant_id: str = Form("default"),
) -> dict:
    """Convert a file to Markdown and immediately pass it through SecretRedactor + SemanticGuard."""
    from warden.document_intel.converter import MarkItDownUnavailable, get_converter

    try:
        file_bytes = await file.read()
        result = get_converter().convert_bytes(file_bytes, file.filename or "upload.tmp")
    except MarkItDownUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if not result.markdown.strip():
        return {
            **result.to_dict(),
            "filter": {"allowed": True, "risk_level": "low", "reason": "Empty document after conversion"},
        }

    filter_result: dict = {}
    try:
        from warden.semantic_guard import SemanticGuard
        guard_result = SemanticGuard().analyse(result.markdown[:8_000])
        risk = guard_result.risk_level.lower() if guard_result.risk_level in ("HIGH", "BLOCK") else "low"
        if result.secrets_found and risk == "low":
            risk = "medium"
        filter_result = {
            "allowed": risk not in ("high", "block"),
            "risk_level": risk,
            "semantic_flags": list(guard_result.flags),
            "secrets_found": result.secrets_found,
            "data_class": result.data_class,
        }
    except Exception as exc:
        log.warning("filter pipeline unavailable during doc scan (fail-open): %s", exc)
        filter_result = {
            "allowed": True,
            "risk_level": "low",
            "reason": "Filter pipeline unavailable (fail-open)",
        }

    return {**result.to_dict(), "filter": filter_result}


@router.post("/convert-batch", summary="Convert multiple files in a single request", dependencies=[_Gate])
async def convert_batch(files: list[UploadFile] = File(...)) -> dict:
    """Batch-convert multiple files. Returns a list of conversion results."""
    from warden.document_intel.converter import get_converter

    converter = get_converter()
    results = []
    for f in files:
        try:
            file_bytes = await f.read()
            r = converter.convert_bytes(file_bytes, f.filename or "upload.tmp")
            results.append(r.to_dict())
        except Exception as exc:
            results.append({"filename": f.filename or "unknown", "error": str(exc), "markdown": ""})

    return {"results": results, "count": len(results)}


@router.get("/health", summary="Check MarkItDown availability")
async def health() -> dict:
    try:
        from markitdown import MarkItDown as _MI  # noqa: F401
        return {"status": "ok", "markitdown": "available"}
    except Exception as exc:
        return {"status": "degraded", "markitdown": "unavailable", "error": str(exc)}


@router.get("/formats", summary="List supported input file formats")
async def supported_formats() -> dict:
    from warden.document_intel.converter import SUPPORTED_EXTENSIONS
    return {"supported_extensions": sorted(SUPPORTED_EXTENSIONS)}


@router.get("/stats", summary="Conversion statistics from Redis (total, cache hits, errors, sensitive docs)")
async def doc_intel_stats() -> dict:
    from warden.document_intel.converter import get_converter
    return get_converter().get_stats()
