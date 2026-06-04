"""
warden/api/sdk.py
─────────────────
REST endpoints for the Shadow Warden OTel SDK (IN-21).

GET  /sdk/status   — version, config summary, aggregate processor stats
GET  /sdk/stats    — counters only (for Prometheus / dashboards)
POST /sdk/ping     — test-fire a span-like payload through /filter

Tier gate: Pro+  (sdk_otel_enabled)
"""
from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from warden.billing.feature_gate import require_feature
from warden.sdk.otel import (
    WardenSpanProcessor,
    WardenAsyncSpanProcessor,
    get_sdk_stats,
)
from warden.sdk import __version__ as _SDK_VERSION

router = APIRouter(
    prefix="/sdk",
    tags=["SDK"],
    dependencies=[require_feature("sdk_otel_enabled")],
)


class PingRequest(BaseModel):
    span_name: str = "test.span"
    attributes: dict = {}
    tenant_id: str = "sdk-ping"


@router.get("/status", summary="OTel SDK version and aggregate processor stats")
async def sdk_status() -> dict:
    return {
        "sdk_version":    _SDK_VERSION,
        "processor_types": [
            WardenSpanProcessor.__name__,
            WardenAsyncSpanProcessor.__name__,
        ],
        "default_api_url":  "https://api.shadow-warden-ai.com",
        "default_min_risk": "HIGH",
        "default_skip_names_count": 10,
        **get_sdk_stats(),
    }


@router.get("/stats", summary="Aggregate ingestion counters across all processors")
async def sdk_stats() -> dict:
    return get_sdk_stats()


@router.post("/ping", summary="Test-fire a synthetic span through the Warden /filter endpoint")
async def sdk_ping(body: PingRequest) -> dict:
    """
    Constructs a synthetic span from the provided name + attributes and
    runs it through the Warden /filter endpoint, returning the result.
    Useful for smoke-testing SDK connectivity without a real OTel pipeline.
    """
    from warden.sdk.otel import _span_to_text  # noqa: PLC0415

    class _FakeSpan:
        def __init__(self):
            self.name   = body.span_name
            self.attributes = body.attributes
            self.events = []
            self.resource = None
            self.context  = None
            self.status   = None

    text = _span_to_text(_FakeSpan(), skip_names=frozenset())
    if not text:
        raise HTTPException(422, "No scannable text produced from span attributes")

    try:
        import httpx  # noqa: PLC0415
        api_url = os.getenv("WARDEN_SELF_URL", "http://localhost:8001")
        api_key = os.getenv("WARDEN_API_KEY", "")
        resp = httpx.post(
            f"{api_url}/filter",
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
            json={"content": text, "tenant_id": body.tenant_id, "context": "otel_ping"},
            timeout=10.0,
        )
        return {"text_sent": text, "warden_response": resp.json(), "status_code": resp.status_code}
    except Exception as exc:
        raise HTTPException(503, detail=f"Warden /filter unreachable: {exc}")
