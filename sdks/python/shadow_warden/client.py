"""
sdks/python/shadow_warden/client.py  (DEV-01)
──────────────────────────────────────────────
Shadow Warden AI Python SDK — async + sync client.

Async usage
-----------
    from shadow_warden import AsyncWardenClient

    async with AsyncWardenClient(api_key="sw_...") as client:
        result = await client.filter("Tell me how to hack")
        if result.blocked:
            print("Blocked:", result.flags)

Sync usage
----------
    from shadow_warden import WardenClient

    client = WardenClient(api_key="sw_...")
    result = client.filter("Tell me how to hack")
"""
from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from typing import Any


@dataclass
class FilterResult:
    blocked:          bool
    action:           str
    risk_level:       str
    risk_score:       float
    filtered_content: str
    flags:            list[str]     = field(default_factory=list)
    processing_ms:    int           = 0
    request_id:       str           = ""
    secrets_found:    list[dict]    = field(default_factory=list)
    raw:              dict          = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict) -> FilterResult:
        return cls(
            blocked          = data.get("blocked", False),
            action           = data.get("action", "ALLOW"),
            risk_level       = data.get("risk_level", "LOW"),
            risk_score       = float(data.get("risk_score", 0.0)),
            filtered_content = data.get("filtered_content", data.get("content", "")),
            flags            = data.get("flags", []),
            processing_ms    = int(data.get("processing_ms", 0)),
            request_id       = data.get("request_id", ""),
            secrets_found    = data.get("secrets_found", []),
            raw              = data,
        )


class AsyncWardenClient:
    """Async Shadow Warden AI client."""

    def __init__(
        self,
        api_key:   str  | None = None,
        base_url:  str         = "https://api.shadow-warden-ai.com",
        timeout:   float       = 10.0,
        tenant_id: str         = "default",
    ) -> None:
        self._api_key   = api_key or os.getenv("WARDEN_API_KEY", "")
        self._base_url  = base_url.rstrip("/")
        self._timeout   = timeout
        self._tenant_id = tenant_id
        self._client    = None

    async def __aenter__(self) -> AsyncWardenClient:
        import httpx  # noqa: PLC0415
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=self._timeout,
            headers={"X-API-Key": self._api_key, "Content-Type": "application/json"},
        )
        return self

    async def __aexit__(self, *_) -> None:
        if self._client:
            await self._client.aclose()

    def _headers(self) -> dict:
        return {"X-API-Key": self._api_key, "Content-Type": "application/json"}

    async def filter(
        self,
        text:       str,
        tenant_id:  str | None = None,
        session_id: str | None = None,
        image_b64:  str | None = None,
        audio_b64:  str | None = None,
    ) -> FilterResult:
        """Filter a text (and optional multimodal inputs) through the 9-layer pipeline."""
        payload: dict[str, Any] = {
            "content":   text,
            "tenant_id": tenant_id or self._tenant_id,
        }
        if session_id:
            payload["session_id"] = session_id
        if image_b64:
            payload["image_base64"] = image_b64
        if audio_b64:
            payload["audio_base64"] = audio_b64

        import httpx  # noqa: PLC0415
        client = self._client or httpx.AsyncClient(
            base_url=self._base_url, timeout=self._timeout, headers=self._headers()
        )
        try:
            resp = await client.post("/filter", json=payload)
            resp.raise_for_status()
            return FilterResult.from_dict(resp.json())
        finally:
            if not self._client:
                await client.aclose()

    async def health(self) -> dict:
        """Check gateway health."""
        import httpx  # noqa: PLC0415
        client = self._client or httpx.AsyncClient(
            base_url=self._base_url, timeout=self._timeout, headers=self._headers()
        )
        try:
            resp = await client.get("/health")
            resp.raise_for_status()
            return resp.json()
        finally:
            if not self._client:
                await client.aclose()

    async def stats(self, tenant_id: str | None = None) -> dict:
        """Retrieve filter statistics for a tenant."""
        import httpx  # noqa: PLC0415
        client = self._client or httpx.AsyncClient(
            base_url=self._base_url, timeout=self._timeout, headers=self._headers()
        )
        try:
            resp = await client.get("/stats", params={"tenant_id": tenant_id or self._tenant_id})
            resp.raise_for_status()
            return resp.json()
        finally:
            if not self._client:
                await client.aclose()


class WardenClient:
    """Synchronous Shadow Warden AI client (wraps AsyncWardenClient)."""

    def __init__(
        self,
        api_key:   str  | None = None,
        base_url:  str         = "https://api.shadow-warden-ai.com",
        timeout:   float       = 10.0,
        tenant_id: str         = "default",
    ) -> None:
        self._async = AsyncWardenClient(
            api_key=api_key, base_url=base_url,
            timeout=timeout, tenant_id=tenant_id,
        )

    def _run(self, coro):
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures  # noqa: PLC0415
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    return pool.submit(asyncio.run, coro).result()
            return loop.run_until_complete(coro)
        except RuntimeError:
            return asyncio.run(coro)

    def filter(
        self,
        text:       str,
        tenant_id:  str | None = None,
        session_id: str | None = None,
        image_b64:  str | None = None,
        audio_b64:  str | None = None,
    ) -> FilterResult:
        return self._run(self._async.filter(text, tenant_id, session_id, image_b64, audio_b64))

    def health(self) -> dict:
        return self._run(self._async.health())

    def stats(self, tenant_id: str | None = None) -> dict:
        return self._run(self._async.stats(tenant_id))
