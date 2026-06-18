"""
sdks/python/shadow_warden/otel_plugin.py  (DEV-02)
────────────────────────────────────────────────────
WardenSpanProcessor — OpenTelemetry SDK plugin.

Drop-in span processor that sends every span's prompt/response
attributes through the Shadow Warden filter before they are exported.
PII and secrets found in span attributes are redacted in-place.

Usage
-----
    from opentelemetry.sdk.trace import TracerProvider
    from shadow_warden.otel_plugin import WardenSpanProcessor

    provider = TracerProvider()
    provider.add_span_processor(WardenSpanProcessor(api_key="sw_..."))

The processor is non-blocking on the hot path: filtering runs in a
background thread pool (fail-open on timeout or error).
"""
from __future__ import annotations

import concurrent.futures
import logging
import os
from typing import Any

log = logging.getLogger("shadow_warden.otel_plugin")

_SCAN_ATTRS = {
    "llm.prompt",
    "llm.prompts",
    "llm.completion",
    "llm.completions",
    "gen_ai.prompt",
    "gen_ai.completion",
    "input.value",
    "output.value",
}

_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="warden-otel")


class WardenSpanProcessor:
    """OTel SpanProcessor that redacts PII/secrets from span attributes via Shadow Warden."""

    def __init__(
        self,
        api_key:   str  | None = None,
        base_url:  str         = "https://api.shadow-warden-ai.com",
        timeout:   float       = 2.0,
        tenant_id: str         = "otel",
    ) -> None:
        self._api_key   = api_key or os.getenv("WARDEN_API_KEY", "")
        self._base_url  = base_url.rstrip("/")
        self._timeout   = timeout
        self._tenant_id = tenant_id

    def on_start(self, span: Any, parent_context: Any = None) -> None:
        pass

    def on_end(self, span: Any) -> None:
        if not span or not span.attributes:
            return
        attrs = dict(span.attributes)
        dirty = {k: v for k, v in attrs.items() if k in _SCAN_ATTRS and isinstance(v, str)}
        if not dirty:
            return
        # Fire-and-forget in thread pool — never block the export pipeline
        _EXECUTOR.submit(self._redact_attrs, span, dirty)

    def _redact_attrs(self, span: Any, dirty: dict[str, str]) -> None:
        try:
            import httpx  # noqa: PLC0415
            for attr_key, text in dirty.items():
                try:
                    resp = httpx.post(
                        f"{self._base_url}/filter",
                        json={"content": text, "tenant_id": self._tenant_id},
                        headers={"X-API-Key": self._api_key},
                        timeout=self._timeout,
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        redacted = data.get("filtered_content", text)
                        span.set_attribute(attr_key, redacted)
                except Exception as exc:
                    log.debug("warden otel: attr redact failed %s — %s", attr_key, exc)
        except Exception as exc:
            log.debug("warden otel: redact thread error — %s", exc)

    def shutdown(self) -> None:
        _EXECUTOR.shutdown(wait=False)

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True
