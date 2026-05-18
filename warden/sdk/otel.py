"""
warden/sdk/otel.py  (IN-21)
────────────────────────────
WardenSpanProcessor — OpenTelemetry SDK span processor that sends every
completed span through the Shadow Warden AI /filter endpoint for
real-time security scanning.

Usage
─────
  from warden.sdk.otel import WardenSpanProcessor
  from opentelemetry.sdk.trace import TracerProvider

  provider = TracerProvider()
  provider.add_span_processor(WardenSpanProcessor(
      api_url="https://api.shadow-warden-ai.com",
      api_key=os.getenv("WARDEN_API_KEY", ""),
      min_risk="HIGH",   # only report HIGH/BLOCK (default)
  ))

The processor is non-blocking:
  • Sends attribute values (never full payloads) to Warden.
  • Drops silently on HTTP errors (fail-open).
  • Respects GDPR — attribute values are serialized to plain text
    and subject to Warden's existing redaction pipeline.

Requires: opentelemetry-sdk, httpx
"""
from __future__ import annotations

import logging
import threading
from typing import Any, Sequence

log = logging.getLogger("warden.sdk.otel")

_RISK_ORDER = {"ALLOW": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "BLOCK": 4}


def _risk_gte(actual: str, minimum: str) -> bool:
    return _RISK_ORDER.get(actual.upper(), 0) >= _RISK_ORDER.get(minimum.upper(), 2)


class WardenSpanProcessor:
    """
    OTel SpanProcessor that security-scans span attribute text via
    the Warden /filter API and logs findings.

    Parameters
    ──────────
    api_url   Base URL of the Shadow Warden AI gateway.
    api_key   X-API-Key header value.
    min_risk  Minimum risk level to log (default: "HIGH").
    tenant_id Tenant identifier forwarded to Warden.
    """

    def __init__(
        self,
        api_url:   str = "https://api.shadow-warden-ai.com",
        api_key:   str = "",
        min_risk:  str = "HIGH",
        tenant_id: str = "otel-sdk",
    ) -> None:
        self._api_url   = api_url.rstrip("/")
        self._api_key   = api_key
        self._min_risk  = min_risk.upper()
        self._tenant_id = tenant_id
        self._lock      = threading.Lock()
        self._queue: list[str] = []

    # Required OTel interface stubs
    def on_start(self, span: Any, parent_context: Any = None) -> None:
        pass

    def on_end(self, span: Any) -> None:
        try:
            attrs = getattr(span, "attributes", {}) or {}
            if not attrs:
                return
            text = " ".join(str(v) for v in attrs.values() if isinstance(v, (str, int, float)))[:2000]
            if not text.strip():
                return
            threading.Thread(target=self._scan, args=(text,), daemon=True).start()
        except Exception as exc:
            log.debug("WardenSpanProcessor on_end error: %s", exc)

    def shutdown(self) -> None:
        pass

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        return True

    def _scan(self, text: str) -> None:
        try:
            import httpx
            resp = httpx.post(
                f"{self._api_url}/filter",
                headers={"X-API-Key": self._api_key, "Content-Type": "application/json"},
                json={"content": text, "tenant_id": self._tenant_id, "context": "otel_span"},
                timeout=5.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                risk = data.get("risk_level", "")
                if _risk_gte(risk, self._min_risk):
                    log.warning(
                        "WardenSpanProcessor: %s threat in OTel span — flags=%s",
                        risk, data.get("flags", []),
                    )
        except Exception as exc:
            log.debug("WardenSpanProcessor scan error: %s", exc)
