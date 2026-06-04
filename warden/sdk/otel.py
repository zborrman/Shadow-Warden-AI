"""
warden/sdk/otel.py  (IN-21)
────────────────────────────
WardenSpanProcessor — OpenTelemetry SDK span processor that security-scans
every completed span through the Shadow Warden AI /filter endpoint for
real-time threat detection in any OTel-instrumented application.

Two processor variants
──────────────────────
  WardenSpanProcessor       — sync (thread-pool); works with any OTel setup
  WardenAsyncSpanProcessor  — submits to a running asyncio event loop;
                              optimal for FastAPI / ASGI applications

Quick start
───────────
  from opentelemetry.sdk.trace import TracerProvider
  from warden.sdk.otel import WardenSpanProcessor

  provider = TracerProvider()
  provider.add_span_processor(WardenSpanProcessor(
      api_url="https://api.shadow-warden-ai.com",
      api_key=os.getenv("WARDEN_API_KEY", ""),
  ))
  # Warden now scans every completed span's attributes for jailbreaks,
  # leaked secrets, PII, and prompt injection.

Configuration
─────────────
  api_url         Shadow Warden gateway URL
  api_key         X-API-Key header value
  min_risk        Minimum risk level to log / trigger callback (default: HIGH)
  tenant_id       Tenant identifier forwarded in every /filter request
  max_workers     ThreadPoolExecutor workers for _sync_ processor (default: 4)
  max_queue       Max pending scans; extras are dropped fail-open (default: 512)
  on_finding      Optional callback(result_dict) called on HIGH/BLOCK findings
  skip_span_names Set of span names to skip scanning (e.g. health probes)
  max_attr_length Max characters extracted per attribute value (default: 500)
  timeout_s       HTTP request timeout in seconds (default: 5.0)

GDPR note
─────────
  Only attribute values (plain text) are forwarded — never raw span bytes,
  binary payloads, or full protobuf frames.  Warden's SecretRedactor runs on
  every /filter call, so secrets in spans are stripped before logging.
"""
from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

log = logging.getLogger("warden.sdk.otel")

_RISK_ORDER: dict[str, int] = {
    "ALLOW": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "BLOCK": 4,
}

# Span names that are never worth scanning (high-frequency, no payload)
_DEFAULT_SKIP: frozenset[str] = frozenset({
    "GET /health", "GET /metrics", "GET /favicon.ico",
    "OPTIONS", "OPTIONS /",
    "MIDDLEWARE", "ROUTING",
    "health", "metrics",
})

# Module-level registry so /sdk/status can aggregate across processors
_REGISTRY: list[WardenSpanProcessor] = []


# ── Stats ─────────────────────────────────────────────────────────────────────

@dataclass
class ProcessorStats:
    spans_seen:         int = 0
    spans_scanned:      int = 0
    spans_skipped:      int = 0
    high_risk_detected: int = 0
    errors:             int = 0
    queue_drops:        int = 0
    last_finding_ts:    float | None = None

    def to_dict(self) -> dict:
        return dict(self.__dict__)


# ── Span text / metadata extraction ──────────────────────────────────────────

def _span_to_text(
    span: Any,
    max_attr_length: int = 500,
    skip_names: frozenset[str] | None = _DEFAULT_SKIP,
) -> str | None:
    """
    Extract a plain-text summary of a span's observable content.
    Returns None if the span should be skipped or yields no scannable text.
    """
    name: str = getattr(span, "name", "") or ""
    if skip_names and name in skip_names:
        return None

    parts: list[str] = []

    # Span name — often contains HTTP method + path or RPC name
    if name:
        parts.append(f"span:{name}")

    # Attribute values (string / numeric only — skip bytes and arrays)
    attrs: dict = getattr(span, "attributes", {}) or {}
    for k, v in attrs.items():
        if isinstance(v, (str, int, float, bool)):
            sv = str(v)[:max_attr_length]
            if sv:
                parts.append(f"{k}={sv}")

    # Event messages (e.g. exception tracebacks, log messages)
    for event in getattr(span, "events", []) or []:
        e_attrs: dict = getattr(event, "attributes", {}) or {}
        for k, v in e_attrs.items():
            if isinstance(v, str):
                parts.append(f"event.{event.name}.{k}={v[:200]}")

    text = " | ".join(parts)[:2000]
    return text if text.strip() else None


def _span_meta(span: Any) -> dict:
    """Extract trace identifiers for Warden context enrichment."""
    ctx = getattr(span, "context", None)
    resource = getattr(span, "resource", None)
    resource_attrs: dict = getattr(resource, "attributes", {}) or {}
    _tid = getattr(ctx, "trace_id", None) if ctx else None
    _sid = getattr(ctx, "span_id",  None) if ctx else None
    return {
        "span_name":  getattr(span, "name", "unknown"),
        "service":    str(resource_attrs.get("service.name", "unknown")),
        "trace_id":   format(_tid, "032x") if isinstance(_tid, int) else None,
        "span_id":    format(_sid, "016x") if isinstance(_sid, int) else None,
        "status":     str(getattr(getattr(span, "status", None), "status_code", "UNSET")),
    }


def _risk_gte(actual: str, minimum: str) -> bool:
    return _RISK_ORDER.get(actual.upper(), 0) >= _RISK_ORDER.get(minimum.upper(), 2)


# ── WardenSpanProcessor (sync, thread-pool) ───────────────────────────────────

class WardenSpanProcessor:
    """
    OTel SpanProcessor — security-scans span attributes via Shadow Warden.

    Thread-safe, non-blocking: on_end() submits to a bounded ThreadPool.
    Safe to add to any TracerProvider without affecting trace latency.
    """

    def __init__(
        self,
        api_url:         str = "https://api.shadow-warden-ai.com",
        api_key:         str = "",
        min_risk:        str = "HIGH",
        tenant_id:       str = "otel-sdk",
        max_workers:     int = 4,
        max_queue:       int = 512,
        on_finding:      Callable[[dict], None] | None = None,
        skip_span_names: set[str] | None = None,
        max_attr_length: int = 500,
        timeout_s:       float = 5.0,
    ) -> None:
        self._api_url        = api_url.rstrip("/")
        self._api_key        = api_key
        self._min_risk       = min_risk.upper()
        self._tenant_id      = tenant_id
        self._on_finding     = on_finding
        self._max_attr_len   = max_attr_length
        self._timeout        = timeout_s
        self._skip           = frozenset(skip_span_names or set()) | _DEFAULT_SKIP
        self._max_queue      = max_queue
        self._stats          = ProcessorStats()
        self._lock           = threading.Lock()
        self._pending        = 0          # futures in flight
        self._executor       = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="warden-otel",
        )
        _REGISTRY.append(self)

    # ── OTel SpanProcessor interface ─────────────────────────────────────────

    def on_start(self, span: Any, parent_context: Any = None) -> None:
        pass

    def on_end(self, span: Any) -> None:
        with self._lock:
            self._stats.spans_seen += 1
            if self._pending >= self._max_queue:
                self._stats.queue_drops += 1
                return

        text = _span_to_text(span, self._max_attr_len, self._skip)
        if not text:
            with self._lock:
                self._stats.spans_skipped += 1
            return

        meta = _span_meta(span)
        with self._lock:
            self._pending += 1

        try:
            self._executor.submit(self._scan_and_release, text, meta)
        except Exception:
            with self._lock:
                self._pending -= 1
                self._stats.errors += 1

    def shutdown(self) -> None:
        """Drain pending scans then shut down the thread pool."""
        self._executor.shutdown(wait=True, cancel_futures=False)
        import contextlib
        with contextlib.suppress(ValueError):
            _REGISTRY.remove(self)

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        """Block until all queued scans complete or timeout is reached."""
        deadline = time.monotonic() + timeout_millis / 1000.0
        while self._pending > 0 and time.monotonic() < deadline:
            time.sleep(0.05)
        return self._pending == 0

    # ── Internal ──────────────────────────────────────────────────────────────

    @property
    def stats(self) -> dict:
        return self._stats.to_dict()

    def _scan_and_release(self, text: str, meta: dict) -> None:
        try:
            self._scan(text, meta)
        finally:
            with self._lock:
                self._pending -= 1

    def _scan(self, text: str, meta: dict | None = None) -> None:
        if meta is None:
            meta = {}
        try:
            import httpx  # noqa: PLC0415
            resp = httpx.post(
                f"{self._api_url}/filter",
                headers={
                    "X-API-Key":     self._api_key,
                    "Content-Type":  "application/json",
                },
                json={
                    "content":   text,
                    "tenant_id": self._tenant_id,
                    "context":   "otel_span",
                    **{f"otel_{k}": v for k, v in meta.items() if v},
                },
                timeout=self._timeout,
            )

            with self._lock:
                self._stats.spans_scanned += 1

            if resp.status_code != 200:
                return

            data  = resp.json()
            risk  = data.get("risk_level", "")
            flags = data.get("flags", [])

            if _risk_gte(risk, self._min_risk):
                with self._lock:
                    self._stats.high_risk_detected += 1
                    self._stats.last_finding_ts = time.time()

                log.warning(
                    "WardenSpanProcessor: %s finding in span '%s' "
                    "(service=%s trace=%s) flags=%s",
                    risk,
                    meta.get("span_name", "?"),
                    meta.get("service", "?"),
                    (meta.get("trace_id") or "")[:16],
                    flags,
                )

                if self._on_finding:
                    try:
                        self._on_finding({**data, "span_meta": meta})
                    except Exception as cb_exc:
                        log.debug("on_finding callback error: %s", cb_exc)

        except Exception as exc:
            log.debug("WardenSpanProcessor scan error: %s", exc)
            with self._lock:
                self._stats.errors += 1


# ── WardenAsyncSpanProcessor (asyncio) ───────────────────────────────────────

class WardenAsyncSpanProcessor(WardenSpanProcessor):
    """
    Async variant — submits HTTP calls to a running asyncio event loop.

    Optimal for FastAPI / ASGI applications where the event loop is always
    available.  Falls back to a daemon thread when no loop is running
    (e.g. during CLI scripts or tests).

    Usage (FastAPI lifespan)::

        from warden.sdk.otel import WardenAsyncSpanProcessor

        provider = TracerProvider()
        processor = WardenAsyncSpanProcessor(
            api_url=os.getenv("WARDEN_API_URL"),
            api_key=os.getenv("WARDEN_API_KEY"),
            on_finding=lambda r: logger.critical("WARDEN HIT: %s", r),
        )
        provider.add_span_processor(processor)
    """

    def on_end(self, span: Any) -> None:
        with self._lock:
            self._stats.spans_seen += 1
            if self._pending >= self._max_queue:
                self._stats.queue_drops += 1
                return

        text = _span_to_text(span, self._max_attr_len, self._skip)
        if not text:
            with self._lock:
                self._stats.spans_skipped += 1
            return

        meta = _span_meta(span)
        with self._lock:
            self._pending += 1

        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._async_scan_and_release(text, meta))
        except RuntimeError:
            # No running loop — fall back to thread (same as sync variant)
            try:
                self._executor.submit(self._scan_and_release, text, meta)
            except Exception:
                with self._lock:
                    self._pending -= 1
                    self._stats.errors += 1

    async def _async_scan_and_release(self, text: str, meta: dict) -> None:
        try:
            await self._async_scan(text, meta)
        finally:
            with self._lock:
                self._pending -= 1

    async def _async_scan(self, text: str, meta: dict | None = None) -> None:
        if meta is None:
            meta = {}
        try:
            import httpx  # noqa: PLC0415
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    f"{self._api_url}/filter",
                    headers={
                        "X-API-Key":    self._api_key,
                        "Content-Type": "application/json",
                    },
                    json={
                        "content":   text,
                        "tenant_id": self._tenant_id,
                        "context":   "otel_span",
                        **{f"otel_{k}": v for k, v in meta.items() if v},
                    },
                )

            with self._lock:
                self._stats.spans_scanned += 1

            if resp.status_code != 200:
                return

            data  = resp.json()
            risk  = data.get("risk_level", "")
            flags = data.get("flags", [])

            if _risk_gte(risk, self._min_risk):
                with self._lock:
                    self._stats.high_risk_detected += 1
                    self._stats.last_finding_ts = time.time()

                log.warning(
                    "WardenAsyncSpanProcessor: %s finding in span '%s' flags=%s",
                    risk, meta.get("span_name", "?"), flags,
                )

                if self._on_finding:
                    try:
                        self._on_finding({**data, "span_meta": meta})
                    except Exception as cb_exc:
                        log.debug("on_finding callback error: %s", cb_exc)

        except Exception as exc:
            log.debug("WardenAsyncSpanProcessor scan error: %s", exc)
            with self._lock:
                self._stats.errors += 1


# ── Registry helpers ──────────────────────────────────────────────────────────

def get_sdk_stats() -> dict:
    """Aggregate stats across all active WardenSpanProcessor instances."""
    processors = list(_REGISTRY)
    aggregate: dict = {
        "processors": len(processors),
        "spans_seen": 0, "spans_scanned": 0, "spans_skipped": 0,
        "high_risk_detected": 0, "errors": 0, "queue_drops": 0,
    }
    per: list[dict] = []
    for p in processors:
        s = p.stats
        per.append({"class": type(p).__name__, "tenant_id": p._tenant_id, **s})
        for k in ("spans_seen", "spans_scanned", "spans_skipped",
                  "high_risk_detected", "errors", "queue_drops"):
            aggregate[k] += s.get(k, 0)
    aggregate["per_processor"] = per
    return aggregate
