"""
warden/telemetry.py
━━━━━━━━━━━━━━━━━━━
OpenTelemetry distributed tracing for Shadow Warden AI.

Exports traces to OTLP endpoint (default: Jaeger all-in-one on :4318).
Each filter pipeline stage becomes a child span so P99 latency breakdowns
are visible per-stage (obfuscation / redaction / rules / ml / decision).

Configuration
─────────────
  OTEL_ENABLED=false             opt-in (default disabled)
  OTEL_SERVICE_NAME=shadow-warden
  OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4318  (OTLP HTTP)
  OTEL_SAMPLE_RATE=1.0           (1.0 = 100% sampling)

Usage in code::

    from warden.telemetry import get_tracer, trace_stage

    tracer = get_tracer()
    with trace_stage("ml_inference", {"tenant_id": tid}) as span:
        result = brain_guard.check(text)
        span.set_attribute("ml.score", result.score)
"""
from __future__ import annotations

import logging
import os
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

log = logging.getLogger("warden.telemetry")

_ENABLED      = os.getenv("OTEL_ENABLED",         "false").lower() == "true"
_SERVICE_NAME = os.getenv("OTEL_SERVICE_NAME",     "shadow-warden")
_ENDPOINT     = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://jaeger:4318")
_SAMPLE_RATE  = float(os.getenv("OTEL_SAMPLE_RATE", "1.0"))

_tracer = None
_initialized = False


def init_telemetry(app=None) -> None:
    """
    Initialize OpenTelemetry SDK.  Call once from FastAPI lifespan().
    If OTEL_ENABLED=false (default), this is a no-op.
    """
    global _tracer, _initialized
    if not _ENABLED or _initialized:
        return

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import SERVICE_NAME, Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.trace.sampling import TraceIdRatioBased

        resource = Resource.create({SERVICE_NAME: _SERVICE_NAME})
        sampler  = TraceIdRatioBased(_SAMPLE_RATE)
        provider = TracerProvider(resource=resource, sampler=sampler)
        exporter = OTLPSpanExporter(endpoint=f"{_ENDPOINT}/v1/traces")
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer(_SERVICE_NAME)

        # Auto-instrument FastAPI if app provided
        if app is not None:
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
            FastAPIInstrumentor.instrument_app(app)

        _initialized = True
        log.info(
            "OpenTelemetry initialized: service=%s endpoint=%s sample_rate=%.1f",
            _SERVICE_NAME, _ENDPOINT, _SAMPLE_RATE,
        )
    except ImportError as exc:
        log.warning(
            "OpenTelemetry packages not installed (%s). Tracing disabled. "
            "Install: opentelemetry-sdk opentelemetry-exporter-otlp-proto-http "
            "opentelemetry-instrumentation-fastapi",
            exc,
        )
    except Exception as exc:
        log.warning("OpenTelemetry init failed (tracing disabled): %s", exc)


def get_tracer():
    """Return the initialized tracer, or a no-op sentinel if OTel is disabled."""
    return _tracer


@contextmanager
def trace_stage(
    name:       str,
    attributes: dict[str, Any] | None = None,
) -> Generator[Any, None, None]:
    """
    Context manager that wraps a filter pipeline stage in an OTel span.
    If tracing is disabled this is a zero-overhead no-op.

    Usage::

        with trace_stage("ml_inference", {"tenant_id": tid}) as span:
            result = brain_guard.check(text)
    """
    if _tracer is None:
        yield _NoOpSpan()
        return

    with _tracer.start_as_current_span(name) as span:
        if attributes:
            for k, v in attributes.items():
                span.set_attribute(k, v)
        yield span


class _NoOpSpan:
    """Returned by trace_stage when tracing is disabled — all calls are no-ops."""

    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def set_status(self, *args: Any, **kwargs: Any) -> None:
        pass

    def record_exception(self, exc: Exception) -> None:
        pass
