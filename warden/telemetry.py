"""
warden/telemetry.py
━━━━━━━━━━━━━━━━━━━
OpenTelemetry distributed tracing for Shadow Warden AI.

Exports traces to OTLP endpoint (default: Jaeger all-in-one on :4318).
Each filter pipeline stage becomes a child span, giving full P99 breakdowns:
  obfuscation → redaction → rules → ml_inference → decision

Configuration
─────────────
  OTEL_ENABLED=false                      opt-in (default disabled)
  OTEL_SERVICE_NAME=shadow-warden
  OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4318
  OTEL_SAMPLE_RATE=1.0                    (0.0–1.0, default 100 %)

Public API
──────────
  setup_telemetry(app)      — init SDK + FastAPIInstrumentor; call from lifespan()
  init_telemetry(app)       — alias for setup_telemetry()
  get_tracer()              — active tracer or None
  trace_stage(name, attrs)  — context manager wrapping a pipeline stage
  traced(span_name)         — decorator for sync/async functions

Usage::

    # lifespan.py / main.py
    from warden.telemetry import setup_telemetry
    setup_telemetry(app)

    # anywhere in the filter pipeline
    from warden.telemetry import trace_stage, traced

    with trace_stage("ml_inference", {"tenant_id": tid, "request_id": rid}) as span:
        result = await brain_guard.check_async(text)
        span.set_attribute("ml.score", result.score)
        span.set_attribute("ml.is_jailbreak", result.is_jailbreak)

    @traced("secret_redaction")
    def redact(text: str) -> RedactResult:
        ...
"""
from __future__ import annotations

import contextlib
import functools
import inspect
import logging
import os
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

log = logging.getLogger("warden.telemetry")

_ENABLED      = os.getenv("OTEL_ENABLED",                  "false").lower() == "true"
_SERVICE_NAME = os.getenv("OTEL_SERVICE_NAME",             "shadow-warden")
_ENDPOINT     = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT",  "http://jaeger:4318")
_SAMPLE_RATE  = float(os.getenv("OTEL_SAMPLE_RATE",       "1.0"))

_tracer       = None
_initialized  = False


# ── Initialisation ─────────────────────────────────────────────────────────────

def setup_telemetry(app: Any = None) -> None:
    """
    Initialise the OpenTelemetry SDK and optionally instrument a FastAPI app.

    Call once from the FastAPI lifespan() startup hook::

        from warden.telemetry import setup_telemetry

        @asynccontextmanager
        async def lifespan(app):
            setup_telemetry(app)
            yield

    When OTEL_ENABLED=false (default) this is a zero-cost no-op.
    Missing packages are logged as warnings — they never raise.
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

        if app is not None:
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
            FastAPIInstrumentor.instrument_app(
                app,
                excluded_urls="/health,/metrics",   # skip high-frequency probes
            )

        _initialized = True
        log.info(
            "OpenTelemetry: service=%s  endpoint=%s  sample_rate=%.2f",
            _SERVICE_NAME, _ENDPOINT, _SAMPLE_RATE,
        )

    except ImportError as exc:
        log.warning(
            "OpenTelemetry packages missing (%s) — tracing disabled. "
            "Install: opentelemetry-sdk opentelemetry-exporter-otlp-proto-http "
            "opentelemetry-instrumentation-fastapi",
            exc,
        )
    except Exception as exc:
        log.warning("OpenTelemetry init failed (tracing disabled): %s", exc)


# Alias kept for backward compatibility with existing callers.
init_telemetry = setup_telemetry


def get_tracer() -> Any:
    """Return the active tracer, or None when tracing is disabled."""
    return _tracer


# ── trace_stage context manager ────────────────────────────────────────────────

@contextmanager
def trace_stage(
    name:       str,
    attributes: dict[str, Any] | None = None,
) -> Generator[Any, None, None]:
    """
    Wrap a synchronous or async filter-pipeline stage in an OTel child span.

    When tracing is disabled (_tracer is None) this is a pure no-op —
    no function call overhead beyond a single None-check.

    Usage::

        with trace_stage("obfuscation", {"request_id": rid}) as span:
            decoded = decoder.decode(text)
            span.set_attribute("obfuscation.detected", decoded != text)

        with trace_stage("ml_inference", {"tenant_id": tid}) as span:
            result = await brain_guard.check_async(text)
            span.set_attribute("ml.score",        result.score)
            span.set_attribute("ml.is_jailbreak", result.is_jailbreak)
    """
    if _tracer is None:
        yield _NoOpSpan()
        return

    with _tracer.start_as_current_span(name) as span:
        if attributes:
            for k, v in attributes.items():
                with contextlib.suppress(Exception):
                    span.set_attribute(k, v)
        try:
            yield span
        except Exception as exc:
            span.record_exception(exc)
            raise


# ── @traced decorator ──────────────────────────────────────────────────────────

def traced(span_name: str, attributes: dict[str, Any] | None = None):
    """
    Decorator that wraps a sync or async function in an OTel span.

    Usage::

        @traced("secret_redaction")
        def redact(text: str) -> RedactResult: ...

        @traced("corpus_embedding", {"backend": "onnx"})
        async def embed_batch(texts: list[str]) -> np.ndarray: ...
    """
    def decorator(fn):
        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                with trace_stage(span_name, attributes):
                    return await fn(*args, **kwargs)
            return async_wrapper
        else:
            @functools.wraps(fn)
            def sync_wrapper(*args, **kwargs):
                with trace_stage(span_name, attributes):
                    return fn(*args, **kwargs)
            return sync_wrapper
    return decorator


# ── No-op span ─────────────────────────────────────────────────────────────────

class _NoOpSpan:
    """Zero-overhead stand-in returned by trace_stage when tracing is disabled."""

    __slots__ = ()

    def set_attribute(self, key: str, value: Any) -> None:  # noqa: ARG002
        pass

    def set_status(self, *args: Any, **kwargs: Any) -> None:
        pass

    def record_exception(self, exc: Exception) -> None:  # noqa: ARG002
        pass

    def add_event(self, name: str, attributes: dict | None = None) -> None:  # noqa: ARG002
        pass
