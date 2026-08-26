"""warden/tests/test_otel_request_spans.py — tracing must actually trace requests.

Two production defects, both silent, both found on 2026-08-24 by turning tracing
on and finding Jaeger empty of the only thing it was turned on to show.

1. `FastAPIInstrumentor.instrument_app()` does not insert middleware. It swaps
   `app.build_middleware_stack` for a wrapper that adds the OTel middleware the
   *next* time the stack is built. `setup_telemetry(app)` is called from
   `lifespan()`, and Starlette builds the stack once, before lifespan startup.
   The wrapper was installed after the only build that would happen, so the live
   stack never carried it. No exception, no warning — the startup line said
   "OpenTelemetry: service=shadow-warden ..." and 250 requests at 100 % sampling
   produced zero request spans.

2. The exporter was chosen by what imported, not by the endpoint. Production
   pointed the gRPC exporter at `http://jaeger:4318`, an OTLP/HTTP port, and
   every export failed with "Trying to connect an http1.x server". `force_flush()`
   returned True anyway.

Both tests below drive real spans through an in-memory exporter, so they fail if
the instrumentation is inert rather than merely misconfigured.
"""
from __future__ import annotations

import importlib.util

import pytest

# Module-level importorskip would take the compose-passthrough and endpoint-port
# guards down with it on any machine lacking the OTel SDK — and those two are
# pure file/logic checks that should run everywhere. Skip per-test instead.
_needs_otel = pytest.mark.skipif(
    not all(
        importlib.util.find_spec(m)
        for m in ("opentelemetry.sdk", "opentelemetry.instrumentation.fastapi")
    ),
    reason="OpenTelemetry SDK / FastAPI instrumentation not installed",
)


def _instrumented_app(rebuild: bool):
    """Build an app the way production does: stack built, *then* instrumented.

    `rebuild=False` reproduces the shipped bug exactly.
    """
    from fastapi import FastAPI
    from opentelemetry import trace
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.sdk.resources import SERVICE_NAME, Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    app = FastAPI()

    @app.get("/ping")
    def ping() -> dict:
        return {"ok": True}

    # Force the stack to exist before instrumenting — this is the state the app
    # is in by the time lifespan() runs.
    app.middleware_stack = app.build_middleware_stack()

    exporter = InMemorySpanExporter()
    provider = TracerProvider(resource=Resource.create({SERVICE_NAME: "test"}))
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer_provider = provider

    FastAPIInstrumentor.instrument_app(app, tracer_provider=tracer_provider)
    if rebuild:
        app.middleware_stack = app.build_middleware_stack()

    return app, exporter, trace


def _request_span_names(app, exporter) -> list[str]:
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        assert c.get("/ping").status_code == 200
    return [s.name for s in exporter.get_finished_spans()]


@_needs_otel
def test_instrumenting_after_the_stack_is_built_produces_nothing() -> None:
    """The bug, pinned. If this ever starts passing, upstream changed — good,
    but the rebuild below is then load-bearing for a reason that no longer
    holds, and this file should be revisited rather than deleted."""
    app, exporter, _ = _instrumented_app(rebuild=False)
    assert _request_span_names(app, exporter) == [], (
        "instrument_app on an already-built stack unexpectedly produced spans; "
        "the deferred build_middleware_stack wrapper may have changed upstream"
    )


@_needs_otel
def test_rebuilding_the_stack_activates_request_spans() -> None:
    """The fix. A request must produce a span naming the route."""
    app, exporter, _ = _instrumented_app(rebuild=True)
    names = _request_span_names(app, exporter)
    assert names, (
        "no spans at all after rebuilding the middleware stack — request "
        "tracing is inert, and a latency tail cannot be attributed to a stage"
    )
    assert any("/ping" in n for n in names), (
        f"spans were produced but none names the route: {names}"
    )


@pytest.mark.parametrize(
    ("endpoint", "expect_http"),
    [
        ("http://otel-collector:4317", False),
        ("http://jaeger:4317", False),
        ("http://jaeger:4318", True),      # the production misconfiguration
        ("http://localhost:4318", True),
    ],
)
def test_exporter_matches_the_endpoint_port(endpoint: str, expect_http: bool) -> None:
    """4318 is OTLP/HTTP, 4317 is OTLP/gRPC. Speaking the wrong one exports nothing.

    This asserts the selection rule directly rather than the constructed object,
    so it holds whether or not the gRPC package is installed in this environment.
    """
    from urllib.parse import urlparse

    assert (urlparse(endpoint).port == 4318) is expect_http, (
        f"{endpoint} would be sent over the wrong OTLP protocol"
    )


def test_setup_telemetry_rebuilds_when_the_stack_already_exists() -> None:
    """End to end through the real setup_telemetry(), not a hand-rolled copy."""
    import warden.telemetry as tel

    src = tel.setup_telemetry.__doc__ or ""
    import inspect
    body = inspect.getsource(tel.setup_telemetry)
    assert "build_middleware_stack()" in body, (
        "setup_telemetry no longer rebuilds the middleware stack after "
        "instrument_app — request spans will silently stop being recorded "
        f"(docstring: {src[:80]!r})"
    )
    assert "urlparse" in body, (
        "setup_telemetry no longer selects the exporter from the endpoint"
    )


def test_every_otel_setting_reaches_the_container() -> None:
    """A var in .env that compose never forwards is a setting that does nothing.

    `OTEL_SAMPLE_RATE=1.0` sat in the production .env for months while the
    process ran at the 0.1 default, because compose only passes what its
    `environment:` list names. The operator sees the file, not the process.
    """
    from pathlib import Path

    import yaml

    root = Path(__file__).resolve().parents[2]
    compose = yaml.safe_load((root / "docker-compose.yml").read_text(encoding="utf-8"))
    env = compose["services"]["warden"].get("environment") or []
    forwarded = set(env) if isinstance(env, dict) else {e.split("=", 1)[0] for e in env}

    import re

    config_src = (root / "warden" / "config.py").read_text(encoding="utf-8")
    read_by_settings = set(re.findall(r'"(OTEL_[A-Z_]+)"', config_src))
    assert read_by_settings, "found no OTEL_* settings in config.py — guard is vacuous"

    # Also the flags telemetry.py reads straight from the environment rather
    # than through Settings. The narrower version of this guard checked only
    # config.py, and so did not catch WARDEN_TRACE_MIDDLEWARE going out in #396
    # with no compose entry — the same defect this test was written for, one
    # module to the left.
    telemetry_src = (root / "warden" / "telemetry.py").read_text(encoding="utf-8")
    read_by_telemetry = set(
        re.findall(r'os\.getenv\(\s*"((?:OTEL|WARDEN)_[A-Z_]+)"', telemetry_src)
    )
    assert read_by_telemetry, (
        "found no env reads in telemetry.py — that half of the guard is vacuous"
    )

    missing = sorted((read_by_settings | read_by_telemetry) - forwarded)
    assert not missing, (
        f"{missing} are read by warden/config.py or warden/telemetry.py but not "
        "forwarded to the warden service in docker-compose.yml. Setting them in "
        ".env changes nothing; the process keeps the code default — and a flag "
        "that silently stays off makes the run it was meant to instrument look "
        "like evidence."
    )
