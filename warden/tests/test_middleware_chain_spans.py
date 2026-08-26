"""warden/tests/test_middleware_chain_spans.py

A ~5.03s stall sits between the request span opening and the app reading the
request body — before any handler code runs. Measured on production across three
organic requests:

    01:15:00.356  total 7500ms   body read at 01:15:05.388   (5031ms)
    02:30:00.552  total 7470ms   body read at 02:30:05.587   (5035ms)
    06:21:00.864  total 5241ms   body read at 06:21:05.905   (5042ms)

Ruled out by measurement rather than by reading the source: not
`process_blocked` (its window starts *after* the body is read — zero overlap),
not container cold start (stalls on an instance up for hours), not the proxy
(reproduces on localhost inside the container), not worker recycling (no
``--limit-max-requests``).

Nothing is instrumented in that window. "No span" is not "no work": five of the
nine middlewares are ``BaseHTTPMiddleware`` and none of them are traced. So the
chain gets wrapped generically — including the layers we do not own — rather
than by editing each class and still missing those.

Off by default (``WARDEN_TRACE_MIDDLEWARE``), because the stall is rare and this
should not be a permanent per-request cost.
"""
from __future__ import annotations

import asyncio

import pytest
from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware

from warden.telemetry import instrument_middleware_stack


class _Slow(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        await asyncio.sleep(0.05)
        return await call_next(request)


class _Passthrough(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        return await call_next(request)


def _app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(_Passthrough)
    app.add_middleware(_Slow)

    @app.get("/ping")
    def ping() -> dict:
        return {"ok": True}

    return app


def test_every_layer_is_wrapped() -> None:
    app = _app()
    before = [getattr(mw.cls, "__name__", "") for mw in app.user_middleware]
    n = instrument_middleware_stack(app)
    after = [getattr(mw.cls, "__name__", "") for mw in app.user_middleware]

    assert n == len(before), f"wrapped {n} of {len(before)} layers: {after}"
    assert all(name.startswith("Traced") for name in after), after


def test_wrapping_is_idempotent() -> None:
    """setup_telemetry can run more than once per process (multiple workers,
    test re-imports). Double-wrapping would nest spans and misreport depth."""
    app = _app()
    instrument_middleware_stack(app)
    second = instrument_middleware_stack(app)
    assert second == 0, "a second pass re-wrapped already-traced layers"


def test_the_app_still_serves_after_wrapping() -> None:
    """The wrapper sits in the request path of every request. If it breaks the
    ASGI contract, it takes the whole gateway with it — so this is the test that
    matters more than the spans."""
    from fastapi.testclient import TestClient

    app = _app()
    instrument_middleware_stack(app)
    app.middleware_stack = app.build_middleware_stack()

    with TestClient(app) as c:
        r = c.get("/ping")
    assert r.status_code == 200, r.text
    assert r.json() == {"ok": True}


def test_non_http_scopes_bypass_the_span() -> None:
    """Lifespan and websocket scopes must pass through untouched — opening a
    request span around a lifespan would attach startup work to a request."""
    from warden.telemetry import _wrap_middleware_class

    seen = []

    class _Recorder:
        def __init__(self, app, *a, **kw):
            self.app = app

        async def __call__(self, scope, receive, send):
            seen.append(scope["type"])
            return None

    wrapped = _wrap_middleware_class(_Recorder)(None)
    asyncio.run(wrapped({"type": "lifespan"}, None, None))
    asyncio.run(wrapped({"type": "http"}, None, None))
    assert seen == ["lifespan", "http"], seen


@pytest.mark.parametrize("value,expected", [("true", True), ("1", True),
                                            ("false", False), ("", False)])
def test_the_flag_defaults_to_off(monkeypatch, value, expected) -> None:
    """A per-request span for every middleware layer is a diagnostic, not a
    default. The stall is rare — three in twelve hours."""
    monkeypatch.setenv("WARDEN_TRACE_MIDDLEWARE", value)
    import importlib

    import warden.telemetry as tel
    importlib.reload(tel)
    assert tel._TRACE_MIDDLEWARE is expected
    monkeypatch.delenv("WARDEN_TRACE_MIDDLEWARE", raising=False)
    importlib.reload(tel)
    assert tel._TRACE_MIDDLEWARE is False, "the default is not off"


def test_layers_emit_nested_spans_that_localise_a_stall() -> None:
    """The point of the whole exercise.

    Each layer's span covers that layer *and everything beneath it*, so the cost
    of one layer is the difference between consecutive spans. A stall that shows
    up at layer N but not at layer N+1 was spent in layer N — which is exactly
    the attribution missing from the 5.03s window.
    """
    pytest.importorskip("opentelemetry.sdk")

    from fastapi.testclient import TestClient
    from opentelemetry import trace
    from opentelemetry.sdk.resources import SERVICE_NAME, Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    import warden.telemetry as tel

    exporter = InMemorySpanExporter()
    provider = TracerProvider(resource=Resource.create({SERVICE_NAME: "t"}))
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    prev_tracer, prev_enabled = tel._tracer, tel._ENABLED
    tel._tracer = trace.get_tracer("test", tracer_provider=provider)
    tel._ENABLED = True
    try:
        app = _app()
        instrument_middleware_stack(app)
        app.middleware_stack = app.build_middleware_stack()
        with TestClient(app) as c:
            assert c.get("/ping").status_code == 200
    finally:
        tel._tracer, tel._ENABLED = prev_tracer, prev_enabled

    spans = {s.name: s for s in exporter.get_finished_spans()}
    assert "mw._Slow" in spans and "mw._Passthrough" in spans, (
        f"middleware layers produced no spans: {sorted(spans)}"
    )

    def _ms(s) -> float:
        return (s.end_time - s.start_time) / 1e6

    slow, fast = _ms(spans["mw._Slow"]), _ms(spans["mw._Passthrough"])
    assert slow - fast >= 30, (
        f"_Slow sleeps 50ms but its span ({slow:.1f}ms) is not measurably longer "
        f"than the layer beneath it ({fast:.1f}ms) — the difference between "
        "consecutive layers is what attributes a stall, so this must hold"
    )
