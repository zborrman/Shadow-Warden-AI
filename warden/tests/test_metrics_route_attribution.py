"""
warden/tests/test_metrics_route_attribution.py

Every Grafana panel, the error-rate alert, the availability SLO and all four
burn-rate rules are built on `http_requests_total` and the latency histograms,
and all of them are sliced by the `handler` label. A handler label that says
`none` is not a measurement of anything — it is every route in the product
poured into one bucket.

That is what production had. `warden/main.py` carried a monkeypatch written for
prometheus_fastapi_instrumentator 8.0.x, which could not resolve the
`_IncludedRouter` objects FastAPI >= 0.116 puts in `app.routes`, so the patch
filtered them out:

    safe_routes = [r for r in routes if hasattr(r, "path") and hasattr(r, "matches")]

8.1.0 learned to expand those objects itself. The filter then removed precisely
the routes the library had just learned to read, and every endpoint registered
through a router — all of them but the few declared on `app` directly — became
`handler="none"`. Measured on production 2026-09-20: one real path across every
series, and two live requests to `/billing/tiers` produced no new label.

A version pin cannot express this. The test makes a request through a nested
router and reads the label back out of the registry.
"""
from __future__ import annotations

import pytest

pytest.importorskip("prometheus_fastapi_instrumentator")

from fastapi import APIRouter, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from prometheus_client import CollectorRegistry  # noqa: E402
from prometheus_fastapi_instrumentator import Instrumentator  # noqa: E402


def _app_with_nested_router() -> FastAPI:
    """Shaped like the gateway: a router included into a router, then into the
    app. The nesting matters — it is what produced the wrapper objects the old
    patch discarded."""
    app = FastAPI()

    leaf = APIRouter(prefix="/tiers")

    @leaf.get("/{tier_id}")
    def _tier(tier_id: str):  # noqa: ANN202
        return {"tier": tier_id}

    billing = APIRouter(prefix="/billing")
    billing.include_router(leaf)
    app.include_router(billing)

    # Declared straight on the app, the way `/filter` is: this one resolved even
    # with the patch in place, so on its own it proves nothing.
    @app.get("/filter")
    def _filter():  # noqa: ANN202
        return {}

    return app


def _handlers_seen(registry: CollectorRegistry) -> set[str]:
    seen: set[str] = set()
    for metric in registry.collect():
        for sample in metric.samples:
            handler = sample.labels.get("handler")
            if handler is not None:
                seen.add(handler)
    return seen


@pytest.fixture()
def instrumented():
    app = _app_with_nested_router()
    registry = CollectorRegistry()
    Instrumentator(registry=registry).instrument(app)
    with TestClient(app) as client:
        yield client, registry


def test_a_route_behind_two_routers_is_named_not_bucketed(instrumented):
    client, registry = instrumented
    assert client.get("/billing/tiers/pro").status_code == 200

    handlers = _handlers_seen(registry)
    assert "/billing/tiers/{tier_id}" in handlers, (
        f"the templated path never reached the label; saw {sorted(handlers)}. "
        "Every router-registered endpoint is being recorded as one bucket."
    )
    assert "none" not in handlers, (
        f"a matched route was recorded as untemplated; saw {sorted(handlers)}"
    )


def test_a_route_declared_on_the_app_is_not_the_only_one_that_works(instrumented):
    """`/filter` resolved even while everything else did not, which is how the
    defect stayed invisible: the metrics were never empty, just nearly."""
    client, registry = instrumented
    client.get("/filter")
    client.get("/billing/tiers/enterprise")

    handlers = _handlers_seen(registry)
    assert {"/filter", "/billing/tiers/{tier_id}"} <= handlers, sorted(handlers)


def test_an_unmatched_path_is_still_grouped_as_none(instrumented):
    """The bucket itself is correct and must stay: a request that matches no
    route has no templated path, and grouping those keeps a scanner probing
    random URLs from opening a new time series per URL."""
    client, registry = instrumented
    assert client.get("/no/such/route").status_code == 404
    assert "none" in _handlers_seen(registry)
