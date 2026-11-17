"""
Who may read the analytics service, and what answers the public hostname.

The service is reachable from the internet (the Cloudflare Tunnel maps its
hostname straight to the container; Caddy is not on that path). Until this file
existed it had no authentication on any route, and the only reason it leaked
nothing was a second defect: it read its log from a directory that did not
exist. These tests hold both repairs in place, and they enumerate the routes
from the app itself so a route added later is covered without being listed.
"""
from __future__ import annotations

import importlib
import json

import pytest
from fastapi.testclient import TestClient
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

import analytics.main as analytics_main
from analytics.main import app
from warden.middleware.edge_hidden import EdgeHiddenPathsMiddleware

KEY = "analytics-access-test-key"


def _data_routes() -> list[str]:
    # From the router, not `app.routes`: this FastAPI keeps an included router
    # as one mount, so the app-level list does not show the routes inside it.
    out = []
    for r in analytics_main.api.routes:
        path = getattr(r, "path", "")
        if "GET" in (getattr(r, "methods", None) or ()):
            out.append(path.replace("{request_id}", "x").replace("{session_id}", "x"))
    return sorted(out)


def test_nothing_serves_data_outside_the_guarded_router():
    direct = {
        getattr(r, "path", "")
        for r in app.routes
        if getattr(r, "methods", None) and getattr(r, "path", "").startswith("/api/")
    }
    assert direct == set(), f"routes registered on the app bypass the key: {direct}"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("ANALYTICS_API_KEY", raising=False)
    monkeypatch.delenv("WARDEN_API_KEY", raising=False)
    with TestClient(app) as c:
        yield c


def test_there_are_data_routes_to_guard():
    # A guard over an empty list passes vacuously.
    assert len(_data_routes()) >= 10
    assert all(p.startswith("/api/v1/") for p in _data_routes())


@pytest.mark.parametrize("path", _data_routes())
def test_no_key_configured_is_503_not_data(client, path):
    resp = client.get(path, headers={"X-API-Key": "anything"})
    assert resp.status_code == 503


@pytest.mark.parametrize("path", _data_routes())
def test_anonymous_is_401(client, monkeypatch, path):
    monkeypatch.setenv("ANALYTICS_API_KEY", KEY)
    assert client.get(path).status_code == 401


@pytest.mark.parametrize("presented", ["", "wrong", KEY[:-1], KEY + "x"])
def test_a_wrong_key_is_401(client, monkeypatch, presented):
    monkeypatch.setenv("ANALYTICS_API_KEY", KEY)
    resp = client.get("/api/v1/stats", headers={"X-API-Key": presented})
    assert resp.status_code == 401


def test_the_service_key_is_accepted(client, monkeypatch):
    monkeypatch.setenv("ANALYTICS_API_KEY", KEY)
    assert client.get("/api/v1/stats", headers={"X-API-Key": KEY}).status_code == 200


def test_the_gateway_key_is_accepted(client, monkeypatch):
    # The dashboard proxy presents WARDEN_API_KEY to this service.
    monkeypatch.setenv("WARDEN_API_KEY", KEY)
    assert client.get("/api/v1/stats", headers={"X-API-Key": KEY}).status_code == 200


def test_health_stays_open_for_the_healthcheck(client):
    assert client.get("/health").status_code == 200


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_the_interactive_docs_are_off(client, path):
    assert client.get(path).status_code == 404


def test_cors_names_no_origin_by_default(client):
    resp = client.get("/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in resp.headers


@pytest.mark.parametrize("edge_header", ["CF-Ray", "CF-Connecting-IP"])
def test_metrics_do_not_answer_the_edge(client, edge_header):
    assert client.get("/metrics", headers={edge_header: "x"}).status_code == 404


def test_metrics_answer_the_internal_network(client):
    resp = client.get("/metrics")
    # 200 where the instrumentator is installed; never the edge refusal body.
    assert resp.status_code in (200, 404)
    if resp.status_code == 404:
        pytest.skip("prometheus instrumentator not installed in this environment")
    assert "python_info" in resp.text or "http_request" in resp.text


def test_the_log_path_follows_the_env_var(monkeypatch, tmp_path):
    """compose sets LOGS_PATH; the module used to ignore it and read a directory
    that does not exist, so every route reported zero events."""
    log = tmp_path / "logs.json"
    log.write_text(
        json.dumps({"ts": "2999-01-01T00:00:00+00:00", "request_id": "r1", "allowed": True})
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("LOGS_PATH", str(log))
    monkeypatch.delenv("SESSIONS_PATH", raising=False)
    try:
        mod = importlib.reload(analytics_main)
        assert log == mod.LOGS_PATH
        assert tmp_path / "sessions.json" == mod.SESSIONS_PATH
        assert len(mod._load()) == 1
    finally:
        monkeypatch.undo()
        importlib.reload(analytics_main)


# ── gateway: the same rule for /metrics ──────────────────────────────────────


def _edge_app() -> TestClient:
    async def metrics(_request):
        return PlainTextResponse("metric 1")

    async def other(_request):
        return PlainTextResponse("ok")

    inner = Starlette(routes=[Route("/metrics", metrics), Route("/health", other)])
    return TestClient(EdgeHiddenPathsMiddleware(inner))


def test_gateway_metrics_answer_without_an_edge_header():
    assert _edge_app().get("/metrics").text == "metric 1"


@pytest.mark.parametrize("edge_header", ["CF-Ray", "cf-connecting-ip"])
@pytest.mark.parametrize("path", ["/metrics", "/metrics/"])
def test_gateway_metrics_are_hidden_from_the_edge(edge_header, path):
    resp = _edge_app().get(path, headers={edge_header: "x"}, follow_redirects=False)
    assert resp.status_code == 404
    assert "metric" not in resp.text


def test_other_paths_are_untouched_at_the_edge():
    assert _edge_app().get("/health", headers={"CF-Ray": "x"}).text == "ok"


def test_the_gateway_registers_the_middleware():
    from warden.main import app as gateway

    assert any(m.cls is EdgeHiddenPathsMiddleware for m in gateway.user_middleware)
