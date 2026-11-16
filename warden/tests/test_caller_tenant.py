"""A tenant id in a request is a claim, not an identity (H-5, wave 2).

`bind_tenant` / `caller_tenant` decide which tenant a request acts on. The
commerce router took `tenant_id` from the query string on twelve reads and from
the body on three writes, so a key holder could list another tenant's mandates
and orders, approve its pending purchases and place orders against its mandate
by typing its name.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from warden import auth_guard as ag
from warden.business_community.agentic_commerce import api as commerce


def _auth(tenant: str) -> ag.AuthResult:
    return ag.AuthResult(api_key="k", tenant_id=tenant)


# ── bind_tenant ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("claimed", [None, "", "   ", "acme", " acme "])
def test_no_claim_or_own_claim_is_the_callers_tenant(claimed):
    assert ag.bind_tenant(_auth("acme"), claimed) == "acme"


def test_a_foreign_claim_is_refused(monkeypatch):
    monkeypatch.setenv("ADMIN_KEY", "s3cret")
    with pytest.raises(HTTPException) as exc:
        ag.bind_tenant(_auth("acme"), "globex")
    assert exc.value.status_code == 403


def test_a_wrong_admin_key_does_not_unlock_a_foreign_claim(monkeypatch):
    monkeypatch.setenv("ADMIN_KEY", "s3cret")
    with pytest.raises(HTTPException):
        ag.bind_tenant(_auth("acme"), "globex", "guess")


def test_an_unset_admin_key_never_matches_an_empty_header(monkeypatch):
    monkeypatch.delenv("ADMIN_KEY", raising=False)
    with pytest.raises(HTTPException):
        ag.bind_tenant(_auth("acme"), "globex", "")


def test_the_admin_key_acts_on_a_named_tenant(monkeypatch):
    monkeypatch.setenv("ADMIN_KEY", "s3cret")
    assert ag.bind_tenant(_auth("acme"), " globex ", "s3cret") == "globex"


def test_the_master_key_acts_on_a_named_tenant():
    assert ag.bind_tenant(_auth("default"), "globex") == "globex"
    assert ag.bind_tenant(_auth("default"), None) == "default"


# ── the commerce router ───────────────────────────────────────────────────────

@pytest.fixture
def client(monkeypatch):
    """Commerce router as tenant `acme`, with every backend call recorded."""
    seen: dict[str, str] = {}

    from warden.business_community.agentic_commerce import semantic_budget, service

    def _summary(tenant_id):
        seen["budget"] = tenant_id
        return {"tenant_id": tenant_id}

    async def _workflow(self, tenant_id, **_kw):
        seen["order"] = tenant_id
        return {"success": True, "tenant_id": tenant_id}

    def _history(self, tenant_id, limit=50):
        seen["orders"] = tenant_id
        return []

    monkeypatch.setattr(semantic_budget, "get_spend_summary", _summary)
    monkeypatch.setattr(service.AgenticCommerceService, "create_purchase_workflow", _workflow)
    monkeypatch.setattr(service.AgenticCommerceService, "get_order_history", _history)
    monkeypatch.setenv("ADMIN_KEY", "s3cret")

    app = FastAPI()
    app.include_router(commerce.router)
    app.dependency_overrides[ag.require_api_key] = lambda: _auth("acme")
    app.dependency_overrides[commerce._Gate.dependency] = lambda: None
    c = TestClient(app)
    c.seen = seen
    return c


_BASE = "/business-community/commerce"


def test_a_read_without_a_tenant_is_the_callers_own(client):
    assert client.get(f"{_BASE}/budget").status_code == 200
    assert client.seen["budget"] == "acme"


def test_a_read_naming_the_callers_tenant_still_works(client):
    assert client.get(f"{_BASE}/orders", params={"tenant_id": "acme"}).status_code == 200
    assert client.seen["orders"] == "acme"


@pytest.mark.parametrize("path", ["/budget", "/orders", "/mandates", "/auctions", "/analytics/spend"])
def test_a_read_naming_another_tenant_is_refused(client, path):
    resp = client.get(f"{_BASE}{path}", params={"tenant_id": "globex"})
    assert resp.status_code == 403
    assert not client.seen


def test_an_operator_reads_a_named_tenant(client):
    resp = client.get(f"{_BASE}/budget", params={"tenant_id": "globex"},
                      headers={"X-Admin-Key": "s3cret"})
    assert resp.status_code == 200
    assert client.seen["budget"] == "globex"


def test_an_order_cannot_be_placed_as_another_tenant(client):
    body = {"tenant_id": "globex", "store_url": "https://shop.example", "mandate_id": "m1", "items": []}
    resp = client.post(f"{_BASE}/orders", json=body)
    assert resp.status_code == 403
    assert "order" not in client.seen


def test_an_order_is_placed_as_the_caller(client):
    body = {"tenant_id": "acme", "store_url": "https://shop.example", "mandate_id": "m1", "items": []}
    assert client.post(f"{_BASE}/orders", json=body).status_code == 200
    assert client.seen["order"] == "acme"


# ── the other places a tenant is claimed: path, header, form, optional filter ─

@pytest.fixture
def shapes(monkeypatch):
    """One route per dependency, authenticated as tenant `acme`."""
    monkeypatch.setenv("ADMIN_KEY", "s3cret")
    app = FastAPI()
    app.dependency_overrides[ag.require_api_key] = lambda: _auth("acme")

    @app.get("/p/{tenant_id}")
    def _path(tenant_id: str = ag.Depends(ag.caller_tenant_path)):
        return {"t": tenant_id}

    @app.get("/h")
    def _header(x_tenant_id: str = ag.Depends(ag.caller_tenant_header)):
        return {"t": x_tenant_id}

    @app.post("/f")
    def _form(tenant_id: str = ag.Depends(ag.caller_tenant_form)):
        return {"t": tenant_id}

    @app.get("/s")
    def _scope(tenant_id: str | None = ag.Depends(ag.caller_tenant_scope)):
        return {"t": tenant_id}

    @app.get("/pub")
    def _public(tenant_id: str | None = ag.Depends(ag.public_tenant_filter)):
        return {"t": tenant_id}

    @app.get("/label")
    def _label(tenant_id: str = ag.Depends(ag.caller_label)):
        return {"t": tenant_id}

    return TestClient(app), app


def test_a_path_tenant_must_be_the_callers(shapes):
    client, _ = shapes
    assert client.get("/p/acme").json() == {"t": "acme"}
    assert client.get("/p/globex").status_code == 403
    assert client.get("/p/globex", headers={"X-Admin-Key": "s3cret"}).json() == {"t": "globex"}


def test_a_header_tenant_must_be_the_callers(shapes):
    client, _ = shapes
    assert client.get("/h").json() == {"t": "acme"}
    assert client.get("/h", headers={"X-Tenant-ID": "acme"}).json() == {"t": "acme"}
    assert client.get("/h", headers={"X-Tenant-ID": "globex"}).status_code == 403


def test_a_form_tenant_must_be_the_callers(shapes):
    client, _ = shapes
    assert client.post("/f").json() == {"t": "acme"}
    assert client.post("/f", data={"tenant_id": "acme"}).json() == {"t": "acme"}
    assert client.post("/f", data={"tenant_id": "globex"}).status_code == 403


def test_an_unfiltered_listing_is_the_callers_own_rows_for_a_customer(shapes):
    # `tenant_id=None` used to mean "every tenant" for whoever asked.
    client, _ = shapes
    assert client.get("/s").json() == {"t": "acme"}
    assert client.get("/s", params={"tenant_id": "acme"}).json() == {"t": "acme"}
    assert client.get("/s", params={"tenant_id": "globex"}).status_code == 403


def test_an_unfiltered_listing_is_every_tenant_for_the_operator_only(shapes):
    client, app = shapes
    assert client.get("/s", headers={"X-Admin-Key": "s3cret"}).json() == {"t": None}
    assert client.get("/s", headers={"X-Admin-Key": "guess"}).json() == {"t": "acme"}
    app.dependency_overrides[ag.require_api_key] = lambda: _auth("default")
    assert client.get("/s").json() == {"t": None}
    assert client.get("/s", params={"tenant_id": "globex"}).json() == {"t": "globex"}


def test_a_public_filter_authenticates_nobody_and_says_so(shapes):
    client, app = shapes
    app.dependency_overrides.clear()          # no key at all
    assert client.get("/pub").json() == {"t": None}
    assert client.get("/pub", params={"tenant_id": " globex "}).json() == {"t": "globex"}


def test_a_log_label_comes_from_the_key_never_from_a_field(shapes, monkeypatch):
    client, _ = shapes
    monkeypatch.setattr(ag, "resolve_tenant_id", lambda key: {"k-acme": "acme"}.get(key))
    assert client.get("/label").json() == {"t": "anonymous"}
    assert client.get("/label", params={"tenant_id": "globex"}).json() == {"t": "anonymous"}
    assert client.get("/label", headers={"X-API-Key": "k-acme"}).json() == {"t": "acme"}


def test_public_tenant_filter_is_used_only_on_routes_recorded_as_public():
    """`public_tenant_filter` satisfies the isolation scanner without checking
    anything, so its use is pinned: each route must be in the anonymous-read
    baseline, where a human wrote down why its rows are public."""
    import ast
    import json
    from pathlib import Path

    root = Path(ag.__file__).resolve().parent
    public = json.loads(
        (root / "tests" / "anonymous_read_baseline.json").read_text(encoding="utf-8")
    )["answers_anonymously"]
    users = []
    for path in root.rglob("*.py"):
        if "tests" in path.parts or path.name == "auth_guard.py":
            continue
        src = path.read_text(encoding="utf-8")
        if "public_tenant_filter" not in src:
            continue
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and \
                    "public_tenant_filter" in ast.unparse(node.args):
                users.append(f"{path.relative_to(root).as_posix()}::{node.name}")
    assert sorted(users) == [
        "marketplace/api.py::marketplace_agent_leaderboard",
        "marketplace/api.py::marketplace_analytics_summary",
        "marketplace/api.py::marketplace_stats",
        "marketplace/api.py::marketplace_volume_series",
        "marketplace/api_agents.py::list_agents",
    ]
    for route in ("GET /marketplace/agents", "GET /marketplace/stats",
                  "GET /marketplace/analytics/agents", "GET /marketplace/analytics/summary",
                  "GET /marketplace/analytics/volume"):
        assert route in public, route
