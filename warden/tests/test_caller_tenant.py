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
