"""
A tenant named in a request body, or in a header read inside the code, is bound
to the key exactly like a tenant in a query string.

The first tenant-isolation pass (#745) took 152 parameter claims to zero. The
re-audit of 2026-11-16 found the same claim arriving two ways its scanner could
not see: 41 handlers read ``body.tenant_id`` (39 of them protected only by a
plan gate, so any paying tenant could write into any other), and code read
``X-Tenant-ID`` to decide whose add-on was checked, whose credits were spent and
whose usage was billed.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import warden.auth_guard as ag
from warden.auth_guard import AuthResult, CallerTenant, request_tenant
from warden.hooks import tenant_isolation as ti

# ── the scanner ──────────────────────────────────────────────────────────────

_MODEL = """
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
router = APIRouter()
class Body(BaseModel):
    tenant_id: str
    note: str = ""
"""


def _scan(src: str) -> list[ti.Finding]:
    return ti.scan_source(_MODEL + src, "warden/api/x.py", models={})


def test_a_body_claim_is_reported():
    found = _scan("""
@router.post("/x")
async def h(body: Body):
    return save(body.tenant_id)
""")
    assert [f.param for f in found] == ["body.tenant_id"]
    assert found[0].source == "body"


def test_a_bound_body_claim_is_not():
    assert _scan("""
@router.post("/x")
async def h(body: Body, b = Depends(caller_binding)):
    body.tenant_id = b.bind(body.tenant_id)
    return save(body.tenant_id)
""") == []


def test_a_body_claim_compared_and_rejected_is_bound():
    assert _scan("""
@router.post("/x")
async def h(body: Body, caller: str = Depends(_caller_tenant)):
    if body.tenant_id != caller:
        raise HTTPException(403)
    return save(body.tenant_id)
""") == []


def test_the_auth_object_is_not_a_body():
    # `auth.tenant_id` is the answer, not a claim.
    assert _scan("""
@router.post("/x")
async def h(auth: Body = Depends(require_api_key)):
    return save(auth.tenant_id)
""") == []


def test_an_operator_check_binds_a_body_claim():
    assert _scan("""
@router.post("/x")
async def h(body: Body, x_admin_key: str = Header(None)):
    _require_admin(x_admin_key)
    return save(body.tenant_id)
""") == []


def test_a_header_read_in_a_helper_is_reported():
    found = _scan("""
def _tenant(request: Request) -> str:
    return request.headers.get("X-Tenant-ID", "unknown")
""")
    assert [f.param for f in found] == ["header:x-tenant-id"]
    assert found[0].route == "helper"


def test_a_header_read_under_the_dev_check_is_not():
    assert _scan("""
def _tenant(request: Request) -> str:
    if tier_header_trusted():
        return request.headers.get("X-Tenant-ID", "")
    return "anonymous"
""") == []


def test_every_proven_claim_still_names_a_real_finding_and_a_reason():
    """An entry outliving its route would excuse whatever lands there next."""
    from pathlib import Path

    root = Path(ti.__file__).resolve().parents[2]
    raw = []
    for key in ti.PROVEN_CLAIMS:
        path, func, _param = key.split("::")
        src = (root / path).read_text(encoding="utf-8")
        assert f"def {func}(" in src, f"stale PROVEN_CLAIMS entry: {key}"
        saved = dict(ti.PROVEN_CLAIMS)
        try:
            ti.PROVEN_CLAIMS.clear()
            raw += [f for f in ti.scan_source(src, path) if f.func == func]
        finally:
            ti.PROVEN_CLAIMS.update(saved)
    assert {f"{f.path}::{f.func}::{f.param}" for f in raw} == set(ti.PROVEN_CLAIMS)
    assert all(len(reason) > 40 for reason in ti.PROVEN_CLAIMS.values())


# ── the binders ──────────────────────────────────────────────────────────────

A = AuthResult(api_key="ka", tenant_id="tenant-a")


@pytest.fixture
def prod(monkeypatch):
    monkeypatch.setattr(ag, "tier_header_trusted", lambda: False)
    monkeypatch.delenv("ADMIN_KEY", raising=False)


def test_own_or_empty_claim_binds_to_the_key(prod):
    assert CallerTenant(A).bind("tenant-a") == "tenant-a"
    assert CallerTenant(A).bind(None) == "tenant-a"
    assert CallerTenant(A).bind("  ") == "tenant-a"


def test_a_foreign_claim_is_refused(prod):
    with pytest.raises(HTTPException) as exc:
        CallerTenant(A).bind("tenant-b")
    assert exc.value.status_code == 403


def test_the_operator_may_name_a_tenant(prod, monkeypatch):
    monkeypatch.setenv("ADMIN_KEY", "adm")
    assert CallerTenant(A, "adm").bind("tenant-b") == "tenant-b"
    assert CallerTenant(None, "adm").bind("tenant-b") == "tenant-b"


def test_no_key_owns_no_tenant(prod):
    assert CallerTenant(None).bind("tenant-b") == "anonymous"


def test_dev_mode_keeps_the_claim(monkeypatch):
    monkeypatch.setattr(ag, "tier_header_trusted", lambda: True)
    assert CallerTenant(None).bind("tenant-b") == "tenant-b"


class _Req:
    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.state = type("S", (), {})()


def test_request_tenant_ignores_the_header_in_production(prod, monkeypatch):
    monkeypatch.setattr(ag, "resolve_tenant_id", lambda k: "tenant-a" if k == "ka" else None)
    assert request_tenant(_Req({"X-API-Key": "ka", "X-Tenant-ID": "tenant-b"})) == "tenant-a"
    assert request_tenant(_Req({"X-Tenant-ID": "tenant-b"})) == "unknown"
    assert request_tenant(_Req({"Authorization": "Bearer ka"})) == "tenant-a"


def test_request_tenant_honours_the_header_in_dev(monkeypatch):
    monkeypatch.setattr(ag, "tier_header_trusted", lambda: True)
    monkeypatch.setattr(ag, "resolve_tenant_id", lambda k: None)
    assert request_tenant(_Req({"X-Tenant-ID": "tenant-b"})) == "tenant-b"


def test_the_addon_gate_asks_about_the_key_not_the_header(prod, monkeypatch):
    """Naming a tenant that bought the add-on used to pass the 402 check."""
    from warden.billing import addons

    monkeypatch.setattr(ag, "resolve_tenant_id", lambda k: "tenant-a" if k == "ka" else None)
    req = _Req({"X-API-Key": "ka", "X-Tenant-ID": "tenant-who-paid"})
    assert addons._get_tenant_id_from_request(req) == "tenant-a"


def test_the_x402_gate_charges_the_key_not_the_header(prod, monkeypatch):
    from warden.marketplace import x402_gate

    monkeypatch.setattr(ag, "resolve_tenant_id", lambda k: "tenant-a" if k == "ka" else None)
    req = _Req({"X-API-Key": "ka", "X-Tenant-ID": "tenant-with-credits"})
    assert x402_gate._get_tenant_id(req) == "tenant-a"


# ── one route end to end ─────────────────────────────────────────────────────


def test_a_paying_tenant_cannot_set_another_tenants_budget(prod, monkeypatch):
    from fastapi import FastAPI

    import warden.billing.feature_gate as fg
    from warden.api.budget import router

    monkeypatch.setattr(ag, "_VALID_KEY", "")
    monkeypatch.setattr(ag.settings, "allow_unauthenticated", False, raising=False)
    monkeypatch.setattr(fg, "_get_tenant_tier", lambda request: "community_business")
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[ag.require_api_key] = lambda: A
    client = TestClient(app)
    saved: list[str] = []
    import warden.financial.budget as budget

    monkeypatch.setattr(budget, "set_budget_cap", lambda **kw: saved.append(kw["tenant_id"]) or "cap-1")
    resp = client.post("/financial/budget/caps", json={"tenant_id": "tenant-b", "cap_usd": 1.0})
    assert resp.status_code == 403, resp.text
    assert saved == []

    own = client.post("/financial/budget/caps", json={"tenant_id": "tenant-a", "cap_usd": 1.0})
    assert own.status_code == 200, own.text
    assert saved == ["tenant-a"]
