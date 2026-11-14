"""
warden/m2m_store/tests/test_store_plans.py
───────────────────────────────────────────
Store plans: the limit table, where it is enforced, and who may change a plan.

Run against the plan a new seller actually lands on (free), not the widest one
the other store modules pin in conftest.
"""
from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("ANTHROPIC_API_KEY", "")

API = "/m2m-store"
ADMIN = "plans-test-admin"


@pytest.fixture(autouse=True)
def fresh_store(tmp_path, monkeypatch, _widest_plan_by_default):
    monkeypatch.setenv("M2M_STORE_DB_PATH", str(tmp_path / "m2m.db"))
    monkeypatch.setenv("ADMIN_KEY", ADMIN)
    monkeypatch.setenv("ALLOW_UNAUTHENTICATED", "false")
    from warden.m2m_store import inventory as inv_mod
    from warden.m2m_store import plans
    inv_mod._inventory = inv_mod.InventoryManager()
    monkeypatch.setattr(plans, "DEFAULT_PLAN", "store_free")
    yield
    from warden.db.connect import close_cached_connections
    close_cached_connections()


@pytest.fixture
def client():
    from warden.auth_guard import AuthResult, require_api_key
    from warden.m2m_store.api import require_store_owner, router

    app = FastAPI()
    app.include_router(router)

    def _auth(request: Request) -> AuthResult:
        return AuthResult(api_key="k", tenant_id=request.headers.get("X-Test-Tenant", "tenant-a"))

    app.dependency_overrides[require_api_key] = _auth
    app.dependency_overrides[require_store_owner] = _auth
    return TestClient(app)


def _as(tenant: str) -> dict:
    return {"X-Test-Tenant": tenant}


def _store(client, slug="acme", tenant="tenant-a", **kw):
    body = {"slug": slug, "name": "Acme", "locales": ["en"]} | kw
    return client.post(f"{API}/stores", json=body, headers=_as(tenant))


def _product(client, store_id, tenant="tenant-a", **kw):
    body = {"name": "Widget", "price_base": 10, "stock": 5, "store_id": store_id} | kw
    return client.post(f"{API}/products", json=body, headers=_as(tenant))


def _grant(client, tenant, plan, **kw):
    return client.put(f"{API}/admin/plans/{tenant}", json={"plan": plan} | kw,
                      headers={"X-Admin-Key": ADMIN})


# ── The table itself ──────────────────────────────────────────────────────────

class TestPlanTable:
    def test_every_plan_has_every_limit_and_a_price(self):
        from warden.billing import pricing as p
        keys = {frozenset(v) for v in p.STORE_PLAN_LIMITS.values()}
        assert len(keys) == 1, "plans disagree about which limits exist"
        assert set(p.STORE_PLAN_LIMITS) == set(p.STORE_PLAN_PRICE_USD_MONTH)

    def test_a_dearer_plan_never_allows_less(self):
        from warden.billing import pricing as p
        ladder = sorted(p.STORE_PLAN_LIMITS, key=p.STORE_PLAN_PRICE_USD_MONTH.__getitem__)
        for lower, higher in zip(ladder, ladder[1:], strict=False):
            for name, value in p.STORE_PLAN_LIMITS[lower].items():
                assert p.STORE_PLAN_LIMITS[higher][name] >= value, (lower, higher, name)

    def test_annual_price_is_derived_not_typed(self):
        from warden.billing import pricing as p
        for plan, monthly in p.STORE_PLAN_PRICE_USD_MONTH.items():
            if monthly:
                assert p.store_annual_price_usd(plan) == round(
                    monthly * 12 * (1 - p.ANNUAL_DISCOUNT), 2)
            else:
                assert p.store_annual_price_usd(plan) is None

    def test_ai_budget_never_exceeds_what_the_margin_leaves(self):
        from warden.billing import pricing as p
        for plan, monthly in p.STORE_PLAN_PRICE_USD_MONTH.items():
            if monthly:
                assert p.store_ai_budget_usd(plan) <= monthly * (1 - p.TARGET_GROSS_MARGIN) + 0.005

    def test_default_and_trial_plans_exist(self):
        from warden.billing import pricing as p
        assert p.STORE_DEFAULT_PLAN in p.STORE_PLAN_LIMITS
        assert p.STORE_TRIAL_PLAN in p.STORE_PLAN_LIMITS
        assert p.STORE_PLAN_PRICE_USD_MONTH[p.STORE_DEFAULT_PLAN] == 0


# ── Limits, at the point of writing ───────────────────────────────────────────

class TestLimits:
    def test_a_new_seller_is_on_the_free_plan(self, client):
        r = client.get(f"{API}/plan", headers=_as("tenant-a"))
        assert r.status_code == 200
        body = r.json()
        assert body["plan"] == "store_free" and body["source"] == "default"
        assert body["limits"] == {"stores": 1, "products": 25, "locales": 2}
        assert body["usage"] == {"stores": 0, "products": 0}
        assert body["trial_available"] is True

    def test_the_plan_response_carries_no_price(self, client):
        """A price the API serves is a public claim, and nothing can be bought yet."""
        text = client.get(f"{API}/plan", headers=_as("tenant-a")).text
        assert "price" not in text and "usd" not in text.lower()

    def test_second_store_is_refused_on_free(self, client):
        assert _store(client, "one").status_code == 201
        r = _store(client, "two")
        assert r.status_code == 403
        assert r.json()["detail"] == {
            "error": "plan_limit", "limit": "stores", "max": 1, "plan": "store_free"}

    def test_a_deleted_store_frees_its_slot(self, client):
        sid = _store(client, "one").json()["id"]
        assert client.delete(f"{API}/stores/{sid}", headers=_as("tenant-a")).status_code == 204
        assert _store(client, "two").status_code == 201

    def test_locales_beyond_the_plan_are_refused(self, client):
        r = _store(client, "poly", locales=["en", "de", "fr"])
        assert r.status_code == 403
        assert r.json()["detail"]["limit"] == "locales"
        assert _store(client, "duo", locales=["en", "de"]).status_code == 201

    def test_product_limit_is_exact(self, client, monkeypatch):
        from warden.billing import pricing
        monkeypatch.setitem(pricing.STORE_PLAN_LIMITS["store_free"], "products", 3)
        sid = _store(client).json()["id"]
        for i in range(3):
            assert _product(client, sid, name=f"p{i}").status_code == 201
        r = _product(client, sid, name="one too many")
        assert r.status_code == 403
        assert r.json()["detail"] == {
            "error": "plan_limit", "limit": "products", "max": 3, "plan": "store_free"}

    def test_updating_an_existing_product_is_not_a_new_one(self, client, monkeypatch):
        from warden.billing import pricing
        monkeypatch.setitem(pricing.STORE_PLAN_LIMITS["store_free"], "products", 1)
        sid = _store(client).json()["id"]
        pid = _product(client, sid).json()["id"]
        assert _product(client, sid, id=pid, name="Renamed").status_code == 201

    def test_a_deleted_product_frees_its_slot(self, client, monkeypatch):
        from warden.billing import pricing
        monkeypatch.setitem(pricing.STORE_PLAN_LIMITS["store_free"], "products", 1)
        sid = _store(client).json()["id"]
        pid = _product(client, sid).json()["id"]
        assert _product(client, sid, name="blocked").status_code == 403
        assert client.delete(f"{API}/products/{pid}", headers=_as("tenant-a")).status_code == 204
        assert _product(client, sid, name="fits now").status_code == 201

    def test_one_tenants_usage_does_not_count_against_another(self, client):
        assert _store(client, "a-shop", tenant="tenant-a").status_code == 201
        assert _store(client, "b-shop", tenant="tenant-b").status_code == 201

    def test_the_limit_holds_below_the_route(self, monkeypatch):
        """Enforcement lives in the function that writes the row, so a caller
        that skips the HTTP layer is held to the plan just the same."""
        from warden.m2m_store import plans
        from warden.m2m_store import storefront as sf
        from warden.m2m_store.models import StoreIn
        sf.create_store("tenant-z", StoreIn(slug="first", name="First"))
        with pytest.raises(plans.PlanLimitError) as exc:
            sf.create_store("tenant-z", StoreIn(slug="second", name="Second"))
        assert exc.value.limit == "stores"


# ── Going over the limit destroys nothing ─────────────────────────────────────

class TestDowngradeKeepsData:
    def test_revoking_a_plan_keeps_every_store_and_product(self, client):
        assert _grant(client, "tenant-a", "store_business").status_code == 200
        ids = [_store(client, f"s{i}").json()["id"] for i in range(3)]
        for sid in ids:
            assert _product(client, sid).status_code == 201

        assert client.delete(f"{API}/admin/plans/tenant-a",
                             headers={"X-Admin-Key": ADMIN}).status_code == 204

        plan = client.get(f"{API}/plan", headers=_as("tenant-a")).json()
        assert plan["plan"] == "store_free"
        assert plan["usage"] == {"stores": 3, "products": 3}      # over the limit, intact
        assert len(client.get(f"{API}/stores", headers=_as("tenant-a")).json()) == 3
        for i in range(3):                                         # still published
            assert client.get(f"{API}/storefront/s{i}").status_code == 200
        assert _store(client, "s9").status_code == 403             # only new ones blocked

    def test_an_expired_grant_falls_back_to_free(self, client):
        from warden.m2m_store import plans
        from warden.m2m_store.inventory import _conn
        assert _grant(client, "tenant-a", "store_seller", days=30).status_code == 200
        past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
        with _conn() as con:
            con.execute("UPDATE m2m_store_plans SET expires_at=? WHERE tenant_id=?",
                        (past, "tenant-a"))
        assert plans.get_plan("tenant-a").plan == "store_free"

    def test_a_row_naming_a_retired_plan_is_free_not_unlimited(self, client):
        from warden.m2m_store import plans
        from warden.m2m_store.inventory import _conn
        _grant(client, "tenant-a", "store_seller")
        with _conn() as con:
            con.execute("UPDATE m2m_store_plans SET plan='store_gone' WHERE tenant_id='tenant-a'")
        assert plans.get_plan("tenant-a").plan == "store_free"


# ── Trial ─────────────────────────────────────────────────────────────────────

class TestTrial:
    def test_trial_gives_the_paid_plan_for_a_fixed_window(self, client):
        r = client.post(f"{API}/plan/trial", headers=_as("tenant-a"))
        assert r.status_code == 201
        body = r.json()
        assert body["plan"] == "store_seller" and body["source"] == "trial"
        expires = datetime.fromisoformat(body["expires_at"])
        assert timedelta(days=13) < expires - datetime.now(UTC) <= timedelta(days=14)
        assert _store(client, "poly", locales=["en", "de", "fr", "it", "es"]).status_code == 201

    def test_the_trial_is_single_use(self, client):
        assert client.post(f"{API}/plan/trial", headers=_as("tenant-a")).status_code == 201
        assert client.post(f"{API}/plan/trial", headers=_as("tenant-a")).status_code == 409

    def test_the_trial_cannot_be_restarted_after_it_expires(self, client):
        from warden.m2m_store.inventory import _conn
        client.post(f"{API}/plan/trial", headers=_as("tenant-a"))
        past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
        with _conn() as con:
            con.execute("UPDATE m2m_store_plans SET expires_at=? WHERE tenant_id='tenant-a'",
                        (past,))
        plan = client.get(f"{API}/plan", headers=_as("tenant-a")).json()
        assert plan["plan"] == "store_free" and plan["trial_available"] is False
        assert client.post(f"{API}/plan/trial", headers=_as("tenant-a")).status_code == 409

    def test_a_refused_trial_is_not_burned(self, client):
        """A seller already on a granted plan is refused - and keeps the trial."""
        _grant(client, "tenant-a", "store_business")
        assert client.post(f"{API}/plan/trial", headers=_as("tenant-a")).status_code == 409
        assert client.get(f"{API}/plan", headers=_as("tenant-a")).json()["plan"] == "store_business"
        client.delete(f"{API}/admin/plans/tenant-a", headers={"X-Admin-Key": ADMIN})
        assert client.post(f"{API}/plan/trial", headers=_as("tenant-a")).status_code == 201

    def test_one_tenants_trial_is_not_anothers(self, client):
        assert client.post(f"{API}/plan/trial", headers=_as("tenant-a")).status_code == 201
        assert client.post(f"{API}/plan/trial", headers=_as("tenant-b")).status_code == 201


# ── Who may change a plan ─────────────────────────────────────────────────────

class TestGrantIsOperatorOnly:
    @pytest.mark.parametrize("method", ["put", "delete", "get"])
    def test_no_admin_key_is_refused(self, client, method):
        kw = {"json": {"plan": "store_business"}} if method == "put" else {}
        r = getattr(client, method)(f"{API}/admin/plans/tenant-a", headers=_as("tenant-a"), **kw)
        assert r.status_code == 403

    def test_a_wrong_admin_key_is_refused(self, client):
        r = client.put(f"{API}/admin/plans/tenant-a", json={"plan": "store_business"},
                       headers={"X-Admin-Key": "not-it"})
        assert r.status_code == 403
        assert client.get(f"{API}/plan", headers=_as("tenant-a")).json()["plan"] == "store_free"

    def test_unset_admin_key_disables_the_route_rather_than_opening_it(self, client, monkeypatch):
        monkeypatch.delenv("ADMIN_KEY")
        r = client.put(f"{API}/admin/plans/tenant-a", json={"plan": "store_business"},
                       headers={"X-Admin-Key": "anything"})
        assert r.status_code == 503

    def test_a_seller_cannot_raise_its_own_plan(self, client):
        """There is no seller-facing route that takes a plan name."""
        r = client.put(f"{API}/plan", json={"plan": "store_business"}, headers=_as("tenant-a"))
        assert r.status_code == 405
        r = client.post(f"{API}/plan/trial", json={"plan": "store_business"},
                        headers=_as("tenant-a"))
        assert r.json()["plan"] == "store_seller"          # the body is ignored

    def test_grant_validates_plan_source_and_duration(self, client):
        assert _grant(client, "tenant-a", "store_platinum").status_code == 422
        assert _grant(client, "tenant-a", "store_seller", source="subscription").status_code == 422
        assert _grant(client, "tenant-a", "store_seller", source="trial").status_code == 422
        assert _grant(client, "tenant-a", "store_seller", days=99999).status_code == 422

    def test_every_change_leaves_an_audit_row(self, client):
        _grant(client, "tenant-a", "store_seller", source="founding", days=365)
        client.delete(f"{API}/admin/plans/tenant-a", headers={"X-Admin-Key": ADMIN})
        client.post(f"{API}/plan/trial", headers=_as("tenant-a"))
        r = client.get(f"{API}/admin/plans/tenant-a", headers={"X-Admin-Key": ADMIN})
        events = [(e["event"], e["source"]) for e in r.json()["history"]]
        assert sorted(events) == sorted(
            [("granted", "founding"), ("revoked", "admin"), ("trial_started", "trial")])
