"""
FT-3 slice 3b — credit-purchase idempotency (`marketplace/credits.py` + API).

The bug: `POST /marketplace/credits/purchase` called `purchase_credits()` with no
idempotency key at all. A retried Lemon Squeezy webhook or a double-submitted
checkout call granted credits TWICE — real duplicated spendable balance, not
just a duplicate log row (worse than the clearing-log bug FT-3 slice 3a closed).
`purchase_credits(tenant_id, package_id, idempotency_key=...)` now records each
grant and returns the cached balance on replay, granting nothing new. The whole
check-then-grant-then-record sequence is serialized under the module's existing
`_db_lock` to close the race between two concurrent callers with the same key.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from warden.marketplace import credits


@pytest.fixture()
def iso(tmp_path, monkeypatch):
    monkeypatch.setattr(credits, "_DB_PATH", str(tmp_path / "mkt.db"))


class TestPurchaseCreditsIdempotency:
    def test_replay_grants_nothing_new(self, iso):
        first = credits.purchase_credits("t1", "credits_100", idempotency_key="evt-1")
        second = credits.purchase_credits("t1", "credits_100", idempotency_key="evt-1")
        assert first == 100
        assert second == 100
        assert credits.get_balance("t1") == 100   # NOT 200

    def test_different_keys_both_grant(self, iso):
        credits.purchase_credits("t1", "credits_100", idempotency_key="evt-1")
        credits.purchase_credits("t1", "credits_100", idempotency_key="evt-2")
        assert credits.get_balance("t1") == 200

    def test_no_key_keeps_old_ungated_behaviour(self, iso):
        """Callers that omit idempotency_key (direct test-seeding path) are
        unaffected — no new restriction on that call shape."""
        credits.purchase_credits("t1", "credits_100")
        credits.purchase_credits("t1", "credits_100")
        assert credits.get_balance("t1") == 200

    def test_replay_recorded_row_matches_original(self, iso):
        credits.purchase_credits("t1", "credits_1000", idempotency_key="evt-9")
        row = credits._read_purchase("evt-9")
        assert row == {
            "tenant_id": "t1", "package_id": "credits_1000",
            "credits_added": 1000, "new_balance": 1000,
        }

    def test_unknown_key_returns_none(self, iso):
        assert credits._read_purchase("nope") is None


class TestPurchaseEndpointRequiresIdempotencyKey:
    def _app(self):
        from fastapi import FastAPI

        from warden.marketplace.api import router
        app = FastAPI()
        app.include_router(router, prefix="/marketplace")
        return app

    def test_missing_header_rejected(self, iso):
        client = TestClient(self._app())
        resp = client.post("/marketplace/credits/purchase", json={"package_id": "credits_100"})
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "idempotency_key_required"
        assert credits.get_balance("unknown") == 0   # nothing granted

    def test_present_header_succeeds_and_is_idempotent(self, iso):
        client = TestClient(self._app())
        headers = {"Idempotency-Key": "evt-abc", "X-Tenant-ID": "t1"}
        r1 = client.post("/marketplace/credits/purchase",
                         json={"package_id": "credits_100"}, headers=headers)
        r2 = client.post("/marketplace/credits/purchase",
                         json={"package_id": "credits_100"}, headers=headers)
        assert r1.status_code == 200 and r2.status_code == 200
        assert r1.json()["balance"] == 100
        assert r2.json()["balance"] == 100
        assert credits.get_balance("t1") == 100   # NOT 200 — the double-grant bug
