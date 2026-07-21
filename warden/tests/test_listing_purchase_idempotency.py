"""
FT-3 slice 3c — listing-purchase idempotency (`marketplace/listing.py` + API).

The bug: purchase_listing() had no idempotency key. A retried POST /purchase
(double-submit, webhook retry) created a SECOND purchase record AND a second
escrow for the same buyer intent on the same listing — a real double-charge,
not just a duplicate log row. purchase_listing(..., idempotency_key=...) now
records the key on the purchase row (partial-unique index) and returns the
original response unchanged on replay.
"""
from __future__ import annotations

import os
import sqlite3
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from warden.db.ddl_registry import ensure_schema
from warden.marketplace import listing


@pytest.fixture()
def db(tmp_path):
    path = str(tmp_path / "mkt.db")
    con = sqlite3.connect(path)
    ensure_schema(con, "marketplace", path)
    now = datetime.now(UTC).isoformat()
    con.execute(
        """INSERT INTO marketplace_listings
           (listing_id, asset_id, seller_agent, community_id, tenant_id,
            asset_type, price_usd, currency, pricing_strategy, status,
            demand_score, listed_at, chain)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        ("lst-1", "asset-1", "seller-1", "cid", "tenant-1",
         "rule", 9.99, "USD", "fixed", "active", 0.5, now, "sepolia"),
    )
    con.commit()
    con.close()
    return path


class TestPurchaseIdempotency:
    def test_replay_creates_no_second_purchase(self, db):
        first = listing.purchase_listing("lst-1", "buyer-1", db_path=db, idempotency_key="evt-1")
        second = listing.purchase_listing("lst-1", "buyer-1", db_path=db, idempotency_key="evt-1")

        assert second["purchase_id"] == first["purchase_id"]
        assert second["replayed"] is True
        assert first["replayed"] is False

        con = sqlite3.connect(db)
        n = con.execute(
            "SELECT COUNT(*) FROM marketplace_purchases WHERE listing_id='lst-1'"
        ).fetchone()[0]
        con.close()
        assert n == 1   # exactly one purchase row, not two

    def test_replay_response_matches_original(self, db):
        first = listing.purchase_listing("lst-1", "buyer-1", db_path=db, idempotency_key="evt-2")
        second = listing.purchase_listing("lst-1", "buyer-1", db_path=db, idempotency_key="evt-2")
        assert second["price_paid"] == first["price_paid"]
        assert second["escrow_id"] == first["escrow_id"]
        assert second["asset_type"] == first["asset_type"] == "rule"

    def test_different_keys_are_independent(self, db):
        con = sqlite3.connect(db)
        now = datetime.now(UTC).isoformat()
        con.execute(
            """INSERT INTO marketplace_listings
               (listing_id, asset_id, seller_agent, community_id, tenant_id,
                asset_type, price_usd, currency, pricing_strategy, status,
                demand_score, listed_at, chain)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("lst-2", "asset-2", "seller-1", "cid", "tenant-1",
             "rule", 4.99, "USD", "fixed", "active", 0.5, now, "sepolia"),
        )
        con.commit()
        con.close()

        a = listing.purchase_listing("lst-1", "buyer-1", db_path=db, idempotency_key="evt-a")
        b = listing.purchase_listing("lst-2", "buyer-1", db_path=db, idempotency_key="evt-b")
        assert a["purchase_id"] != b["purchase_id"]
        assert a["replayed"] is False and b["replayed"] is False

    def test_missing_listing_raises_before_any_write(self, db):
        with pytest.raises(ValueError, match="not found"):
            listing.purchase_listing("nope", "buyer-1", db_path=db, idempotency_key="evt-4")
        assert listing.get_purchase_by_idempotency_key("evt-4", db_path=db) is None

    def test_no_key_keeps_old_behaviour(self, db):
        r1 = listing.purchase_listing("lst-1", "buyer-1", db_path=db)
        r2 = listing.purchase_listing("lst-1", "buyer-1", db_path=db)
        assert r1["purchase_id"] != r2["purchase_id"]   # unaffected, pre-existing shape


class TestPurchaseEndpointRequiresIdempotencyKey:
    """purchase_listing()'s db_path defaults to _DB_PATH, bound at import time —
    the endpoint calls it with no db_path override. Reload both modules AFTER
    setting the env var so the default re-binds to this test's tmp DB,
    regardless of what an earlier test file imported them with. Reload again on
    teardown to undo the process-global mutation — a bare reload with no
    restore would leak this test's DB path into every test that runs after it
    in the same session."""

    @pytest.fixture(autouse=True)
    def _app_module_state(self):
        import importlib

        from warden.marketplace import api_listings
        from warden.marketplace import listing as listing_mod
        original_path = os.environ.get("MARKETPLACE_DB_PATH")
        yield
        if original_path is None:
            os.environ.pop("MARKETPLACE_DB_PATH", None)
        else:
            os.environ["MARKETPLACE_DB_PATH"] = original_path
        importlib.reload(listing_mod)
        importlib.reload(api_listings)

    def _app(self, db_path: str, monkeypatch):
        import importlib
        monkeypatch.setenv("MARKETPLACE_DB_PATH", db_path)
        from warden.marketplace import api_listings
        from warden.marketplace import listing as listing_mod
        importlib.reload(listing_mod)
        importlib.reload(api_listings)

        from fastapi import FastAPI
        app = FastAPI()
        app.include_router(api_listings.router, prefix="/marketplace")
        return app

    def test_missing_header_rejected(self, db, monkeypatch):
        client = TestClient(self._app(db, monkeypatch))
        resp = client.post("/marketplace/listings/lst-1/purchase",
                           json={"buyer_agent_id": "buyer-1"})
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "idempotency_key_required"

    def test_present_header_is_idempotent(self, db, monkeypatch):
        client = TestClient(self._app(db, monkeypatch))
        headers = {"Idempotency-Key": "evt-http-1"}
        r1 = client.post("/marketplace/listings/lst-1/purchase",
                         json={"buyer_agent_id": "buyer-1"}, headers=headers)
        r2 = client.post("/marketplace/listings/lst-1/purchase",
                         json={"buyer_agent_id": "buyer-1"}, headers=headers)
        assert r1.status_code == 201
        assert r1.json()["purchase_id"] == r2.json()["purchase_id"]
