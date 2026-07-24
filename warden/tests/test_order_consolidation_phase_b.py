"""
warden/tests/test_order_consolidation_phase_b.py
FT-6 order-model consolidation, Phase B (docs/order-model-consolidation-plan.md).

Covers: the asset_id NOT NULL -> nullable table rebuild (idempotent, data
preserving, all indexes recreated), and upsert_mirrored_order() (insert,
upsert-on-conflict, price_paid never clobbered by a later status-only call).
"""
from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

import pytest

from warden.db.ddl_registry import ensure_schema
from warden.marketplace import listing


@pytest.fixture()
def db_path(tmp_path):
    return str(tmp_path / "mkt_phase_b.db")


class TestAssetIdRebuild:
    def test_rebuild_makes_asset_id_nullable(self, db_path):
        with listing._conn(db_path) as con:
            info = con.execute("PRAGMA table_info(marketplace_purchases)").fetchall()
        asset_id_row = next(r for r in info if r[1] == "asset_id")
        assert asset_id_row[3] == 0   # notnull flag

    def test_existing_rows_preserved_across_rebuild(self, db_path):
        con = sqlite3.connect(db_path)
        ensure_schema(con, "marketplace", db_path)
        now = datetime.now(UTC).isoformat()
        con.execute(
            "INSERT INTO marketplace_purchases "
            "(purchase_id, listing_id, asset_id, buyer_agent, seller_agent, "
            " price_paid, status, purchased_at) VALUES (?,?,?,?,?,?,?,?)",
            ("p-1", "lst-1", "asset-1", "buyer-1", "seller-1", 42.5, "completed", now),
        )
        con.commit()
        con.close()

        with listing._conn(db_path) as con:
            row = con.execute(
                "SELECT purchase_id, listing_id, asset_id, buyer_agent, seller_agent, "
                "price_paid, status, purchased_at FROM marketplace_purchases WHERE purchase_id='p-1'"
            ).fetchone()
        assert tuple(row) == ("p-1", "lst-1", "asset-1", "buyer-1", "seller-1", 42.5, "completed", now)

    def test_null_asset_id_insert_succeeds_after_rebuild(self, db_path):
        with listing._conn(db_path) as con:
            con.execute(
                "INSERT INTO marketplace_purchases "
                "(purchase_id, listing_id, asset_id, buyer_agent, seller_agent, "
                " price_paid, status, purchased_at) VALUES (?,?,?,?,?,?,?,?)",
                ("p-null", "", None, "buyer-1", "", 5.0, "pending", "2026-01-01T00:00:00Z"),
            )
            row = con.execute(
                "SELECT asset_id FROM marketplace_purchases WHERE purchase_id='p-null'"
            ).fetchone()
        assert row[0] is None

    def test_rebuild_is_idempotent(self, db_path):
        with listing._conn(db_path):
            pass
        with listing._conn(db_path):
            pass   # second run must not raise (asset_id already nullable, short-circuits)
        with listing._conn(db_path) as con:
            n = con.execute("SELECT COUNT(*) FROM marketplace_purchases").fetchone()[0]
        assert n == 0

    def test_all_indexes_recreated_after_rebuild(self, db_path):
        with listing._conn(db_path) as con:
            names = {
                row[0] for row in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='marketplace_purchases'"
                )
            }
        for expected in (
            "idx_mp_buyer", "idx_mp_seller", "idx_mp_listing",
            "idx_mp_idempotency_key", "idx_mp_domain", "idx_mp_tenant",
        ):
            assert expected in names, f"missing index: {expected}"


class TestUpsertMirroredOrder:
    def test_insert_creates_row(self, db_path):
        listing.upsert_mirrored_order(
            "m2m_store", "ord-1", buyer_agent="buyer-1", asset_id="prod-1",
            price_paid=9.99, status="PAID", db_path=db_path,
        )
        with listing._conn(db_path) as con:
            row = con.execute(
                "SELECT domain, buyer_agent, asset_id, price_paid, status "
                "FROM marketplace_purchases WHERE purchase_id='ord-1'"
            ).fetchone()
        assert tuple(row) == ("m2m_store", "buyer-1", "prod-1", 9.99, "PAID")

    def test_second_call_updates_status_without_clobbering_price(self, db_path):
        listing.upsert_mirrored_order(
            "m2m_store", "ord-2", buyer_agent="buyer-1", asset_id="prod-1",
            price_paid=15.0, status="PAID", db_path=db_path,
        )
        listing.upsert_mirrored_order(
            "m2m_store", "ord-2", status="SHIPPED", shipped_at="2026-01-02T00:00:00Z",
            db_path=db_path,
        )
        with listing._conn(db_path) as con:
            row = con.execute(
                "SELECT price_paid, status, shipped_at FROM marketplace_purchases WHERE purchase_id='ord-2'"
            ).fetchone()
        assert row[0] == 15.0   # price NOT clobbered to the default 0.0
        assert row[1] == "SHIPPED"
        assert row[2] == "2026-01-02T00:00:00Z"

    def test_receipt_json_update_preserves_earlier_metadata(self, db_path):
        listing.upsert_mirrored_order(
            "agentic_commerce", "ord-3", price_paid=20.0, status="PENDING",
            metadata_json='{"store_url": "https://x.example"}', db_path=db_path,
        )
        listing.upsert_mirrored_order(
            "agentic_commerce", "ord-3", status="PAID",
            receipt_json='{"receipt_id": "r-1"}', db_path=db_path,
        )
        with listing._conn(db_path) as con:
            row = con.execute(
                "SELECT status, receipt_json, metadata_json FROM marketplace_purchases WHERE purchase_id='ord-3'"
            ).fetchone()
        assert row[0] == "PAID"
        assert row[1] == '{"receipt_id": "r-1"}'
        assert row[2] == '{"store_url": "https://x.example"}'   # not clobbered by the receipt-only call

    def test_mirror_failure_does_not_raise(self, monkeypatch, db_path):
        """Fail-soft: mirror is best-effort, never propagates to the caller."""
        import warden.marketplace.listing as listing_mod
        def _boom(*a, **kw):
            raise RuntimeError("db exploded")
        monkeypatch.setattr(listing_mod, "_conn", _boom)
        listing.upsert_mirrored_order("m2m_store", "ord-4", db_path=db_path)   # must not raise


class TestM2mStoreMirror:
    def test_save_order_mirrors_to_marketplace(self, tmp_path, monkeypatch):
        import warden.m2m_store.inventory as inv_mod
        from warden.m2m_store.models import Order

        m2m_db = str(tmp_path / "m2m.db")
        mkt_db = str(tmp_path / "mkt.db")
        monkeypatch.setattr(inv_mod, "_get_db_path", lambda: m2m_db)
        monkeypatch.setattr(listing, "_DB_PATH", mkt_db)

        mgr = inv_mod.InventoryManager()
        order = Order(
            id="m2m-1", agent_id="buyer-9", offer_id="off-1", product_id="prod-9",
            mandate_id="mnd-1", qty=2, total=19.98, status="PAID",
            tenant_id="tenant-9", stix_chain_id="stix-1",
        )
        mgr.save_order(order)

        with listing._conn(mkt_db) as con:
            row = con.execute(
                "SELECT domain, buyer_agent, asset_id, price_paid, status, tenant_id, mandate_id, stix_chain_id "
                "FROM marketplace_purchases WHERE purchase_id='m2m-1'"
            ).fetchone()
        assert tuple(row) == ("m2m_store", "buyer-9", "prod-9", 19.98, "PAID", "tenant-9", "mnd-1", "stix-1")


class TestAgenticCommerceMirror:
    def test_save_order_mirrors_with_null_asset_id(self, tmp_path, monkeypatch):
        import warden.business_community.agentic_commerce.service as svc_mod
        from warden.business_community.agentic_commerce.models import PurchaseOrder

        commerce_db = str(tmp_path / "commerce.db")
        mkt_db = str(tmp_path / "mkt.db")
        monkeypatch.setattr(svc_mod, "_DB_PATH", commerce_db)
        monkeypatch.setattr(listing, "_DB_PATH", mkt_db)

        svc = svc_mod.AgenticCommerceService.__new__(svc_mod.AgenticCommerceService)
        order = PurchaseOrder(
            id="cm-1", tenant_id="tenant-5", store_url="https://merchant.example",
            total=50.0, mandate_id="mnd-5", status="PENDING",
        )
        svc._save_order(order)

        with listing._conn(mkt_db) as con:
            row = con.execute(
                "SELECT domain, asset_id, price_paid, status, tenant_id "
                "FROM marketplace_purchases WHERE purchase_id='cm-1'"
            ).fetchone()
        assert tuple(row) == ("agentic_commerce", None, 50.0, "PENDING", "tenant-5")
