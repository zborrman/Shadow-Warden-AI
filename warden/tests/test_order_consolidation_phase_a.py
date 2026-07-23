"""
warden/tests/test_order_consolidation_phase_a.py
FT-6 order-model consolidation, Phase A (docs/order-model-consolidation-plan.md).

Pins the additive schema migration: nine new nullable columns on
marketplace_purchases, `domain` defaulting to 'marketplace' for every
pre-existing and newly-created row, and idempotent re-application (running
the migration twice must not error or duplicate columns/indexes).
"""
from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

import pytest

from warden.db.ddl_registry import ensure_schema
from warden.marketplace import listing


@pytest.fixture()
def db_path(tmp_path):
    return str(tmp_path / "mkt_phase_a.db")


class TestOrderConsolidationColumns:
    def test_fresh_db_gets_new_columns_via_conn(self, db_path):
        with listing._conn(db_path) as con:
            cols = {row[1] for row in con.execute("PRAGMA table_info(marketplace_purchases)")}
        for col in (
            "domain", "tenant_id", "mandate_id", "payment_token",
            "reservation_id", "stix_chain_id", "shipped_at",
            "receipt_json", "metadata_json",
        ):
            assert col in cols, f"missing column: {col}"

    def test_existing_row_defaults_domain_to_marketplace(self, db_path):
        con = sqlite3.connect(db_path)
        ensure_schema(con, "marketplace", db_path)
        now = datetime.now(UTC).isoformat()
        con.execute(
            "INSERT INTO marketplace_purchases "
            "(purchase_id, listing_id, asset_id, buyer_agent, seller_agent, "
            " price_paid, status, purchased_at) VALUES (?,?,?,?,?,?,?,?)",
            ("p-1", "lst-1", "asset-1", "buyer-1", "seller-1", 9.99, "completed", now),
        )
        con.commit()
        con.close()

        with listing._conn(db_path) as con:
            row = con.execute(
                "SELECT domain, tenant_id, mandate_id FROM marketplace_purchases WHERE purchase_id='p-1'"
            ).fetchone()
        assert row[0] == "marketplace"
        assert row[1] is None
        assert row[2] is None

    def test_migration_is_idempotent(self, db_path):
        with listing._conn(db_path):
            pass
        # Second connection re-runs every _migrate_* function; must not raise.
        with listing._conn(db_path) as con:
            cols = [row[1] for row in con.execute("PRAGMA table_info(marketplace_purchases)")]
        assert cols.count("domain") == 1

    def test_domain_and_tenant_indexes_exist(self, db_path):
        with listing._conn(db_path) as con:
            names = {
                row[0] for row in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='marketplace_purchases'"
                )
            }
        assert "idx_mp_domain" in names
        assert "idx_mp_tenant" in names

    def test_new_columns_are_nullable_except_domain(self, db_path):
        with listing._conn(db_path) as con:
            con.execute(
                "INSERT INTO marketplace_purchases "
                "(purchase_id, listing_id, asset_id, buyer_agent, seller_agent, "
                " price_paid, status, purchased_at, tenant_id, mandate_id, "
                " payment_token, reservation_id, stix_chain_id, shipped_at, "
                " receipt_json, metadata_json) "
                "VALUES ('p-2','lst-2','asset-2','buyer-2','seller-2',1.0,'pending',"
                "'2026-01-01T00:00:00Z',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)"
            )
            row = con.execute(
                "SELECT domain FROM marketplace_purchases WHERE purchase_id='p-2'"
            ).fetchone()
        assert row[0] == "marketplace"   # DEFAULT applies when column omitted, but explicit NULL insert above didn't include it
