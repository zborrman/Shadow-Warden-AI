"""Tests for DataLifecycleManager (Phase 4-10)."""
import os
from datetime import UTC, datetime

import pytest


@pytest.fixture()
def lcm(tmp_path):
    from warden.marketplace.data_lifecycle import DataLifecycleManager
    return DataLifecycleManager(
        lifecycle_db=str(tmp_path / "lifecycle.db"),
        marketplace_db=str(tmp_path / "marketplace.db"),
    )


class TestRegistration:
    def test_register_negotiation_default_ttl(self, lcm):
        entry = lcm.register_entity("negotiation", "neg-001")
        assert entry.entity_type == "negotiation"
        assert entry.entity_id == "neg-001"
        assert not entry.purged
        expires = datetime.fromisoformat(entry.expires_at)
        now = datetime.now(UTC)
        # Should be ~90 days
        assert (expires - now).days >= 89

    def test_register_escrow_default_ttl(self, lcm):
        entry = lcm.register_entity("escrow", "esc-001")
        expires = datetime.fromisoformat(entry.expires_at)
        now = datetime.now(UTC)
        assert (expires - now).days >= 365 * 6  # ~7 years

    def test_register_custom_ttl(self, lcm):
        entry = lcm.register_entity("negotiation", "neg-002", ttl_days=5)
        expires = datetime.fromisoformat(entry.expires_at)
        now = datetime.now(UTC)
        assert (expires - now).days <= 5

    def test_register_idempotent(self, lcm):
        lcm.register_entity("negotiation", "neg-003")
        lcm.register_entity("negotiation", "neg-003")  # no-op INSERT OR IGNORE
        expired = lcm.check_expired()
        assert sum(1 for e in expired if e.entity_id == "neg-003") == 0


class TestCheckExpired:
    def test_not_expired_returns_empty(self, lcm):
        lcm.register_entity("negotiation", "neg-future", ttl_days=365)
        expired = lcm.check_expired()
        ids = [e.entity_id for e in expired]
        assert "neg-future" not in ids

    def test_expired_appears(self, lcm, monkeypatch):
        lcm.register_entity("negotiation", "neg-past", ttl_days=1)
        # Override expires_at to past
        import sqlite3
        con = sqlite3.connect(lcm.lifecycle_db)
        con.execute(
            "UPDATE mkt_data_lifecycle SET expires_at=? WHERE entity_id=?",
            ("2000-01-01T00:00:00+00:00", "neg-past"),
        )
        con.commit()
        con.close()

        expired = lcm.check_expired()
        ids = [e.entity_id for e in expired]
        assert "neg-past" in ids

    def test_already_purged_excluded(self, lcm):
        lcm.register_entity("negotiation", "neg-purged", ttl_days=1)
        import sqlite3
        con = sqlite3.connect(lcm.lifecycle_db)
        con.execute(
            "UPDATE mkt_data_lifecycle SET expires_at=?, purged=1 WHERE entity_id=?",
            ("2000-01-01T00:00:00+00:00", "neg-purged"),
        )
        con.commit()
        con.close()
        expired = lcm.check_expired()
        ids = [e.entity_id for e in expired]
        assert "neg-purged" not in ids


class TestPurge:
    def _expire(self, lcm, entity_type, entity_id):
        """Helper: register + immediately expire entry."""
        lcm.register_entity(entity_type, entity_id, ttl_days=1)
        import sqlite3
        con = sqlite3.connect(lcm.lifecycle_db)
        con.execute(
            "UPDATE mkt_data_lifecycle SET expires_at=? WHERE entity_id=?",
            ("2000-01-01T00:00:00+00:00", entity_id),
        )
        con.commit()
        con.close()

    def test_purge_marks_as_purged(self, lcm):
        self._expire(lcm, "negotiation", "neg-x")
        result = lcm.purge_expired()
        assert result["total"] >= 1
        # Should not appear in check_expired any more
        expired = lcm.check_expired()
        assert all(e.entity_id != "neg-x" for e in expired)

    def test_purge_returns_counts_by_type(self, lcm):
        self._expire(lcm, "negotiation", "neg-a")
        self._expire(lcm, "negotiation", "neg-b")
        self._expire(lcm, "escrow", "esc-a")
        result = lcm.purge_expired()
        assert result["purged"].get("negotiation", 0) >= 2
        assert result["purged"].get("escrow", 0) >= 1

    def test_purge_empty_returns_zero(self, lcm):
        result = lcm.purge_expired()
        assert result["total"] == 0

    def test_unknown_type_still_marks_purged(self, lcm):
        """Unknown entity types have no content purge but are still marked done."""
        self._expire(lcm, "unknown_type", "unk-1")
        result = lcm.purge_expired()
        assert result["total"] >= 1


class TestAdminEndpoint:
    def test_purge_endpoint(self, tmp_path):
        os.environ["LIFECYCLE_DB_PATH"] = str(tmp_path / "lc.db")
        os.environ["MARKETPLACE_DB_PATH"] = str(tmp_path / "mkt.db")

        # Reset singleton
        import warden.marketplace.data_lifecycle as dlm
        dlm._mgr = None

        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from warden.marketplace.data_lifecycle import router
        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)
        resp = client.post("/admin/data-lifecycle/purge")
        assert resp.status_code == 200
        body = resp.json()
        assert "purged" in body
        assert "total" in body

    def test_expired_endpoint(self, tmp_path):
        os.environ["LIFECYCLE_DB_PATH"] = str(tmp_path / "lc2.db")
        os.environ["MARKETPLACE_DB_PATH"] = str(tmp_path / "mkt2.db")

        import warden.marketplace.data_lifecycle as dlm
        dlm._mgr = None

        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from warden.marketplace.data_lifecycle import router
        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)
        resp = client.get("/admin/data-lifecycle/expired")
        assert resp.status_code == 200
        body = resp.json()
        assert "expired" in body
        assert "count" in body
