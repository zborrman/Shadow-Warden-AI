"""
SR-7.2 — end-to-end coverage for the GDPR REST endpoints (warden/api/gdpr.py).

test_gdpr_idor.py pins the authorization *dependencies*; this file drives the
endpoint bodies through a TestClient so the Art. 17 / 20 erasure + export flows,
the audit trail, retention policy and the cron retention purge are exercised.

Dev-mode auth (conftest: ALLOW_UNAUTHENTICATED=true, WARDEN_API_KEY="") resolves
every caller to tenant "default", so tenant-scoped paths use "default"; the
admin-only bulk purge is driven with an X-Admin-Key.
"""
from __future__ import annotations

import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    import warden.analytics.logger as lg
    from warden.api.gdpr import router

    # Point the logger at an isolated NDJSON file the endpoints will read/rewrite.
    logs = tmp_path / "logs.json"
    monkeypatch.setattr(lg, "LOGS_PATH", logs)

    app = FastAPI()
    app.include_router(router)
    return TestClient(app), logs


def _seed(logs, rows):
    logs.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


# ── Session purge (Art. 17) ────────────────────────────────────────────────────

class TestPurgeSession:
    def test_purge_removes_matching_log_lines(self, client):
        c, logs = client
        sid = "abcdef1234567890"
        _seed(logs, [
            {"request_id": sid[:8] + "-1", "tenant_id": "default"},
            {"request_id": "other999", "tenant_id": "default"},
        ])
        r = c.delete(f"/gdpr/purge/session/{sid}")
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["records_removed"] >= 1
        # The non-matching line survives.
        assert "other999" in logs.read_text()

    def test_purge_missing_logs_is_still_ok(self, client):
        c, _logs = client
        r = c.delete("/gdpr/purge/session/no-such-session")
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_malformed_log_line_is_kept(self, client):
        """A corrupt NDJSON line must be preserved, not dropped, during purge."""
        c, logs = client
        logs.write_text('{ not json\n{"request_id":"other","tenant_id":"default"}\n', encoding="utf-8")
        r = c.delete("/gdpr/purge/session/abcdef12")
        assert r.status_code == 200
        assert "not json" in logs.read_text()   # malformed line survived

    def test_purge_clears_minio_and_redis(self, client, monkeypatch):
        """The MinIO evidence + Redis ERS best-effort branches both run."""
        c, logs = client
        _seed(logs, [{"request_id": "zzz", "tenant_id": "default"}])

        class _Storage:
            async def put_object_async(self, bucket, key, data):
                return True

        class _Redis:
            def keys(self, pattern):
                return ["warden:ers:k1", "warden:ers:k2"]

            def delete(self, *keys):
                return len(keys)

        import warden.cache as cache
        import warden.storage.s3 as s3
        monkeypatch.setattr(s3, "get_storage", lambda: _Storage())
        monkeypatch.setattr(cache, "_get_client", lambda: _Redis())
        r = c.delete("/gdpr/purge/session/session-with-evidence")
        assert r.status_code == 200
        assert r.json()["records_removed"] >= 3   # 1 MinIO + 2 Redis keys


# ── Export (Art. 20) ───────────────────────────────────────────────────────────

class TestExportSession:
    def test_export_returns_record(self, client, monkeypatch):
        import warden.analytics.logger as lg
        c, _ = client
        monkeypatch.setattr(lg, "read_by_request_id", lambda rid: {"request_id": rid, "risk": "low"})
        r = c.get("/gdpr/export/session/sess-xyz")
        assert r.status_code == 200
        assert r.json()["record"]["request_id"] == "sess-xyz"

    def test_export_survives_logger_error(self, client, monkeypatch):
        import warden.analytics.logger as lg
        c, _ = client

        def _boom(_rid):
            raise RuntimeError("read failed")

        monkeypatch.setattr(lg, "read_by_request_id", _boom)
        r = c.get("/gdpr/export/session/sess-xyz")
        assert r.status_code == 200
        assert r.json()["record"] is None      # fail-open: no crash


# ── Bulk purge before date (admin-only) ────────────────────────────────────────

class TestPurgeBeforeDate:
    def test_admin_can_bulk_purge(self, client, monkeypatch):
        import warden.analytics.logger as lg
        c, _ = client
        monkeypatch.setenv("ADMIN_KEY", "admin-secret")
        monkeypatch.setattr(lg, "purge_before", lambda dt: 7)
        r = c.delete("/gdpr/purge/before/2026-01-01", headers={"X-Admin-Key": "admin-secret"})
        assert r.status_code == 200
        assert r.json()["records_removed"] == 7

    def test_non_admin_forbidden(self, client, monkeypatch):
        c, _ = client
        monkeypatch.delenv("ADMIN_KEY", raising=False)
        r = c.delete("/gdpr/purge/before/2026-01-01")
        assert r.status_code == 403

    def test_invalid_date_is_422(self, client, monkeypatch):
        c, _ = client
        monkeypatch.setenv("ADMIN_KEY", "admin-secret")
        r = c.delete("/gdpr/purge/before/not-a-date", headers={"X-Admin-Key": "admin-secret"})
        assert r.status_code == 422

    def test_logger_error_is_500(self, client, monkeypatch):
        import warden.analytics.logger as lg
        c, _ = client
        monkeypatch.setenv("ADMIN_KEY", "admin-secret")

        def _boom(_dt):
            raise RuntimeError("disk gone")

        monkeypatch.setattr(lg, "purge_before", _boom)
        r = c.delete("/gdpr/purge/before/2026-01-01", headers={"X-Admin-Key": "admin-secret"})
        assert r.status_code == 500


# ── Tenant purge (own-tenant) ──────────────────────────────────────────────────

class TestPurgeTenant:
    def test_own_tenant_purge(self, client):
        c, logs = client
        _seed(logs, [
            {"request_id": "a", "tenant_id": "default"},
            {"request_id": "b", "tenant_id": "someone-else"},
        ])
        r = c.delete("/gdpr/purge/tenant/default")
        assert r.status_code == 200
        assert r.json()["records_removed"] == 1
        # Other tenant's line is preserved.
        assert "someone-else" in logs.read_text()

    def test_cross_tenant_forbidden(self, client, monkeypatch):
        c, _ = client
        monkeypatch.delenv("ADMIN_KEY", raising=False)
        r = c.delete("/gdpr/purge/tenant/victim-corp")
        assert r.status_code == 403

    def test_tenant_purge_keeps_malformed_lines_and_clears_redis(self, client, monkeypatch):
        c, logs = client
        logs.write_text(
            '{ bad line\n{"request_id":"a","tenant_id":"default"}\n', encoding="utf-8"
        )

        class _Redis:
            def scan_iter(self, pattern):
                yield "warden:ers:x"

            def delete(self, key):
                return 1

        import warden.cache as cache
        monkeypatch.setattr(cache, "_get_client", lambda: _Redis())
        r = c.delete("/gdpr/purge/tenant/default")
        assert r.status_code == 200
        assert "bad line" in logs.read_text()      # malformed line preserved


# ── Retention policy + audit trail ─────────────────────────────────────────────

class TestPolicyAndAudit:
    def test_retention_policy(self, client):
        c, _ = client
        r = c.get("/gdpr/retention-policy")
        assert r.status_code == 200
        assert "log_retention_days" in r.json()

    def test_audit_lists_recorded_operations(self, client):
        c, logs = client
        _seed(logs, [{"request_id": "x", "tenant_id": "default"}])
        # Perform an auditable op first, then read the trail for the same tenant.
        c.delete("/gdpr/purge/tenant/default")
        r = c.get("/gdpr/audit/default")
        assert r.status_code == 200
        assert r.json()["tenant_id"] == "default"
        assert isinstance(r.json()["operations"], list)

    def test_audit_cross_tenant_forbidden(self, client, monkeypatch):
        c, _ = client
        monkeypatch.delenv("ADMIN_KEY", raising=False)
        r = c.get("/gdpr/audit/other-tenant")
        assert r.status_code == 403

    def test_audit_trail_is_capped(self, monkeypatch):
        """The in-memory audit trail must not grow unbounded (ring-buffer at _AUDIT_CAP)."""
        import warden.api.gdpr as g
        monkeypatch.setattr(g, "_audit", [])
        for i in range(g._AUDIT_CAP + 50):
            g._record_audit("op", f"subject-{i}")
        assert len(g._audit) == g._AUDIT_CAP


# ── POST export / purge (request-id variants) ──────────────────────────────────

class TestPostVariants:
    def test_post_export_found(self, client, monkeypatch):
        import warden.api.gdpr as g
        c, _ = client
        monkeypatch.setattr(g.event_logger, "read_by_request_id", lambda rid: {"id": rid})
        r = c.post("/gdpr/export", json={"request_id": "req-1"})
        assert r.status_code == 200
        assert r.json()["entry"]["id"] == "req-1"

    def test_post_export_not_found_is_404(self, client, monkeypatch):
        import warden.api.gdpr as g
        c, _ = client
        monkeypatch.setattr(g.event_logger, "read_by_request_id", lambda rid: None)
        r = c.post("/gdpr/export", json={"request_id": "ghost"})
        assert r.status_code == 404

    def test_post_purge_valid(self, client, monkeypatch):
        import warden.api.gdpr as g
        c, _ = client
        monkeypatch.setattr(g.event_logger, "purge_before", lambda dt: 4)
        r = c.post("/gdpr/purge", json={"before": "2026-01-01T00:00:00Z"})
        assert r.status_code == 200
        assert r.json()["removed"] == 4

    def test_post_purge_invalid_date_is_422(self, client):
        c, _ = client
        r = c.post("/gdpr/purge", json={"before": "nonsense"})
        assert r.status_code == 422


# ── Cron retention purge ───────────────────────────────────────────────────────

class TestRunRetentionPurge:
    @pytest.mark.asyncio
    async def test_run_retention_purge_success(self, monkeypatch):
        import warden.analytics.logger as lg
        import warden.api.gdpr as g
        monkeypatch.setattr(lg, "purge_old_entries", lambda: 12)
        assert await g.run_retention_purge() == 12

    @pytest.mark.asyncio
    async def test_run_retention_purge_failure_returns_zero(self, monkeypatch):
        import warden.analytics.logger as lg
        import warden.api.gdpr as g

        def _boom():
            raise RuntimeError("logger down")

        monkeypatch.setattr(lg, "purge_old_entries", _boom)
        assert await g.run_retention_purge() == 0
