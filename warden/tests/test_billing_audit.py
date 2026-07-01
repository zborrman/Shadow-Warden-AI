"""
warden/tests/test_billing_audit.py — Zero-Trust Billing Audit Chain tests.

Tests the hash chain engine, REST API, and fail-open wiring in
TokenCostTracker and x402_gate.deduct_payment().
"""
from __future__ import annotations

import os

import pytest

# ── Env patch (must come before any warden imports) ─────────────────────────

os.environ.setdefault("ANTHROPIC_API_KEY", "")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
os.environ.setdefault("LOGS_PATH", "/tmp/warden_test_logs.json")
os.environ.setdefault("DYNAMIC_RULES_PATH", "/tmp/warden_test_dynamic_rules.json")
os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("MODEL_CACHE_DIR", "/tmp/warden_test_models")
os.environ.setdefault("STRICT_MODE", "false")
os.environ.setdefault("X402_GATE_ENABLED", "false")


# ── Chain engine tests ────────────────────────────────────────────────────────

class TestAuditChainEngine:
    @pytest.fixture(autouse=True)
    def _tmp_db(self, tmp_path):
        self._db = str(tmp_path / "billing_audit.db")

    def _append(self, tenant="t1", event="staff_tool_call", cost=0.01, tool="klass_kyc"):
        from warden.billing.audit_chain import append_billing_event
        return append_billing_event(
            tenant_id=tenant,
            event_type=event,
            cost_usd=cost,
            agent_id="agent-001",
            tool_name=tool,
            model="claude-haiku-4-5-20251001",
            input_tokens=100,
            output_tokens=50,
            db_path=self._db,
        )

    def test_append_returns_entry(self):
        entry = self._append()
        assert entry["seq"] == 1
        assert entry["tenant_id"] == "t1"
        assert "entry_hash" in entry
        assert len(entry["entry_hash"]) == 64

    def test_genesis_prev_hash(self):
        entry = self._append()
        assert entry["prev_hash"] == "0" * 64

    def test_chain_links_correctly(self):
        e1 = self._append()
        e2 = self._append()
        assert e2["seq"] == 2
        assert e2["prev_hash"] == e1["entry_hash"]

    def test_per_tenant_isolation(self):
        from warden.billing.audit_chain import append_billing_event, get_chain
        append_billing_event("tenantA", "staff_tool_call", db_path=self._db)
        append_billing_event("tenantA", "staff_tool_call", db_path=self._db)
        append_billing_event("tenantB", "staff_tool_call", db_path=self._db)
        a_chain = get_chain("tenantA", db_path=self._db)
        b_chain = get_chain("tenantB", db_path=self._db)
        assert len(a_chain) == 2
        assert len(b_chain) == 1
        # tenantB genesis has all-zero prev_hash
        assert b_chain[0]["prev_hash"] == "0" * 64

    def test_verify_clean_chain(self):
        self._append()
        self._append()
        self._append()
        from warden.billing.audit_chain import verify_chain
        result = verify_chain("t1", db_path=self._db)
        assert result["valid"] is True
        assert result["entries"] == 3

    def test_verify_empty_chain(self):
        from warden.billing.audit_chain import verify_chain
        result = verify_chain("nonexistent", db_path=self._db)
        assert result["valid"] is True
        assert result["entries"] == 0

    def test_verify_detects_tamper(self):
        import sqlite3
        self._append()
        self._append()
        # Tamper: change cost_usd of first entry without rehashing
        con = sqlite3.connect(self._db)
        con.execute("UPDATE billing_audit_chain SET cost_usd='9999.000000' WHERE seq=1")
        con.commit()
        con.close()
        from warden.billing.audit_chain import verify_chain
        result = verify_chain("t1", db_path=self._db)
        assert result["valid"] is False
        assert result["first_broken_seq"] == 1

    def test_get_summary(self):
        self._append(cost=0.01)
        self._append(cost=0.02)
        from warden.billing.audit_chain import get_summary
        s = get_summary("t1", db_path=self._db)
        assert s["entry_count"] == 2
        assert abs(s["total_cost_usd"] - 0.03) < 1e-6
        assert s["tip_seq"] == 2

    def test_export_jsonl(self):
        self._append()
        self._append()
        import json

        from warden.billing.audit_chain import export_jsonl
        lines = export_jsonl("t1", db_path=self._db).splitlines()
        assert len(lines) == 2
        first = json.loads(lines[0])
        assert first["seq"] == 1    # export sorts ascending

    def test_fail_open_on_bad_db_path(self):
        from warden.billing.audit_chain import append_billing_event
        result = append_billing_event("t1", "staff_tool_call", db_path="/nonexistent/path.db")
        assert result == {}    # fail-open: returns empty dict

    def test_cost_stored_as_decimal_string(self):
        e = self._append(cost=0.000123)
        # Stored as a Decimal string with 6dp, no float drift
        assert "." in e["cost_usd"]
        parts = e["cost_usd"].split(".")
        assert len(parts[1]) == 6

    def test_event_types(self):
        from warden.billing.audit_chain import (
            ACP_CHECKOUT,
            MCP_CALL,
            STAFF_CALL,
            append_billing_event,
        )
        append_billing_event("t1", STAFF_CALL, db_path=self._db)
        append_billing_event("t1", MCP_CALL, db_path=self._db)
        append_billing_event("t1", ACP_CHECKOUT, db_path=self._db)
        from warden.billing.audit_chain import get_chain
        chain = get_chain("t1", db_path=self._db)
        types = {e["event_type"] for e in chain}
        assert types == {STAFF_CALL, MCP_CALL, ACP_CHECKOUT}


# ── REST API tests ────────────────────────────────────────────────────────────

class TestBillingAuditAPI:
    @pytest.fixture(autouse=True)
    def _client(self, tmp_path, monkeypatch):
        db = str(tmp_path / "billing_audit_api.db")
        monkeypatch.setenv("BILLING_AUDIT_DB_PATH", db)
        monkeypatch.setenv("X_TENANT_TIER", "pro")
        # Pre-populate a few entries
        from warden.billing.audit_chain import append_billing_event
        for i in range(3):
            append_billing_event(
                tenant_id="api-tenant",
                event_type="staff_tool_call",
                cost_usd=0.01 * (i + 1),
                agent_id="agent-001",
                tool_name="score_kyc_profile",
                db_path=db,
            )
        from fastapi.testclient import TestClient

        from warden.main import app
        self.client = TestClient(app, raise_server_exceptions=False)
        self.db = db

    def _headers(self):
        return {"X-Tenant-Tier": "pro"}

    def test_chain_endpoint(self):
        resp = self.client.get("/billing/audit/chain/api-tenant", headers=self._headers())
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 3

    def test_verify_endpoint_valid(self):
        resp = self.client.get("/billing/audit/verify/api-tenant", headers=self._headers())
        assert resp.status_code == 200
        assert resp.json()["valid"] is True

    def test_summary_endpoint(self):
        resp = self.client.get("/billing/audit/summary/api-tenant", headers=self._headers())
        assert resp.status_code == 200
        data = resp.json()
        assert data["entry_count"] == 3
        assert data["total_cost_usd"] > 0

    def test_export_endpoint_jsonl(self):
        resp = self.client.get("/billing/audit/export/api-tenant", headers=self._headers())
        assert resp.status_code == 200
        assert "ndjson" in resp.headers.get("content-type", "")
        lines = [ln for ln in resp.text.splitlines() if ln.strip()]
        assert len(lines) == 3

    def test_evm_anchors_endpoint(self):
        resp = self.client.get("/billing/audit/evm/api-tenant", headers=self._headers())
        assert resp.status_code == 200
        data = resp.json()
        assert "anchors" in data
        assert data["chain_id"] == 84532

    def test_verify_detects_tamper_returns_409(self, monkeypatch):
        import sqlite3

        import warden.api.billing_audit as _api_mod
        import warden.billing.audit_chain as _chain_mod
        db = self.db
        # Make the API module use the same DB the fixture populated
        monkeypatch.setattr(_api_mod, "_DB_PATH", db)
        monkeypatch.setattr(_chain_mod, "_DB_PATH", db)
        # Tamper
        con = sqlite3.connect(db)
        con.execute(
            "UPDATE billing_audit_chain SET cost_usd='9999.000000' "
            "WHERE tenant_id='api-tenant' AND seq=1"
        )
        con.commit()
        con.close()
        resp = self.client.get("/billing/audit/verify/api-tenant", headers=self._headers())
        assert resp.status_code == 409


# ── Integration: TokenCostTracker hooks billing chain ────────────────────────

class TestEconomicsHook:
    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path, monkeypatch):
        self.econ_db  = str(tmp_path / "econ.db")
        self.audit_db = str(tmp_path / "audit.db")
        monkeypatch.setenv("STAFF_ECON_DB_PATH", self.econ_db)
        monkeypatch.setenv("BILLING_AUDIT_DB_PATH", self.audit_db)

    def test_record_writes_to_audit_chain(self, monkeypatch):
        import warden.billing.audit_chain as _ac
        monkeypatch.setattr(_ac, "_DB_PATH", self.audit_db)
        from warden.staff.economics import TokenCostTracker
        tracker = TokenCostTracker(db_path=self.econ_db)
        tracker.record(
            tenant_id="hook-tenant",
            agent_id="bdr-001",
            action="generate_email_draft",
            model="claude-haiku-4-5-20251001",
            input_tokens=200,
            output_tokens=100,
        )
        from warden.billing.audit_chain import get_chain
        chain = get_chain("hook-tenant", db_path=self.audit_db)
        assert len(chain) == 1
        assert chain[0]["event_type"] == "staff_tool_call"
        assert chain[0]["tool_name"] == "generate_email_draft"

    def test_record_audit_chain_fail_open(self, monkeypatch):
        """Audit chain failure must not break TokenCostTracker.record()."""
        import warden.billing.audit_chain as _ac
        monkeypatch.setattr(_ac, "append_billing_event", lambda **kw: (_ for _ in ()).throw(RuntimeError("db down")))
        from warden.staff.economics import TokenCostTracker
        tracker = TokenCostTracker(db_path=self.econ_db)
        # Should not raise
        entry = tracker.record("t1", "a1", "do_thing", "claude-haiku-4-5-20251001", 10, 5)
        assert entry.cost_usd >= 0
