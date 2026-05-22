"""
warden/tests/test_cost_allocation.py
Tests for BL-23 AI Cost Allocation and BL-24 Budget Dashboard.
"""
from __future__ import annotations

import json
import os
import tempfile
import uuid

os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")


def _tid() -> str:
    return f"tenant-{uuid.uuid4().hex[:8]}"


def _tmp_db() -> str:
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        return f.name


# ── BL-23 Cost Allocation ────────────────────────────────────────────────────

class TestCostAllocation:
    def test_record_cost_returns_id(self):
        from warden.financial.cost_allocation import record_cost
        db  = _tmp_db()
        tid = _tid()
        aid = record_cost(tid, 1.50, db_path=db)
        assert aid and len(aid) == 36

    def test_monthly_summary_total(self):
        from warden.financial.cost_allocation import get_monthly_summary, record_cost
        db  = _tmp_db()
        tid = _tid()
        record_cost(tid, 5.00, department="eng",     period_month="2025-12", db_path=db)
        record_cost(tid, 3.25, department="marketing", period_month="2025-12", db_path=db)
        s = get_monthly_summary(tid, "2025-12", db_path=db)
        assert s["total_usd"] == 8.25

    def test_monthly_summary_by_department(self):
        from warden.financial.cost_allocation import get_monthly_summary, record_cost
        db  = _tmp_db()
        tid = _tid()
        record_cost(tid, 10.0, department="eng",     period_month="2025-12", db_path=db)
        record_cost(tid, 2.0,  department="finance",  period_month="2025-12", db_path=db)
        s = get_monthly_summary(tid, "2025-12", db_path=db)
        assert s["by_department"]["eng"] == 10.0

    def test_monthly_summary_by_vendor(self):
        from warden.financial.cost_allocation import get_monthly_summary, record_cost
        db  = _tmp_db()
        tid = _tid()
        record_cost(tid, 7.50, vendor_id="openai", period_month="2025-12", db_path=db)
        s = get_monthly_summary(tid, "2025-12", db_path=db)
        assert s["by_vendor"]["openai"] == 7.50

    def test_cost_type_normalization(self):
        from warden.financial.cost_allocation import get_monthly_summary, record_cost
        db  = _tmp_db()
        tid = _tid()
        record_cost(tid, 1.0, cost_type="INVALID_TYPE", period_month="2026-01", db_path=db)
        s = get_monthly_summary(tid, "2026-01", db_path=db)
        assert "other" in s["by_type"]

    def test_vendor_spend(self):
        from datetime import UTC, datetime

        from warden.financial.cost_allocation import get_vendor_spend, record_cost
        db     = _tmp_db()
        tid    = _tid()
        period = datetime.now(UTC).strftime("%Y-%m")
        record_cost(tid, 12.0, vendor_id="anthropic", period_month=period, db_path=db)
        result = get_vendor_spend(tid, "anthropic", months=1, db_path=db)
        assert result["total"] == 12.0

    def test_import_from_logs(self):
        db  = _tmp_db()
        tid = _tid()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as log_file:
            log_file.write(json.dumps({"verdict": "BLOCK", "request_id": "r1"}) + "\n")
            log_file.write(json.dumps({"verdict": "ALLOW", "request_id": "r2"}) + "\n")
            log_file.write(json.dumps({"verdict": "HIGH",  "request_id": "r3"}) + "\n")
            log_path = log_file.name
        from warden.financial.cost_allocation import import_from_logs
        count = import_from_logs(tid, logs_path=log_path, db_path=db)
        assert count == 2

    def test_import_from_missing_logs(self):
        from warden.financial.cost_allocation import import_from_logs
        db = _tmp_db()
        assert import_from_logs("t1", logs_path="/no/such/path.json", db_path=db) == 0


# ── BL-24 Budget Dashboard ────────────────────────────────────────────────────

class TestBudgetDashboard:
    def test_set_budget_cap(self):
        from warden.financial.budget import set_budget_cap
        db  = _tmp_db()
        tid = _tid()
        cap_id = set_budget_cap(tid, 100.0, department="eng", db_path=db)
        assert cap_id

    def test_set_budget_cap_upsert(self):
        from warden.financial.budget import set_budget_cap
        db  = _tmp_db()
        tid = _tid()
        id1 = set_budget_cap(tid, 100.0, department="eng", db_path=db)
        id2 = set_budget_cap(tid, 200.0, department="eng", db_path=db)
        assert id1 == id2  # same cap updated in place

    def test_check_budget_ok(self):
        from warden.financial.budget import check_budget, set_budget_cap
        db  = _tmp_db()
        tid = _tid()
        set_budget_cap(tid, 100.0, department="eng", db_path=db)
        result = check_budget(tid, "eng", 30.0, db_path=db)
        assert result["status"] == "ok"
        assert result["pct_used"] == 0.3

    def test_check_budget_alert(self):
        from warden.financial.budget import check_budget, set_budget_cap
        db  = _tmp_db()
        tid = _tid()
        set_budget_cap(tid, 100.0, department="eng", alert_pct=0.8, db_path=db)
        result = check_budget(tid, "eng", 85.0, db_path=db)
        assert result["status"] == "alert"

    def test_check_budget_over(self):
        from warden.financial.budget import check_budget, set_budget_cap
        db  = _tmp_db()
        tid = _tid()
        set_budget_cap(tid, 100.0, department="eng", db_path=db)
        result = check_budget(tid, "eng", 120.0, db_path=db)
        assert result["status"] == "over_budget"
        assert result["remaining"] == 0.0

    def test_check_budget_no_cap(self):
        from warden.financial.budget import check_budget
        db  = _tmp_db()
        result = check_budget("t1", "no-dept", 50.0, db_path=db)
        assert result["status"] == "no_cap"

    def test_realtime_status(self):
        from warden.financial.budget import get_realtime_status, set_budget_cap
        db  = _tmp_db()
        tid = _tid()
        set_budget_cap(tid, 500.0, department="eng", db_path=db)
        status = get_realtime_status(tid, db_path=db)
        assert status["total_caps"] == 1
        assert len(status["departments"]) == 1

    def test_approval_flow(self):
        from warden.financial.budget import list_approvals, request_approval, resolve_approval
        db  = _tmp_db()
        tid = _tid()
        aid = request_approval(tid, "alice", "eng", 500.0, reason="New LLM API", db_path=db)
        assert aid
        items = list_approvals(tid, status="pending", db_path=db)
        assert len(items) == 1
        assert resolve_approval(aid, "bob", approve=True, db_path=db)
        items = list_approvals(tid, status="approved", db_path=db)
        assert len(items) == 1

    def test_approval_reject(self):
        from warden.financial.budget import list_approvals, request_approval, resolve_approval
        db  = _tmp_db()
        tid = _tid()
        aid = request_approval(tid, "alice", "marketing", 10000.0, db_path=db)
        resolve_approval(aid, "cfo", approve=False, db_path=db)
        items = list_approvals(tid, status="rejected", db_path=db)
        assert len(items) == 1

    def test_resolve_already_resolved(self):
        from warden.financial.budget import request_approval, resolve_approval
        db  = _tmp_db()
        tid = _tid()
        aid = request_approval(tid, "a", "b", 100.0, db_path=db)
        resolve_approval(aid, "mgr", approve=True, db_path=db)
        assert not resolve_approval(aid, "mgr2", approve=False, db_path=db)
