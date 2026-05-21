"""
warden/tests/test_smb_suite.py
Tests for IN-25 SMB AI Governance Suite.
"""
from __future__ import annotations

import os
import tempfile
import uuid
from unittest.mock import patch

import pytest

os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")


def _tid() -> str:
    return f"tenant-{uuid.uuid4().hex[:8]}"


def _cid() -> str:
    return f"comm-{uuid.uuid4().hex[:8]}"


def _tmp_db() -> str:
    f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    f.close()
    return f.name


class TestProvision:
    def test_provision_returns_result(self):
        from warden.integrations.smb_suite import provision_suite
        db = _tmp_db()
        r  = provision_suite(_tid(), _cid(), sep_db_path=db, vendor_db_path=db, cost_db_path=db)
        assert r.tenant_id and r.community_id
        assert r.provisioned_at

    def test_provision_ueciid_assigned(self):
        from warden.integrations.smb_suite import provision_suite
        db = _tmp_db()
        r  = provision_suite(_tid(), _cid(), sep_db_path=db, vendor_db_path=db, cost_db_path=db)
        assert r.ueciid

    def test_provision_incident_register_ok(self):
        from warden.integrations.smb_suite import provision_suite
        db = _tmp_db()
        r  = provision_suite(_tid(), _cid(), sep_db_path=db, vendor_db_path=db, cost_db_path=db)
        assert r.incident_register is True

    def test_provision_prompt_library_ok(self):
        from warden.integrations.smb_suite import provision_suite
        db = _tmp_db()
        r  = provision_suite(_tid(), _cid(), sep_db_path=db, vendor_db_path=db, cost_db_path=db)
        assert r.prompt_library is True

    def test_provision_training_program_created(self):
        from warden.integrations.smb_suite import provision_suite
        db = _tmp_db()
        r  = provision_suite(_tid(), _cid(), sep_db_path=db, vendor_db_path=db, cost_db_path=db)
        assert r.training_programs == 1

    def test_provision_with_budget(self):
        from warden.integrations.smb_suite import provision_suite
        db  = _tmp_db()
        cfg = {"monthly_budget_usd": 500.0}
        r   = provision_suite(_tid(), _cid(), config=cfg, sep_db_path=db, vendor_db_path=db, cost_db_path=db)
        assert r.budget_caps_set == 1

    def test_provision_no_budget_skipped(self):
        from warden.integrations.smb_suite import provision_suite
        db = _tmp_db()
        r  = provision_suite(_tid(), _cid(), config={"monthly_budget_usd": 0.0},
                             sep_db_path=db, vendor_db_path=db, cost_db_path=db)
        assert r.budget_caps_set == 0

    def test_provision_with_vendors(self):
        from warden.integrations.smb_suite import provision_suite
        db  = _tmp_db()
        cfg = {
            "vendors": [
                {"display_name": "OpenAI",     "website": "https://openai.com",    "provider_type": "LLM"},
                {"display_name": "Anthropic",  "website": "https://anthropic.com", "provider_type": "LLM"},
            ],
        }
        r = provision_suite(_tid(), _cid(), config=cfg, sep_db_path=db, vendor_db_path=db, cost_db_path=db)
        assert r.vendor_count == 2
        assert r.supplier_risk is True

    def test_provision_to_dict(self):
        from warden.integrations.smb_suite import provision_suite
        db = _tmp_db()
        r  = provision_suite(_tid(), _cid(), sep_db_path=db, vendor_db_path=db, cost_db_path=db)
        d  = r.to_dict()
        assert "tenant_id" in d
        assert "ueciid" in d
        assert "errors" in d

    def test_provision_errors_list(self):
        from warden.integrations.smb_suite import provision_suite
        db = _tmp_db()
        r  = provision_suite(_tid(), _cid(), sep_db_path=db, vendor_db_path=db, cost_db_path=db)
        assert isinstance(r.errors, list)

    def test_provision_idempotent_training(self):
        from warden.integrations.smb_suite import provision_suite
        db  = _tmp_db()
        tid = _tid()
        cid = _cid()
        provision_suite(tid, cid, sep_db_path=db, vendor_db_path=db, cost_db_path=db)
        r2 = provision_suite(tid, cid, sep_db_path=db, vendor_db_path=db, cost_db_path=db)
        assert r2.training_programs >= 1


class TestHealth:
    def test_health_returns_modules(self):
        from warden.integrations.smb_suite import get_suite_health
        db = _tmp_db()
        h  = get_suite_health(_tid(), sep_db_path=db, vendor_db_path=db, cost_db_path=db)
        assert "modules" in h
        assert len(h["modules"]) == 7

    def test_health_overall_field(self):
        from warden.integrations.smb_suite import get_suite_health
        db = _tmp_db()
        h  = get_suite_health(_tid(), sep_db_path=db, vendor_db_path=db, cost_db_path=db)
        assert h["overall"] in {"healthy", "degraded"}

    def test_health_modules_ok_count(self):
        from warden.integrations.smb_suite import get_suite_health
        db = _tmp_db()
        h  = get_suite_health(_tid(), sep_db_path=db, vendor_db_path=db, cost_db_path=db)
        assert 0 <= h["modules_ok"] <= h["modules_total"]

    def test_health_after_provision(self):
        from warden.integrations.smb_suite import provision_suite, get_suite_health
        db  = _tmp_db()
        tid = _tid()
        cid = _cid()
        provision_suite(tid, cid, sep_db_path=db, vendor_db_path=db, cost_db_path=db)
        h = get_suite_health(tid, community_id=cid, sep_db_path=db, vendor_db_path=db, cost_db_path=db)
        assert h["modules"]["incident_register"]["status"] == "ok"
        assert h["modules"]["prompt_library"]["status"] == "ok"
