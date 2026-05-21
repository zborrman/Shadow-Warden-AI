"""
warden/tests/test_training_records.py
Tests for CM-38 Employee AI Training Records.
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


def _cid() -> str:
    return f"com-{uuid.uuid4().hex[:8]}"


def _eid() -> str:
    return f"emp-{uuid.uuid4().hex[:8]}"


def _tmp_db() -> str:
    f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    f.close()
    return f.name


class TestPrograms:
    def test_create_program_basic(self):
        from warden.communities.training_records import create_program
        db  = _tmp_db()
        cid = _cid()
        p   = create_program(cid, "AI Safety Basics", db_path=db)
        assert p.program_id
        assert p.title == "AI Safety Basics"
        assert p.passing_score == 0.8
        assert p.valid_days == 365

    def test_create_program_custom_params(self):
        from warden.communities.training_records import create_program
        db  = _tmp_db()
        cid = _cid()
        p   = create_program(
            cid, "Advanced AI Ethics",
            passing_score=0.9, valid_days=180, required_for=["manager", "dev"],
            db_path=db,
        )
        assert p.passing_score == 0.9
        assert p.valid_days == 180
        assert "manager" in p.required_for

    def test_get_program_found(self):
        from warden.communities.training_records import create_program, get_program
        db  = _tmp_db()
        cid = _cid()
        p   = create_program(cid, "Test", db_path=db)
        fetched = get_program(p.program_id, db_path=db)
        assert fetched is not None and fetched.title == "Test"

    def test_get_program_not_found(self):
        from warden.communities.training_records import get_program
        db = _tmp_db()
        assert get_program("no-such-id", db_path=db) is None

    def test_list_programs_by_community(self):
        from warden.communities.training_records import create_program, list_programs
        db  = _tmp_db()
        c1, c2 = _cid(), _cid()
        create_program(c1, "P1", db_path=db)
        create_program(c1, "P2", db_path=db)
        create_program(c2, "P3", db_path=db)
        assert len(list_programs(c1, db_path=db)) == 2
        assert len(list_programs(c2, db_path=db)) == 1

    def test_passing_score_clamped(self):
        from warden.communities.training_records import create_program
        db  = _tmp_db()
        cid = _cid()
        p   = create_program(cid, "Clamped", passing_score=1.5, db_path=db)
        assert p.passing_score == 1.0


class TestCompletions:
    def test_record_completion_passed(self):
        from warden.communities.training_records import create_program, record_completion
        db  = _tmp_db()
        cid = _cid()
        p   = create_program(cid, "P", passing_score=0.7, db_path=db)
        with patch("warden.communities.training_records._fire_behavioral_event"):
            c = record_completion(p.program_id, cid, _eid(), score=0.85, db_path=db)
        assert c.passed
        assert c.attestation != ""

    def test_record_completion_failed(self):
        from warden.communities.training_records import create_program, record_completion
        db  = _tmp_db()
        cid = _cid()
        p   = create_program(cid, "P", passing_score=0.8, db_path=db)
        with patch("warden.communities.training_records._fire_behavioral_event"):
            c = record_completion(p.program_id, cid, _eid(), score=0.5, db_path=db)
        assert not c.passed

    def test_record_completion_program_not_found(self):
        from warden.communities.training_records import record_completion
        db = _tmp_db()
        with pytest.raises(ValueError, match="not found"):
            record_completion("no-such-program", "com", "emp", score=0.9, db_path=db)

    def test_attestation_verifiable(self):
        from warden.communities.training_records import create_program, record_completion, verify_attestation
        db  = _tmp_db()
        cid = _cid()
        p   = create_program(cid, "P", db_path=db)
        with patch("warden.communities.training_records._fire_behavioral_event"):
            c = record_completion(p.program_id, cid, _eid(), score=0.9, db_path=db)
        assert verify_attestation(c.to_dict())

    def test_attestation_tampered_fails(self):
        from warden.communities.training_records import create_program, record_completion, verify_attestation
        db  = _tmp_db()
        cid = _cid()
        p   = create_program(cid, "P", db_path=db)
        with patch("warden.communities.training_records._fire_behavioral_event"):
            c = record_completion(p.program_id, cid, _eid(), score=0.9, db_path=db)
        tampered             = c.to_dict()
        tampered["score"]    = 1.0  # fake perfect score
        assert not verify_attestation(tampered)

    def test_behavioral_event_fired(self):
        from warden.communities.training_records import create_program, record_completion
        db  = _tmp_db()
        cid = _cid()
        p   = create_program(cid, "P", db_path=db)
        with patch("warden.communities.training_records._fire_behavioral_event") as mock_be:
            record_completion(p.program_id, cid, _eid(), score=0.9, db_path=db)
        mock_be.assert_called_once()


class TestEmployeeStatusAndReport:
    def test_employee_status_compliant(self):
        from warden.communities.training_records import create_program, record_completion, get_employee_status
        db  = _tmp_db()
        cid = _cid()
        eid = _eid()
        p   = create_program(cid, "P", db_path=db)
        with patch("warden.communities.training_records._fire_behavioral_event"):
            record_completion(p.program_id, cid, eid, score=0.9, db_path=db)
        status = get_employee_status(cid, eid, db_path=db)
        assert status["overall_status"] == "compliant"
        assert status["programs"][0]["status"] == "compliant"

    def test_employee_status_not_completed(self):
        from warden.communities.training_records import create_program, get_employee_status
        db  = _tmp_db()
        cid = _cid()
        eid = _eid()
        create_program(cid, "P", db_path=db)
        status = get_employee_status(cid, eid, db_path=db)
        assert status["overall_status"] == "non_compliant"
        assert status["programs"][0]["status"] == "not_completed"

    def test_compliance_report_structure(self):
        from warden.communities.training_records import create_program, record_completion, get_compliance_report
        db  = _tmp_db()
        cid = _cid()
        p   = create_program(cid, "P", db_path=db)
        with patch("warden.communities.training_records._fire_behavioral_event"):
            record_completion(p.program_id, cid, _eid(), score=0.9, db_path=db)
            record_completion(p.program_id, cid, _eid(), score=0.4, db_path=db)
        report = get_compliance_report(cid, db_path=db)
        assert report["total_completions"] == 2
        assert report["passed"] == 1
        assert report["pass_rate"] == 0.5
        assert report["unique_employees"] == 2

    def test_compliance_report_empty(self):
        from warden.communities.training_records import get_compliance_report
        db = _tmp_db()
        r  = get_compliance_report("no-such-community", db_path=db)
        assert r["total_completions"] == 0
        assert r["pass_rate"] == 0.0
