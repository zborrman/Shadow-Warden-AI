"""
warden/tests/test_incident_register.py
Tests for CM-35 AI Incident Register.
"""
from __future__ import annotations

import os
import tempfile
import uuid

import pytest

os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")


def _tid() -> str:
    return f"tenant-{uuid.uuid4().hex[:8]}"


def _tmp_db() -> str:
    f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    f.close()
    return f.name


class TestIncidentLogging:
    def test_log_incident_returns_id(self):
        from warden.communities.incident_register import log_incident
        db  = _tmp_db()
        iid = log_incident("t1", "Test incident", db_path=db)
        assert iid and len(iid) == 36

    def test_log_incident_defaults(self):
        from warden.communities.incident_register import log_incident, get_incident
        db  = _tmp_db()
        iid = log_incident("t1", "Default incident", db_path=db)
        inc = get_incident(iid, db_path=db)
        assert inc is not None
        assert inc["severity"] == "MEDIUM"
        assert inc["category"] == "OTHER"
        assert inc["status"]   == "open"

    def test_log_incident_normalizes_severity(self):
        from warden.communities.incident_register import log_incident, get_incident
        db  = _tmp_db()
        iid = log_incident("t1", "High risk", severity="high", db_path=db)
        inc = get_incident(iid, db_path=db)
        assert inc is not None and inc["severity"] == "HIGH"

    def test_log_incident_invalid_severity_fallback(self):
        from warden.communities.incident_register import log_incident, get_incident
        db  = _tmp_db()
        iid = log_incident("t1", "Bad severity", severity="EXTREME", db_path=db)
        inc = get_incident(iid, db_path=db)
        assert inc is not None and inc["severity"] == "MEDIUM"

    def test_log_incident_normalizes_category(self):
        from warden.communities.incident_register import log_incident, get_incident
        db  = _tmp_db()
        iid = log_incident("t1", "Jailbreak", category="jailbreak", db_path=db)
        inc = get_incident(iid, db_path=db)
        assert inc is not None and inc["category"] == "JAILBREAK"

    def test_log_incident_invalid_category_fallback(self):
        from warden.communities.incident_register import log_incident, get_incident
        db  = _tmp_db()
        iid = log_incident("t1", "Weird", category="UNKNOWN_CAT", db_path=db)
        inc = get_incident(iid, db_path=db)
        assert inc is not None and inc["category"] == "OTHER"

    def test_stix_chain_id_populated(self):
        from warden.communities.incident_register import log_incident, get_incident
        db  = _tmp_db()
        iid = log_incident("t1", "Chain test", community_id="com-abc", db_path=db)
        inc = get_incident(iid, db_path=db)
        assert inc is not None
        assert inc["stix_chain_id"] != ""

    def test_stix_entry_in_db(self):
        import sqlite3
        from warden.communities.incident_register import log_incident
        db  = _tmp_db()
        iid = log_incident("t1", "STIX test", community_id="com-xyz", db_path=db)
        con = sqlite3.connect(db)
        row = con.execute(
            "SELECT * FROM sep_stix_chain WHERE transfer_id = ?", (iid,)
        ).fetchone()
        con.close()
        assert row is not None


class TestStatusTransitions:
    def test_update_status_open_to_investigating(self):
        from warden.communities.incident_register import log_incident, update_status, get_incident
        db  = _tmp_db()
        iid = log_incident("t1", "Investigating", db_path=db)
        ok  = update_status(iid, "investigating", db_path=db)
        assert ok
        inc = get_incident(iid, db_path=db)
        assert inc is not None and inc["status"] == "investigating"

    def test_update_status_resolved_with_timestamp(self):
        from warden.communities.incident_register import log_incident, update_status, get_incident
        from datetime import UTC, datetime
        db  = _tmp_db()
        iid = log_incident("t1", "Resolve me", db_path=db)
        ts  = datetime.now(UTC).isoformat()
        ok  = update_status(iid, "resolved", resolved_at=ts, db_path=db)
        assert ok
        inc = get_incident(iid, db_path=db)
        assert inc is not None and inc["status"] == "resolved" and inc["resolved_at"] == ts

    def test_update_status_invalid(self):
        from warden.communities.incident_register import log_incident, update_status
        db  = _tmp_db()
        iid = log_incident("t1", "Bad status", db_path=db)
        assert not update_status(iid, "INVALID_STATUS", db_path=db)

    def test_update_status_not_found(self):
        from warden.communities.incident_register import update_status
        db = _tmp_db()
        assert not update_status("no-such-id", "closed", db_path=db)


class TestIncidentListAndStats:
    def test_list_incidents_by_tenant(self):
        from warden.communities.incident_register import log_incident, list_incidents
        db  = _tmp_db()
        t1  = _tid()
        t2  = _tid()
        log_incident(t1, "I1", db_path=db)
        log_incident(t1, "I2", db_path=db)
        log_incident(t2, "I3", db_path=db)
        assert len(list_incidents(t1, db_path=db)) == 2
        assert len(list_incidents(t2, db_path=db)) == 1

    def test_list_incidents_filter_severity(self):
        from warden.communities.incident_register import log_incident, list_incidents
        db  = _tmp_db()
        tid = _tid()
        log_incident(tid, "Low", severity="LOW", db_path=db)
        log_incident(tid, "Critical", severity="CRITICAL", db_path=db)
        assert len(list_incidents(tid, severity="CRITICAL", db_path=db)) == 1

    def test_list_incidents_filter_status(self):
        from warden.communities.incident_register import log_incident, update_status, list_incidents
        db  = _tmp_db()
        tid = _tid()
        i1  = log_incident(tid, "Open",   db_path=db)
        i2  = log_incident(tid, "Closed", db_path=db)
        update_status(i2, "closed", db_path=db)
        assert len(list_incidents(tid, status="open",   db_path=db)) == 1
        assert len(list_incidents(tid, status="closed", db_path=db)) == 1

    def test_list_incidents_limit(self):
        from warden.communities.incident_register import log_incident, list_incidents
        db  = _tmp_db()
        tid = _tid()
        for i in range(10):
            log_incident(tid, f"Incident {i}", db_path=db)
        assert len(list_incidents(tid, limit=3, db_path=db)) == 3

    def test_stats_structure(self):
        from warden.communities.incident_register import log_incident, get_incident_stats
        db  = _tmp_db()
        tid = _tid()
        log_incident(tid, "J1", severity="HIGH", category="JAILBREAK", db_path=db)
        log_incident(tid, "J2", severity="CRITICAL", category="JAILBREAK", db_path=db)
        log_incident(tid, "P1", severity="LOW", category="PII_LEAK", db_path=db)
        stats = get_incident_stats(tid, db_path=db)
        assert stats["total"] == 3
        assert stats["open"]  == 3
        assert stats["high_critical"] == 2
        assert stats["by_category"]["JAILBREAK"] == 2

    def test_stats_empty_tenant(self):
        from warden.communities.incident_register import get_incident_stats
        db = _tmp_db()
        s  = get_incident_stats("no-such-tenant", db_path=db)
        assert s["total"] == 0


class TestAutoLog:
    def test_auto_log_block_event(self):
        from warden.communities.incident_register import auto_log_from_filter_event, get_incident
        db  = _tmp_db()
        ev  = {"verdict": "BLOCK", "request_id": "req-123", "flags": ["JAILBREAK"]}
        iid = auto_log_from_filter_event("t1", ev, db_path=db)
        assert iid is not None
        inc = get_incident(iid, db_path=db)
        assert inc is not None and inc["category"] == "JAILBREAK"

    def test_auto_log_high_event(self):
        from warden.communities.incident_register import auto_log_from_filter_event
        db  = _tmp_db()
        ev  = {"verdict": "HIGH", "request_id": "req-456"}
        iid = auto_log_from_filter_event("t1", ev, db_path=db)
        assert iid is not None

    def test_auto_log_ignores_safe(self):
        from warden.communities.incident_register import auto_log_from_filter_event
        db  = _tmp_db()
        ev  = {"verdict": "ALLOW", "request_id": "req-789"}
        iid = auto_log_from_filter_event("t1", ev, db_path=db)
        assert iid is None
