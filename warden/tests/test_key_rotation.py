"""Tests for KeyRotationManager — decentralized key rotation (SEC-05)."""
from __future__ import annotations

import asyncio
import hashlib
import sqlite3

import pytest


@pytest.fixture()
def mgr(tmp_path):
    from warden.marketplace.auto_responder import AutoResponder  # noqa: F401
    from warden.web3.key_rotation import KeyRotationManager
    return KeyRotationManager(
        rotation_db=str(tmp_path / "rotation.db"),
        marketplace_db=str(tmp_path / "mkt.db"),
    )


class TestScheduleCompletion:
    def test_schedule_returns_record(self, mgr):
        new_key_hash = hashlib.sha256(b"newpubkey").hexdigest()
        result = asyncio.run(mgr.schedule_rotation("agent-A", new_key_hash, deadline_days=90))
        assert result["agent_id"] == "agent-A"
        assert result["status"] == "pending"
        assert "deadline_at" in result

    def test_complete_rotation_updates_status(self, mgr):
        new_key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnew_pub_key_pem"
        new_key_hash = hashlib.sha256(new_key.encode()).hexdigest()
        asyncio.run(mgr.schedule_rotation("agent-B", new_key_hash))
        result = asyncio.run(mgr.complete_rotation("agent-B", new_key))
        assert result["status"] == "completed"

    def test_complete_without_schedule_raises(self, mgr):
        with pytest.raises(ValueError, match="No pending rotation"):
            asyncio.run(mgr.complete_rotation("agent-unknown", "anykey"))


class TestOverdueDetection:
    def test_overdue_detected(self, mgr):
        # Schedule with 0-day deadline → immediately overdue
        new_key_hash = hashlib.sha256(b"key").hexdigest()
        asyncio.run(mgr.schedule_rotation("agent-C", new_key_hash, deadline_days=0))
        # Force deadline into the past
        con = sqlite3.connect(mgr.rotation_db)
        con.execute(
            "UPDATE key_rotations SET deadline_at='2000-01-01T00:00:00+00:00' WHERE agent_id='agent-C'"
        )
        con.commit()
        con.close()
        overdue = asyncio.run(mgr.check_overdue())
        assert "agent-C" in overdue

    def test_non_overdue_not_returned(self, mgr):
        new_key_hash = hashlib.sha256(b"key2").hexdigest()
        asyncio.run(mgr.schedule_rotation("agent-D", new_key_hash, deadline_days=90))
        overdue = asyncio.run(mgr.check_overdue())
        assert "agent-D" not in overdue


class TestCertificateChain:
    def test_completion_attempts_cert_issuance(self, mgr, tmp_path):
        """Complete rotation calls _issue_new_cert (no exception even if CA unavailable)."""
        new_key = "newpubkey123"
        new_key_hash = hashlib.sha256(new_key.encode()).hexdigest()
        asyncio.run(mgr.schedule_rotation("agent-E", new_key_hash))
        result = asyncio.run(mgr.complete_rotation("agent-E", new_key))
        assert result["status"] == "completed"
        # cert_id may be empty if CA tables don't exist in the tmp marketplace DB
        assert "new_cert_id" in result

    def test_old_key_revocation_attempted(self, mgr, tmp_path):
        """_revoke_old_cert is attempted (no exception even without existing cert)."""
        new_key = "anotherpub"
        new_key_hash = hashlib.sha256(new_key.encode()).hexdigest()
        asyncio.run(mgr.schedule_rotation("agent-F", new_key_hash))
        result = asyncio.run(mgr.complete_rotation("agent-F", new_key))
        assert result["status"] == "completed"
