"""
warden/tests/test_threat_store.py
───────────────────────────────────
Unit tests for ThreatStore — the SQLite threat intelligence ledger.
"""
from __future__ import annotations

import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from warden.threat_store import ThreatStore

# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def store(tmp_path: Path) -> Generator[ThreatStore, None, None]:
    ts = ThreatStore(db_path=tmp_path / "test_threats.db")
    yield ts
    ts.close()


def _ip() -> str:
    return f"10.0.{uuid.uuid4().int % 256}.{uuid.uuid4().int % 256}"


# ── record_block_event ─────────────────────────────────────────────────────────

class TestRecordBlockEvent:
    def test_creates_threat_event(self, store: ThreatStore) -> None:
        ip = _ip()
        store.record_block_event(ip, "default", "high", ["PROMPT_INJECTION"])
        events = store.get_recent_events(ip=ip)
        assert len(events) == 1
        assert events[0]["event_type"] == "block_event"
        assert events[0]["ip"] == ip
        assert events[0]["risk_level"] == "high"
        assert "PROMPT_INJECTION" in events[0]["flags"]

    def test_creates_attacker_profile(self, store: ThreatStore) -> None:
        ip = _ip()
        store.record_block_event(ip, "default", "block", [])
        profiles = store.get_profiles()
        ips = [p["ip"] for p in profiles]
        assert ip in ips

    def test_increments_block_count(self, store: ThreatStore) -> None:
        ip = _ip()
        store.record_block_event(ip, "default", "high", [])
        store.record_block_event(ip, "default", "high", [])
        profiles = store.get_profiles()
        profile = next(p for p in profiles if p["ip"] == ip)
        assert profile["block_count"] == 2

    def test_empty_ip_is_noop(self, store: ThreatStore) -> None:
        store.record_block_event("", "default", "high", [])
        assert store.get_recent_events() == []

    def test_empty_flags_list(self, store: ThreatStore) -> None:
        ip = _ip()
        store.record_block_event(ip, "default", "medium", None)
        events = store.get_recent_events(ip=ip)
        assert events[0]["flags"] == []


# ── record_session_threat ──────────────────────────────────────────────────────

class TestRecordSessionThreat:
    def test_creates_session_threat_event(self, store: ThreatStore) -> None:
        ip = _ip()
        store.record_session_threat(ip, "default", "sess-1", "RAPID_BLOCK", "HIGH")
        events = store.get_recent_events(ip=ip)
        assert len(events) == 1
        assert events[0]["event_type"] == "session_threat"
        assert events[0]["pattern"] == "RAPID_BLOCK"
        assert events[0]["severity"] == "HIGH"
        assert events[0]["session_id"] == "sess-1"

    def test_adds_pattern_to_profile(self, store: ThreatStore) -> None:
        ip = _ip()
        store.record_session_threat(ip, "default", "sess-2", "TOOL_VELOCITY", "MEDIUM")
        profiles = store.get_profiles()
        profile = next(p for p in profiles if p["ip"] == ip)
        assert "TOOL_VELOCITY" in profile["threat_types"]

    def test_threat_count_incremented(self, store: ThreatStore) -> None:
        ip = _ip()
        store.record_session_threat(ip, "default", "s1", "EVASION_ATTEMPT", "HIGH")
        store.record_session_threat(ip, "default", "s2", "RAPID_BLOCK", "HIGH")
        profile = next(p for p in store.get_profiles() if p["ip"] == ip)
        assert profile["threat_count"] == 2

    def test_empty_ip_is_noop(self, store: ThreatStore) -> None:
        store.record_session_threat("", "default", "s1", "RAPID_BLOCK", "HIGH")
        assert store.get_recent_events() == []

    def test_duplicate_pattern_not_added_twice(self, store: ThreatStore) -> None:
        ip = _ip()
        store.record_session_threat(ip, "default", "s1", "RAPID_BLOCK", "HIGH")
        store.record_session_threat(ip, "default", "s2", "RAPID_BLOCK", "HIGH")
        profile = next(p for p in store.get_profiles() if p["ip"] == ip)
        assert profile["threat_types"].count("RAPID_BLOCK") == 1


# ── block_ip / unblock_ip / is_blocked ────────────────────────────────────────

class TestBlocklist:
    def test_block_and_is_blocked(self, store: ThreatStore) -> None:
        ip = _ip()
        assert not store.is_blocked(ip)
        store.block_ip(ip, reason="manual test")
        assert store.is_blocked(ip)

    def test_unblock_returns_true(self, store: ThreatStore) -> None:
        ip = _ip()
        store.block_ip(ip, reason="test")
        assert store.unblock_ip(ip) is True
        assert not store.is_blocked(ip)

    def test_unblock_unknown_returns_false(self, store: ThreatStore) -> None:
        assert store.unblock_ip("1.2.3.4") is False

    def test_empty_ip_is_not_blocked(self, store: ThreatStore) -> None:
        assert store.is_blocked("") is False

    def test_block_upsert_replaces_existing(self, store: ThreatStore) -> None:
        ip = _ip()
        store.block_ip(ip, reason="first")
        store.block_ip(ip, reason="updated")
        entries = store.get_blocked_ips()
        entry = next(e for e in entries if e["ip"] == ip)
        assert entry["reason"] == "updated"

    def test_permanent_block_has_no_expiry(self, store: ThreatStore) -> None:
        ip = _ip()
        store.block_ip(ip)
        entries = store.get_blocked_ips()
        entry = next(e for e in entries if e["ip"] == ip)
        assert entry["expires_at"] is None

    def test_expired_block_is_not_blocked(self, store: ThreatStore) -> None:
        ip = _ip()
        past = (datetime.now(UTC) - timedelta(seconds=10)).isoformat()
        store.block_ip(ip, expires_at=past)
        assert not store.is_blocked(ip)

    def test_future_expiry_block_is_blocked(self, store: ThreatStore) -> None:
        ip = _ip()
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        store.block_ip(ip, expires_at=future)
        assert store.is_blocked(ip)

    def test_per_tenant_isolation(self, store: ThreatStore) -> None:
        ip = _ip()
        store.block_ip(ip, tenant_id="tenant-a", reason="tenant a only")
        assert store.is_blocked(ip, "tenant-a")
        assert not store.is_blocked(ip, "tenant-b")


# ── get_profiles ───────────────────────────────────────────────────────────────

class TestGetProfiles:
    def test_empty_store_returns_empty(self, store: ThreatStore) -> None:
        assert store.get_profiles() == []

    def test_limit_respected(self, store: ThreatStore) -> None:
        for _ in range(5):
            store.record_block_event(_ip(), "default", "high", [])
        profiles = store.get_profiles(limit=3)
        assert len(profiles) == 3

    def test_tenant_filter(self, store: ThreatStore) -> None:
        ip_a, ip_b = _ip(), _ip()
        store.record_block_event(ip_a, "tenant-a", "high", [])
        store.record_block_event(ip_b, "tenant-b", "high", [])
        profiles_a = store.get_profiles(tenant_id="tenant-a")
        ips = [p["ip"] for p in profiles_a]
        assert ip_a in ips
        assert ip_b not in ips


# ── get_blocked_ips ────────────────────────────────────────────────────────────

class TestGetBlockedIps:
    def test_returns_active_blocks(self, store: ThreatStore) -> None:
        ip = _ip()
        store.block_ip(ip, reason="test")
        entries = store.get_blocked_ips()
        assert any(e["ip"] == ip for e in entries)

    def test_excludes_expired(self, store: ThreatStore) -> None:
        ip = _ip()
        past = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
        store.block_ip(ip, expires_at=past)
        entries = store.get_blocked_ips()
        assert not any(e["ip"] == ip for e in entries)

    def test_tenant_filter(self, store: ThreatStore) -> None:
        ip1, ip2 = _ip(), _ip()
        store.block_ip(ip1, tenant_id="x")
        store.block_ip(ip2, tenant_id="y")
        entries = store.get_blocked_ips(tenant_id="x")
        ips = [e["ip"] for e in entries]
        assert ip1 in ips
        assert ip2 not in ips


# ── get_recent_events ──────────────────────────────────────────────────────────

class TestGetRecentEvents:
    def test_filter_by_ip(self, store: ThreatStore) -> None:
        ip1, ip2 = _ip(), _ip()
        store.record_block_event(ip1, "default", "high", [])
        store.record_block_event(ip2, "default", "high", [])
        events = store.get_recent_events(ip=ip1)
        assert all(e["ip"] == ip1 for e in events)

    def test_filter_by_tenant(self, store: ThreatStore) -> None:
        ip = _ip()
        store.record_block_event(ip, "tenant-a", "high", [])
        store.record_block_event(ip, "tenant-b", "high", [])
        events = store.get_recent_events(tenant_id="tenant-a")
        assert all(e["tenant_id"] == "tenant-a" for e in events)

    def test_limit_respected(self, store: ThreatStore) -> None:
        ip = _ip()
        for _ in range(10):
            store.record_block_event(ip, "default", "high", [])
        events = store.get_recent_events(ip=ip, limit=5)
        assert len(events) == 5

    def test_returns_newest_first(self, store: ThreatStore) -> None:
        ip = _ip()
        store.record_block_event(ip, "default", "low", [])
        store.record_block_event(ip, "default", "high", [])
        events = store.get_recent_events(ip=ip)
        assert events[0]["risk_level"] == "high"
        assert events[1]["risk_level"] == "low"
