"""
warden/tests/test_community_factory.py
───────────────────────────────────────
Tests for community_factory.py: keypair generation and STIX audit flags
auto-set on community creation.
"""
from __future__ import annotations

import os
import uuid

_TEST_DB = f"/tmp/test_comm_factory_{uuid.uuid4().hex[:8]}.db"
os.environ.setdefault("COMM_DB_PATH", _TEST_DB)
os.environ.setdefault("MODEL_CACHE_DIR", "/tmp/warden_test_models")
os.environ.setdefault("DYNAMIC_RULES_PATH", "/tmp/warden_test_dynamic_rules.json")


def _tid() -> str:
    return f"tenant-{uuid.uuid4().hex[:8]}"


# ── Creation flags ─────────────────────────────────────────────────────────────

def test_create_community_sets_keypair_generated():
    from warden.communities.community_factory import create_community
    comm = create_community("KP Test", "desc", _tid())
    assert comm.keypair_generated is True


def test_create_community_sets_audit_enabled():
    from warden.communities.community_factory import create_community
    comm = create_community("Audit Test", "desc", _tid())
    assert comm.audit_enabled is True


def test_keypair_generated_reflected_in_settings():
    from warden.communities.community_factory import create_community
    comm = create_community("Settings Test", "desc", _tid())
    assert comm.settings.get("keypair_generated") is True
    assert comm.settings.get("audit_enabled") is True


# ── Persistence ────────────────────────────────────────────────────────────────

def test_flags_persisted_and_loaded_via_get_community():
    from warden.communities.community_factory import create_community, get_community
    comm = create_community("Persist Test", "desc", _tid())
    loaded = get_community(comm.community_id)
    assert loaded is not None
    assert loaded.keypair_generated is True
    assert loaded.audit_enabled is True


def test_get_community_returns_none_for_unknown():
    from warden.communities.community_factory import get_community
    assert get_community("does-not-exist-xyz") is None


# ── Existing custom settings preserved ────────────────────────────────────────

def test_custom_settings_merged_with_flags():
    from warden.communities.community_factory import create_community
    comm = create_community("Custom Test", "desc", _tid(), settings={"my_key": "my_val"})
    assert comm.settings["my_key"] == "my_val"
    assert comm.settings["keypair_generated"] is True
    assert comm.settings["audit_enabled"] is True


# ── List and stats ─────────────────────────────────────────────────────────────

def test_list_communities_includes_newly_created():
    from warden.communities.community_factory import create_community, list_communities
    tid = _tid()
    comm = create_community("List Test", "desc", tid)
    result = list_communities(creator_tenant_id=tid)
    assert any(c.community_id == comm.community_id for c in result)


def test_get_community_stats_returns_dict():
    from warden.communities.community_factory import get_community_stats
    stats = get_community_stats()
    assert "total" in stats
    assert "active" in stats
