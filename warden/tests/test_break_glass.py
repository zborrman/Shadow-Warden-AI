"""Tests for warden/communities/break_glass.py and key_archive.py."""
import os
import tempfile
import pytest

os.environ.setdefault("BREAK_GLASS_TTL_S", "3600")
os.environ.setdefault("BREAK_GLASS_M_SIGS", "2")


# ── key_archive tests ─────────────────────────────────────────────────────────

@pytest.fixture()
def archive_db(tmp_path, monkeypatch):
    db = str(tmp_path / "test_archive.db")
    monkeypatch.setenv("COMMUNITY_KEY_ARCHIVE_PATH", db)
    # Force fresh module state
    import warden.communities.key_archive as ka
    ka._cache.clear()
    # Patch db path directly
    monkeypatch.setattr(ka, "_ARCHIVE_DB_PATH", db)
    return ka


@pytest.fixture()
def sample_keypair():
    from warden.communities.keypair import generate_community_keypair
    return generate_community_keypair("test-community-01", kid="v1")


def test_store_and_get_entry(archive_db, sample_keypair):
    archive_db.store_keypair(sample_keypair)
    entry = archive_db.get_entry("test-community-01", "v1")
    assert entry is not None
    assert entry.kid == "v1"
    assert entry.status == archive_db.KeyStatus.ACTIVE
    assert entry.ed25519_pub_b64
    assert entry.x25519_pub_b64


def test_get_entry_cache(archive_db, sample_keypair):
    archive_db.store_keypair(sample_keypair)
    e1 = archive_db.get_entry("test-community-01", "v1")
    e2 = archive_db.get_entry("test-community-01", "v1")
    assert e1 is e2  # served from cache


def test_get_entry_missing(archive_db):
    assert archive_db.get_entry("does-not-exist", "v99") is None


def test_get_active_entry(archive_db, sample_keypair):
    archive_db.store_keypair(sample_keypair)
    entry = archive_db.get_active_entry("test-community-01")
    assert entry is not None
    assert entry.status == archive_db.KeyStatus.ACTIVE


def test_get_active_entry_missing(archive_db):
    assert archive_db.get_active_entry("ghost-community") is None


def test_set_status(archive_db, sample_keypair):
    archive_db.store_keypair(sample_keypair)
    result = archive_db.set_status("test-community-01", "v1", archive_db.KeyStatus.ROTATION_ONLY)
    assert result is True
    entry = archive_db.get_entry("test-community-01", "v1")
    assert entry.status == archive_db.KeyStatus.ROTATION_ONLY


def test_set_status_nonexistent(archive_db):
    result = archive_db.set_status("none", "v99", archive_db.KeyStatus.SHREDDED)
    assert result is False


def test_crypto_shred(archive_db, sample_keypair):
    archive_db.store_keypair(sample_keypair)
    ok = archive_db.crypto_shred("test-community-01", "v1")
    assert ok is True
    entry = archive_db.get_entry("test-community-01", "v1")
    assert entry.status == archive_db.KeyStatus.SHREDDED
    assert entry.ed_priv_enc_b64 is None
    assert entry.x_priv_enc_b64 is None


def test_crypto_shred_already_shredded(archive_db, sample_keypair):
    archive_db.store_keypair(sample_keypair)
    archive_db.crypto_shred("test-community-01", "v1")
    ok2 = archive_db.crypto_shred("test-community-01", "v1")
    assert ok2 is False  # no-op second shred


def test_load_keypair_from_entry(archive_db, sample_keypair):
    archive_db.store_keypair(sample_keypair)
    entry = archive_db.get_entry("test-community-01", "v1")
    kp = archive_db.load_keypair_from_entry(entry)
    assert kp.kid == "v1"
    assert kp.community_id == "test-community-01"


def test_load_keypair_from_shredded_entry(archive_db, sample_keypair):
    archive_db.store_keypair(sample_keypair)
    archive_db.crypto_shred("test-community-01", "v1")
    entry = archive_db.get_entry("test-community-01", "v1")
    with pytest.raises(ValueError, match="shredded"):
        archive_db.load_keypair_from_entry(entry)


def test_list_entries(archive_db, sample_keypair):
    archive_db.store_keypair(sample_keypair)
    kp2 = __import__("warden.communities.keypair", fromlist=["generate_community_keypair"]).generate_community_keypair("test-community-01", kid="v2")
    archive_db.store_keypair(kp2)
    entries = archive_db.list_entries("test-community-01")
    assert len(entries) == 2
    kids = {e.kid for e in entries}
    assert kids == {"v1", "v2"}


def test_invalidate_cache(archive_db, sample_keypair):
    archive_db.store_keypair(sample_keypair)
    archive_db.get_entry("test-community-01", "v1")  # populate cache
    archive_db.invalidate_cache("test-community-01", "v1")
    # Should re-fetch from DB (no error)
    entry = archive_db.get_entry("test-community-01", "v1")
    assert entry is not None


# ── break_glass tests ─────────────────────────────────────────────────────────

@pytest.fixture()
def bg_env(tmp_path, monkeypatch, archive_db, sample_keypair):
    """Set up break_glass with a real archived keypair."""
    import warden.communities.break_glass as bg
    archive_db.store_keypair(sample_keypair)

    audit_path = str(tmp_path / "bg_audit.jsonl")
    monkeypatch.setattr(bg, "_AUDIT_LOG_PATH", audit_path)
    monkeypatch.setattr(bg, "BREAK_GLASS_M", 2)
    monkeypatch.setattr(bg, "BREAK_GLASS_TIER", "mcp")
    bg._requests.clear()
    return bg


def test_initiate_break_glass(bg_env):
    req = bg_env.initiate_break_glass(
        community_id="test-community-01", kid="v1",
        reason="forensics", requested_by="admin@test",
        tenant_tier="mcp",
    )
    assert req.status == "PENDING"
    assert req.request_id
    assert req.community_id == "test-community-01"


def test_initiate_wrong_tier(bg_env):
    with pytest.raises(PermissionError, match="MCP tier"):
        bg_env.initiate_break_glass(
            community_id="c", kid="v1", reason="x", requested_by="u",
            tenant_tier="pro",
        )


def test_sign_break_glass(bg_env):
    req = bg_env.initiate_break_glass(
        community_id="test-community-01", kid="v1",
        reason="test", requested_by="a@b", tenant_tier="mcp",
    )
    result = bg_env.sign_break_glass(req.request_id, "signer1", "sig_aaa")
    assert result["sigs"] == 1
    assert result["status"] == "PENDING"

    result2 = bg_env.sign_break_glass(req.request_id, "signer2", "sig_bbb")
    assert result2["sigs"] == 2
    assert result2["status"] == "READY"


def test_sign_not_found(bg_env):
    with pytest.raises(ValueError, match="not found"):
        bg_env.sign_break_glass("nonexistent-id", "s1", "sig")


def test_sign_wrong_status(bg_env):
    req = bg_env.initiate_break_glass(
        community_id="test-community-01", kid="v1",
        reason="test", requested_by="a@b", tenant_tier="mcp",
    )
    bg_env.sign_break_glass(req.request_id, "s1", "sig1")
    bg_env.sign_break_glass(req.request_id, "s2", "sig2")
    bg_env.activate_break_glass(req.request_id)
    with pytest.raises(ValueError, match="not PENDING"):
        bg_env.sign_break_glass(req.request_id, "s3", "sig3")


def test_activate_break_glass(bg_env):
    req = bg_env.initiate_break_glass(
        community_id="test-community-01", kid="v1",
        reason="test", requested_by="a@b", tenant_tier="mcp",
    )
    bg_env.sign_break_glass(req.request_id, "s1", "sig1")
    bg_env.sign_break_glass(req.request_id, "s2", "sig2")
    kp = bg_env.activate_break_glass(req.request_id)
    assert kp.kid == "v1"
    loaded = bg_env._load(req.request_id)
    assert loaded.status == "ACTIVE"


def test_activate_insufficient_sigs(bg_env):
    req = bg_env.initiate_break_glass(
        community_id="test-community-01", kid="v1",
        reason="test", requested_by="a@b", tenant_tier="mcp",
    )
    bg_env.sign_break_glass(req.request_id, "s1", "sig1")
    with pytest.raises(PermissionError, match="Insufficient"):
        bg_env.activate_break_glass(req.request_id)


def test_activate_not_found(bg_env):
    with pytest.raises(ValueError, match="not found"):
        bg_env.activate_break_glass("bad-id")


def test_close_break_glass(bg_env):
    req = bg_env.initiate_break_glass(
        community_id="test-community-01", kid="v1",
        reason="test", requested_by="a@b", tenant_tier="mcp",
    )
    bg_env.sign_break_glass(req.request_id, "s1", "sig1")
    bg_env.sign_break_glass(req.request_id, "s2", "sig2")
    bg_env.activate_break_glass(req.request_id)
    bg_env.close_break_glass(req.request_id)
    loaded = bg_env._load(req.request_id)
    assert loaded.status == "CLOSED"


def test_close_nonexistent_is_noop(bg_env):
    bg_env.close_break_glass("does-not-exist")  # must not raise


def test_audit_file_written(bg_env, tmp_path):
    import json
    req = bg_env.initiate_break_glass(
        community_id="test-community-01", kid="v1",
        reason="audit-test", requested_by="a@b", tenant_tier="mcp",
    )
    lines = open(bg_env._AUDIT_LOG_PATH).readlines()
    assert len(lines) >= 1
    entry = json.loads(lines[0])
    assert entry["event"] == "INITIATED"
    assert entry["request_id"] == req.request_id


def test_activate_missing_archive_entry(bg_env):
    req = bg_env.initiate_break_glass(
        community_id="test-community-01", kid="v99",  # no such key in archive
        reason="test", requested_by="a@b", tenant_tier="mcp",
    )
    bg_env.sign_break_glass(req.request_id, "s1", "sig1")
    bg_env.sign_break_glass(req.request_id, "s2", "sig2")
    with pytest.raises(ValueError, match="not found"):
        bg_env.activate_break_glass(req.request_id)


def test_activate_shredded_key(bg_env, archive_db, sample_keypair):
    archive_db.crypto_shred("test-community-01", "v1")
    req = bg_env.initiate_break_glass(
        community_id="test-community-01", kid="v1",
        reason="test", requested_by="a@b", tenant_tier="mcp",
    )
    bg_env.sign_break_glass(req.request_id, "s1", "sig1")
    bg_env.sign_break_glass(req.request_id, "s2", "sig2")
    with pytest.raises(ValueError, match="shredded|permanently"):
        bg_env.activate_break_glass(req.request_id)
