"""
warden/tests/test_auth_guard.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Unit tests for warden.auth_guard — focusing on the rate_limit field
that flows from the JSON key store through _KeyEntry → AuthResult.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import warden.auth_guard as ag

# ── Helpers ───────────────────────────────────────────────────────────────────

def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _write_key_file(tmp_path: Path, keys: list[dict]) -> str:
    p = tmp_path / "keys.json"
    p.write_text(json.dumps({"keys": keys}))
    return str(p)


def _reset_store():
    """Clear the module-level key store cache between tests."""
    ag._key_store.clear()
    ag._key_store_loaded = False


# ── _KeyEntry defaults ────────────────────────────────────────────────────────

def test_key_entry_default_rate_limit():
    entry = ag._KeyEntry(
        key_hash="abc", tenant_id="t1", label="test", active=True
    )
    assert entry.rate_limit == 60


def test_key_entry_custom_rate_limit():
    entry = ag._KeyEntry(
        key_hash="abc", tenant_id="t1", label="test", active=True, rate_limit=300
    )
    assert entry.rate_limit == 300


# ── _load_key_store reads rate_limit ─────────────────────────────────────────

def test_load_key_store_reads_rate_limit(tmp_path, monkeypatch):
    _reset_store()
    key_file = _write_key_file(tmp_path, [
        {"key_hash": _sha256("secret"), "tenant_id": "acme",
         "label": "prod", "active": True, "rate_limit": 200},
    ])
    monkeypatch.setattr(ag, "_KEYS_PATH", key_file)

    store = ag._load_key_store()
    assert len(store) == 1
    assert store[0].rate_limit == 200


def test_load_key_store_default_rate_limit_when_missing(tmp_path, monkeypatch):
    _reset_store()
    key_file = _write_key_file(tmp_path, [
        {"key_hash": _sha256("secret"), "tenant_id": "acme",
         "label": "prod", "active": True},   # no rate_limit field
    ])
    monkeypatch.setattr(ag, "_KEYS_PATH", key_file)
    monkeypatch.setattr(ag, "_DEFAULT_KEY_RATE", 42)

    store = ag._load_key_store()
    assert store[0].rate_limit == 42


# ── AuthResult carries rate_limit ─────────────────────────────────────────────

def test_auth_result_default_rate_limit():
    result = ag.AuthResult(api_key="k", tenant_id="t")
    assert result.rate_limit == 60


def test_auth_result_custom_rate_limit():
    result = ag.AuthResult(api_key="k", tenant_id="t", rate_limit=150)
    assert result.rate_limit == 150


# ── require_api_key propagates rate_limit ────────────────────────────────────

def test_dev_mode_uses_default_rate(monkeypatch):
    """Dev mode (no keys configured) returns _DEFAULT_KEY_RATE."""
    monkeypatch.setattr(ag, "_VALID_KEY", "")
    monkeypatch.setattr(ag, "_KEYS_PATH", "")
    monkeypatch.setattr(ag, "_DEFAULT_KEY_RATE", 99)

    result = ag.require_api_key(api_key=None)
    assert result.tenant_id == "default"
    assert result.rate_limit == 99


def test_single_shared_key_uses_default_rate(monkeypatch):
    """Single-key mode returns _DEFAULT_KEY_RATE."""
    monkeypatch.setattr(ag, "_VALID_KEY", "mysecret")
    monkeypatch.setattr(ag, "_KEYS_PATH", "")
    monkeypatch.setattr(ag, "_DEFAULT_KEY_RATE", 77)

    result = ag.require_api_key(api_key="mysecret")
    assert result.rate_limit == 77


def test_multi_key_uses_per_key_rate_limit(tmp_path, monkeypatch):
    """Multi-key mode returns the individual key's rate_limit."""
    _reset_store()
    api_key = "premium-key"
    key_file = _write_key_file(tmp_path, [
        {"key_hash": _sha256(api_key), "tenant_id": "premium",
         "label": "premium tier", "active": True, "rate_limit": 500},
    ])
    monkeypatch.setattr(ag, "_VALID_KEY", "")
    monkeypatch.setattr(ag, "_KEYS_PATH", key_file)

    result = ag.require_api_key(api_key=api_key)
    assert result.tenant_id == "premium"
    assert result.rate_limit == 500


def test_multi_key_inactive_falls_through_to_401(tmp_path, monkeypatch):
    """Inactive keys are not matched; 401 is raised."""
    from fastapi import HTTPException
    _reset_store()
    api_key = "inactive-key"
    key_file = _write_key_file(tmp_path, [
        {"key_hash": _sha256(api_key), "tenant_id": "gone",
         "label": "revoked", "active": False, "rate_limit": 100},
    ])
    monkeypatch.setattr(ag, "_VALID_KEY", "")
    monkeypatch.setattr(ag, "_KEYS_PATH", key_file)

    with pytest.raises(HTTPException) as exc_info:
        ag.require_api_key(api_key=api_key)
    assert exc_info.value.status_code == 401


def test_different_keys_different_rate_limits(tmp_path, monkeypatch):
    """Each key can have an independent rate_limit."""
    _reset_store()
    keys = [
        {"key_hash": _sha256("trial-key"),   "tenant_id": "trial",
         "label": "trial",   "active": True, "rate_limit": 10},
        {"key_hash": _sha256("pro-key"),     "tenant_id": "pro",
         "label": "pro",     "active": True, "rate_limit": 600},
    ]
    key_file = _write_key_file(tmp_path, keys)
    monkeypatch.setattr(ag, "_VALID_KEY", "")
    monkeypatch.setattr(ag, "_KEYS_PATH", key_file)

    trial  = ag.require_api_key(api_key="trial-key")
    pro    = ag.require_api_key(api_key="pro-key")

    assert trial.rate_limit == 10
    assert pro.rate_limit   == 600


# ── _load_key_store edge cases ────────────────────────────────────────────────

def test_load_key_store_empty_path_returns_empty(monkeypatch):
    """No WARDEN_API_KEYS_PATH configured → empty store, no error."""
    _reset_store()
    monkeypatch.setattr(ag, "_KEYS_PATH", "")
    assert ag._load_key_store() == []


def test_load_key_store_missing_file_disables_multikey(tmp_path, monkeypatch):
    """A configured-but-nonexistent key file must not crash — multi-key stays empty."""
    _reset_store()
    monkeypatch.setattr(ag, "_KEYS_PATH", str(tmp_path / "does-not-exist.json"))
    assert ag._load_key_store() == []


def test_load_key_store_malformed_json_is_swallowed(tmp_path, monkeypatch):
    """Corrupt key file must fail-safe to an empty store, not raise."""
    _reset_store()
    p = tmp_path / "keys.json"
    p.write_text("{ this is not valid json ]")
    monkeypatch.setattr(ag, "_KEYS_PATH", str(p))
    assert ag._load_key_store() == []


def test_load_key_store_is_memoized(tmp_path, monkeypatch):
    """Second call returns the cached store without re-reading the file."""
    _reset_store()
    key_file = _write_key_file(tmp_path, [
        {"key_hash": _sha256("k"), "tenant_id": "t", "label": "", "active": True},
    ])
    monkeypatch.setattr(ag, "_KEYS_PATH", key_file)
    first = ag._load_key_store()
    assert len(first) == 1
    # Truncate the file; a memoized store must not notice.
    Path(key_file).write_text("{}")
    assert ag._load_key_store() is first


# ── resolve_tenant_id ─────────────────────────────────────────────────────────

def test_resolve_tenant_id_dev_mode_returns_none(monkeypatch):
    monkeypatch.setattr(ag, "_VALID_KEY", "")
    monkeypatch.setattr(ag, "_KEYS_PATH", "")
    assert ag.resolve_tenant_id("anything") is None


def test_resolve_tenant_id_missing_key_returns_none(monkeypatch):
    monkeypatch.setattr(ag, "_VALID_KEY", "secret")
    monkeypatch.setattr(ag, "_KEYS_PATH", "")
    assert ag.resolve_tenant_id(None) is None


def test_resolve_tenant_id_single_key(monkeypatch):
    monkeypatch.setattr(ag, "_VALID_KEY", "secret")
    monkeypatch.setattr(ag, "_KEYS_PATH", "")
    assert ag.resolve_tenant_id("secret") == "default"
    assert ag.resolve_tenant_id("wrong") is None


def test_resolve_tenant_id_multi_key(tmp_path, monkeypatch):
    _reset_store()
    key_file = _write_key_file(tmp_path, [
        {"key_hash": _sha256("acme-key"), "tenant_id": "acme",
         "label": "", "active": True},
    ])
    monkeypatch.setattr(ag, "_VALID_KEY", "")
    monkeypatch.setattr(ag, "_KEYS_PATH", key_file)
    assert ag.resolve_tenant_id("acme-key") == "acme"
    assert ag.resolve_tenant_id("unknown-key") is None


# ── reload_keys ───────────────────────────────────────────────────────────────

def test_reload_keys_picks_up_new_file_contents(tmp_path, monkeypatch):
    """reload_keys clears the memoized store and re-reads from disk."""
    _reset_store()
    key_file = _write_key_file(tmp_path, [
        {"key_hash": _sha256("one"), "tenant_id": "t1", "label": "", "active": True},
    ])
    monkeypatch.setattr(ag, "_KEYS_PATH", key_file)
    assert ag.reload_keys() == 1

    # Add a second key on disk, then force a reload.
    _write_key_file(tmp_path, [
        {"key_hash": _sha256("one"), "tenant_id": "t1", "label": "", "active": True},
        {"key_hash": _sha256("two"), "tenant_id": "t2", "label": "", "active": True},
    ])
    assert ag.reload_keys() == 2


# ── set_default_rate_limit ────────────────────────────────────────────────────

def test_set_default_rate_limit_updates_box_and_env(monkeypatch):
    monkeypatch.delenv("RATE_LIMIT_PER_MINUTE", raising=False)
    monkeypatch.setattr(ag, "_rate_limit_box", [60])   # isolate from global state
    ag.set_default_rate_limit(123)
    assert ag._rate_limit_box[0] == 123
    assert ag.os.environ["RATE_LIMIT_PER_MINUTE"] == "123"


def test_set_default_rate_limit_floors_at_one(monkeypatch):
    monkeypatch.delenv("RATE_LIMIT_PER_MINUTE", raising=False)
    monkeypatch.setattr(ag, "_rate_limit_box", [60])
    ag.set_default_rate_limit(0)
    assert ag._rate_limit_box[0] == 1


# ── require_api_key missing-key 401 ───────────────────────────────────────────

def test_require_api_key_missing_header_raises_401(monkeypatch):
    from fastapi import HTTPException
    monkeypatch.setattr(ag, "_VALID_KEY", "secret")
    monkeypatch.setattr(ag, "_KEYS_PATH", "")
    with pytest.raises(HTTPException) as exc:
        ag.require_api_key(api_key=None)
    assert exc.value.status_code == 401


# ── tier_header_trusted ───────────────────────────────────────────────────────

def test_tier_header_trusted_when_unauthenticated_allowed(monkeypatch):
    monkeypatch.setattr(ag.settings, "allow_unauthenticated", True)
    assert ag.tier_header_trusted() is True


def test_tier_header_trusted_false_in_production(monkeypatch):
    """Real key configured + auth enforced → client X-Tenant-Tier must be ignored."""
    monkeypatch.setattr(ag.settings, "allow_unauthenticated", False)
    monkeypatch.setattr(ag, "_VALID_KEY", "secret")
    monkeypatch.setattr(ag, "_KEYS_PATH", "")
    assert ag.tier_header_trusted() is False


def test_tier_header_trusted_in_dev_mode(monkeypatch):
    monkeypatch.setattr(ag.settings, "allow_unauthenticated", False)
    monkeypatch.setattr(ag, "_VALID_KEY", "")
    monkeypatch.setattr(ag, "_KEYS_PATH", "")
    assert ag.tier_header_trusted() is True


# ── get_rate_limit ────────────────────────────────────────────────────────────

def test_get_rate_limit_empty_key_is_default(monkeypatch):
    monkeypatch.setattr(ag, "_rate_limit_box", [55])
    assert ag.get_rate_limit("") == 55


def test_get_rate_limit_multi_key(tmp_path, monkeypatch):
    _reset_store()
    key_file = _write_key_file(tmp_path, [
        {"key_hash": _sha256("fast-key"), "tenant_id": "fast",
         "label": "", "active": True, "rate_limit": 999},
    ])
    monkeypatch.setattr(ag, "_VALID_KEY", "")
    monkeypatch.setattr(ag, "_KEYS_PATH", key_file)
    assert ag.get_rate_limit("fast-key") == 999


def test_get_rate_limit_single_key_and_unknown(monkeypatch):
    monkeypatch.setattr(ag, "_VALID_KEY", "secret")
    monkeypatch.setattr(ag, "_KEYS_PATH", "")
    monkeypatch.setattr(ag, "_rate_limit_box", [88])
    assert ag.get_rate_limit("secret") == 88
    assert ag.get_rate_limit("nope") == 88   # unknown → default


# ── require_ext_auth (hybrid OIDC / API-key) ──────────────────────────────────

def test_require_ext_auth_bearer_uses_oidc(monkeypatch):
    """A Bearer token routes through Warden Identity (OIDC) and never logs raw email."""
    import warden.auth.oidc_guard as oidc
    monkeypatch.setattr(oidc, "verify_oidc_token", lambda tok: ("acme-tenant", "user@acme.com"))
    result = ag.require_ext_auth(x_api_key=None, authorization="Bearer abc.def.ghi")
    assert result.tenant_id == "acme-tenant"
    assert result.api_key == ""
    assert result.entity_key  # GDPR-safe hash, non-empty


def test_require_ext_auth_falls_back_to_api_key(monkeypatch):
    """No Bearer header → classic API-key auth path."""
    monkeypatch.setattr(ag, "_VALID_KEY", "secret")
    monkeypatch.setattr(ag, "_KEYS_PATH", "")
    result = ag.require_ext_auth(x_api_key="secret", authorization=None)
    assert result.tenant_id == "default"
