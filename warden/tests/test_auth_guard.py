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
