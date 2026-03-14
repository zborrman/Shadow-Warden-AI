"""
warden/tests/test_per_tenant_rate_limit.py
──────────────────────────────────────────
Unit tests for per-tenant rate limiting.

Covers:
  - get_rate_limit() returns per-key configured value
  - get_rate_limit() falls back to default for unknown keys
  - _tenant_key() returns API key header when present, IP as fallback
  - _tenant_limit() returns per-tenant limit string
  - MTLSMiddleware is bypassed (MTLS_ENABLED=false in conftest)
"""
from __future__ import annotations

import hashlib
from unittest.mock import MagicMock

# ── auth_guard.get_rate_limit ──────────────────────────────────────────────

class TestGetRateLimit:
    def test_empty_key_returns_default(self):
        from warden.auth_guard import _DEFAULT_KEY_RATE, get_rate_limit
        assert get_rate_limit("") == _DEFAULT_KEY_RATE

    def test_unknown_key_returns_default(self):
        from warden.auth_guard import _DEFAULT_KEY_RATE, get_rate_limit
        assert get_rate_limit("not-a-real-key-xyzxyz") == _DEFAULT_KEY_RATE

    def test_single_shared_key_returns_default(self, monkeypatch):
        """WARDEN_API_KEY set → matched key returns _DEFAULT_KEY_RATE."""
        from warden import auth_guard
        monkeypatch.setattr(auth_guard, "_VALID_KEY", "shared-secret")
        monkeypatch.setattr(auth_guard, "_KEYS_PATH", "")
        from warden.auth_guard import _DEFAULT_KEY_RATE, get_rate_limit
        assert get_rate_limit("shared-secret") == _DEFAULT_KEY_RATE

    def test_multi_key_returns_configured_rate(self, monkeypatch, tmp_path):
        """Key with rate_limit:200 in JSON store → returns 200."""
        import json

        from warden import auth_guard

        raw_key = "tenant-a-secret"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        keys_file = tmp_path / "keys.json"
        keys_file.write_text(json.dumps({
            "keys": [{"key_hash": key_hash, "tenant_id": "acme", "label": "",
                      "active": True, "rate_limit": 200}]
        }))

        monkeypatch.setattr(auth_guard, "_KEYS_PATH", str(keys_file))
        monkeypatch.setattr(auth_guard, "_key_store", [])
        monkeypatch.setattr(auth_guard, "_key_store_loaded", False)

        from warden.auth_guard import get_rate_limit
        assert get_rate_limit(raw_key) == 200

    def test_multi_key_different_tenants(self, monkeypatch, tmp_path):
        """Different keys → different rate limits."""
        import json

        from warden import auth_guard

        key_a, key_b = "key-alpha", "key-beta"
        hash_a = hashlib.sha256(key_a.encode()).hexdigest()
        hash_b = hashlib.sha256(key_b.encode()).hexdigest()
        keys_file = tmp_path / "keys.json"
        keys_file.write_text(json.dumps({
            "keys": [
                {"key_hash": hash_a, "tenant_id": "free", "label": "",
                 "active": True, "rate_limit": 30},
                {"key_hash": hash_b, "tenant_id": "enterprise", "label": "",
                 "active": True, "rate_limit": 500},
            ]
        }))

        monkeypatch.setattr(auth_guard, "_KEYS_PATH", str(keys_file))
        monkeypatch.setattr(auth_guard, "_key_store", [])
        monkeypatch.setattr(auth_guard, "_key_store_loaded", False)

        from warden.auth_guard import get_rate_limit
        assert get_rate_limit(key_a) == 30
        assert get_rate_limit(key_b) == 500

    def test_revoked_key_returns_default(self, monkeypatch, tmp_path):
        """Revoked key (active=false) is not matched → returns default."""
        import json

        from warden import auth_guard

        raw_key = "revoked-key"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        keys_file = tmp_path / "keys.json"
        keys_file.write_text(json.dumps({
            "keys": [{"key_hash": key_hash, "tenant_id": "gone", "label": "",
                      "active": False, "rate_limit": 999}]
        }))

        monkeypatch.setattr(auth_guard, "_KEYS_PATH", str(keys_file))
        monkeypatch.setattr(auth_guard, "_key_store", [])
        monkeypatch.setattr(auth_guard, "_key_store_loaded", False)

        from warden.auth_guard import _DEFAULT_KEY_RATE, get_rate_limit
        assert get_rate_limit(raw_key) == _DEFAULT_KEY_RATE


# ── main._tenant_key and _tenant_limit ────────────────────────────────────

class TestTenantKeyFunc:
    def _make_request(self, headers: dict) -> MagicMock:
        req = MagicMock()
        req.headers = headers
        req.client = MagicMock()
        req.client.host = "10.0.0.1"
        return req

    def test_returns_api_key_when_present(self):
        from warden.main import _tenant_key
        req = self._make_request({"x-api-key": "my-key-123"})
        assert _tenant_key(req) == "my-key-123"

    def test_falls_back_to_ip_when_no_key(self):
        from warden.main import _tenant_key
        req = self._make_request({})
        assert _tenant_key(req) == "10.0.0.1"

    def test_empty_key_header_falls_back_to_ip(self):
        from warden.main import _tenant_key
        req = self._make_request({"x-api-key": ""})
        assert _tenant_key(req) == "10.0.0.1"


class TestTenantLimitFunc:
    """
    _tenant_limit(key: str) receives the value from _tenant_key (API key or IP).
    slowapi calls it as limit_func(key_func(request)) when the parameter is
    named 'key' — see LimitGroup.__iter__ in slowapi/wrappers.py.
    """

    def test_returns_default_for_unknown_key(self):
        from warden.auth_guard import _DEFAULT_KEY_RATE
        from warden.main import _tenant_limit
        assert _tenant_limit("unknown-xyz") == f"{_DEFAULT_KEY_RATE}/minute"

    def test_returns_default_for_ip_fallback(self):
        from warden.auth_guard import _DEFAULT_KEY_RATE
        from warden.main import _tenant_limit
        assert _tenant_limit("192.168.1.1") == f"{_DEFAULT_KEY_RATE}/minute"

    def test_returns_configured_rate_for_known_key(self, monkeypatch, tmp_path):
        import json

        from warden import auth_guard

        raw_key = "enterprise-key"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        keys_file = tmp_path / "keys.json"
        keys_file.write_text(json.dumps({
            "keys": [{"key_hash": key_hash, "tenant_id": "bigcorp", "label": "",
                      "active": True, "rate_limit": 300}]
        }))
        monkeypatch.setattr(auth_guard, "_KEYS_PATH", str(keys_file))
        monkeypatch.setattr(auth_guard, "_key_store", [])
        monkeypatch.setattr(auth_guard, "_key_store_loaded", False)

        from warden.main import _tenant_limit
        assert _tenant_limit(raw_key) == "300/minute"

    def test_format_is_slowapi_compatible(self):
        """Verify the string matches the `N/minute` format slowapi expects."""
        from warden.main import _tenant_limit
        result = _tenant_limit("")
        parts = result.split("/")
        assert len(parts) == 2
        assert parts[0].isdigit()
        assert parts[1] == "minute"
