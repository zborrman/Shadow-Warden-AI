"""
warden/auth_guard.py
━━━━━━━━━━━━━━━━━━━
Per-tenant API-key authentication for the Warden gateway.

Key store
─────────
  • Single-key mode (env var): set WARDEN_API_KEY to a shared secret.
    All requests using that key are mapped to tenant_id="default".
  • Multi-key mode (JSON file): set WARDEN_API_KEYS_PATH to a JSON file
    containing an array of key objects.  Each key is mapped to a tenant_id
    and can be individually rotated (active/revoked).

Dev mode: both env var and file path unset → all requests pass through
with tenant_id="default".

JSON key file format::

    {
      "keys": [
        {
          "key_hash": "<sha256 hex digest of the API key>",
          "tenant_id": "acme-corp",
          "label": "production key",
          "active": true,
          "created_at": "2025-01-01T00:00:00Z",
          "rotated_at": null
        }
      ]
    }

Generate a key hash::

    python -c "import hashlib; print(hashlib.sha256(b'your-api-key').hexdigest())"
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

log = logging.getLogger("warden.auth")

_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

# ── Single shared key (backwards compatible) ─────────────────────────────────
_VALID_KEY: str = os.getenv("WARDEN_API_KEY", "")

# ── Multi-key file ───────────────────────────────────────────────────────────
_KEYS_PATH: str = os.getenv("WARDEN_API_KEYS_PATH", "")

MAX_KEYS = 1000  # safety cap


@dataclass(frozen=True)
class _KeyEntry:
    key_hash:  str
    tenant_id: str
    label:     str
    active:    bool


_key_store: list[_KeyEntry] = []
_key_store_loaded = False


def _load_key_store() -> list[_KeyEntry]:
    """Load multi-tenant key store from JSON file.  Called once on first auth."""
    global _key_store_loaded
    if _key_store_loaded:
        return _key_store

    _key_store_loaded = True

    if not _KEYS_PATH:
        return _key_store

    path = Path(_KEYS_PATH)
    if not path.exists():
        log.warning("WARDEN_API_KEYS_PATH=%s does not exist — multi-key auth disabled.", _KEYS_PATH)
        return _key_store

    try:
        data = json.loads(path.read_text())
        for entry in data.get("keys", [])[:MAX_KEYS]:
            _key_store.append(_KeyEntry(
                key_hash=entry["key_hash"],
                tenant_id=entry.get("tenant_id", "default"),
                label=entry.get("label", ""),
                active=entry.get("active", True),
            ))
        log.info("Loaded %d API key(s) from %s", len(_key_store), _KEYS_PATH)
    except Exception:
        log.exception("Failed to load API keys from %s", _KEYS_PATH)

    return _key_store


def _lookup_multi_key(api_key: str) -> _KeyEntry | None:
    """Check api_key against the multi-key store.  Returns the matching entry or None."""
    incoming_hash = hashlib.sha256(api_key.encode()).hexdigest()
    store = _load_key_store()
    for entry in store:
        if hmac.compare_digest(incoming_hash, entry.key_hash) and entry.active:
            return entry
    return None


@dataclass(frozen=True)
class AuthResult:
    """Returned by require_api_key — carries the resolved tenant_id."""
    api_key:   str
    tenant_id: str


def require_api_key(api_key: str | None = Security(_API_KEY_HEADER)) -> AuthResult:
    """
    FastAPI Security dependency.

    Resolution order:
      1. Multi-key file (WARDEN_API_KEYS_PATH) — SHA-256 hash lookup
      2. Single shared key (WARDEN_API_KEY) — constant-time compare
      3. Dev mode (both unset) — all requests pass
    """
    # Dev / air-gapped mode
    if not _VALID_KEY and not _KEYS_PATH:
        return AuthResult(api_key="", tenant_id="default")

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # 1. Try multi-key store
    if _KEYS_PATH:
        entry = _lookup_multi_key(api_key)
        if entry:
            return AuthResult(api_key=api_key, tenant_id=entry.tenant_id)

    # 2. Single shared key
    if _VALID_KEY and hmac.compare_digest(api_key.encode(), _VALID_KEY.encode()):
        return AuthResult(api_key=api_key, tenant_id="default")

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing X-API-Key header.",
        headers={"WWW-Authenticate": "ApiKey"},
    )


def reload_keys() -> int:
    """Force-reload the key store from disk.  Returns the new key count."""
    global _key_store_loaded
    _key_store.clear()
    _key_store_loaded = False
    _load_key_store()
    return len(_key_store)
