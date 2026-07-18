"""
FT-3a — key hygiene for AP2 mandate-vault encryption (`agentic_commerce/ap2.py`).

Regression tests for a silent data-loss + fail-open-crypto bug: the Fernet cipher
was built at *import* time as

    _vault_key = os.getenv("VAULT_MASTER_KEY", "")
    _FERNET    = Fernet(_vault_key.encode() if _vault_key else Fernet.generate_key())

Two defects:
  1. Import-time snapshot — the key was captured before the env was populated
     (violates the Phase-7 "resolve keys per call" rule).
  2. Random fallback — with no VAULT_MASTER_KEY, a fresh ephemeral key was minted
     on every process start, so every stored mandate became undecryptable after
     a restart, with no error.

`_fernet()` now resolves per call, is backward-compatible when VAULT_MASTER_KEY is
set, derives a deterministic dev key otherwise, and fails CLOSED in production.
"""
from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from warden.business_community.agentic_commerce import ap2
from warden.secret_keys import InsecureKeyError

_VALID_FERNET_KEY = Fernet.generate_key().decode()


class TestBackwardCompatibleWithMasterKey:
    def test_roundtrip_with_vault_master_key(self, monkeypatch):
        monkeypatch.setenv("VAULT_MASTER_KEY", _VALID_FERNET_KEY)
        blob = ap2._encrypt({"amount": 10, "sku": "x"})
        assert ap2._decrypt(blob) == {"amount": 10, "sku": "x"}

    def test_key_is_vault_master_key_verbatim(self, monkeypatch):
        """A blob written under Fernet(VAULT_MASTER_KEY) — the pre-fix scheme —
        must still decrypt, proving no key derivation was introduced for the
        production (key-set) path."""
        monkeypatch.setenv("VAULT_MASTER_KEY", _VALID_FERNET_KEY)
        legacy = Fernet(_VALID_FERNET_KEY.encode()).encrypt(b'{"v": 1}')
        assert ap2._decrypt(legacy) == {"v": 1}


class TestNoRandomFallbackNoSnapshot:
    def test_key_stable_across_calls_simulating_restart(self, monkeypatch):
        """Two independent _fernet() resolutions must produce interoperable
        ciphers — the old random fallback failed exactly this."""
        monkeypatch.delenv("VAULT_MASTER_KEY", raising=False)
        monkeypatch.delenv("COMMUNITY_VAULT_KEY", raising=False)
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED", "true")  # dev mode → deterministic key
        blob = ap2._fernet().encrypt(b"payload")
        assert ap2._fernet().decrypt(blob) == b"payload"

    def test_resolution_is_per_call_not_import(self, monkeypatch):
        """Changing the env after import must change the cipher — proves the key
        is no longer snapshotted at module load."""
        monkeypatch.setenv("VAULT_MASTER_KEY", _VALID_FERNET_KEY)
        blob = ap2._encrypt({"a": 1})
        other = Fernet.generate_key().decode()
        monkeypatch.setenv("VAULT_MASTER_KEY", other)
        with pytest.raises(Exception):  # noqa: B017 — InvalidToken under the new key
            ap2._decrypt(blob)


class TestFailClosedInProduction:
    def test_no_key_and_not_dev_raises(self, monkeypatch):
        monkeypatch.delenv("VAULT_MASTER_KEY", raising=False)
        monkeypatch.delenv("COMMUNITY_VAULT_KEY", raising=False)
        monkeypatch.delenv("AP2_VAULT_KEY", raising=False)
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED", "false")
        monkeypatch.setenv("ALLOW_INSECURE_SECRETS", "false")
        with pytest.raises(InsecureKeyError):
            ap2._encrypt({"amount": 1})


class TestExplicitOverride:
    def test_ap2_vault_key_derives_valid_fernet(self, monkeypatch):
        """When only the derived path is used, the result is a valid Fernet key
        (32 url-safe base64 bytes) and round-trips."""
        monkeypatch.delenv("VAULT_MASTER_KEY", raising=False)
        monkeypatch.delenv("COMMUNITY_VAULT_KEY", raising=False)
        monkeypatch.setenv("AP2_VAULT_KEY", "an-explicit-operator-override-secret")
        cipher = ap2._fernet()
        blob = cipher.encrypt(b"z")
        assert ap2._fernet().decrypt(blob) == b"z"
