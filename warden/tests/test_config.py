"""Deep-Eng P1 — typed config validation + auditable redacted dump.

Tests construct Settings with explicit kwargs rather than relying on ambient env
(conftest sets ALLOW_UNAUTHENTICATED=true etc.), so they are deterministic.
"""
from __future__ import annotations

import pytest

from warden.config import ConfigValidationError, Settings


def test_failclosed_auth_gap_flagged():
    s = Settings(warden_api_key="", warden_api_keys_path="", allow_unauthenticated=False)
    assert any("fail closed at auth" in p for p in s.validate())


def test_dev_config_is_clean():
    s = Settings(allow_unauthenticated=True, vault_master_key="")
    assert s.validate() == []


def test_out_of_range_threshold_flagged():
    s = Settings(allow_unauthenticated=True)
    s.semantic_threshold = 1.5
    assert any("semantic_threshold" in p for p in s.validate())


def test_nonpositive_timeout_flagged():
    s = Settings(allow_unauthenticated=True)
    s.nim_timeout_seconds = 0
    assert any("nim_timeout_seconds" in p for p in s.validate())


def test_invalid_fernet_key_flagged():
    s = Settings(allow_unauthenticated=True, vault_master_key="not-a-valid-fernet-key")
    assert any("VAULT_MASTER_KEY" in p for p in s.validate())


def test_valid_fernet_key_ok():
    from cryptography.fernet import Fernet
    s = Settings(allow_unauthenticated=True, vault_master_key=Fernet.generate_key().decode())
    assert s.validate() == []


def test_redacted_dump_masks_secrets():
    s = Settings(warden_api_key="sk-supersecret", anthropic_api_key="sk-ant-xyz")
    d = s.redacted_dump()
    assert d["warden_api_key"] == "***set***"
    assert d["anthropic_api_key"] == "***set***"
    assert d["semantic_threshold"] == s.semantic_threshold          # non-secret passes through
    assert Settings(slack_webhook_url="").redacted_dump()["slack_webhook_url"] == ""  # empty not masked


def test_validate_or_raise():
    s = Settings(allow_unauthenticated=True)
    s.phish_url_threshold = 9.0
    with pytest.raises(ConfigValidationError):
        s.validate_or_raise()
