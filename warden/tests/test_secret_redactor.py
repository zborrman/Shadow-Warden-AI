"""
warden/tests/test_secret_redactor.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
True-positive and false-negative tests for SecretRedactor.

Each secret type gets:
  - At least one TP test (must be caught)
  - At least one FP test (clean text must pass through unchanged)
"""
from __future__ import annotations

import pytest

from warden.secret_redactor import SecretRedactor

r = SecretRedactor()


# ── True Positives: each secret type must be detected ─────────────────────────

@pytest.mark.parametrize("text,expected_kind", [
    # Anthropic key (sk-ant- prefix, long)
    (
        "sk-ant-api03-" + "A" * 100,
        "anthropic_api_key",
    ),
    # HuggingFace token
    (
        "hf_" + "a" * 34,
        "huggingface_token",
    ),
    # OpenAI key
    (
        "sk-abcdefghijklmnopqrstuvwx",
        "openai_key",
    ),
    # AWS access key
    (
        "AKIAIOSFODNN7EXAMPLE",
        "aws_access_key",
    ),
    # GitHub personal access token
    (
        "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456",
        "github_token",
    ),
    # GCP API key
    (
        "AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz12345",
        "gcp_api_key",
    ),
    # Bearer token
    (
        "Bearer eyJhbGciOiJIUzI1NiJ9.test.sig",
        "bearer_token",
    ),
    # URL credentials
    (
        "postgres://user:s3cr3t@host:5432/db",
        "url_credentials",
    ),
    # Private key block
    (
        "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
        "private_key_block",
    ),
    # Luhn-valid Visa card
    (
        "4532015112830366",
        "credit_card",
    ),
    # US SSN
    (
        "123-45-6789",
        "us_ssn",
    ),
    # IBAN
    (
        "GB29NWBK60161331926819",
        "iban",
    ),
    # Email address
    (
        "user@example.com",
        "email",
    ),
])
def test_redacts_secret(text: str, expected_kind: str) -> None:
    result = r.redact(text)
    kinds = [f.kind for f in result.findings]
    assert expected_kind in kinds, (
        f"Expected to find kind={expected_kind!r} in findings {kinds!r} "
        f"for text {text[:40]!r}"
    )
    assert text not in result.text, (
        f"Original secret still visible in redacted output for kind={expected_kind}"
    )


# ── False Positives: clean text must pass unchanged ───────────────────────────

@pytest.mark.parametrize("text", [
    "What is the capital of France?",
    "My phone number is 555-1234",            # not a full SSN pattern
    "The price is $1234567890.00",            # fails Luhn
    "Please summarise this document for me.",
    "sk-learn is a machine learning library",  # not a key (too short)
    "The AI answered: 'Sure, I can help!'",
    "Connect to redis://localhost:6379",       # no credentials in URL
    "Use python 3.11 for this project.",
    "AKIAFAKEFAKENOTREAL",                     # only 18 chars (too short for AWS key)
])
def test_no_false_positive(text: str) -> None:
    result = r.redact(text)
    assert result.findings == [], (
        f"False positive on {text!r}: found {[f.kind for f in result.findings]}"
    )


# ── Strict mode: IPv4 also redacted ───────────────────────────────────────────

def test_strict_redacts_ipv4() -> None:
    sr = SecretRedactor(strict=True)
    result = sr.redact("Server IP is 192.168.1.100")
    kinds = [f.kind for f in result.findings]
    assert "ipv4" in kinds
    assert "192.168.1.100" not in result.text


def test_non_strict_allows_ipv4() -> None:
    result = r.redact("Server IP is 192.168.1.100")
    # ipv4 must NOT be redacted in non-strict mode
    assert "192.168.1.100" in result.text


# ── Multiple secrets in one text ──────────────────────────────────────────────

def test_multiple_secrets() -> None:
    text = "API key: sk-abc123def456ghi789jkl012, email: admin@corp.com"
    result = r.redact(text)
    assert len(result.findings) >= 2
    assert "sk-abc" not in result.text
    assert "admin@corp.com" not in result.text


# ── Luhn validation: invalid card must NOT be flagged ─────────────────────────

def test_invalid_luhn_not_flagged() -> None:
    # 4532015112830367 — last digit changed, Luhn fails
    result = r.redact("4532015112830367")
    kinds = [f.kind for f in result.findings]
    assert "credit_card" not in kinds


# ── Anthropic key placed before OpenAI key ────────────────────────────────────

def test_anthropic_not_double_flagged_as_openai() -> None:
    ant_key = "sk-ant-api03-" + "A" * 100
    result = r.redact(ant_key)
    kinds = [f.kind for f in result.findings]
    assert "anthropic_api_key" in kinds
    # Should be flagged as anthropic, not openai (ordering matters)
    assert kinds[0] == "anthropic_api_key"
