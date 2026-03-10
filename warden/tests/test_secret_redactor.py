"""
warden/tests/test_secret_redactor.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
True-positive and false-negative tests for SecretRedactor.

Each secret type gets:
  - At least one TP test (must be caught)
  - At least one FP test (clean text must pass through unchanged)

Redaction policy tests cover FULL / MASKED / RAW for every secret category.
"""
from __future__ import annotations

import re

import pytest

from warden.schemas import RedactionPolicy
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
    # Phone number (US with country code)
    (
        "+1 (555) 867-5309",
        "phone_number",
    ),
    # Ethereum address
    (
        "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
        "ethereum_address",
    ),
    # Bitcoin P2PKH address
    (
        "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
        "bitcoin_address",
    ),
    # Bitcoin P2SH address
    (
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
        "bitcoin_address",
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


# ═══════════════════════════════════════════════════════════════════════════════
# RedactionPolicy tests
# ═══════════════════════════════════════════════════════════════════════════════

# ── FULL policy: same as default behaviour ────────────────────────────────────

@pytest.mark.parametrize("text,kind", [
    ("sk-abcdefghijklmnopqrstuvwx",       "openai_key"),
    ("4532015112830366",                   "credit_card"),
    ("user@example.com",                   "email"),
    ("123-45-6789",                        "us_ssn"),
    ("GB29NWBK60161331926819",             "iban"),
    ("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456", "github_token"),
    ("Bearer eyJhbGciOiJIUzI1NiJ9.t.s",   "bearer_token"),
    ("postgres://user:s3cr3t@host/db",     "url_credentials"),
    (
        "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
        "private_key_block",
    ),
])
def test_full_policy_replaces_secret(text: str, kind: str) -> None:
    result = r.redact(text, RedactionPolicy.FULL)
    assert result.findings, f"No findings for kind={kind!r}"
    assert text not in result.text, "Original secret must not appear in output"
    assert result.findings[0].redacted_to.startswith("[REDACTED:"), (
        f"FULL token should start with [REDACTED:, got {result.findings[0].redacted_to!r}"
    )


def test_full_is_default() -> None:
    """Calling redact() without policy must behave identically to FULL."""
    text = "sk-abcdefghijklmnopqrstuvwx"
    assert r.redact(text).text == r.redact(text, RedactionPolicy.FULL).text


# ── MASKED policy: partial reveal ─────────────────────────────────────────────

def test_masked_credit_card_format() -> None:
    # Luhn-valid Visa: 4532015112830366 → last 4 digits = 0366
    result = r.redact("4532015112830366", RedactionPolicy.MASKED)
    assert result.findings
    replacement = result.findings[0].redacted_to
    assert re.fullmatch(r"\*{4}-\*{4}-\*{4}-\d{4}", replacement), (
        f"Credit card mask must match ****-****-****-XXXX, got {replacement!r}"
    )
    # Last 4 digits preserved correctly
    assert replacement.endswith("-0366")
    # Original must not appear
    assert "4532015112830366" not in result.text


def test_masked_email_keeps_domain() -> None:
    result = r.redact("john.doe@example.com", RedactionPolicy.MASKED)
    assert result.findings
    replacement = result.findings[0].redacted_to
    # Domain must be preserved
    assert replacement.endswith("@example.com"), (
        f"Email mask must preserve domain, got {replacement!r}"
    )
    # Local part must be partially hidden
    assert "***" in replacement
    # First char preserved
    assert replacement.startswith("j")
    # Full original must not appear
    assert "john.doe" not in result.text


def test_masked_ssn_keeps_last_four() -> None:
    result = r.redact("123-45-6789", RedactionPolicy.MASKED)
    assert result.findings
    replacement = result.findings[0].redacted_to
    assert replacement == "***-**-6789", (
        f"SSN mask must be ***-**-XXXX, got {replacement!r}"
    )
    assert "123-45" not in result.text


def test_masked_api_key_keeps_last_four_alphanum() -> None:
    # Last 4 alphanum of "sk-abcdefghijklmnopqrstuvwx" are "uvwx"
    result = r.redact("sk-abcdefghijklmnopqrstuvwx", RedactionPolicy.MASKED)
    assert result.findings
    replacement = result.findings[0].redacted_to
    assert replacement.startswith("[MASKED:openai_key:...")
    assert replacement.endswith("uvwx]"), (
        f"Masked key must end with last 4 alphanum chars, got {replacement!r}"
    )
    assert "sk-abcdefghijklmnopqrstuvwx" not in result.text


def test_masked_private_key_never_reveals_content() -> None:
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ==\n-----END RSA PRIVATE KEY-----"
    result = r.redact(pem, RedactionPolicy.MASKED)
    assert result.findings
    replacement = result.findings[0].redacted_to
    # Must not reveal any key material
    assert "MIIE" not in replacement
    assert replacement == "[MASKED:private_key]"


def test_masked_url_credentials_never_reveals_password() -> None:
    result = r.redact("postgres://admin:s3cr3t@db.host/prod", RedactionPolicy.MASKED)
    assert result.findings
    replacement = result.findings[0].redacted_to
    assert "s3cr3t" not in replacement
    assert "admin" not in replacement
    assert replacement == "[MASKED:url_credentials]://"


@pytest.mark.parametrize("text,kind", [
    ("GB29NWBK60161331926819",             "iban"),
    ("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456", "github_token"),
    ("AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz12345", "gcp_api_key"),
    ("Bearer eyJhbGciOiJIUzI1NiJ9.test.sig", "bearer_token"),
])
def test_masked_generic_keeps_last_four(text: str, kind: str) -> None:
    result = r.redact(text, RedactionPolicy.MASKED)
    assert result.findings, f"No findings for kind={kind!r}"
    replacement = result.findings[0].redacted_to
    assert replacement.startswith(f"[MASKED:{kind}:..."), (
        f"Generic mask format wrong for {kind}: {replacement!r}"
    )
    # Last 4 alphanum of original text must appear at the end
    alphanum = re.sub(r"[^A-Za-z0-9]", "", text)
    assert replacement.endswith(alphanum[-4:] + "]"), (
        f"Last 4 chars mismatch for {kind}: {replacement!r}"
    )
    # Original secret must not appear verbatim
    assert text not in result.text


# ── RAW policy: detect only, no text modification ────────────────────────────

@pytest.mark.parametrize("text,kind", [
    ("sk-abcdefghijklmnopqrstuvwx",       "openai_key"),
    ("4532015112830366",                   "credit_card"),
    ("user@example.com",                   "email"),
    ("123-45-6789",                        "us_ssn"),
    ("GB29NWBK60161331926819",             "iban"),
    ("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456", "github_token"),
    ("Bearer eyJhbGciOiJIUzI1NiJ9.t.s",   "bearer_token"),
    ("postgres://user:s3cr3t@host/db",     "url_credentials"),
    (
        "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
        "private_key_block",
    ),
])
def test_raw_policy_preserves_text(text: str, kind: str) -> None:
    result = r.redact(text, RedactionPolicy.RAW)
    # Text must be completely unchanged
    assert result.text == text, (
        f"RAW policy must not modify text for kind={kind!r}"
    )
    # But findings must still be populated
    kinds = [f.kind for f in result.findings]
    assert kind in kinds, (
        f"RAW policy must still detect kind={kind!r}, got findings={kinds!r}"
    )


def test_raw_findings_use_detected_prefix() -> None:
    result = r.redact("user@example.com", RedactionPolicy.RAW)
    assert result.findings
    for finding in result.findings:
        assert finding.redacted_to.startswith("[DETECTED:"), (
            f"RAW findings must use [DETECTED:...] prefix, got {finding.redacted_to!r}"
        )


def test_raw_has_secrets_still_true() -> None:
    """has_secrets must reflect detection even when text is unchanged."""
    result = r.redact("sk-abcdefghijklmnopqrstuvwx", RedactionPolicy.RAW)
    assert result.has_secrets is True


def test_raw_multi_secret_all_detected_none_replaced() -> None:
    text = "card 4532015112830366 email user@example.com key sk-abcdefghijklmnopqrstuvwx"
    result = r.redact(text, RedactionPolicy.RAW)
    assert result.text == text
    assert len(result.findings) == 3
    for f in result.findings:
        assert f.redacted_to.startswith("[DETECTED:")


# ── Policy isolation: policies do not cross-contaminate ──────────────────────

def test_policies_produce_independent_results() -> None:
    """The same SecretRedactor instance must return correct results for each
    policy when called consecutively — no shared mutable state."""
    text = "key sk-abcdefghijklmnopqrstuvwx and card 4532015112830366"
    full   = r.redact(text, RedactionPolicy.FULL)
    masked = r.redact(text, RedactionPolicy.MASKED)
    raw    = r.redact(text, RedactionPolicy.RAW)

    # FULL: opaque tokens
    assert "[REDACTED:openai_key]" in full.text
    assert "[REDACTED:credit_card]" in full.text

    # MASKED: partial reveal
    assert "[MASKED:openai_key:..." in masked.text
    assert "****-****-****-" in masked.text

    # RAW: original text intact
    assert raw.text == text

    # Each call produced its own independent findings list
    for f in full.findings:
        assert f.redacted_to.startswith("[REDACTED:")
    for f in masked.findings:
        assert f.redacted_to.startswith(("[MASKED:", "****-", "j***@"))
    for f in raw.findings:
        assert f.redacted_to.startswith("[DETECTED:")


# ═══════════════════════════════════════════════════════════════════════════════
# New PII patterns: phone, ethereum, bitcoin, passport
# ═══════════════════════════════════════════════════════════════════════════════

# ── Strict mode: passport also redacted ───────────────────────────────────────

def test_strict_redacts_us_passport() -> None:
    sr = SecretRedactor(strict=True)
    result = sr.redact("Passport: A12345678")
    kinds = [f.kind for f in result.findings]
    assert "us_passport" in kinds
    assert "A12345678" not in result.text


def test_non_strict_ignores_us_passport() -> None:
    result = r.redact("Passport: A12345678")
    kinds = [f.kind for f in result.findings]
    assert "us_passport" not in kinds


# ── has_pii returns True for new PII kinds ────────────────────────────────────

@pytest.mark.parametrize("text,kind", [
    ("+1 (555) 867-5309",                          "phone_number"),
    ("0x71C7656EC7ab88b098defB751B7401B5f6d8976F",  "ethereum_address"),
    ("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",          "bitcoin_address"),
])
def test_has_pii_true_for_new_kinds(text: str, kind: str) -> None:
    result = r.redact(text)
    assert result.has_pii, f"has_pii must be True for kind={kind!r}"


# ── MASKED policy for new PII kinds ──────────────────────────────────────────

def test_masked_phone_shows_last_four_digits() -> None:
    result = r.redact("+1 (555) 867-5309", RedactionPolicy.MASKED)
    assert result.findings
    replacement = result.findings[0].redacted_to
    assert replacement == "***-***-5309"
    assert "555" not in result.text


def test_masked_ethereum_shows_last_four() -> None:
    eth = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
    result = r.redact(eth, RedactionPolicy.MASKED)
    assert result.findings
    replacement = result.findings[0].redacted_to
    assert replacement.startswith("[MASKED:ethereum_address:...")
    # last 4 alphanum of "0x71C7656EC7ab88b098defB751B7401B5f6d8976F" → "976F"
    assert replacement.endswith("976F]")
    assert eth not in result.text


def test_masked_bitcoin_shows_last_four() -> None:
    # "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2" — last 4 alphanum = "NVN2"
    btc = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
    result = r.redact(btc, RedactionPolicy.MASKED)
    assert result.findings
    replacement = result.findings[0].redacted_to
    assert replacement.startswith("[MASKED:bitcoin_address:...")
    assert replacement.endswith("NVN2]")
    assert btc not in result.text
