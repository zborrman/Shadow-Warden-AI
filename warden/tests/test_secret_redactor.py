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


# ── Pattern-registry invariants (SR-7.3) ──────────────────────────────────────
#
# Added to kill surviving mutants found by `mutmut run` on this module. Two
# whole classes of mutation were surviving because nothing asserted them:
#
#   1. `pii=True/False` on a _Pattern could be flipped with every test still
#      green. That flag feeds _PII_KINDS → Result.has_pii → the PII_DETECTED
#      flag raised in both /filter paths (main.py), so a silent flip is a GDPR
#      classification change that no test would catch.
#   2. The FULL-mode `[REDACTED:*]` token could be rewritten arbitrarily. The
#      existing tests only assert the secret is *gone*, never that it was
#      labelled correctly — so the label is what downstream consumers key on
#      and it was untested.
#
# These tests pin the registry itself rather than any one detection, so the
# table stays honest as patterns are added.

from warden.secret_redactor import _PATTERNS, _PII_KINDS, _TOKEN  # noqa: E402

# Every kind in the registry, with the GDPR personal-data flag it must carry.
# Keep alphabetically grouped by category, matching _PATTERNS order.
_EXPECTED_PII: dict[str, bool] = {
    # ── API / service keys — credentials, not personal data ───────────────
    "anthropic_api_key":      False,
    "huggingface_token":      False,
    "openai_key":             False,
    "aws_access_key":         False,
    "aws_secret_key":         False,
    "github_token":           False,
    "stripe_key":             False,
    "gcp_api_key":            False,
    "bearer_token":           False,
    "url_credentials":        False,
    "private_key_block":      False,
    # ── Financial — a PAN is personal data under GDPR Art. 4(1) ───────────
    "credit_card":            True,
    "iban":                   True,
    "bic_swift":              True,
    # ── Direct identifiers ────────────────────────────────────────────────
    "us_ssn":                 True,
    "email":                  True,
    "ipv4":                   True,
    "phone_number":           True,
    "ethereum_address":       True,
    "bitcoin_address":        True,
    "us_passport":            True,
    # ── ICS / SCADA — infrastructure addresses, not personal data ─────────
    "opcua_endpoint":         False,
    "siemens_db_address":     False,
    "modbus_register":        False,
    "ics_station_address":    False,
    "ics_default_credential": False,
    "ethernetip_connection":  False,
    "scada_config_path":      False,
    "plc_tag_address":        False,
}


def test_registry_covered_by_expected_pii_table() -> None:
    """Every _Pattern must be listed above — a new pattern forces a decision."""
    registry = {p.kind for p in _PATTERNS}
    assert registry == set(_EXPECTED_PII), (
        f"registry drift: missing from test table={registry - set(_EXPECTED_PII)}, "
        f"stale in test table={set(_EXPECTED_PII) - registry}"
    )


@pytest.mark.parametrize("kind,expected", sorted(_EXPECTED_PII.items()))
def test_pattern_pii_flag_is_pinned(kind: str, expected: bool) -> None:
    """The GDPR personal-data flag is asserted per pattern, not inferred."""
    pattern = next(p for p in _PATTERNS if p.kind == kind)
    assert pattern.pii is expected, (
        f"{kind}: pii={pattern.pii} but table says {expected}. This flag drives "
        f"Result.has_pii → FlagType.PII_DETECTED in /filter — do not flip it "
        f"without changing the table and the downstream expectation."
    )


def test_pii_kinds_matches_registry() -> None:
    """_PII_KINDS is derived from _PATTERNS; pin the derivation, not a literal."""
    assert frozenset(k for k, v in _EXPECTED_PII.items() if v) == _PII_KINDS


# url_credentials keeps the scheme separator so the rewritten URL still parses:
#   postgres://user:pw@host  →  [REDACTED:url_credentials]://host
_TOKEN_SUFFIX: dict[str, str] = {"url_credentials": "://"}


@pytest.mark.parametrize("kind", sorted(_EXPECTED_PII))
def test_full_mode_token_is_well_formed(kind: str) -> None:
    """FULL-mode placeholder must be exactly [REDACTED:<label>] + known suffix."""
    token = _TOKEN[kind]
    suffix = _TOKEN_SUFFIX.get(kind, "")
    assert token.startswith("[REDACTED:"), f"{kind}: token {token!r} lost its prefix"
    assert token.endswith("]" + suffix), (
        f"{kind}: token {token!r} should end with {']' + suffix!r}"
    )
    label = token[len("[REDACTED:"):-(1 + len(suffix))]
    assert label, f"{kind}: token {token!r} has an empty label"


def test_full_mode_tokens_are_unique() -> None:
    """Two kinds sharing a placeholder would make redacted output ambiguous."""
    seen: dict[str, str] = {}
    for kind, token in _TOKEN.items():
        assert token not in seen, f"{kind} and {seen[token]} share token {token!r}"
        seen[token] = kind


@pytest.mark.parametrize("text,kind,token", [
    ("sk-ant-" + "a" * 95,                          "anthropic_api_key", "[REDACTED:anthropic_api_key]"),
    ("AKIAIOSFODNN7EXAMPLE",                        "aws_access_key",    "[REDACTED:aws_key]"),
    ("sk_live_" + "a" * 30,                         "stripe_key",        "[REDACTED:stripe_key]"),
    ("user@example.com",                            "email",             "[REDACTED:email]"),
    ("123-45-6789",                                 "us_ssn",            "[REDACTED:ssn]"),
    ("GB82WEST12345698765432",                      "iban",              "[REDACTED:iban]"),
    ("DEUTDEFF500",                                 "bic_swift",         "[REDACTED:bic_swift]"),
])
def test_full_mode_writes_the_registry_token(text: str, kind: str, token: str) -> None:
    """The exact placeholder reaches the output — not just 'the secret is gone'."""
    result = r.redact(text, RedactionPolicy.FULL)
    kinds = [f.kind for f in result.findings]
    assert kind in kinds, f"expected kind={kind!r}, got {kinds}"
    assert token in result.text, f"expected {token!r} in {result.text!r}"
    assert text not in result.text


# ── Direct unit tests for private helpers (SR-7.3 mutation-testing gaps) ──────
# These pin exact values, not just "did it detect something" — the indirect
# TP/FP tests above rarely constrain arithmetic/comparison internals tightly
# enough to catch off-by-one or operator-swap mutants.

class TestShannonEntropy:
    def test_empty_string_is_zero(self) -> None:
        from warden.secret_redactor import _shannon_entropy
        assert _shannon_entropy("") == 0.0

    def test_single_repeated_char_is_zero(self) -> None:
        from warden.secret_redactor import _shannon_entropy
        assert _shannon_entropy("aaaaaaaa") == 0.0

    def test_two_symbols_even_split_is_one_bit(self) -> None:
        from warden.secret_redactor import _shannon_entropy
        # "abab" — 2 symbols, each p=0.5 → entropy = 1.0 bit exactly
        assert _shannon_entropy("abab") == pytest.approx(1.0)

    def test_four_symbols_even_split_is_two_bits(self) -> None:
        from warden.secret_redactor import _shannon_entropy
        # "abcd" — 4 symbols, each p=0.25 → entropy = 2.0 bits exactly
        assert _shannon_entropy("abcd") == pytest.approx(2.0)

    def test_higher_entropy_for_more_distinct_symbols(self) -> None:
        from warden.secret_redactor import _shannon_entropy
        assert _shannon_entropy("abcdefgh") > _shannon_entropy("aabbccdd")


class TestFindHighEntropyTokens:
    def test_low_entropy_long_run_not_flagged(self) -> None:
        from warden.secret_redactor import _find_high_entropy_tokens
        # 40 identical chars: passes the length regex but entropy is 0.
        assert _find_high_entropy_tokens("a" * 40) == []

    def test_high_entropy_token_span_is_exact(self) -> None:
        from warden.secret_redactor import _find_high_entropy_tokens
        token = "aB3xQ9zK7mP2vN8wR4tY6uI1oL5jH0gF"  # 32 chars, mixed case+digits
        assert len(token) == 32
        text = f"prefix {token} suffix"
        spans = _find_high_entropy_tokens(text)
        assert spans == [(7, 7 + len(token))]
        assert text[spans[0][0]:spans[0][1]] == token

    def test_short_high_entropy_run_not_flagged(self) -> None:
        from warden.secret_redactor import _find_high_entropy_tokens
        # 31 chars — one under the length floor — must not match at all.
        token = "aB3xQ9zK7mP2vN8wR4tY6uI1oL5jH0g"
        assert len(token) == 31
        assert _find_high_entropy_tokens(token) == []


class TestLuhnValid:
    def test_known_valid_card_number(self) -> None:
        from warden.secret_redactor import _luhn_valid
        assert _luhn_valid("4111111111111111") is True

    def test_known_invalid_card_number(self) -> None:
        from warden.secret_redactor import _luhn_valid
        # last digit flipped from the valid number above
        assert _luhn_valid("4111111111111112") is False

    def test_non_digit_characters_are_ignored(self) -> None:
        from warden.secret_redactor import _luhn_valid
        assert _luhn_valid("4111-1111-1111-1111") is True

    def test_single_digit_zero_is_valid(self) -> None:
        from warden.secret_redactor import _luhn_valid
        # digits=[0], i=0 is even → no doubling; total=0; 0 % 10 == 0
        assert _luhn_valid("0") is True

    def test_single_digit_nine_is_invalid(self) -> None:
        from warden.secret_redactor import _luhn_valid
        assert _luhn_valid("9") is False


class TestMaskValue:
    def test_credit_card_strips_separators_before_last_four(self) -> None:
        from warden.secret_redactor import _mask_value
        assert _mask_value("4111-1111-1111-1111", "credit_card") == "****-****-****-1111"

    def test_credit_card_short_digits_kept_as_is(self) -> None:
        from warden.secret_redactor import _mask_value
        assert _mask_value("12", "credit_card") == "****-****-****-12"

    def test_email_reveals_first_char_and_domain(self) -> None:
        from warden.secret_redactor import _mask_value
        assert _mask_value("jdoe@example.com", "email") == "j***@example.com"

    def test_us_ssn_shows_last_four(self) -> None:
        from warden.secret_redactor import _mask_value
        assert _mask_value("123-45-6789", "us_ssn") == "***-**-6789"

    def test_private_key_block_never_reveals_content(self) -> None:
        from warden.secret_redactor import _mask_value
        assert _mask_value("-----BEGIN PRIVATE KEY-----abc", "private_key_block") == "[MASKED:private_key]"

    def test_url_credentials_never_reveals_content(self) -> None:
        from warden.secret_redactor import _mask_value
        assert _mask_value("user:pass@", "url_credentials") == "[MASKED:url_credentials]://"

    def test_phone_number_shows_last_four(self) -> None:
        from warden.secret_redactor import _mask_value
        assert _mask_value("+1 (555) 867-5309", "phone_number") == "***-***-5309"

    def test_generic_kind_shows_last_four_alphanum(self) -> None:
        from warden.secret_redactor import _mask_value
        assert _mask_value("0x71C7656EC7ab88b098defB751B7401B5f6d8976F", "ethereum_address") == "[MASKED:ethereum_address:...976F]"

    def test_generic_kind_short_value_kept_as_is(self) -> None:
        from warden.secret_redactor import _mask_value
        assert _mask_value("ab", "some_kind") == "[MASKED:some_kind:...ab]"


def test_credit_card_sets_has_pii() -> None:
    """A PAN is personal data under GDPR Art. 4(1) — has_pii must reflect that.

    Regression guard for SR-7.3: credit_card was the only financial identifier
    in the registry without pii=True (iban and bic_swift both carried it), so a
    card number was redacted but never raised FlagType.PII_DETECTED in /filter.
    """
    result = r.redact("4532015112830366")          # Luhn-valid Visa
    assert "credit_card" in [f.kind for f in result.findings]
    assert result.has_pii, "a detected card number must set has_pii"
