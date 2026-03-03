"""
SecretRedactor — detects and redacts sensitive patterns from text
before it ever reaches the AI model or external services.

Covers:
  • API / service keys (Anthropic, OpenAI, AWS, GCP, GitHub, Stripe,
                        HuggingFace, generic bearer)
  • Credentials in URLs (user:pass@host)
  • Private keys / PEM blocks
  • Credit card numbers (Luhn-validated)
  • US Social Security Numbers
  • IBAN / bank account numbers
  • Email addresses  (GDPR PII)
  • IPv4 addresses flagged in strict mode
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from warden.schemas import SecretFinding

# ── Pattern registry ──────────────────────────────────────────────────────────

@dataclass
class _Pattern:
    kind:        str
    regex:       re.Pattern[str]
    token:       str        # replacement placeholder
    pii:         bool = False   # GDPR personal-data flag


_PATTERNS: list[_Pattern] = [
    # ── API / service keys ────────────────────────────────────────────────
    # Anthropic key MUST come before the generic OpenAI pattern because both
    # share the "sk-" prefix.  More specific patterns first.
    _Pattern("anthropic_api_key",
             re.compile(r"sk-ant-[A-Za-z0-9\-_]{90,}", re.ASCII),
             "[REDACTED:anthropic_api_key]"),

    _Pattern("huggingface_token",
             re.compile(r"\bhf_[A-Za-z0-9]{34,}\b", re.ASCII),
             "[REDACTED:huggingface_token]"),

    _Pattern("openai_key",
             re.compile(r"sk-[A-Za-z0-9]{20,60}", re.ASCII),
             "[REDACTED:openai_key]"),

    _Pattern("aws_access_key",
             re.compile(r"(?<![A-Z0-9])(AKIA|AIPA|ABIA|ACCA)[A-Z0-9]{16}(?![A-Z0-9])"),
             "[REDACTED:aws_key]"),

    _Pattern("aws_secret_key",
             re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
             "[REDACTED:aws_secret]"),

    _Pattern("github_token",
             re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}", re.ASCII),
             "[REDACTED:github_token]"),

    _Pattern("stripe_key",
             re.compile(r"(sk|pk)_(live|test)_[A-Za-z0-9]{24,}", re.ASCII),
             "[REDACTED:stripe_key]"),

    _Pattern("gcp_api_key",
             re.compile(r"AIza[A-Za-z0-9\-_]{35}", re.ASCII),
             "[REDACTED:gcp_api_key]"),

    _Pattern("bearer_token",
             re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*"),
             "[REDACTED:bearer_token]"),

    # ── Credentials embedded in URLs ─────────────────────────────────────
    _Pattern("url_credentials",
             re.compile(r"(?i)(https?|ftp|postgresql|mysql|mongodb)://[^:@\s]+:[^@\s]+@"),
             "[REDACTED:url_credentials]://"),

    # ── Private key / PEM blocks ──────────────────────────────────────────
    _Pattern("private_key_block",
             re.compile(
                 r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
                 re.DOTALL),
             "[REDACTED:private_key]"),

    # ── Credit cards (Luhn validated separately) ──────────────────────────
    _Pattern("credit_card",
             re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|"
                        r"3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|"
                        r"(?:2131|1800|35\d{3})\d{11})\b"),
             "[REDACTED:credit_card]"),

    # ── US Social Security Numbers ────────────────────────────────────────
    _Pattern("us_ssn",
             re.compile(r"\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b"),
             "[REDACTED:ssn]",
             pii=True),

    # ── IBAN ─────────────────────────────────────────────────────────────
    _Pattern("iban",
             re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b"),
             "[REDACTED:iban]",
             pii=True),

    # ── Email addresses (GDPR PII) ────────────────────────────────────────
    _Pattern("email",
             re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
             "[REDACTED:email]",
             pii=True),

    # ── IPv4 (flagged but only redacted in strict mode) ───────────────────
    _Pattern("ipv4",
             re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
                        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
             "[REDACTED:ipv4]",
             pii=True),
]


# ── Luhn check (credit cards) ─────────────────────────────────────────────────

def _luhn_valid(number: str) -> bool:
    digits = [int(d) for d in reversed(number) if d.isdigit()]
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ── SecretRedactor ────────────────────────────────────────────────────────────

@dataclass
class SecretRedactor:
    """
    Scans text for secrets / PII and replaces them with safe tokens.

    Usage::

        redactor = SecretRedactor(strict=True)
        result   = redactor.redact(raw_text)
        safe_text    = result.text
        findings     = result.findings   # list[SecretFinding]
        contains_pii = result.has_pii
    """

    strict: bool = False   # when True, also redacts IPs and raises on any PII

    # ── Result container ──────────────────────────────────────────────────

    @dataclass
    class Result:
        text:     str
        findings: list[SecretFinding] = field(default_factory=list)

        @property
        def has_pii(self) -> bool:
            return any(f.kind in ("email", "us_ssn", "iban", "ipv4")
                       for f in self.findings)

        @property
        def has_secrets(self) -> bool:
            return bool(self.findings)

    # ── Public API ────────────────────────────────────────────────────────

    def redact(self, text: str) -> SecretRedactor.Result:
        findings: list[SecretFinding] = []
        for pat in _PATTERNS:
            # IPv4 only redacted in strict mode
            if pat.kind == "ipv4" and not self.strict:
                continue

            for match in pat.regex.finditer(text):
                # Extra Luhn validation for credit cards
                if pat.kind == "credit_card":
                    raw = re.sub(r"\D", "", match.group())
                    if not _luhn_valid(raw):
                        continue

                original_start = match.start()
                original_end   = match.end()

                findings.append(SecretFinding(
                    kind=pat.kind,
                    start=original_start,
                    end=original_end,
                    redacted_to=pat.token,
                ))

        # Apply replacements in reverse order so offsets stay valid
        findings.sort(key=lambda f: f.start, reverse=True)
        for finding in findings:
            # Find which pattern owns this finding
            token = next(
                p.token for p in _PATTERNS if p.kind == finding.kind
            )
            text = text[:finding.start] + token + text[finding.end:]

        # Re-sort findings into document order for the response
        findings.sort(key=lambda f: f.start)

        return SecretRedactor.Result(text=text, findings=findings)
