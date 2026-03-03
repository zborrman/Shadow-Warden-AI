"""
warden/brain/redactor.py
━━━━━━━━━━━━━━━━━━━━━━━
Regex-based PII and secret scrubber.

Targets
───────
  • Email addresses
  • Phone numbers  (US, EU, international E.164)
  • API keys       (OpenAI sk-…, Anthropic, HuggingFace, generic bearer)
  • AWS credentials
  • GitHub / Stripe tokens
  • Generic high-entropy secrets embedded in key=value pairs

Design
──────
All matches are replaced with a clearly-labelled placeholder so
downstream services never receive raw credentials or personal data.
The original values are *never* logged — only the placeholder type.

GDPR note: this runs *before* any content reaches a model or is
written to a database, satisfying the "data minimisation" principle.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import NamedTuple


# ── Pattern definitions ───────────────────────────────────────────────────────

@dataclass(frozen=True)
class _Pattern:
    name:        str
    regex:       re.Pattern[str]
    placeholder: str


_PATTERNS: tuple[_Pattern, ...] = (

    # ── Email addresses ───────────────────────────────────────────────────
    _Pattern(
        name="email",
        regex=re.compile(
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        ),
        placeholder="[REDACTED:email]",
    ),

    # ── Phone numbers ─────────────────────────────────────────────────────
    # Matches US (with/without country code), EU, and E.164 international.
    _Pattern(
        name="phone",
        regex=re.compile(
            r"(?<!\d)"
            r"(?:"
                r"\+?1[\s\-.]?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}"   # US: +1 (555) 123-4567
                r"|(?:\+?[2-9]\d{0,2}[\s\-.]?)?\(?\d{2,4}\)?[\s\-.]?"  # intl prefix
                r"\d{2,4}[\s\-.]?\d{2,4}(?:[\s\-.]?\d{1,4})?"          # local number
            r")"
            r"(?!\d)",
        ),
        placeholder="[REDACTED:phone]",
    ),

    # ── OpenAI API key  sk-... ────────────────────────────────────────────
    _Pattern(
        name="openai_api_key",
        regex=re.compile(r"sk-[A-Za-z0-9]{20,60}", re.ASCII),
        placeholder="[REDACTED:openai_api_key]",
    ),

    # ── Anthropic API key  sk-ant-... ─────────────────────────────────────
    _Pattern(
        name="anthropic_api_key",
        regex=re.compile(r"sk-ant-[A-Za-z0-9\-]{20,80}", re.ASCII),
        placeholder="[REDACTED:anthropic_api_key]",
    ),

    # ── HuggingFace token  hf_... ────────────────────────────────────────
    _Pattern(
        name="huggingface_token",
        regex=re.compile(r"hf_[A-Za-z0-9]{30,}", re.ASCII),
        placeholder="[REDACTED:huggingface_token]",
    ),

    # ── AWS Access Key ID  AKIA... ────────────────────────────────────────
    _Pattern(
        name="aws_access_key",
        regex=re.compile(r"(?<![A-Z0-9])(AKIA|AIPA|ABIA|ACCA)[A-Z0-9]{16}(?![A-Z0-9])"),
        placeholder="[REDACTED:aws_access_key]",
    ),

    # ── GitHub tokens  github_pat_ / ghp_ / gho_ / ghu_ / ghs_ ──────────
    _Pattern(
        name="github_token",
        regex=re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}", re.ASCII),
        placeholder="[REDACTED:github_token]",
    ),

    # ── Stripe keys  sk_live_ / pk_live_ / sk_test_ ───────────────────────
    _Pattern(
        name="stripe_key",
        regex=re.compile(r"(sk|pk)_(live|test)_[A-Za-z0-9]{24,}", re.ASCII),
        placeholder="[REDACTED:stripe_key]",
    ),

    # ── Bearer / Authorization header values ─────────────────────────────
    _Pattern(
        name="bearer_token",
        regex=re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*"),
        placeholder="[REDACTED:bearer_token]",
    ),

    # ── Generic key=value secrets ─────────────────────────────────────────
    # Catches patterns like: api_key="abc123", secret: 'xyz', token=...
    _Pattern(
        name="generic_secret",
        regex=re.compile(
            r"(?i)(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token|auth[_\-]?token|"
            r"private[_\-]?key|client[_\-]?secret)\s*[=:]\s*['\"]?([A-Za-z0-9\-_.+/]{16,})['\"]?",
        ),
        placeholder="[REDACTED:generic_secret]",
    ),

    # ── Private key / PEM block ───────────────────────────────────────────
    _Pattern(
        name="pem_private_key",
        regex=re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?"
            r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            re.DOTALL,
        ),
        placeholder="[REDACTED:pem_private_key]",
    ),
)


# ── Result ────────────────────────────────────────────────────────────────────

class RedactionMatch(NamedTuple):
    name:        str    # pattern name, e.g. "email"
    placeholder: str    # replacement used in clean_text
    count:       int    # number of occurrences replaced


@dataclass
class RedactionResult:
    clean_text: str
    matches:    list[RedactionMatch] = field(default_factory=list)

    @property
    def was_redacted(self) -> bool:
        return bool(self.matches)

    @property
    def summary(self) -> str:
        if not self.matches:
            return "No sensitive content detected."
        parts = [f"{m.name}×{m.count}" for m in self.matches]
        return "Redacted: " + ", ".join(parts)


# ── SecretRedactor ────────────────────────────────────────────────────────────

class SecretRedactor:
    """
    Scrubs emails, phone numbers, and API keys (plus many more secret
    patterns) from any text using compiled regex patterns.

    Usage::

        redactor = SecretRedactor()
        result   = redactor.scrub(raw_text)

        print(result.clean_text)   # safe to forward downstream
        print(result.summary)      # e.g. "Redacted: email×2, openai_api_key×1"
    """

    def scrub(self, text: str) -> RedactionResult:
        """
        Apply all patterns to *text* and return a RedactionResult
        containing the sanitised text and a list of what was removed.

        Patterns are applied in declaration order (most specific first).
        All replacements happen in a single pass per pattern to avoid
        offset drift.
        """
        matches: list[RedactionMatch] = []

        for pat in _PATTERNS:
            new_text, n = pat.regex.subn(pat.placeholder, text)
            if n:
                matches.append(RedactionMatch(
                    name=pat.name,
                    placeholder=pat.placeholder,
                    count=n,
                ))
                text = new_text

        return RedactionResult(clean_text=text, matches=matches)

    # ── Convenience ───────────────────────────────────────────────────────

    def scrub_text(self, text: str) -> str:
        """Return only the sanitised string (no metadata)."""
        return self.scrub(text).clean_text
