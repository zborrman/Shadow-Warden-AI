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

Redaction policies (RedactionPolicy):
  • FULL   — replace entirely with [REDACTED:<kind>]  (default)
  • MASKED — keep last 4 non-sensitive chars for audit roles
             e.g. ****-****-****-1234, j***@example.com
  • RAW    — detect only; leave content unchanged (service-to-service)
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from warden.schemas import RedactionPolicy, SecretFinding
from warden.telemetry import trace_stage as _trace_stage

# ── Pattern registry ──────────────────────────────────────────────────────────

@dataclass
class _Pattern:
    kind:        str
    regex:       re.Pattern[str]
    token:       str        # FULL-mode replacement placeholder
    pii:         bool = False   # GDPR personal-data flag
    strict_only: bool = False   # when True, only active in strict mode


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
             re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}", re.ASCII),
             "[REDACTED:github_token]"),

    _Pattern("stripe_key",
             re.compile(r"(sk|pk)_(live|test)_[A-Za-z0-9]{24,}", re.ASCII),
             "[REDACTED:stripe_key]"),

    _Pattern("gcp_api_key",
             re.compile(r"AIza[A-Za-z0-9\-_]{33,}", re.ASCII),
             "[REDACTED:gcp_api_key]"),

    _Pattern("bearer_token",
             re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*"),
             "[REDACTED:bearer_token]"),

    # ── Credentials embedded in URLs ─────────────────────────────────────
    _Pattern("url_credentials",
             re.compile(r"(?i)(https?|ftp|postgres(?:ql)?|mysql|mongodb)://[^:@\s]+:[^@\s]+@"),
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
                        r"(?:2131|1800|35\d{3})\d{11})\b"
                        r"|(?:\d{4}[- ]){3}\d{4}"),
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

    # ── BIC / SWIFT codes ─────────────────────────────────────────────────
    # Format: 4 bank + 2 country + 2 location + optional 3 branch (ISO 9362)
    # Require word boundary to avoid false positives on random 8/11-char strings.
    _Pattern("bic_swift",
             re.compile(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b"),
             "[REDACTED:bic_swift]",
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

    # ── Phone numbers (US + E.164) ────────────────────────────────────────
    # US branch: optional +1 prefix, tolerates spaces/dashes/dots between groups.
    # E.164 branch: requires explicit '+' for international — prevents matching
    # bare digit sequences like credit card numbers or prices.
    _Pattern("phone_number",
             re.compile(
                 r"(?<!\d)"
                 r"(?:"
                 r"\+?1[\s\-.]?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}"
                 r"|\+[1-9]\d{0,2}[\s\-.]?\d{2,4}(?:[\s\-.]?\d{2,4})+"
                 r")"
                 r"(?!\d)"
             ),
             "[REDACTED:phone_number]",
             pii=True),

    # ── Ethereum wallet addresses (ERC-20 / EVM) ─────────────────────────
    _Pattern("ethereum_address",
             re.compile(r"\b0x[0-9a-fA-F]{40}\b"),
             "[REDACTED:ethereum_address]",
             pii=True),

    # ── Bitcoin addresses (P2PKH, P2SH, Bech32) ──────────────────────────
    _Pattern("bitcoin_address",
             re.compile(
                 r"\b(?:1[A-Za-z0-9]{24,33}|3[A-Za-z0-9]{24,33}|bc1[a-z0-9]{25,62})\b"
             ),
             "[REDACTED:bitcoin_address]",
             pii=True),

    # ── US Passport number (strict mode only) ────────────────────────────
    _Pattern("us_passport",
             re.compile(r"\b[A-Z][0-9]{8}\b"),
             "[REDACTED:us_passport]",
             pii=True,
             strict_only=True),

    # ── OT/ICS Critical Infrastructure patterns (v3.1) ────────────────────
    # OPC-UA endpoint URLs  (opc.tcp://host:port/UAServer)
    _Pattern("opcua_endpoint",
             re.compile(r"opc\.tcp://[A-Za-z0-9.\-_]+(:[0-9]{1,5})?(?:/[^\s]*)?",
                        re.IGNORECASE),
             "[REDACTED:opcua_endpoint]"),

    # Siemens S7 DB address format (DB1.DBX0.0, DB42.DBD4)
    _Pattern("siemens_db_address",
             re.compile(r"\bDB\d{1,4}\.DB(?:X|B|W|D)\d{1,5}(?:\.\d)?\b"),
             "[REDACTED:siemens_db_address]"),

    # Modbus register/coil address in config context
    _Pattern("modbus_register",
             re.compile(
                 r"(?:modbus[\s_](?:address|register|coil|holding|input)|"
                 r"(?:holding|input)\s+register)\s*[=:]\s*[0-9]{1,5}\b",
                 re.IGNORECASE),
             "[REDACTED:modbus_register]"),

    # DNP3 / IEC-101/104 station address in config context
    _Pattern("ics_station_address",
             re.compile(
                 r"(?:dnp3?|iec[\s_-]?10[14])\s*(?:station|slave|master|address)\s*[=:]\s*[0-9]{1,5}\b",
                 re.IGNORECASE),
             "[REDACTED:ics_station_address]"),

    # SCADA/ICS default credential patterns
    _Pattern("ics_default_credential",
             re.compile(
                 r"(?:username|user|login|password|pass|passwd)\s*[=:]\s*"
                 r"(?:1234|12345|password|admin|administrator|rockwell|siemens|schneider|"
                 r"scada|plc|hmi|operator|control)\b",
                 re.IGNORECASE),
             "[REDACTED:ics_default_credential]"),

    # EtherNet/IP CIP connection strings
    _Pattern("ethernetip_connection",
             re.compile(r"CIP\s+(?:connection|path|segment)\s*[=:][^\n]{4,80}",
                        re.IGNORECASE),
             "[REDACTED:ethernetip_connection]"),

    # SCADA historian / software config file paths
    _Pattern("scada_config_path",
             re.compile(
                 r"(?:C:\\(?:Program Files|Inductive Automation|Wonderware|OSIsoft)[^\s\"'<>|]{4,80}|"
                 r"/(?:usr|opt|etc)/(?:ignition|wonderware|osisoft|aveva)[^\s\"'<>|]{4,80})",
                 re.IGNORECASE),
             "[REDACTED:scada_config_path]"),

    # Rockwell / Allen-Bradley PLC tag addresses in config context (strict only to reduce FP)
    _Pattern("plc_tag_address",
             re.compile(
                 r"(?:address|tag|register)\s*[=:]\s*"
                 r"(?:Program:\w+\.\w+|[A-Z][0-9]+:[0-9]+(?:/[0-9]+)?)",
                 re.IGNORECASE),
             "[REDACTED:plc_tag_address]",
             strict_only=True),
]

# ── Token lookup (used by both FULL and MASKED helpers) ───────────────────────

_TOKEN: dict[str, str] = {p.kind: p.token for p in _PATTERNS}

# ── PII kind set (auto-populated from _PATTERNS) ──────────────────────────────

_PII_KINDS: frozenset[str] = frozenset(p.kind for p in _PATTERNS if p.pii)


# ── High-entropy token detection ─────────────────────────────────────────────
# Catches unknown API keys and tokens that don't match any named pattern.
# Threshold: truly random alphanumeric strings score ~5.0 bits/char.
# We flag at 4.5 to catch slightly structured secrets while avoiding normal words.

_HIGH_ENTROPY_RE = re.compile(r"[A-Za-z0-9+/=_\-]{32,}")
_ENTROPY_THRESHOLD = 4.5
_ENTROPY_EXCLUSIONS = re.compile(
    r"[A-Za-z0-9+/]{32,}={0,2}"  # already caught by pattern matching above
    r"|AKIA[A-Z0-9]{16}"         # AWS access key — has its own pattern
)


def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/character."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((n / total) * math.log2(n / total) for n in freq.values())


def _find_high_entropy_tokens(text: str) -> list[tuple[int, int]]:
    """
    Return (start, end) spans of high-entropy tokens not matched by named patterns.

    Finds alphanumeric runs ≥ 32 chars with Shannon entropy ≥ _ENTROPY_THRESHOLD.
    This catches API keys, bearer tokens, and session secrets that don't match
    any named pattern — e.g., a custom service's key format.
    """
    spans = []
    for m in _HIGH_ENTROPY_RE.finditer(text):
        token = m.group()
        if _shannon_entropy(token) >= _ENTROPY_THRESHOLD:
            spans.append((m.start(), m.end()))
    return spans


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


# ── Masked replacement builder ────────────────────────────────────────────────

def _mask_value(matched: str, kind: str) -> str:
    """
    Build a MASKED replacement that reveals only the minimum needed for
    audit/admin use-cases — never enough to reconstruct the original secret.

    Rules by kind:
      credit_card      → ****-****-****-<last4 digits>
      email            → <first char>***@<domain>
      us_ssn           → ***-**-<last4 digits>
      iban             → [MASKED:iban:...<last4 alphanum>]
      private_key_block→ [MASKED:private_key]          (never reveal any part)
      url_credentials  → [MASKED:url_credentials]://   (never reveal credentials)
      everything else  → [MASKED:<kind>:...<last4 alphanum>]
    """
    if kind == "credit_card":
        digits = re.sub(r"\D", "", matched)
        last4 = digits[-4:] if len(digits) >= 4 else digits
        return f"****-****-****-{last4}"

    if kind == "email":
        local, _, domain = matched.partition("@")
        first = local[0] if local else "*"
        return f"{first}***@{domain}"

    if kind == "us_ssn":
        digits = re.sub(r"\D", "", matched)
        last4 = digits[-4:] if len(digits) >= 4 else digits
        return f"***-**-{last4}"

    if kind == "private_key_block":
        return "[MASKED:private_key]"

    if kind == "url_credentials":
        return "[MASKED:url_credentials]://"

    if kind == "phone_number":
        digits = re.sub(r"\D", "", matched)
        last4 = digits[-4:] if len(digits) >= 4 else digits
        return f"***-***-{last4}"

    # Generic: last 4 alphanumeric characters of the matched text
    alphanum = re.sub(r"[^A-Za-z0-9]", "", matched)
    last4 = alphanum[-4:] if len(alphanum) >= 4 else alphanum
    return f"[MASKED:{kind}:...{last4}]"


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

    Redaction policy::

        # Default — replace entirely:
        result = redactor.redact(text)
        result = redactor.redact(text, RedactionPolicy.FULL)

        # Admin/audit — keep last 4 chars:
        result = redactor.redact(text, RedactionPolicy.MASKED)

        # Internal service — detect only, no replacement:
        result = redactor.redact(text, RedactionPolicy.RAW)
    """

    strict: bool = False   # when True, also redacts IPs and raises on any PII

    # ── Result container ──────────────────────────────────────────────────

    @dataclass
    class Result:
        text:     str
        findings: list[SecretFinding] = field(default_factory=list)

        @property
        def has_pii(self) -> bool:
            return any(f.kind in _PII_KINDS for f in self.findings)

        @property
        def has_secrets(self) -> bool:
            return bool(self.findings)

    # ── Public API ────────────────────────────────────────────────────────

    def redact(
        self,
        text: str,
        policy: RedactionPolicy = RedactionPolicy.FULL,
    ) -> SecretRedactor.Result:
        """
        Scan *text* for secrets/PII and apply *policy*:

        * ``FULL``   — replace matches with opaque tokens (default).
        * ``MASKED`` — replace with partially-revealed tokens (last 4 chars).
        * ``RAW``    — detect only; return original text unchanged.
        """
        with _trace_stage("SecretRedactor.redact", {
            "layer":        "secret_redactor",
            "input.length": len(text),
            "policy":       policy.value,
        }) as _sp:
            return self._redact_inner(text, policy, _sp)

    def _redact_inner(
        self,
        text: str,
        policy: RedactionPolicy,
        _sp: object,
    ) -> "SecretRedactor.Result":
        findings: list[SecretFinding] = []
        # Maps (start, end) → original matched text; needed for MASKED calculation
        # when we apply replacements in reverse order.
        _matched: dict[tuple[int, int], str] = {}

        for pat in _PATTERNS:
            # IPv4 only redacted in strict mode
            if pat.kind == "ipv4" and not self.strict:
                continue
            # strict_only patterns (e.g. us_passport) skipped in non-strict mode
            if pat.strict_only and not self.strict:
                continue

            for match in pat.regex.finditer(text):
                # Extra Luhn validation for credit cards
                if pat.kind == "credit_card":
                    raw = re.sub(r"\D", "", match.group())
                    if not _luhn_valid(raw):
                        continue

                start, end = match.start(), match.end()
                _matched[(start, end)] = match.group()

                findings.append(SecretFinding(
                    kind=pat.kind,
                    start=start,
                    end=end,
                    redacted_to=_TOKEN[pat.kind],  # updated below for non-FULL
                ))

        # ── High-entropy token scan (catches unknown secret formats) ──────────
        # Only run when no named patterns already cover the span to avoid double-flagging.
        covered_spans: set[tuple[int, int]] = {(f.start, f.end) for f in findings}
        for start, end in _find_high_entropy_tokens(text):
            # Skip if this span is already covered by a named pattern
            if any(s <= start and end <= e for s, e in covered_spans):
                continue
            findings.append(SecretFinding(
                kind="high_entropy_secret",
                start=start,
                end=end,
                redacted_to="[REDACTED:high_entropy_secret]",
            ))
            _matched[(start, end)] = text[start:end]
            covered_spans.add((start, end))

        # Apply replacements right-to-left so earlier offsets stay valid
        findings.sort(key=lambda f: f.start, reverse=True)

        for finding in findings:
            matched_text = _matched[(finding.start, finding.end)]

            if policy is RedactionPolicy.RAW:
                # Detect only — no text modification
                finding.redacted_to = f"[DETECTED:{finding.kind}]"
                continue

            if policy is RedactionPolicy.MASKED:
                replacement = _mask_value(matched_text, finding.kind)
            else:
                # FULL (default) — fall back to pre-set redacted_to for unknown kinds
                replacement = _TOKEN.get(finding.kind, finding.redacted_to)

            finding.redacted_to = replacement
            text = text[: finding.start] + replacement + text[finding.end :]

        # Re-sort findings into document order for the caller
        findings.sort(key=lambda f: f.start)

        _sp.set_attribute("secrets_found", len(findings))
        _sp.set_attribute("verdict", "redacted" if findings else "clean")
        return SecretRedactor.Result(text=text, findings=findings)
