"""
warden/output_guard.py
━━━━━━━━━━━━━━━━━━━━━━
Stage 4 — OutputGuard v2: business-layer + safety output guardrails.

v1 risks (business logic):
  ① Price Manipulation      — unauthorized discounts / free offers
  ② Unauthorized Commitments — guarantees / promises the AI cannot make
  ③ Competitor Mentions     — AI promoting competitor brands
  ④ Policy Violations       — AI hallucinating return/warranty policies

v2 risks (safety + data protection):
  ⑤ Hallucinated URLs       — HTTP/HTTPS links in LLM output (LLM09)
  ⑥ Hallucinated Statistics — unverifiable "studies show / research finds"
  ⑦ PII Leakage             — credit cards / SSNs / emails in AI response
  ⑧ Toxic Content           — threats / hate speech / severe profanity
  ⑨ System Prompt Echo      — AI leaking its own instructions/context
  ⑩ Sensitive Data Exposure — API keys / passwords / tokens in output

Per-tenant config:
  Pass a TenantOutputConfig to scan() to override defaults per request.
  Use OutputGuard.from_env_config(overrides) to build a tenant config dict.

OWASP mapping:
  ① ② ④ ⑥  →  LLM09 — Misinformation
  ③         →  Brand Risk
  ⑤         →  LLM09 — Hallucination
  ⑦         →  LLM02 — Sensitive Information Disclosure
  ⑧         →  LLM01 — Safety (content moderation)
  ⑨         →  LLM07 — System Prompt Leakage
  ⑩         →  LLM02 — Sensitive Information Disclosure
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from enum import StrEnum

log = logging.getLogger("warden.output_guard")

# ── Runtime config (read once at import) ─────────────────────────────────────

# Maximum allowed discount percentage in LLM output.
# Outputs containing "60% off" when this is 50 → PRICE_MANIPULATION flag.
_MAX_DISCOUNT_PCT = int(os.getenv("OUTPUT_MAX_DISCOUNT_PCT", "50"))

# Whether unauthorized commitment language results in sanitization (true = yes).
_BLOCK_COMMITMENTS = os.getenv("OUTPUT_COMMITMENT_BLOCK", "true").lower() == "true"

# Comma-separated list of competitor brand names to flag.
# Leave blank to disable competitor detection.
_COMPETITOR_NAMES = [
    n.strip() for n in os.getenv("OUTPUT_COMPETITOR_NAMES", "").split(",") if n.strip()
]

_GUARDRAILS_ENABLED = os.getenv("OUTPUT_GUARDRAILS_ENABLED", "true").lower() == "true"


# ── Risk types ────────────────────────────────────────────────────────────────

class BusinessRisk(StrEnum):
    # v1 — business logic
    PRICE_MANIPULATION    = "price_manipulation"
    UNAUTHORIZED_COMMIT   = "unauthorized_commitment"
    COMPETITOR_MENTION    = "competitor_mention"
    POLICY_VIOLATION      = "policy_violation"
    # v2 — safety + data protection
    HALLUCINATED_URL      = "hallucinated_url"
    HALLUCINATED_STAT     = "hallucinated_statistic"
    PII_LEAKAGE           = "pii_leakage"
    TOXIC_CONTENT         = "toxic_content"
    PROMPT_ECHO           = "prompt_echo"
    SENSITIVE_DATA        = "sensitive_data_exposure"


OWASP_LABEL: dict[BusinessRisk, str] = {
    BusinessRisk.PRICE_MANIPULATION:  "LLM09 — Misinformation (price manipulation)",
    BusinessRisk.UNAUTHORIZED_COMMIT: "LLM09 — Misinformation (unauthorized commitment)",
    BusinessRisk.COMPETITOR_MENTION:  "Brand Risk — competitor mention in output",
    BusinessRisk.POLICY_VIOLATION:    "LLM09 — Misinformation (policy hallucination)",
    BusinessRisk.HALLUCINATED_URL:    "LLM09 — Hallucination (unverified URL)",
    BusinessRisk.HALLUCINATED_STAT:   "LLM09 — Hallucination (unverifiable statistic)",
    BusinessRisk.PII_LEAKAGE:         "LLM02 — Sensitive Information Disclosure (PII in output)",
    BusinessRisk.TOXIC_CONTENT:       "LLM01 — Safety (toxic / harmful content)",
    BusinessRisk.PROMPT_ECHO:         "LLM07 — System Prompt Leakage",
    BusinessRisk.SENSITIVE_DATA:      "LLM02 — Sensitive Information Disclosure (credentials)",
}

_REPLACEMENT: dict[BusinessRisk, str] = {
    BusinessRisk.PRICE_MANIPULATION:  "[Цена уточняется — обратитесь к менеджеру / Please contact our team for pricing]",
    BusinessRisk.UNAUTHORIZED_COMMIT: "[Это требует подтверждения — пожалуйста, свяжитесь с нами / Please verify with our team]",
    BusinessRisk.COMPETITOR_MENTION:  "[external service]",
    BusinessRisk.POLICY_VIOLATION:    "[Пожалуйста, уточните политику у менеджера / Please verify this policy with our team]",
    BusinessRisk.HALLUCINATED_URL:    "[link removed — please verify with official sources]",
    BusinessRisk.HALLUCINATED_STAT:   "[statistic unverified — please check primary sources]",
    BusinessRisk.PII_LEAKAGE:         "[PII REDACTED]",
    BusinessRisk.TOXIC_CONTENT:       "[content removed]",
    BusinessRisk.PROMPT_ECHO:         "[system context hidden]",
    BusinessRisk.SENSITIVE_DATA:      "[CREDENTIAL REDACTED]",
}


# ── Per-tenant config ─────────────────────────────────────────────────────────

@dataclass
class TenantOutputConfig:
    """
    Per-request / per-tenant overrides for OutputGuard.

    All fields default to the module-level env-var values so callers can
    pass only the fields they want to change.
    """
    max_discount_pct:         int        = field(default_factory=lambda: _MAX_DISCOUNT_PCT)
    block_commitments:        bool       = field(default_factory=lambda: _BLOCK_COMMITMENTS)
    competitor_names:         list[str]  = field(default_factory=list)
    block_hallucinated_urls:  bool       = True
    block_hallucinated_stats: bool       = True
    block_pii_leakage:        bool       = True
    block_toxic_content:      bool       = True
    block_prompt_echo:        bool       = True
    block_sensitive_data:     bool       = True
    # Extra regex strings added by the tenant (compiled on first use)
    custom_patterns:          list[str]  = field(default_factory=list)


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class BusinessFinding:
    risk:    BusinessRisk
    snippet: str              # offending excerpt (max 120 chars)
    owasp:   str              # human-readable OWASP label
    detail:  str = ""         # why it fired


@dataclass
class BusinessScanResult:
    findings:  list[BusinessFinding] = field(default_factory=list)
    sanitized: str = ""

    @property
    def risky(self) -> bool:
        return bool(self.findings)

    @property
    def risk_types(self) -> list[str]:
        return sorted({f.risk.value for f in self.findings})

    @property
    def owasp_categories(self) -> list[str]:
        return sorted({f.owasp for f in self.findings})


# ── Pattern definitions ───────────────────────────────────────────────────────

# ① Price manipulation — percentage discount detector (numeric comparison in _scan_price)
_DISCOUNT_RE = re.compile(
    r"\b(\d{1,3})\s*%\s*"
    r"(?:off|discount|скидк[аие]|reduction|rebate|promo|rabatt|remise)",
    re.IGNORECASE,
)

# Free / zero-price offers
_FREE_OFFER_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bfor\s+free\b",                        re.IGNORECASE),
    re.compile(r"\bat\s+no\s+(?:extra\s+)?cost\b",       re.IGNORECASE),
    re.compile(r"\bbесплатно\b",                          re.IGNORECASE),
    re.compile(r"\bза\s+0\s+(?:руб|коп|центов?|dollar)", re.IGNORECASE),
    re.compile(r"(?<!\d)\$0(?:\.00)?\b"),
    re.compile(r"\b0\s*(?:USD|EUR|GBP|RUB)\b",           re.IGNORECASE),
    re.compile(r"\bкомплиментарно\b",                    re.IGNORECASE),
]

# ② Unauthorized commitments — phrases an AI should never make on behalf of a business
_COMMITMENT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # English — guarantees
    (re.compile(r"\bI\s+guarantee\b",                     re.IGNORECASE), "AI guarantee"),
    (re.compile(r"\bwe\s+guarantee\b",                    re.IGNORECASE), "company guarantee"),
    (re.compile(r"\bguaranteed\s+(?:delivery|refund|replacement|return)", re.IGNORECASE), "guaranteed delivery/refund"),
    # English — promises
    (re.compile(r"\bI\s+promise\b",                       re.IGNORECASE), "AI promise"),
    (re.compile(r"\bwe\s+promise\b",                      re.IGNORECASE), "company promise"),
    # English — commitments
    (re.compile(r"\bwe\s+(?:will|shall)\s+(?:give|send|provide|deliver|refund|replace|compensate)", re.IGNORECASE), "company commitment"),
    (re.compile(r"\byou\s+will\s+(?:receive|get|be\s+given|have\s+it)", re.IGNORECASE), "delivery commitment"),
    (re.compile(r"\byou\s+are\s+(?:guaranteed|entitled\s+to|owed)\b",    re.IGNORECASE), "entitlement claim"),
    # English — legal claims
    (re.compile(r"\blegally\s+entitled\b",                re.IGNORECASE), "legal entitlement claim"),
    (re.compile(r"\bcompensation\s+of\s+\$?\d",          re.IGNORECASE), "compensation claim"),
    # Russian — guarantees/promises
    (re.compile(r"\bгарантирую\b",                        re.IGNORECASE), "AI гарантирую"),
    (re.compile(r"\bмы\s+гарантируем\b",                  re.IGNORECASE), "company гарантируем"),
    (re.compile(r"\bобещаю\b",                            re.IGNORECASE), "AI обещаю"),
    (re.compile(r"\bмы\s+обещаем\b",                      re.IGNORECASE), "company обещаем"),
    (re.compile(r"\bвы\s+получите\b",                     re.IGNORECASE), "delivery commitment RU"),
    (re.compile(r"\bмы\s+(?:вернём|вернем|компенсируем|возместим)", re.IGNORECASE), "refund/comp RU"),
]

# ③ Policy violations — AI asserting company policies it may not know
_POLICY_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bour\s+return\s+policy\s+(?:is|states?|allows?|guarantees?)", re.IGNORECASE), "return policy claim"),
    (re.compile(r"\bour\s+(?:30|60|90|365)[- ]day\s+(?:return|refund|warranty)", re.IGNORECASE), "specific policy days"),
    (re.compile(r"\bfull\s+refund\s+(?:within|in|after)\s+\d+\s+days?",          re.IGNORECASE), "refund window claim"),
    (re.compile(r"\blifetime\s+(?:warranty|guarantee)\b",                          re.IGNORECASE), "lifetime warranty claim"),
    (re.compile(r"\bнаша\s+политика\s+(?:возврата|обмена)\b",                    re.IGNORECASE), "policy claim RU"),
    (re.compile(r"\bгарантийный\s+срок\s+(?:составляет|равен)\s+\d+",            re.IGNORECASE), "warranty duration RU"),
]

# ⑤ Hallucinated URLs
_URL_RE = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]{8,}', re.IGNORECASE)

# ⑥ Hallucinated statistics
_HALLUCINATED_STAT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'\baccording to (?:a |recent |new |our )?(?:study|studies|research|survey|report|data|statistics)\b', re.IGNORECASE), "unverified study reference"),
    (re.compile(r'\bstudies show\b',                                                 re.IGNORECASE), "studies show"),
    (re.compile(r'\bresearch (?:shows?|indicates?|suggests?|confirms?|finds?)\b',    re.IGNORECASE), "research claim"),
    (re.compile(r'\b(?:scientists?|experts?|analysts?)\s+(?:say|claim|found|report)\b', re.IGNORECASE), "expert claim"),
    (re.compile(r'\b\d{1,3}(?:\.\d+)?\s*%\s+of\s+(?:all\s+)?(?:people|users|companies|businesses|consumers|Americans|adults)\b', re.IGNORECASE), "demographic statistic"),
    (re.compile(r'\bstatistically(?:\s+speaking)?\b',                                re.IGNORECASE), "statistical qualifier"),
    (re.compile(r'\bисследования?\s+показывают\b',                                   re.IGNORECASE), "research claim RU"),
    (re.compile(r'\bпо\s+данным\s+(?:исследования|опроса|статистики)\b',             re.IGNORECASE), "data claim RU"),
]

# ⑦ PII leakage in AI output
_OUTPUT_PII_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'\b(?:\d{4}[- ]){3}\d{4}\b'),                                         "credit card number"),
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),                                              "SSN"),
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),             "email address"),
    (re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),          "phone number"),
    (re.compile(r'\b(?:passport|паспорт)[:\s#]+[A-Z0-9]{6,12}\b', re.IGNORECASE),      "passport number"),
    (re.compile(r'\bIBAN[:\s]+[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b',     re.IGNORECASE),      "IBAN"),
]

# ⑧ Toxic content
_TOXIC_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'\b(?:kill|murder|shoot|stab|bomb|blow\s+up)\s+(?:you|yourself|him|her|them|everyone|people|all)\b', re.IGNORECASE), "violence threat"),
    (re.compile(r'\bI(?:\'ll|\s+will)\s+(?:kill|hurt|harm|destroy|rape|attack)\s+(?:you|him|her|them)\b', re.IGNORECASE), "direct threat"),
    (re.compile(r'\b(?:i hate|я ненавижу)\s+(?:you|you all|all|тебя|вас|всех|этих)\b', re.IGNORECASE), "hate statement"),
    (re.compile(r'\b(?:die|убирайся|сдохни)\b.*?(?:you|ты|вы)\b',  re.IGNORECASE), "hostile directive"),
    (re.compile(r'\b(?:f+u+c+k+|sh[i1]t|c[u*]nt|b[i1]tch|a+s+s+h+o+l+e+)\b', re.IGNORECASE), "severe profanity"),
]

# ⑨ System prompt echo
_PROMPT_ECHO_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'\bmy (?:system\s+)?(?:instructions?|prompt|rules?|directives?)\s+(?:say|state|tell|require|instruct|specify)\b', re.IGNORECASE), "instructions echo"),
    (re.compile(r'\bI(?:\'m|\s+am)\s+(?:instructed|programmed|configured|told|trained)\s+to\b', re.IGNORECASE), "configuration echo"),
    (re.compile(r'\bmy (?:system\s+)?(?:message|context|setup|configuration)\s+(?:is|says?|states?|tells?)\b', re.IGNORECASE), "context echo"),
    (re.compile(r'<\|(?:system|im_start|im_end)\|>',                               re.IGNORECASE), "leaked system token"),
    (re.compile(r'\[(?:INST|SYS|SYSTEM)\]|<<SYS>>',                                re.IGNORECASE), "leaked Llama token"),
    (re.compile(r'\bмои\s+(?:инструкции|правила|директивы)\s+(?:говорят|гласят|требуют)\b', re.IGNORECASE), "instructions echo RU"),
]

# ⑩ Sensitive data exposure
_SENSITIVE_DATA_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'\b(?:sk-|sk-proj-)[A-Za-z0-9]{20,}\b'),                              "OpenAI API key"),
    (re.compile(r'\bAIza[A-Za-z0-9_\-]{35}\b'),                                        "Google API key"),
    (re.compile(r'\b(?:AKIA|ASIA|AROA)[A-Z0-9]{16}\b'),                                "AWS access key"),
    (re.compile(r'\bghp_[A-Za-z0-9]{36}\b'),                                           "GitHub PAT"),
    (re.compile(r'\bxoxb-[0-9A-Za-z\-]{50,}\b'),                                       "Slack bot token"),
    (re.compile(r'\b(?:password|passwd|pwd)\b[^:=\n]{0,20}[:=]\s*\S{4,}', re.IGNORECASE), "password"),
    (re.compile(r'\bBearer\s+[A-Za-z0-9._\-]{20,}\b',           re.IGNORECASE),        "auth bearer token"),
    (re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),                           "private key block"),
]

# ③ Competitor patterns — built dynamically from env var at module load
def _build_competitor_patterns(names: list[str]) -> list[re.Pattern[str]]:
    """Build case-insensitive word-boundary patterns for each competitor name."""
    patterns = []
    for name in names:
        escaped = re.escape(name)
        patterns.append(re.compile(rf"\b{escaped}\b", re.IGNORECASE))
    return patterns

_COMPETITOR_PATTERNS: list[re.Pattern[str]] = _build_competitor_patterns(_COMPETITOR_NAMES)


# ── Sanitization helpers ──────────────────────────────────────────────────────

def _replace_span(text: str, start: int, end: int, replacement: str) -> str:
    return text[:start] + replacement + text[end:]


# ── Main guard ────────────────────────────────────────────────────────────────

class OutputGuard:
    """
    Business-layer output scanner.

    Thread-safe; instantiate once and reuse via :func:`get_output_guard`.
    Stateless — all config is read at module-load time from env vars.
    """

    def scan(
        self,
        text: str,
        tenant_config: TenantOutputConfig | None = None,
    ) -> BusinessScanResult:
        if not _GUARDRAILS_ENABLED or not text:
            return BusinessScanResult(sanitized=text)

        cfg = tenant_config or TenantOutputConfig()
        findings: list[BusinessFinding] = []
        sanitized = text

        # ── ① Price manipulation ──────────────────────────────────────────────

        for m in _DISCOUNT_RE.finditer(text):
            try:
                pct = int(m.group(1))
            except ValueError:
                continue
            if pct > cfg.max_discount_pct:
                snippet = text[max(0, m.start() - 15): m.end() + 15].strip()[:120]
                findings.append(BusinessFinding(
                    risk    = BusinessRisk.PRICE_MANIPULATION,
                    snippet = snippet,
                    owasp   = OWASP_LABEL[BusinessRisk.PRICE_MANIPULATION],
                    detail  = f"{pct}% > configured max {cfg.max_discount_pct}%",
                ))
                sanitized = sanitized.replace(
                    m.group(0), _REPLACEMENT[BusinessRisk.PRICE_MANIPULATION], 1,
                )
                break

        if BusinessRisk.PRICE_MANIPULATION not in {f.risk for f in findings}:
            for pat in _FREE_OFFER_PATTERNS:
                m = pat.search(text)
                if m:
                    snippet = text[max(0, m.start() - 15): m.end() + 15].strip()[:120]
                    findings.append(BusinessFinding(
                        risk    = BusinessRisk.PRICE_MANIPULATION,
                        snippet = snippet,
                        owasp   = OWASP_LABEL[BusinessRisk.PRICE_MANIPULATION],
                        detail  = "free / zero-price offer",
                    ))
                    sanitized = pat.sub(
                        _REPLACEMENT[BusinessRisk.PRICE_MANIPULATION], sanitized, count=1
                    )
                    break

        # ── ② Unauthorized commitments ────────────────────────────────────────

        if cfg.block_commitments:
            for pat, reason in _COMMITMENT_PATTERNS:
                m = pat.search(text)
                if m:
                    snippet = text[max(0, m.start() - 15): m.end() + 30].strip()[:120]
                    findings.append(BusinessFinding(
                        risk    = BusinessRisk.UNAUTHORIZED_COMMIT,
                        snippet = snippet,
                        owasp   = OWASP_LABEL[BusinessRisk.UNAUTHORIZED_COMMIT],
                        detail  = reason,
                    ))
                    sanitized = pat.sub(
                        _REPLACEMENT[BusinessRisk.UNAUTHORIZED_COMMIT], sanitized, count=1
                    )
                    break

        # ── ③ Competitor mentions ─────────────────────────────────────────────

        _comp_pats = (
            _build_competitor_patterns(cfg.competitor_names)
            if cfg.competitor_names
            else _COMPETITOR_PATTERNS
        )
        for pat in _comp_pats:
            m = pat.search(text)
            if m:
                snippet = text[max(0, m.start() - 10): m.end() + 20].strip()[:120]
                findings.append(BusinessFinding(
                    risk    = BusinessRisk.COMPETITOR_MENTION,
                    snippet = snippet,
                    owasp   = OWASP_LABEL[BusinessRisk.COMPETITOR_MENTION],
                    detail  = f"competitor name: {m.group(0)!r}",
                ))
                sanitized = pat.sub(_REPLACEMENT[BusinessRisk.COMPETITOR_MENTION], sanitized)
                break

        # ── ④ Policy violations ───────────────────────────────────────────────

        for pat, reason in _POLICY_PATTERNS:
            m = pat.search(text)
            if m:
                snippet = text[max(0, m.start() - 15): m.end() + 30].strip()[:120]
                findings.append(BusinessFinding(
                    risk    = BusinessRisk.POLICY_VIOLATION,
                    snippet = snippet,
                    owasp   = OWASP_LABEL[BusinessRisk.POLICY_VIOLATION],
                    detail  = reason,
                ))
                sanitized = pat.sub(
                    _REPLACEMENT[BusinessRisk.POLICY_VIOLATION], sanitized, count=1
                )
                break

        # ── ⑤ Hallucinated URLs ───────────────────────────────────────────────

        if cfg.block_hallucinated_urls:
            m = _URL_RE.search(sanitized)
            if m:
                snippet = sanitized[max(0, m.start() - 10): m.end() + 10].strip()[:120]
                findings.append(BusinessFinding(
                    risk    = BusinessRisk.HALLUCINATED_URL,
                    snippet = snippet,
                    owasp   = OWASP_LABEL[BusinessRisk.HALLUCINATED_URL],
                    detail  = f"URL: {m.group(0)[:80]}",
                ))
                sanitized = _URL_RE.sub(_REPLACEMENT[BusinessRisk.HALLUCINATED_URL], sanitized)

        # ── ⑥ Hallucinated statistics ─────────────────────────────────────────

        if cfg.block_hallucinated_stats:
            for pat, reason in _HALLUCINATED_STAT_PATTERNS:
                m = pat.search(sanitized)
                if m:
                    snippet = sanitized[max(0, m.start() - 10): m.end() + 30].strip()[:120]
                    findings.append(BusinessFinding(
                        risk    = BusinessRisk.HALLUCINATED_STAT,
                        snippet = snippet,
                        owasp   = OWASP_LABEL[BusinessRisk.HALLUCINATED_STAT],
                        detail  = reason,
                    ))
                    sanitized = pat.sub(
                        _REPLACEMENT[BusinessRisk.HALLUCINATED_STAT], sanitized, count=1
                    )
                    break

        # ── ⑦ PII leakage in output ───────────────────────────────────────────

        if cfg.block_pii_leakage:
            for pat, reason in _OUTPUT_PII_PATTERNS:
                m = pat.search(sanitized)
                if m:
                    snippet = sanitized[max(0, m.start() - 5): m.end() + 5].strip()[:120]
                    findings.append(BusinessFinding(
                        risk    = BusinessRisk.PII_LEAKAGE,
                        snippet = snippet,
                        owasp   = OWASP_LABEL[BusinessRisk.PII_LEAKAGE],
                        detail  = reason,
                    ))
                    sanitized = pat.sub(_REPLACEMENT[BusinessRisk.PII_LEAKAGE], sanitized)
                    break

        # ── ⑧ Toxic content ───────────────────────────────────────────────────

        if cfg.block_toxic_content:
            for pat, reason in _TOXIC_PATTERNS:
                m = pat.search(sanitized)
                if m:
                    snippet = sanitized[max(0, m.start() - 10): m.end() + 20].strip()[:120]
                    findings.append(BusinessFinding(
                        risk    = BusinessRisk.TOXIC_CONTENT,
                        snippet = snippet,
                        owasp   = OWASP_LABEL[BusinessRisk.TOXIC_CONTENT],
                        detail  = reason,
                    ))
                    sanitized = pat.sub(_REPLACEMENT[BusinessRisk.TOXIC_CONTENT], sanitized)
                    break

        # ── ⑨ System prompt echo ─────────────────────────────────────────────

        if cfg.block_prompt_echo:
            for pat, reason in _PROMPT_ECHO_PATTERNS:
                m = pat.search(sanitized)
                if m:
                    snippet = sanitized[max(0, m.start() - 10): m.end() + 30].strip()[:120]
                    findings.append(BusinessFinding(
                        risk    = BusinessRisk.PROMPT_ECHO,
                        snippet = snippet,
                        owasp   = OWASP_LABEL[BusinessRisk.PROMPT_ECHO],
                        detail  = reason,
                    ))
                    sanitized = pat.sub(_REPLACEMENT[BusinessRisk.PROMPT_ECHO], sanitized, count=1)
                    break

        # ── ⑩ Sensitive data exposure ─────────────────────────────────────────

        if cfg.block_sensitive_data:
            for pat, reason in _SENSITIVE_DATA_PATTERNS:
                m = pat.search(sanitized)
                if m:
                    snippet = sanitized[max(0, m.start() - 5): m.end() + 5].strip()[:120]
                    findings.append(BusinessFinding(
                        risk    = BusinessRisk.SENSITIVE_DATA,
                        snippet = snippet,
                        owasp   = OWASP_LABEL[BusinessRisk.SENSITIVE_DATA],
                        detail  = reason,
                    ))
                    sanitized = pat.sub(_REPLACEMENT[BusinessRisk.SENSITIVE_DATA], sanitized)
                    break

        # ── Custom tenant patterns ────────────────────────────────────────────

        if cfg.custom_patterns:
            for raw_pat in cfg.custom_patterns:
                try:
                    cpat = re.compile(raw_pat, re.IGNORECASE)
                    m = cpat.search(sanitized)
                    if m:
                        findings.append(BusinessFinding(
                            risk    = BusinessRisk.POLICY_VIOLATION,
                            snippet = sanitized[max(0, m.start() - 10): m.end() + 10].strip()[:120],
                            owasp   = OWASP_LABEL[BusinessRisk.POLICY_VIOLATION],
                            detail  = f"custom tenant pattern: {raw_pat[:60]}",
                        ))
                        sanitized = cpat.sub(_REPLACEMENT[BusinessRisk.POLICY_VIOLATION], sanitized)
                        break
                except re.error:
                    log.warning("output_guard: invalid custom pattern %r — skipped", raw_pat)

        if findings:
            log.info(
                "output_guard v2: %d finding(s): %s",
                len(findings),
                [f.risk.value for f in findings],
            )

        return BusinessScanResult(findings=findings, sanitized=sanitized)


# ── Module-level singleton ────────────────────────────────────────────────────

_guard: OutputGuard | None = None


def get_output_guard() -> OutputGuard:
    global _guard
    if _guard is None:
        _guard = OutputGuard()
    return _guard
