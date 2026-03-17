"""
warden/output_guard.py
━━━━━━━━━━━━━━━━━━━━━━
Stage 4: Business-layer output guardrails for SMB / E-commerce deployments.

Complements the technical security scanner (output_sanitizer.py) by catching
business-logic threats that reach clients after a successful prompt injection:

  ① Price Manipulation     — unauthorized discounts / free offers / price floors
  ② Unauthorized Commitments — guarantees, promises, delivery pledges the AI
                               cannot legally make on behalf of the business
  ③ Competitor Mentions    — AI naming or promoting competitor brands
  ④ Policy Violations      — AI claiming return / refund / warranty policies
                               it was not authorized to state

Detection is fully configurable via environment variables — each tenant can
override thresholds through their FilterRequest.context without redeployment.

OWASP mapping:
  ① ② ④  →  LLM09 — Misinformation (AI making false authoritative claims)
  ③      →  custom — Brand Risk

Usage (pipeline — called after upstream LLM response in openai_proxy.py):

    guard  = get_output_guard()
    result = guard.scan(llm_response_text)
    if result.risky:
        # replace content before returning to client
        msg["content"] = result.sanitized

Usage (standalone via POST /filter/output — see main.py):

    result = guard.scan(text)
    return {"safe": not result.risky, "sanitized": result.sanitized, ...}
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
    PRICE_MANIPULATION    = "price_manipulation"     # LLM09
    UNAUTHORIZED_COMMIT   = "unauthorized_commitment" # LLM09
    COMPETITOR_MENTION    = "competitor_mention"      # Brand Risk
    POLICY_VIOLATION      = "policy_violation"        # LLM09


OWASP_LABEL: dict[BusinessRisk, str] = {
    BusinessRisk.PRICE_MANIPULATION:  "LLM09 — Misinformation (price manipulation)",
    BusinessRisk.UNAUTHORIZED_COMMIT: "LLM09 — Misinformation (unauthorized commitment)",
    BusinessRisk.COMPETITOR_MENTION:  "Brand Risk — competitor mention in output",
    BusinessRisk.POLICY_VIOLATION:    "LLM09 — Misinformation (policy hallucination)",
}

# Safe replacement text for each risk type in sanitized output
_REPLACEMENT: dict[BusinessRisk, str] = {
    BusinessRisk.PRICE_MANIPULATION:  "[Цена уточняется — обратитесь к менеджеру / Please contact our team for pricing]",
    BusinessRisk.UNAUTHORIZED_COMMIT: "[Это требует подтверждения — пожалуйста, свяжитесь с нами / Please verify with our team]",
    BusinessRisk.COMPETITOR_MENTION:  "[external service]",
    BusinessRisk.POLICY_VIOLATION:    "[Пожалуйста, уточните политику у менеджера / Please verify this policy with our team]",
}


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
    re.compile(r"\b\$0(?:\.00)?\b"),
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

    def scan(self, text: str) -> BusinessScanResult:
        if not _GUARDRAILS_ENABLED or not text:
            return BusinessScanResult(sanitized=text)

        findings: list[BusinessFinding] = []
        sanitized = text

        # ── ① Price manipulation ──────────────────────────────────────────────

        # Percentage discounts above max threshold
        for m in _DISCOUNT_RE.finditer(text):
            try:
                pct = int(m.group(1))
            except ValueError:
                continue
            if pct > _MAX_DISCOUNT_PCT:
                snippet = text[max(0, m.start() - 15): m.end() + 15].strip()[:120]
                findings.append(BusinessFinding(
                    risk    = BusinessRisk.PRICE_MANIPULATION,
                    snippet = snippet,
                    owasp   = OWASP_LABEL[BusinessRisk.PRICE_MANIPULATION],
                    detail  = f"{pct}% > configured max {_MAX_DISCOUNT_PCT}%",
                ))
                sanitized = sanitized.replace(
                    m.group(0),
                    _REPLACEMENT[BusinessRisk.PRICE_MANIPULATION],
                    1,
                )
                break  # one finding per risk type is enough to flag the response

        # Free / zero-price offers
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

        if _BLOCK_COMMITMENTS:
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
                    break  # one per risk type

        # ── ③ Competitor mentions ─────────────────────────────────────────────

        for pat in _COMPETITOR_PATTERNS:
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

        if findings:
            log.info(
                "output_guard: %d finding(s): %s",
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
