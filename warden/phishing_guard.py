"""
warden/phishing_guard.py
━━━━━━━━━━━━━━━━━━━━━━━
PhishGuard & SE-Arbiter — bidirectional phishing and social engineering detection.

Two threat vectors defended
────────────────────────────
Inbound  (attack ON the LLM / agent)
  • Homoglyph / Punycode URL spoofing inside prompts or document payloads
  • Indirect prompt injection via URL-embedded instructions
  • Psychological manipulation vectors targeting the agent's reasoning

Outbound (LLM output targeting the human user)
  • LLM-hallucinated or compromised-LLM-generated phishing URLs
  • SE-manipulative language in AI responses (urgency, authority, fear, greed)
  • Defanging: dangerous URLs neutralised before reaching the browser

Integration points
──────────────────
  Layer 2  ObfuscationDecoder  — IDNA normalisation (homoglyph step)
  Layer 3  CausalArbiter       — se_risk node added to Bayesian DAG
  Layer 6  MultimodalGuard     — phishing CLIP labels (image_guard.py)
  Layer 9  OutputGuard         — defanging + SE-text warning in output

SE scoring formula (from spec)
───────────────────────────────
  P(SE_RISK | do(content)) =
      0.40 × P(Urgency)
    + 0.30 × P(Authority)
    + 0.30 × P(URL_Anomaly)
    - 0.10 × P(Known_Context)
  Threshold: 0.75 → SOCIAL_ENGINEERING flag

  Extended with secondary SE vectors:
    + 0.10 × P(Fear)
    + 0.05 × P(Greed)
  (not in original formula, added for completeness; capped at 1.0)

Runtime: < 2 ms CPU (regex-only path, no model calls).
Fails open: any exception returns PhishResult with all flags False.
"""
from __future__ import annotations

import logging
import os
import re
import time
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import urlparse

log = logging.getLogger("warden.phishing_guard")

# ── Config ────────────────────────────────────────────────────────────────────

SE_RISK_THRESHOLD   = float(os.getenv("SE_RISK_THRESHOLD",   "0.75"))
PHISH_URL_THRESHOLD = float(os.getenv("PHISH_URL_THRESHOLD", "0.60"))

# ── Top-50 most impersonated brand domains ────────────────────────────────────
# Levenshtein similarity ≥ 0.85 to any of these triggers URL_ANOMALY.
# Subset of top-10 000 Tranco list; kept small for sub-millisecond checks.
_BRAND_DOMAINS: list[str] = [
    "google.com", "microsoft.com", "apple.com", "amazon.com", "facebook.com",
    "paypal.com", "netflix.com", "instagram.com", "twitter.com", "linkedin.com",
    "github.com", "dropbox.com", "icloud.com", "outlook.com", "office365.com",
    "live.com", "hotmail.com", "yahoo.com", "chase.com", "wellsfargo.com",
    "bankofamerica.com", "citibank.com", "hsbc.com", "americanexpress.com",
    "steam.com", "epicgames.com", "roblox.com", "discord.com", "reddit.com",
    "tiktok.com", "whatsapp.com", "telegram.org", "zoom.us", "slack.com",
    "salesforce.com", "adobe.com", "cloudflare.com", "shopify.com",
    "stripe.com", "crypto.com", "coinbase.com", "binance.com",
    "kraken.com", "blockchain.com", "metamask.io", "opensea.io",
    "dhl.com", "fedex.com", "ups.com", "usps.com",
]

# ── URL extractor ─────────────────────────────────────────────────────────────

# Matches explicit URLs (including defanged variants like hxxps://)
_URL_RE = re.compile(
    r'(?:h(?:xx|tt)ps?://|hxxp://)'  # defanged or normal scheme
    r'[^\s<>"{}|\\^`\[\]]{6,}'
    r'|'
    r'https?://[^\s<>"{}|\\^`\[\]]{6,}',
    re.IGNORECASE,
)

# Bare domain heuristic (login/secure path keyword)
_BARE_DOMAIN_RE = re.compile(
    r'\b(?:www\.)?'
    r'([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.'
    r'(?:com|net|org|io|co|uk|de|fr|ru|cn|info|biz|online|site|live|click|xyz))'
    r'(?:/[^\s]*)?',
    re.IGNORECASE,
)

# ── Homoglyph normalisation ───────────────────────────────────────────────────
# Maps confusable Unicode characters to their ASCII equivalents.
# unicodedata.normalize("NFKD") handles most cases; explicit map catches
# the most common Cyrillic / Greek visual lookalikes.
_HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic → Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X",
    # Greek
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i",
    "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u",
    "χ": "x", "ω": "w",
    # Zero-width / invisible characters (common evasion technique)
    "\u200b": "", "\u200c": "", "\u200d": "", "\ufeff": "",
    # Fullwidth ASCII
    "Ａ": "A", "Ｂ": "B", "Ｃ": "C", "０": "0", "１": "1", "２": "2",
}


def _normalize_to_ascii(text: str) -> str:
    """Collapse homoglyphs → ASCII for distance comparison."""
    for src, dst in _HOMOGLYPH_MAP.items():
        text = text.replace(src, dst)
    normalized = unicodedata.normalize("NFKD", text)
    return normalized.encode("ascii", errors="ignore").decode("ascii")


_VALID_DOMAIN_RE = re.compile(
    r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$'
)


def _extract_domain(url: str) -> str:
    """Extract registrable domain from a URL string. Returns '' on failure."""
    try:
        parsed = urlparse(url if "://" in url else "https://" + url)
        host = (parsed.hostname or "").lower().split(":")[0]
        # Normalise IDN / Punycode back to ASCII for comparison
        try:
            host = host.encode("ascii").decode("ascii")
        except (UnicodeEncodeError, UnicodeDecodeError):
            host = _normalize_to_ascii(host)
        host = host[4:] if host.startswith("www.") else host
        # Sanity check — reject strings that look nothing like a domain
        if not _VALID_DOMAIN_RE.match(host):
            return ""
        return host
    except Exception:
        return ""


# ── Levenshtein distance ──────────────────────────────────────────────────────

def _levenshtein(a: str, b: str) -> int:
    """Iterative Levenshtein distance (O(n·m) time, O(n) space)."""
    if a == b:
        return 0
    if len(a) > len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[len(b)]


def _typosquat_score(domain: str) -> tuple[float, str]:
    """
    Compute maximum normalised Levenshtein similarity to any brand domain.
    Returns (similarity 0–1, closest_brand_domain).
    similarity = 1 − edit_distance / max(len(domain), len(brand))
    """
    if not domain:
        return 0.0, ""
    norm = _normalize_to_ascii(domain)
    best_score, best_brand = 0.0, ""
    for brand in _BRAND_DOMAINS:
        dist  = _levenshtein(norm, brand)
        denom = max(len(norm), len(brand))
        score = 1.0 - dist / denom if denom else 0.0
        if score > best_score:
            best_score, best_brand = score, brand
    return round(best_score, 4), best_brand


# ── Structural phishing URL patterns ─────────────────────────────────────────
# Each entry: (pattern, phishing_score, reason_label)

_BRAND_SUBDOMAIN_RE = re.compile(
    r'(?:' + '|'.join(re.escape(b.split('.')[0]) for b in _BRAND_DOMAINS[:30]) + r')'
    r'\.[a-z]{2,6}\.[a-z]{2,6}',
    re.IGNORECASE,
)

_PHISH_PATTERNS: list[tuple[re.Pattern[str], float, str]] = [
    # Brand name used as subdomain: paypal.com.evil.io
    (_BRAND_SUBDOMAIN_RE, 0.85, "brand-in-subdomain"),
    # Raw IP address as host
    (re.compile(r'https?://\d{1,3}(?:\.\d{1,3}){3}[:/]', re.IGNORECASE), 0.72, "IP-address host"),
    # Login/secure/verify as subdomain keyword
    (re.compile(r'https?://(?:secure|login|account|verify|update|signin|webscr)\.',
                re.IGNORECASE), 0.65, "login-keyword subdomain"),
    # Data URI (inline execution)
    (re.compile(r'data:[^;]+;base64,', re.IGNORECASE), 0.92, "data-URI"),
    # Punycode / IDN homograph domains
    (re.compile(r'https?://[^/]*xn--', re.IGNORECASE), 0.75, "Punycode/IDN domain"),
    # URL shorteners hiding the real destination
    (re.compile(
        r'https?://(?:bit\.ly|tinyurl\.com|t\.co|ow\.ly|goo\.gl|rb\.gy|cutt\.ly|'
        r'is\.gd|buff\.ly|short\.io)/',
        re.IGNORECASE,
    ), 0.45, "URL shortener"),
    # Free hosting + login/credential path
    (re.compile(
        r'https?://[^/]*(?:000webhostapp|github\.io|netlify\.app|vercel\.app|'
        r'pages\.dev|glitch\.me|repl\.co)[^/]*/(?:login|signin|verify|account|secure)',
        re.IGNORECASE,
    ), 0.62, "free-host + login path"),
    # Long random hex path (token-phishing / credential reset spoofing)
    (re.compile(r'https?://[^/]+/[a-f0-9]{32,}', re.IGNORECASE), 0.55, "long-hex path"),
]


_DATA_URI_RE = re.compile(r'\bdata:[^;]{1,30};base64,', re.IGNORECASE)


def _analyse_url(url: str) -> tuple[float, list[str]]:
    """
    Compute phishing score (0–1) for a single URL.
    Returns (score, list_of_reasons).
    """
    reasons: list[str] = []
    score = 0.0

    # Data URI check — doesn't have an HTTP scheme but is extremely dangerous
    if _DATA_URI_RE.search(url):
        return 0.92, ["data-URI"]

    # Non-ASCII characters in the URL domain area signal a homoglyph attack
    # even before domain extraction (e.g. https://аpple.com where а=Cyrillic)
    _url_before_path = url.split("/")[2] if "://" in url else url.split("/")[0]
    if any(ord(c) > 127 for c in _url_before_path):
        normalized_host = _normalize_to_ascii(_url_before_path.split(":")[0])
        sim, closest = _typosquat_score(normalized_host)
        if sim >= 0.80:
            score = max(score, 0.82)
            reasons.append(f"homoglyph domain spoofing '{closest}' (sim={sim:.2f})")
        else:
            score = max(score, 0.65)
            reasons.append("non-ASCII/homoglyph characters in domain")
        return min(score, 1.0), reasons

    domain = _extract_domain(url)
    if not domain:
        return 0.0, []

    # Typosquatting / homoglyph similarity
    similarity, closest = _typosquat_score(domain)
    if similarity >= 0.85 and domain != closest:
        score = max(score, 0.82)
        reasons.append(f"typosquat '{closest}' (sim={similarity:.2f})")
    elif 0.70 <= similarity < 0.85 and domain != closest:
        score = max(score, 0.55)
        reasons.append(f"near-match '{closest}' (sim={similarity:.2f})")

    # Structural pattern checks
    for pat, pat_score, reason in _PHISH_PATTERNS:
        if pat.search(url):
            score = max(score, pat_score)
            reasons.append(reason)

    return min(score, 1.0), reasons


# ── SE psychological pressure vectors ────────────────────────────────────────
# Each list contains (compiled_regex, label) pairs.

_URGENCY_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(
        r'\b(?:urgent|urgently|immediately|right now|act now|'
        r'expires?\s+(?:in|at|soon)|(?:24|48|72)[\s\-]?hours?|'
        r'deadline|last chance|limited time|time[\s\-]sensitive|'
        r'your account (?:will be|is being) (?:suspended|terminated|closed|locked)|'
        r'verify (?:now|immediately)|respond within|final notice|last warning|'
        r'action required|срочно|немедленно|аккаунт будет заблокирован)\b',
        re.IGNORECASE,
    ), "urgency/deadline pressure"),
    (re.compile(
        r'\b(?:reply (?:within|by)|expires? in \d|only \d+ (?:hours?|minutes?) left|'
        r'closes? in|offer ends?)\b',
        re.IGNORECASE,
    ), "time-limited offer"),
]

_AUTHORITY_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(
        r'\b(?:IT\s+(?:support|department|team|helpdesk)|system\s+administrator|'
        r'your\s+CEO|management\s+team|HR\s+(?:department|team)|'
        r'legal\s+(?:department|team)|Microsoft\s+support|Apple\s+support|'
        r'Google\s+(?:team|security)|(?:tech|technical)\s+support\s+team|'
        r'security\s+team|compliance\s+(?:team|department)|'
        r'служба\s+(?:безопасности|поддержки)|администратор\s+системы)\b',
        re.IGNORECASE,
    ), "authority impersonation"),
    (re.compile(
        r'\b(?:this\s+is\s+(?:your|the)\s+(?:bank|support|admin|security|IT|legal|'
        r'compliance|fraud)|we\s+are\s+(?:from|contacting)|'
        r'(?:official|verified|authorized)\s+(?:notice|communication|alert|message))\b',
        re.IGNORECASE,
    ), "official impersonation"),
]

_FEAR_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(
        r'\b(?:your\s+(?:account|data|files?|computer|device)\s+(?:has\s+been|is|'
        r'are|will\s+be)\s+(?:compromised|hacked|infected|stolen|suspended|blocked|'
        r'flagged|under\s+attack)|security\s+(?:breach|violation|incident|alert|'
        r'warning)|unauthori[sz]ed\s+(?:access|login|activity)|failure\s+to\s+comply|'
        r'legal\s+action|law\s+enforcement|ваш\s+аккаунт\s+(?:взломан|заблокирован)|'
        r'угроза\s+безопасности)\b',
        re.IGNORECASE,
    ), "fear/threat vector"),
    (re.compile(
        r'\b(?:you\s+must|mandatory|non[\s\-]?compliance|penalty|fine\s+of\s+\$?\d|'
        r'prosecuted|account\s+(?:deletion|termination)\s+(?:pending|imminent))\b',
        re.IGNORECASE,
    ), "compliance pressure"),
]

_GREED_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(
        r'\b(?:you\s+(?:are|have\s+been)\s+(?:selected|chosen|eligible|'
        r'entitled\s+to|approved\s+for)|congratulations?\s+you|'
        r'claim\s+your\s+(?:prize|reward|refund|bonus|gift)|'
        r'unclaimed\s+(?:funds?|reward|refund|prize)|'
        r'(?:tax\s+)?refund\s+(?:of\s+)?\$?\d|you\s+(?:won|have\s+won)|'
        r'free\s+(?:gift|iphone|laptop|money)|'
        r'вы\s+(?:выиграли|были\s+выбраны|имеете\s+право))\b',
        re.IGNORECASE,
    ), "reward/prize lure"),
    (re.compile(
        r'\b(?:double\s+your|guaranteed\s+return|passive\s+income\s+of|'
        r'make\s+\$\d+\s+per|investment\s+opportunity\s+expires?)\b',
        re.IGNORECASE,
    ), "financial lure"),
]

# Known-context discount — educational / simulation / red-team context
_KNOWN_CONTEXT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r'\b(?:for\s+example|such\s+as|phishing\s+simulation|security\s+awareness|'
        r'red\s+team|training\s+(?:email|scenario)|test(?:ing)?\s+campaign|'
        r'пример|учебный|симуляция|демонстрация)\b',
        re.IGNORECASE,
    ),
    re.compile(
        r'\b(?:this\s+is\s+(?:a\s+)?(?:simulated|test|example|demo|fictional)|'
        r'I(?:\'m|\s+am)\s+(?:writing\s+about|analyzing|studying|teaching|simulating))\b',
        re.IGNORECASE,
    ),
]


def _score_vector(patterns: list[tuple[re.Pattern[str], str]], text: str) -> tuple[float, list[str]]:
    """
    Score a single psychological pressure vector.
    Returns (score 0–1, list of matched labels).
    Scoring: 1 match → 0.60, each additional match adds 0.20 (capped at 1.0).
    """
    matched = [label for pat, label in patterns if pat.search(text)]
    if not matched:
        return 0.0, []
    score = min(0.60 + 0.20 * (len(matched) - 1), 1.0)
    return round(score, 4), matched


def _known_context_score(text: str) -> float:
    """Return a discount factor (0–1) when content appears educational/simulated."""
    hits = sum(1 for p in _KNOWN_CONTEXT_PATTERNS if p.search(text))
    return min(hits * 0.40, 1.0)


# ── Result dataclasses ────────────────────────────────────────────────────────

@dataclass
class URLFinding:
    url:      str
    defanged: str           # hxxps://domain[.]com
    score:    float         # phishing probability 0–1
    reasons:  list[str] = field(default_factory=list)


@dataclass
class PhishResult:
    """Combined PhishGuard + SE-Arbiter analysis result."""
    # ── URL-level ──────────────────────────────────────────────────────────────
    is_phishing:    bool             = False
    url_findings:   list[URLFinding] = field(default_factory=list)
    max_url_score:  float            = 0.0

    # ── SE psychological vectors ───────────────────────────────────────────────
    se_risk:              float   = 0.0   # P(SE_RISK | do(content)), 0–1
    is_social_engineering: bool   = False
    p_urgency:            float   = 0.0
    p_authority:          float   = 0.0
    p_fear:               float   = 0.0
    p_greed:              float   = 0.0
    p_url_anomaly:        float   = 0.0
    p_known_context:      float   = 0.0
    se_labels:            list[str] = field(default_factory=list)

    # ── Defanged text (for output scanning mode) ───────────────────────────────
    defanged_text: str  = ""

    elapsed_ms:    float = 0.0


# ── Defanging ─────────────────────────────────────────────────────────────────

def _defang_url(url: str) -> str:
    """
    Convert a URL to defanged threat-intel notation.
      https://evil.com/path → hxxps://evil[.]com/path
    """
    defanged = re.sub(r'^https', 'hxxps', url, flags=re.IGNORECASE)
    defanged = re.sub(r'^http(?!s)', 'hxxp', defanged, flags=re.IGNORECASE)
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if host:
            defanged = defanged.replace(host, host.replace(".", "[.]"), 1)
    except Exception:
        defanged = re.sub(r'(\w+)\.(\w+)', r'\1[.]\2', defanged, count=2)
    return defanged


def defang_suspicious_urls(text: str, phish_result: PhishResult) -> str:
    """
    Replace phishing URLs in text with defanged form + inline warning.
    Used by OutputGuard before forwarding LLM output to the browser/client.

    Example:
      https://paypa1.com/login → hxxps://paypa1[.]com/login
      ⚠️ [Shadow Warden: suspicious URL — typosquat 'paypal.com' (sim=0.94)]
    """
    result = text
    for finding in phish_result.url_findings:
        if finding.score >= PHISH_URL_THRESHOLD:
            reason_str = "; ".join(finding.reasons[:2])
            warning = f"{finding.defanged} ⚠️ [Shadow Warden: suspicious URL — {reason_str}]"
            result = result.replace(finding.url, warning)
    return result


# ── Public API ────────────────────────────────────────────────────────────────

def analyse(text: str) -> PhishResult:
    """
    Run PhishGuard + SE-Arbiter on a piece of text (inbound OR outbound).

    Pipeline:
      1. Extract URLs → compute phishing score per URL
      2. Score 4 SE psychological vectors via regex
      3. Compute P(SE_RISK | do(content)) with spec formula
      4. Build defanged copy of text for safe forwarding

    Runtime: < 2 ms CPU (pure regex, no ML inference).
    Fails open: exceptions return PhishResult with all flags False.
    """
    t0 = time.perf_counter()
    try:
        # ── 1. URL analysis ───────────────────────────────────────────────────
        url_findings: list[URLFinding] = []
        max_url_score = 0.0

        # Data URIs are not matched by _URL_RE (no http scheme) — scan separately
        for m in _DATA_URI_RE.finditer(text):
            data_uri = m.group(0)
            url_findings.append(URLFinding(
                url=data_uri, defanged=f"[data-URI blocked]",
                score=0.92, reasons=["data-URI"],
            ))
            max_url_score = max(max_url_score, 0.92)

        for m in _URL_RE.finditer(text):
            url = m.group(0)
            score, reasons = _analyse_url(url)
            if score > 0.0:
                url_findings.append(URLFinding(
                    url=url, defanged=_defang_url(url), score=score, reasons=reasons,
                ))
                max_url_score = max(max_url_score, score)

        # Fallback: bare-domain scan when no explicit URLs found
        if not url_findings:
            for m in _BARE_DOMAIN_RE.finditer(text):
                score, reasons = _analyse_url(m.group(0))
                if score >= 0.50:
                    url_findings.append(URLFinding(
                        url=m.group(0), defanged=_defang_url(m.group(0)),
                        score=score, reasons=reasons,
                    ))
                    max_url_score = max(max_url_score, score)

        is_phishing = max_url_score >= PHISH_URL_THRESHOLD

        # ── 2. SE psychological vector scoring ────────────────────────────────
        p_urgency,   urgency_labels   = _score_vector(_URGENCY_PATTERNS,   text)
        p_authority, authority_labels = _score_vector(_AUTHORITY_PATTERNS, text)
        p_fear,      fear_labels      = _score_vector(_FEAR_PATTERNS,      text)
        p_greed,     greed_labels     = _score_vector(_GREED_PATTERNS,     text)
        p_known_ctx                   = _known_context_score(text)

        # URL anomaly signal for SE formula
        p_url_anomaly = max_url_score if url_findings else 0.0

        # ── 3. P(SE_RISK | do(content)) — spec formula ────────────────────────
        se_risk = (
            0.40 * p_urgency
            + 0.30 * p_authority
            + 0.30 * p_url_anomaly
            - 0.10 * p_known_ctx
            + 0.10 * p_fear        # secondary booster
            + 0.05 * p_greed       # secondary booster
        )
        se_risk = round(max(0.0, min(se_risk, 1.0)), 4)
        is_se   = se_risk >= SE_RISK_THRESHOLD

        se_labels = urgency_labels + authority_labels + fear_labels + greed_labels

        # ── 4. Defanged text ──────────────────────────────────────────────────
        defanged_text = text
        if url_findings:
            _temp = PhishResult(url_findings=url_findings, max_url_score=max_url_score)
            defanged_text = defang_suspicious_urls(text, _temp)

        elapsed = round((time.perf_counter() - t0) * 1000, 3)

        result = PhishResult(
            is_phishing           = is_phishing,
            url_findings          = url_findings,
            max_url_score         = round(max_url_score, 4),
            se_risk               = se_risk,
            is_social_engineering = is_se,
            p_urgency             = round(p_urgency, 4),
            p_authority           = round(p_authority, 4),
            p_fear                = round(p_fear, 4),
            p_greed               = round(p_greed, 4),
            p_url_anomaly         = round(p_url_anomaly, 4),
            p_known_context       = round(p_known_ctx, 4),
            se_labels             = se_labels,
            defanged_text         = defanged_text,
            elapsed_ms            = elapsed,
        )

        if is_phishing:
            log.warning(
                "PhishGuard PHISHING_URL: max_score=%.3f urls=%d reasons=%s",
                max_url_score, len(url_findings),
                url_findings[0].reasons[:2] if url_findings else [],
            )
        if is_se:
            log.warning(
                "PhishGuard SOCIAL_ENGINEERING: se_risk=%.3f labels=%s",
                se_risk, se_labels[:4],
            )

        return result

    except Exception as exc:
        log.debug("PhishGuard.analyse error (fail-open): %s", exc)
        return PhishResult(elapsed_ms=round((time.perf_counter() - t0) * 1000, 3))
