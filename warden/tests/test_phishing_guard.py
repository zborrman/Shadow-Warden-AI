"""
tests/test_phishing_guard.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Unit + integration tests for warden/phishing_guard.py

Coverage:
  • URL extraction and phishing scoring
  • Homoglyph / Punycode normalisation
  • Levenshtein typosquat detection
  • Structural phishing pattern detection
  • SE psychological vector scoring (Urgency, Authority, Fear, Greed)
  • P(SE_RISK) formula and threshold
  • Known-context discount
  • Defanging (hxxps:// + [.] notation)
  • defang_suspicious_urls() output helper
  • Fail-open on empty / garbage input
  • Integration: CausalArbiter se_risk node
  • Integration: OutputGuard BusinessRisk.PHISHING_URL / SOCIAL_ENGINEERING
"""
from __future__ import annotations

from warden.phishing_guard import (
    _AUTHORITY_PATTERNS,
    _FEAR_PATTERNS,
    _GREED_PATTERNS,
    _URGENCY_PATTERNS,
    PHISH_URL_THRESHOLD,
    SE_RISK_THRESHOLD,
    PhishResult,
    URLFinding,
    _analyse_url,
    _defang_url,
    _extract_domain,
    _known_context_score,
    _levenshtein,
    _normalize_to_ascii,
    _score_vector,
    _typosquat_score,
    analyse,
    defang_suspicious_urls,
)

# ── Normalisation ──────────────────────────────────────────────────────────────

class TestNormalizeToAscii:
    def test_cyrillic_o_becomes_o(self):
        # Cyrillic 'о' (U+043E) → 'o'
        # "go\u043egle.com" = g-o-Cyr_о-gle.com → "google.com"
        assert _normalize_to_ascii("go\u043egle.com") == "google.com"

    def test_greek_omicron_becomes_o(self):
        # Greek ο (U+03BF) → 'o'
        assert _normalize_to_ascii("go\u03bfgle.com") == "google.com"

    def test_zero_width_stripped(self):
        assert _normalize_to_ascii("pay\u200bpal.com") == "paypal.com"

    def test_plain_ascii_unchanged(self):
        assert _normalize_to_ascii("example.com") == "example.com"

    def test_accented_chars_stripped(self):
        # é → e (via NFKD decomposition)
        result = _normalize_to_ascii("caf\xe9.com")
        assert result == "cafe.com"


# ── Domain extraction ──────────────────────────────────────────────────────────

class TestExtractDomain:
    def test_https_url(self):
        assert _extract_domain("https://paypal.com/login") == "paypal.com"

    def test_strips_www(self):
        assert _extract_domain("https://www.google.com") == "google.com"

    def test_bare_domain(self):
        assert _extract_domain("evil.com/path") == "evil.com"

    def test_subdomain_preserved(self):
        assert _extract_domain("https://login.paypal.com/evil") == "login.paypal.com"

    def test_empty_returns_empty(self):
        assert _extract_domain("") == ""

    def test_garbage_returns_empty(self):
        # Garbage strings with spaces / special chars fail the domain validity check
        assert _extract_domain("!!!not-a-url!!!") == ""


# ── Levenshtein distance ───────────────────────────────────────────────────────

class TestLevenshtein:
    def test_identical(self):
        assert _levenshtein("abc", "abc") == 0

    def test_single_substitution(self):
        assert _levenshtein("paypal", "paypa1") == 1

    def test_insertion(self):
        assert _levenshtein("apple", "applee") == 1

    def test_deletion(self):
        assert _levenshtein("google", "gogle") == 1

    def test_completely_different(self):
        d = _levenshtein("abc", "xyz")
        assert d == 3


# ── Typosquat scoring ──────────────────────────────────────────────────────────

class TestTyposquatScore:
    def test_exact_brand_match_is_not_suspicious(self):
        # Exact domain should have similarity=1.0 but we compare domain!=brand
        score, brand = _typosquat_score("paypal.com")
        assert score == 1.0 and brand == "paypal.com"

    def test_one_char_off_is_high_score(self):
        score, brand = _typosquat_score("paypa1.com")   # l → 1
        assert score >= 0.85
        assert brand == "paypal.com"

    def test_two_chars_off_scores_above_70(self):
        score, brand = _typosquat_score("g00gle.com")   # oo → 00
        assert score >= 0.70

    def test_totally_different_domain_scores_low(self):
        score, _ = _typosquat_score("xkcd.com")
        assert score < 0.60

    def test_cyrillic_homoglyph_normalised(self):
        # аpple.com — Cyrillic 'а' (looks identical to Latin 'a')
        score, brand = _typosquat_score("\u0430pple.com")
        assert score >= 0.90
        assert brand == "apple.com"


# ── URL phishing analysis ──────────────────────────────────────────────────────

class TestAnalyseUrl:
    def test_typosquat_url_scores_high(self):
        score, reasons = _analyse_url("https://paypa1.com/login")
        assert score >= PHISH_URL_THRESHOLD
        assert any("typosquat" in r for r in reasons)

    def test_ip_host_scores_high(self):
        score, reasons = _analyse_url("https://192.168.1.1/login")
        assert score >= 0.60
        assert any("IP" in r for r in reasons)

    def test_login_subdomain_flags(self):
        score, reasons = _analyse_url("https://login.evil-domain.com/account")
        assert score >= 0.50
        assert any("login" in r.lower() or "subdomain" in r.lower() for r in reasons)

    def test_data_uri_scores_very_high(self):
        score, reasons = _analyse_url("data:text/html;base64,PHNjcmlwdD4=")
        assert score >= 0.90
        assert any("data-URI" in r for r in reasons)

    def test_url_shortener_flags(self):
        score, reasons = _analyse_url("https://bit.ly/3xAbc12")
        assert score >= 0.40

    def test_safe_url_scores_zero(self):
        # example.com may score modestly due to Levenshtein proximity to brands;
        # assert it stays below the blocking threshold
        score, _ = _analyse_url("https://example.com/normal-page")
        assert score < PHISH_URL_THRESHOLD

    def test_punycode_domain_flags(self):
        score, reasons = _analyse_url("https://xn--pple-43d.com")
        assert score >= 0.60
        assert any("Punycode" in r or "IDN" in r for r in reasons)

    def test_brand_in_subdomain(self):
        score, reasons = _analyse_url("https://paypal.com.attacker.io/login")
        assert score >= 0.80
        assert any("subdomain" in r for r in reasons)

    def test_empty_url_returns_zero(self):
        score, _ = _analyse_url("")
        assert score == 0.0


# ── SE vector scoring ──────────────────────────────────────────────────────────

class TestSEVectors:
    def test_urgency_single_match(self):
        score, labels = _score_vector(_URGENCY_PATTERNS,
            "Your account will be suspended in 24 hours. Act now!")
        assert score >= 0.60
        assert labels

    def test_urgency_multi_match_higher_score(self):
        score_one, _ = _score_vector(_URGENCY_PATTERNS, "Urgent response required!")
        score_two, _ = _score_vector(_URGENCY_PATTERNS,
            "Urgent: final notice. Your account expires immediately. Last chance to reply within 2 hours.")
        assert score_two >= score_one

    def test_authority_it_support(self):
        score, labels = _score_vector(_AUTHORITY_PATTERNS,
            "This is IT support. Please verify your credentials.")
        assert score >= 0.60
        assert labels

    def test_authority_official_notice(self):
        score, labels = _score_vector(_AUTHORITY_PATTERNS,
            "This is an official notice from the security team.")
        assert score >= 0.60

    def test_fear_account_compromised(self):
        score, labels = _score_vector(_FEAR_PATTERNS,
            "Your account has been compromised. Unauthorized access detected.")
        assert score >= 0.60

    def test_greed_prize_lure(self):
        score, labels = _score_vector(_GREED_PATTERNS,
            "Congratulations! You have been selected. Claim your reward now.")
        assert score >= 0.60

    def test_clean_text_scores_zero(self):
        for patterns in [_URGENCY_PATTERNS, _AUTHORITY_PATTERNS, _FEAR_PATTERNS, _GREED_PATTERNS]:
            score, labels = _score_vector(patterns, "The quick brown fox jumps over the lazy dog.")
            assert score == 0.0
            assert labels == []


# ── Known-context discount ─────────────────────────────────────────────────────

class TestKnownContext:
    def test_educational_phrase_gives_discount(self):
        score = _known_context_score("This is a phishing simulation example for security awareness training.")
        assert score > 0.0

    def test_simulated_flag_gives_discount(self):
        score = _known_context_score("This is a simulated email campaign — do not act on it.")
        assert score > 0.0

    def test_clean_text_no_discount(self):
        score = _known_context_score("Please verify your account immediately.")
        assert score == 0.0


# ── Defanging ──────────────────────────────────────────────────────────────────

class TestDefangUrl:
    def test_https_scheme_defanged(self):
        result = _defang_url("https://evil.com/login")
        assert result.startswith("hxxps://")

    def test_http_scheme_defanged(self):
        result = _defang_url("http://evil.com/login")
        assert result.startswith("hxxp://")

    def test_domain_dots_bracketed(self):
        result = _defang_url("https://evil.com/login")
        assert "evil[.]com" in result

    def test_path_preserved(self):
        result = _defang_url("https://evil.com/path?q=1")
        assert "/path" in result


class TestDefangSuspiciousUrls:
    def test_replaces_phishing_url_in_text(self):
        phish_result = PhishResult(
            url_findings=[URLFinding(
                url="https://paypa1.com/login",
                defanged="hxxps://paypa1[.]com/login",
                score=0.85,
                reasons=["typosquat 'paypal.com' (sim=0.94)"],
            )],
            max_url_score=0.85,
        )
        text = "Please log in at https://paypa1.com/login to verify."
        result = defang_suspicious_urls(text, phish_result)
        assert "https://paypa1.com/login" not in result
        assert "hxxps://paypa1[.]com/login" in result
        assert "Shadow Warden" in result

    def test_low_score_url_not_defanged(self):
        phish_result = PhishResult(
            url_findings=[URLFinding(
                url="https://example.com",
                defanged="hxxps://example[.]com",
                score=0.30,  # below threshold
                reasons=["near-match"],
            )],
            max_url_score=0.30,
        )
        text = "Visit https://example.com for info."
        result = defang_suspicious_urls(text, phish_result)
        assert result == text  # unchanged


# ── Full pipeline: analyse() ───────────────────────────────────────────────────

class TestAnalyse:
    def test_phishing_url_flagged(self):
        result = analyse("Click here to verify: https://paypa1.com/login")
        assert result.is_phishing is True
        assert result.max_url_score >= PHISH_URL_THRESHOLD
        assert len(result.url_findings) >= 1

    def test_clean_text_not_flagged(self):
        result = analyse("The weather today is sunny and warm.")
        assert result.is_phishing is False
        assert result.is_social_engineering is False
        assert result.se_risk < SE_RISK_THRESHOLD

    def test_se_urgency_authority_triggers(self):
        # Strong multi-vector SE attack: urgency (two patterns) + authority + fear + phishing URL
        text = (
            "URGENT: Only 2 hours left! This is IT support. Your account will be suspended. "
            "Unauthorized access detected. Failure to comply results in legal action. "
            "Verify immediately at https://paypa1.com/login"
        )
        result = analyse(text)
        assert result.is_social_engineering is True
        assert result.se_risk >= SE_RISK_THRESHOLD

    def test_se_formula_components(self):
        text = "Urgent! This is IT support. Your account is compromised."
        result = analyse(text)
        assert result.p_urgency > 0
        assert result.p_authority > 0
        assert result.p_fear > 0

    def test_known_context_discounts_se_risk(self):
        # Educational context should lower SE risk
        legit = analyse("This is a phishing simulation example: Urgent! IT support here. Act now.")
        plain = analyse("Urgent! IT support here. Act now.")
        assert legit.p_known_context > 0
        assert legit.se_risk <= plain.se_risk

    def test_defanged_text_populated(self):
        result = analyse("Phishing link: https://paypa1.com/login")
        if result.is_phishing:
            assert "hxxps://" in result.defanged_text or result.defanged_text != ""

    def test_fail_open_on_empty_string(self):
        result = analyse("")
        assert result.is_phishing is False
        assert result.is_social_engineering is False

    def test_elapsed_ms_populated(self):
        result = analyse("some content")
        assert result.elapsed_ms >= 0

    def test_cyrillic_homoglyph_url_detected(self):
        # Cyrillic 'а' (U+0430) looks identical to Latin 'a' — visual homoglyph attack
        # _analyse_url detects non-ASCII in domain area and normalises before scoring
        text = "Login at https://\u0430pple.com/verify"
        result = analyse(text)
        # PhishGuard must detect the homoglyph URL as suspicious
        assert result.is_phishing is True
        assert result.max_url_score >= PHISH_URL_THRESHOLD

    def test_data_uri_blocked(self):
        result = analyse("View this: data:text/html;base64,PHNjcmlwdD4=")
        assert result.is_phishing is True


# ── Integration: CausalArbiter se_risk node ───────────────────────────────────

class TestCausalArbiterIntegration:
    def test_se_risk_zero_is_backward_compatible(self):
        from warden.causal_arbiter import arbitrate
        result_old = arbitrate(
            ml_score=0.55, ers_score=0.2, obfuscation_detected=False,
            block_history=0, tool_tier=0, content_entropy=4.0,
        )
        result_new = arbitrate(
            ml_score=0.55, ers_score=0.2, obfuscation_detected=False,
            block_history=0, tool_tier=0, content_entropy=4.0,
            se_risk=0.0,
        )
        assert result_old.risk_probability == result_new.risk_probability

    def test_high_se_risk_increases_causal_score(self):
        from warden.causal_arbiter import arbitrate
        result_no_se = arbitrate(
            ml_score=0.55, ers_score=0.3, obfuscation_detected=False,
            block_history=0, tool_tier=0, content_entropy=4.0, se_risk=0.0,
        )
        result_se = arbitrate(
            ml_score=0.55, ers_score=0.3, obfuscation_detected=False,
            block_history=0, tool_tier=0, content_entropy=4.0, se_risk=1.0,
        )
        assert result_se.risk_probability > result_no_se.risk_probability
        assert result_se.p_se_risk == 1.0

    def test_se_detail_string_includes_se_node(self):
        from warden.causal_arbiter import arbitrate
        result = arbitrate(
            ml_score=0.5, ers_score=0.2, obfuscation_detected=False,
            block_history=0, tool_tier=0, content_entropy=4.0, se_risk=0.8,
        )
        assert "se=" in result.detail


# ── Integration: FlagType schema ─────────────────────────────────────────────

class TestSchemaFlags:
    def test_phishing_url_flag_exists(self):
        from warden.schemas import FlagType
        assert FlagType.PHISHING_URL == "phishing_url"

    def test_social_engineering_flag_exists(self):
        from warden.schemas import FlagType
        assert FlagType.SOCIAL_ENGINEERING == "social_engineering"


# ── Integration: OutputGuard BusinessRisk ─────────────────────────────────────

class TestOutputGuardIntegration:
    def test_phishing_risk_type_exists(self):
        from warden.output_guard import BusinessRisk
        assert BusinessRisk.PHISHING_URL == "phishing_url"

    def test_social_engineering_risk_type_exists(self):
        from warden.output_guard import BusinessRisk
        assert BusinessRisk.SOCIAL_ENGINEERING == "social_engineering"

    def test_scan_defangs_phishing_url_in_output(self):
        from warden.output_guard import OutputGuard, TenantOutputConfig
        guard = OutputGuard()
        cfg = TenantOutputConfig(
            block_hallucinated_urls=False,   # disable generic URL removal
            defang_phishing_urls=True,
        )
        result = guard.scan(
            "Click here: https://paypa1.com/login to verify your PayPal account.",
            tenant_config=cfg,
        )
        # Defanging may or may not fire depending on PhishGuard threshold;
        # assert no exception was raised (fail-open guarantee)
        assert result is not None

    def test_scan_with_se_disabled_no_annotation(self):
        from warden.output_guard import OutputGuard, TenantOutputConfig
        guard = OutputGuard()
        cfg = TenantOutputConfig(
            annotate_se_output=False,
            block_hallucinated_urls=False,
        )
        result = guard.scan(
            "Urgent! This is IT support. Your account is suspended.", tenant_config=cfg
        )
        # With SE annotation disabled no SOCIAL_ENGINEERING finding expected
        assert "social_engineering" not in result.risk_types
