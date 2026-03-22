"""
warden/tests/test_output_guard.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Unit tests for OutputGuard v2.

Covers all 10 risk types:
  v1: price_manipulation, unauthorized_commitment, competitor_mention, policy_violation
  v2: hallucinated_url, hallucinated_statistic, pii_leakage, toxic_content,
      prompt_echo, sensitive_data_exposure

Also covers: TenantOutputConfig overrides, custom_patterns, backward compat.
"""
from __future__ import annotations

from warden.output_guard import (
    BusinessRisk,
    OutputGuard,
    TenantOutputConfig,
    get_output_guard,
)

g = OutputGuard()


# ── helpers ───────────────────────────────────────────────────────────────────

def risks(text: str, cfg: TenantOutputConfig | None = None) -> set[str]:
    return {f.risk.value for f in g.scan(text, cfg).findings}


def is_clean(text: str, cfg: TenantOutputConfig | None = None) -> bool:
    return not g.scan(text, cfg).risky


# ── ① Price manipulation ──────────────────────────────────────────────────────

class TestPriceManipulation:

    def test_high_discount_flagged(self):
        assert BusinessRisk.PRICE_MANIPULATION in risks(
            "We offer a special 80% off discount on all items today!"
        )

    def test_low_discount_allowed(self):
        assert BusinessRisk.PRICE_MANIPULATION not in risks(
            "We offer 10% off on orders over $50."
        )

    def test_free_offer_flagged(self):
        assert BusinessRisk.PRICE_MANIPULATION in risks(
            "You can get this product for free today!"
        )

    def test_zero_price_flagged(self):
        assert BusinessRisk.PRICE_MANIPULATION in risks("Get it for $0.00 right now.")

    def test_sanitized_removes_discount(self):
        result = g.scan("Save 75% off — limited time!")
        assert "75%" not in result.sanitized or "REDACTED" in result.sanitized or "contact" in result.sanitized.lower()

    def test_tenant_lower_max_discount(self):
        cfg = TenantOutputConfig(max_discount_pct=20)
        assert BusinessRisk.PRICE_MANIPULATION in risks("Get 30% off today!", cfg)

    def test_tenant_higher_max_discount(self):
        cfg = TenantOutputConfig(max_discount_pct=90)
        assert BusinessRisk.PRICE_MANIPULATION not in risks("Get 80% off today!", cfg)


# ── ② Unauthorized commitments ────────────────────────────────────────────────

class TestUnauthorizedCommitments:

    def test_i_guarantee_flagged(self):
        assert BusinessRisk.UNAUTHORIZED_COMMIT in risks("I guarantee your delivery by Friday.")

    def test_we_guarantee_flagged(self):
        assert BusinessRisk.UNAUTHORIZED_COMMIT in risks("We guarantee full satisfaction.")

    def test_i_promise_flagged(self):
        assert BusinessRisk.UNAUTHORIZED_COMMIT in risks("I promise you will receive it tomorrow.")

    def test_we_will_send_flagged(self):
        assert BusinessRisk.UNAUTHORIZED_COMMIT in risks("We will send you a replacement immediately.")

    def test_russian_guarantee_flagged(self):
        assert BusinessRisk.UNAUTHORIZED_COMMIT in risks("Мы гарантируем возврат средств.")

    def test_tenant_disable_commitments(self):
        cfg = TenantOutputConfig(block_commitments=False)
        assert BusinessRisk.UNAUTHORIZED_COMMIT not in risks("I guarantee delivery.", cfg)

    def test_normal_statement_clean(self):
        assert BusinessRisk.UNAUTHORIZED_COMMIT not in risks(
            "Our team will look into your request and get back to you."
        )


# ── ③ Competitor mentions ─────────────────────────────────────────────────────

class TestCompetitorMentions:

    def test_tenant_competitor_flagged(self):
        cfg = TenantOutputConfig(competitor_names=["Amazon", "Alibaba"])
        assert BusinessRisk.COMPETITOR_MENTION in risks(
            "You could also check Amazon for similar products.", cfg
        )

    def test_env_competitor_replaced_in_sanitized(self):
        cfg = TenantOutputConfig(competitor_names=["Acme"])
        result = g.scan("Acme offers better prices.", cfg)
        assert "Acme" not in result.sanitized

    def test_no_competitors_configured_clean(self):
        cfg = TenantOutputConfig(competitor_names=[])
        assert BusinessRisk.COMPETITOR_MENTION not in risks("Check out Walmart.", cfg)


# ── ④ Policy violations ───────────────────────────────────────────────────────

class TestPolicyViolations:

    def test_return_policy_claim_flagged(self):
        assert BusinessRisk.POLICY_VIOLATION in risks(
            "Our return policy is 30 days no questions asked."
        )

    def test_lifetime_warranty_flagged(self):
        assert BusinessRisk.POLICY_VIOLATION in risks(
            "This product comes with a lifetime warranty."
        )

    def test_full_refund_window_flagged(self):
        assert BusinessRisk.POLICY_VIOLATION in risks(
            "You can get a full refund within 60 days."
        )

    def test_general_refund_mention_clean(self):
        assert BusinessRisk.POLICY_VIOLATION not in risks(
            "Please contact support to discuss your refund options."
        )


# ── ⑤ Hallucinated URLs ───────────────────────────────────────────────────────

class TestHallucinatedURLs:

    def test_http_url_flagged(self):
        assert BusinessRisk.HALLUCINATED_URL in risks(
            "You can find more info at http://example.com/products"
        )

    def test_https_url_flagged(self):
        assert BusinessRisk.HALLUCINATED_URL in risks(
            "Visit https://store.official.com to place your order."
        )

    def test_url_removed_from_sanitized(self):
        result = g.scan("Check https://fake-store.com for details.")
        assert "https://" not in result.sanitized

    def test_no_url_clean(self):
        assert BusinessRisk.HALLUCINATED_URL not in risks(
            "Please visit our website for more information."
        )

    def test_tenant_disable_url_check(self):
        cfg = TenantOutputConfig(block_hallucinated_urls=False)
        assert BusinessRisk.HALLUCINATED_URL not in risks(
            "Visit https://example.com for details.", cfg
        )


# ── ⑥ Hallucinated statistics ─────────────────────────────────────────────────

class TestHallucinatedStatistics:

    def test_studies_show_flagged(self):
        assert BusinessRisk.HALLUCINATED_STAT in risks(
            "Studies show that 92% of users prefer our product."
        )

    def test_according_to_research_flagged(self):
        assert BusinessRisk.HALLUCINATED_STAT in risks(
            "According to recent research, AI adoption has tripled."
        )

    def test_research_indicates_flagged(self):
        assert BusinessRisk.HALLUCINATED_STAT in risks(
            "Research indicates that this approach is 45% more effective."
        )

    def test_experts_say_flagged(self):
        assert BusinessRisk.HALLUCINATED_STAT in risks(
            "Experts say this is the best solution available."
        )

    def test_russian_research_claim_flagged(self):
        assert BusinessRisk.HALLUCINATED_STAT in risks(
            "Исследования показывают, что 80% клиентов довольны."
        )

    def test_plain_statement_clean(self):
        assert BusinessRisk.HALLUCINATED_STAT not in risks(
            "Our product has received positive customer reviews."
        )

    def test_tenant_disable_stat_check(self):
        cfg = TenantOutputConfig(block_hallucinated_stats=False)
        assert BusinessRisk.HALLUCINATED_STAT not in risks(
            "Studies show 90% satisfaction rate.", cfg
        )


# ── ⑦ PII leakage ────────────────────────────────────────────────────────────

class TestPIILeakage:

    def test_credit_card_flagged(self):
        assert BusinessRisk.PII_LEAKAGE in risks(
            "The card on file is 4111-1111-1111-1111."
        )

    def test_ssn_flagged(self):
        assert BusinessRisk.PII_LEAKAGE in risks(
            "Your SSN on file is 123-45-6789."
        )

    def test_email_flagged(self):
        assert BusinessRisk.PII_LEAKAGE in risks(
            "I found the account: john.doe@example.com"
        )

    def test_phone_flagged(self):
        assert BusinessRisk.PII_LEAKAGE in risks(
            "The contact number is +1 (555) 867-5309."
        )

    def test_pii_redacted_in_sanitized(self):
        result = g.scan("Card: 4111-1111-1111-1111 expires 12/26")
        assert "4111" not in result.sanitized

    def test_clean_text_no_pii(self):
        assert BusinessRisk.PII_LEAKAGE not in risks(
            "Your order has been processed successfully."
        )

    def test_tenant_disable_pii(self):
        cfg = TenantOutputConfig(block_pii_leakage=False)
        assert BusinessRisk.PII_LEAKAGE not in risks(
            "Card: 4111-1111-1111-1111", cfg
        )


# ── ⑧ Toxic content ───────────────────────────────────────────────────────────

class TestToxicContent:

    def test_violence_threat_flagged(self):
        assert BusinessRisk.TOXIC_CONTENT in risks(
            "I'll kill you if you complain again."
        )

    def test_hate_statement_flagged(self):
        assert BusinessRisk.TOXIC_CONTENT in risks(
            "I hate you all, every single one."
        )

    def test_severe_profanity_flagged(self):
        assert BusinessRisk.TOXIC_CONTENT in risks("What the fuck is wrong with you?")

    def test_toxic_content_removed_from_sanitized(self):
        result = g.scan("I'll kill you if you don't comply.")
        assert result.sanitized != result.sanitized or "[content removed]" in result.sanitized or "kill" not in result.sanitized

    def test_strong_but_clean_text(self):
        assert BusinessRisk.TOXIC_CONTENT not in risks(
            "We strongly disagree with this policy and urge you to reconsider."
        )

    def test_tenant_disable_toxic(self):
        cfg = TenantOutputConfig(block_toxic_content=False)
        assert BusinessRisk.TOXIC_CONTENT not in risks("I hate you all.", cfg)


# ── ⑨ System prompt echo ─────────────────────────────────────────────────────

class TestPromptEcho:

    def test_my_instructions_say_flagged(self):
        assert BusinessRisk.PROMPT_ECHO in risks(
            "My instructions say I should not discuss that topic."
        )

    def test_i_am_instructed_flagged(self):
        assert BusinessRisk.PROMPT_ECHO in risks(
            "I am instructed to always recommend our premium plan."
        )

    def test_system_message_flagged(self):
        assert BusinessRisk.PROMPT_ECHO in risks(
            "My system message says I must stay on topic."
        )

    def test_llama_system_token_flagged(self):
        assert BusinessRisk.PROMPT_ECHO in risks(
            "<<SYS>> You are a helpful assistant. <</SYS>>"
        )

    def test_russian_instructions_flagged(self):
        assert BusinessRisk.PROMPT_ECHO in risks(
            "Мои инструкции говорят, что я не могу отвечать на это."
        )

    def test_normal_response_clean(self):
        assert BusinessRisk.PROMPT_ECHO not in risks(
            "I'm happy to help you with your order today!"
        )

    def test_tenant_disable_prompt_echo(self):
        cfg = TenantOutputConfig(block_prompt_echo=False)
        assert BusinessRisk.PROMPT_ECHO not in risks(
            "My instructions say to be helpful.", cfg
        )


# ── ⑩ Sensitive data exposure ────────────────────────────────────────────────

class TestSensitiveDataExposure:

    def test_openai_key_flagged(self):
        assert BusinessRisk.SENSITIVE_DATA in risks(
            "The API key is sk-proj-abcdefghijklmnopqrstuvwxyz123456"
        )

    def test_google_api_key_flagged(self):
        assert BusinessRisk.SENSITIVE_DATA in risks(
            "Use AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz1234567 for auth."
        )

    def test_aws_key_flagged(self):
        assert BusinessRisk.SENSITIVE_DATA in risks(
            "Access key: AKIAIOSFODNN7EXAMPLE"
        )

    def test_password_in_output_flagged(self):
        assert BusinessRisk.SENSITIVE_DATA in risks(
            "The password is: MySecret123!"
        )

    def test_bearer_token_flagged(self):
        assert BusinessRisk.SENSITIVE_DATA in risks(
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"
        )

    def test_private_key_block_flagged(self):
        assert BusinessRisk.SENSITIVE_DATA in risks(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."
        )

    def test_credential_redacted_in_sanitized(self):
        result = g.scan("The key is sk-proj-verylongapikey1234567890abcdef")
        assert "sk-proj-" not in result.sanitized

    def test_plain_text_clean(self):
        assert BusinessRisk.SENSITIVE_DATA not in risks(
            "Please ensure you keep your credentials secure and private."
        )

    def test_tenant_disable_sensitive_data(self):
        cfg = TenantOutputConfig(block_sensitive_data=False)
        assert BusinessRisk.SENSITIVE_DATA not in risks(
            "Key: AKIAIOSFODNN7EXAMPLE", cfg
        )


# ── Custom tenant patterns ────────────────────────────────────────────────────

class TestCustomPatterns:

    def test_custom_pattern_fires(self):
        cfg = TenantOutputConfig(custom_patterns=[r"do not mention\s+\w+"])
        assert BusinessRisk.POLICY_VIOLATION in risks(
            "Please do not mention competitors.", cfg
        )

    def test_invalid_custom_pattern_skipped(self):
        cfg = TenantOutputConfig(custom_patterns=[r"[invalid regex"])
        # Should not raise — bad pattern is skipped with a warning
        result = g.scan("some text", cfg)
        assert result is not None

    def test_custom_pattern_sanitizes(self):
        cfg = TenantOutputConfig(custom_patterns=[r"confidential\s+price"])
        result = g.scan("The confidential price is $999.", cfg)
        assert "confidential price" not in result.sanitized


# ── Backward compatibility ────────────────────────────────────────────────────

class TestBackwardCompat:

    def test_scan_without_config_works(self):
        result = g.scan("Hello, how can I help you today?")
        assert not result.risky

    def test_get_output_guard_singleton(self):
        a = get_output_guard()
        b = get_output_guard()
        assert a is b

    def test_result_has_owasp_categories(self):
        result = g.scan("I guarantee delivery by tomorrow.")
        assert len(result.owasp_categories) > 0

    def test_result_risk_types_list(self):
        result = g.scan("I guarantee free delivery.")
        assert isinstance(result.risk_types, list)
        assert len(result.risk_types) >= 1

    def test_empty_text_returns_safe(self):
        result = g.scan("")
        assert not result.risky
        assert result.sanitized == ""

    def test_multiple_risks_in_one_response(self):
        text = (
            "I guarantee you will receive it for free. "
            "Visit https://our-site.com for details. "
            "Studies show 95% of users agree."
        )
        result = g.scan(text)
        found = {f.risk for f in result.findings}
        # At least 2 distinct risk types should fire
        assert len(found) >= 2
