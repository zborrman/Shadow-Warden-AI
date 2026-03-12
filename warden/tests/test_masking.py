"""
warden/tests/test_masking.py
─────────────────────────────
Unit tests for the Synthetic Data Masking Engine (Yellow Zone).

Tests verify:
  • Entity detection: EMAIL, PHONE, MONEY, DATE, ORG, PERSON, ID
  • Session consistency: same value → same token
  • Cross-session isolation: different sessions use independent vaults
  • Round-trip fidelity: mask() + unmask() restores original text
  • Multi-entity of same type: PERSON_1 vs PERSON_2
  • No false positives for plain non-PII text
  • FastAPI /mask and /unmask endpoints
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from warden.masking.engine import MaskingEngine, MaskResult


# ── Shared engine instance ────────────────────────────────────────────────────

@pytest.fixture
def engine() -> MaskingEngine:
    return MaskingEngine()


# ── Entity detection ──────────────────────────────────────────────────────────

class TestEmailDetection:
    def test_detects_standard_email(self, engine):
        r = engine.mask("Send invoice to john.doe@acme.com for review.", "sid-1")
        assert "john.doe@acme.com" not in r.masked
        assert "[EMAIL_1]" in r.masked

    def test_detects_email_with_subdomains(self, engine):
        r = engine.mask("CC: billing@mail.example.co.uk", "sid-2")
        assert "billing@mail.example.co.uk" not in r.masked

    def test_consistent_token_for_same_email(self, engine):
        r1 = engine.mask("Contact a@b.com", "sid-3")
        r2 = engine.mask("Reply to a@b.com", "sid-3")
        assert r1.masked.split("[")[1].split("]")[0] == r2.masked.split("[")[1].split("]")[0]


class TestPhoneDetection:
    def test_us_phone_with_country_code(self, engine):
        r = engine.mask("Reach us at +1 (800) 555-0199.", "sid-11")
        assert "+1 (800) 555-0199" not in r.masked
        assert "PHONE" in r.summary()

    def test_us_phone_parenthesised_area_code(self, engine):
        r = engine.mask("Main line: (555) 867-5309.", "sid-10")
        assert "(555) 867-5309" not in r.masked
        assert "PHONE" in r.summary()

    def test_international_with_plus(self, engine):
        r = engine.mask("London office: +44 20 7946 0958.", "sid-11b")
        assert "+44 20 7946 0958" not in r.masked
        assert "PHONE" in r.summary()

    def test_no_false_positive_year(self, engine):
        r = engine.mask("The year 2024 was eventful.", "sid-12")
        assert r.entity_count == 0 or "PHONE" not in r.summary()

    def test_no_false_positive_iso_date(self, engine):
        # ISO dates must not be mis-classified as phones
        r = engine.mask("Signed on 2024-03-15.", "sid-13")
        assert "PHONE" not in r.summary()
        assert "DATE" in r.summary()


class TestMoneyDetection:
    def test_dollar_amount(self, engine):
        r = engine.mask("Total contract value: $50,000.", "sid-20")
        assert "$50,000" not in r.masked
        assert "[MONEY_1]" in r.masked

    def test_euro_amount(self, engine):
        r = engine.mask("Invoice: €1,200.50", "sid-21")
        assert "€1,200.50" not in r.masked
        assert "MONEY" in r.masked

    def test_usd_abbreviation(self, engine):
        r = engine.mask("Budget: USD 500K", "sid-22")
        assert "USD 500K" not in r.masked

    def test_written_out_currency(self, engine):
        r = engine.mask("Payment of 50,000 dollars expected.", "sid-23")
        assert "50,000 dollars" not in r.masked

    def test_multiple_money_amounts_get_separate_tokens(self, engine):
        r = engine.mask("Deposit: $10,000. Final: $40,000.", "sid-24")
        assert "[MONEY_1]" in r.masked
        assert "[MONEY_2]" in r.masked


class TestDateDetection:
    def test_iso_date(self, engine):
        r = engine.mask("Contract signed on 2024-03-15.", "sid-30")
        assert "2024-03-15" not in r.masked
        assert "DATE" in r.masked

    def test_us_date_format(self, engine):
        r = engine.mask("Due: 03/15/2024", "sid-31")
        assert "03/15/2024" not in r.masked

    def test_long_form_date(self, engine):
        r = engine.mask("Effective January 15, 2024.", "sid-32")
        assert "January 15, 2024" not in r.masked

    def test_day_month_year(self, engine):
        r = engine.mask("Meeting on 15 March 2024.", "sid-33")
        assert "15 March 2024" not in r.masked


class TestOrgDetection:
    def test_llc_company(self, engine):
        r = engine.mask("Prepared for Riverside Dental LLC.", "sid-40")
        assert "Riverside Dental LLC" not in r.masked
        assert "ORG" in r.masked

    def test_corp_company(self, engine):
        r = engine.mask("Acme Corp has agreed to the terms.", "sid-41")
        assert "Acme Corp" not in r.masked

    def test_ltd_company(self, engine):
        r = engine.mask("Payment from Harbor Holdings Ltd.", "sid-42")
        assert "Harbor Holdings Ltd" not in r.masked


class TestPersonDetection:
    def test_person_with_mr_honorific(self, engine):
        r = engine.mask("Signed by Mr. John Smith.", "sid-50")
        assert "John Smith" not in r.masked
        assert "PERSON" in r.masked

    def test_person_with_dr_honorific(self, engine):
        r = engine.mask("Referred by Dr. Jane Doe.", "sid-51")
        assert "Jane Doe" not in r.masked

    def test_person_after_client_context(self, engine):
        r = engine.mask("client: Robert Johnson agreed.", "sid-52")
        assert "Robert Johnson" not in r.masked
        assert "PERSON" in r.masked

    def test_person_after_signed_by(self, engine):
        r = engine.mask("This agreement was signed by Alice Brown.", "sid-53")
        assert "Alice Brown" not in r.masked

    def test_no_false_positive_without_context(self, engine):
        # "New York" has no honorific or context word — should NOT be detected
        r = engine.mask("The conference will be held in New York.", "sid-54")
        assert "PERSON" not in r.summary()

    def test_two_persons_get_separate_tokens(self, engine):
        r = engine.mask("Client: Mr. John Smith and Dr. Jane Doe.", "sid-55")
        summary = r.summary()
        assert summary.get("PERSON", 0) >= 2


class TestIdDetection:
    def test_contract_id(self, engine):
        r = engine.mask("Please reference contract #ABC-20241501.", "sid-60")
        assert "ABC-20241501" not in r.masked
        assert "ID" in r.masked

    def test_invoice_number(self, engine):
        r = engine.mask("Invoice no. INV2024001 is overdue.", "sid-61")
        assert "INV2024001" not in r.masked


# ── Session consistency ────────────────────────────────────────────────────────

class TestSessionConsistency:
    def test_same_value_same_token_within_session(self, engine):
        sid = "sess-consistent"
        r1 = engine.mask("Mr. John Smith called.", sid)
        # Second call uses same detectable pattern — context word present
        r2 = engine.mask("Client: John Smith confirmed.", sid)
        # Extract the PERSON token from first result
        token1 = next(
            (e.token for e in r1.entities
             if e.entity_type == "PERSON" and e.original == "John Smith"),
            None,
        )
        # Vault should map same value to same token on second call
        if token1:
            assert token1 in r2.masked, "Same value must reuse same token within session"

    def test_different_sessions_independent(self, engine):
        r1 = engine.mask("Mr. John Smith signed.", "sess-A")
        r2 = engine.mask("Mr. John Smith signed.", "sess-B")
        # Both get PERSON_1, but the vaults are independent
        assert r1.masked == r2.masked   # same structure, tokens may coincide
        # Unmask from session A should not affect session B
        unmasked_a = engine.unmask(r1.masked, "sess-A")
        unmasked_b = engine.unmask(r2.masked, "sess-B")
        assert "John Smith" in unmasked_a
        assert "John Smith" in unmasked_b


# ── Round-trip fidelity ───────────────────────────────────────────────────────

class TestRoundTrip:
    def test_email_round_trip(self, engine):
        text = "Please send the report to alice@example.com by Friday."
        sid  = "rt-email"
        r    = engine.mask(text, sid)
        assert engine.unmask(r.masked, sid) == text

    def test_money_round_trip(self, engine):
        text = "The contract value is $125,000 plus $15,000 in expenses."
        sid  = "rt-money"
        r    = engine.mask(text, sid)
        assert engine.unmask(r.masked, sid) == text

    def test_full_business_prompt_round_trip(self, engine):
        text = (
            "Draft a services agreement for client: Robert Johnson of Acme Corp, "
            "for $50,000 starting 2024-06-01. "
            "Contact: ceo@acme-corp.com"
        )
        sid = "rt-full"
        r   = engine.mask(text, sid)
        assert r.has_entities
        # Masked text must not contain raw PII
        assert "Robert Johnson" not in r.masked
        assert "$50,000"        not in r.masked
        assert "2024-06-01"     not in r.masked
        assert "ceo@acme-corp.com" not in r.masked
        # Unmasked text must match original exactly
        assert engine.unmask(r.masked, sid) == text

    def test_no_entities_text_unchanged(self, engine):
        text = "Summarise the key themes in this document."
        sid  = "rt-clean"
        r    = engine.mask(text, sid)
        assert r.masked == text
        assert r.entity_count == 0


# ── LLM response unmasking ────────────────────────────────────────────────────

class TestUnmaskResponse:
    def test_unmask_llm_response_containing_tokens(self, engine):
        sid = "llm-resp"
        engine.mask("Contract for Mr. John Smith, $50,000.", sid)
        # Simulate an LLM response that echoes the tokens
        llm_output = (
            "Dear [PERSON_1], this confirms your payment of [MONEY_1] "
            "has been received."
        )
        result = engine.unmask(llm_output, sid)
        assert "John Smith" in result
        assert "$50,000"    in result
        assert "[PERSON_1]" not in result
        assert "[MONEY_1]"  not in result

    def test_unmask_with_unknown_session_returns_text_unchanged(self, engine):
        text   = "Payment confirmed for [PERSON_1]."
        result = engine.unmask(text, "nonexistent-session-xyz")
        assert result == text


# ── FastAPI endpoint smoke tests ──────────────────────────────────────────────

@pytest.fixture
def client():
    from warden.main import app
    return TestClient(app)


class TestMaskEndpoint:
    def test_mask_returns_masked_text(self, client):
        resp = client.post("/mask", json={"text": "Invoice from john@corp.com for $10,000."})
        assert resp.status_code == 200
        data = resp.json()
        assert "john@corp.com" not in data["masked"]
        assert "$10,000" not in data["masked"]
        assert data["entity_count"] >= 2
        assert data["session_id"]

    def test_mask_preserves_session_id(self, client):
        sid  = "my-fixed-session"
        resp = client.post("/mask", json={"text": "Call +1-555-867-5309.", "session_id": sid})
        assert resp.status_code == 200
        assert resp.json()["session_id"] == sid

    def test_unmask_restores_original(self, client):
        text = "Contract for Dr. Jane Doe, $25,000."
        r1 = client.post("/mask", json={"text": text})
        assert r1.status_code == 200
        sid    = r1.json()["session_id"]
        masked = r1.json()["masked"]

        # Simulate LLM echoing the tokens back
        llm_resp = masked.replace("[PERSON_1]", "[PERSON_1]")  # identical passthrough

        r2 = client.post("/unmask", json={"text": llm_resp, "session_id": sid})
        assert r2.status_code == 200
        assert "Jane Doe" in r2.json()["unmasked"]
        assert "$25,000"  in r2.json()["unmasked"]

    def test_mask_clean_text_entity_count_zero(self, client):
        resp = client.post("/mask", json={"text": "What is the capital of France?"})
        assert resp.status_code == 200
        assert resp.json()["entity_count"] == 0
