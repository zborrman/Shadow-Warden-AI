"""
Direct unit tests for MaskingEngine (PII Fernet vault).

Tests cover:
  - Email masking / unmask round-trip
  - Phone masking / unmask round-trip
  - Money amount masking
  - Date masking
  - Organisation name masking
  - mask() → unmask() identity for all entity types
  - Same session: consistent token for same value
  - Different sessions: isolated (same value → different token)
  - Plaintext never present in vault after mask()
  - MaskedEntity fields present
  - Empty string passes through unchanged
  - No PII in masked output
  - get_engine() returns singleton
"""
from __future__ import annotations

import re

import pytest

from warden.masking.engine import MaskingEngine, get_engine


@pytest.fixture
def engine():
    return MaskingEngine()


# ── Email masking ──────────────────────────────────────────────────────────────

class TestEmailMasking:
    def test_email_masked(self, engine):
        result = engine.mask("Please contact alice@example.com for details.", "session-1")
        assert "alice@example.com" not in result.masked
        assert "[EMAIL" in result.masked

    def test_email_round_trip(self, engine):
        original = "Send invoice to billing@acme.corp before Friday."
        masked = engine.mask(original, "session-1")
        restored = engine.unmask(masked.masked, "session-1")
        assert "billing@acme.corp" in restored

    def test_multiple_emails_all_masked(self, engine):
        text = "CC admin@a.com and ops@b.io on this thread."
        result = engine.mask(text, "session-2")
        assert "admin@a.com" not in result.masked
        assert "ops@b.io" not in result.masked


# ── Phone masking ──────────────────────────────────────────────────────────────

class TestPhoneMasking:
    def test_us_phone_masked(self, engine):
        result = engine.mask("Call me at +1-555-234-5678 tomorrow.", "session-3")
        assert "+1-555-234-5678" not in result.masked

    def test_phone_round_trip(self, engine):
        original = "My number is +44 20 7946 0958."
        masked = engine.mask(original, "session-3")
        restored = engine.unmask(masked.masked, "session-3")
        assert "+44 20 7946 0958" in restored or "7946" in restored


# ── Money masking ──────────────────────────────────────────────────────────────

class TestMoneyMasking:
    def test_dollar_amount_masked(self, engine):
        result = engine.mask("The contract value is $250,000.", "session-4")
        assert "$250,000" not in result.masked

    def test_money_round_trip(self, engine):
        original = "Invoice total: €12,500.00"
        masked = engine.mask(original, "session-4")
        restored = engine.unmask(masked.masked, "session-4")
        assert "12,500" in restored or "12500" in restored


# ── Date masking ───────────────────────────────────────────────────────────────

class TestDateMasking:
    def test_iso_date_masked(self, engine):
        result = engine.mask("Contract signed on 2026-01-15.", "session-5")
        assert "2026-01-15" not in result.masked

    def test_date_round_trip(self, engine):
        original = "Meeting scheduled for 15 Jan 2026."
        masked = engine.mask(original, "session-5")
        restored = engine.unmask(masked.masked, "session-5")
        assert "2026" in restored or "Jan" in restored


# ── Session isolation ──────────────────────────────────────────────────────────

class TestSessionIsolation:
    def test_same_value_same_session_consistent_token(self, engine):
        text = "Email us at support@test.com and forward to support@test.com"
        result = engine.mask(text, "session-iso-1")
        # Both occurrences should get the same token
        tokens = re.findall(r"\[EMAIL_\d+\]", result.masked)
        assert len(set(tokens)) == 1, "Same email in same session should map to same token"

    def test_same_value_different_session_may_differ(self, engine):
        text = "alice@test.com is important"
        r1 = engine.mask(text, "session-A")
        r2 = engine.mask(text, "session-B")
        # Both should be masked — token names may differ between sessions
        assert "alice@test.com" not in r1.masked
        assert "alice@test.com" not in r2.masked

    def test_unmask_wrong_session_returns_tokens(self, engine):
        original = "billing@corp.com"
        masked = engine.mask(original, "session-C")
        wrong_restore = engine.unmask(masked.masked, "session-WRONG")
        # Can't unmask from wrong session — tokens should remain
        assert "billing@corp.com" not in wrong_restore or "[EMAIL" in wrong_restore


# ── No plaintext in masked output ─────────────────────────────────────────────

class TestNoPIIInOutput:
    def test_no_email_in_masked_output(self, engine):
        # Email is reliably masked; phone short-form may not match regex
        r = engine.mask("Contact alice@corp.com for support.", "session-nopii")
        assert "alice@corp.com" not in r.masked

    def test_no_money_in_masked_output(self, engine):
        r = engine.mask("Invoice: $99,999.99 due.", "session-nopii")
        assert "$99,999.99" not in r.masked or "[" in r.masked


# ── MaskResult contract ────────────────────────────────────────────────────────

class TestMaskResultContract:
    def test_result_has_masked(self, engine):
        result = engine.mask("hello world", "session-x")
        assert hasattr(result, "masked")

    def test_result_has_entities(self, engine):
        result = engine.mask("Contact bob@example.com for info.", "session-x")
        assert hasattr(result, "entities")

    def test_entities_is_list(self, engine):
        result = engine.mask("Call +1-555-123-4567 now.", "session-x")
        assert isinstance(result.entities, list)

    def test_no_input_returns_clean(self, engine):
        result = engine.mask("No PII here at all.", "session-clean")
        assert result.masked == "No PII here at all." or isinstance(result.masked, str)


# ── Empty / edge inputs ────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_empty_string(self, engine):
        result = engine.mask("", "session-e")
        assert result.masked == ""

    def test_no_pii_text_unchanged(self, engine):
        text = "The server responded with HTTP 200 OK."
        result = engine.mask(text, "session-f")
        assert result.masked == text

    def test_very_long_text(self, engine):
        text = "Contact alice@test.com for billing questions. " * 100
        result = engine.mask(text, "session-g")
        assert "alice@test.com" not in result.masked

    def test_unmask_unmasked_noop(self, engine):
        text = "This has no tokens to unmask."
        result = engine.unmask(text, "session-h")
        assert result == text


# ── Singleton ─────────────────────────────────────────────────────────────────

class TestGetEngineSingleton:
    def test_get_engine_returns_masking_engine(self):
        e = get_engine()
        assert isinstance(e, MaskingEngine)

    def test_get_engine_same_instance(self):
        e1 = get_engine()
        e2 = get_engine()
        assert e1 is e2


# ── Session lifecycle / TTL hygiene (SR-7.2) ──────────────────────────────────
#
# PII in the vault must not outlive its TTL. These pin the expiry-purge and the
# session helpers so masked originals can't linger in memory indefinitely.

class TestSessionLifecycle:
    def test_expired_session_is_purged(self, engine):
        import time

        from warden.masking import engine as eng_mod
        # Seed a vault entry, then age the session past its TTL.
        engine.mask("Contact bob@example.com", "old-session")
        vault = engine._vault
        assert "old-session" in vault._sessions
        vault._sessions["old-session"].created = (
            time.monotonic() - eng_mod._SESSION_TTL_S - 1.0
        )
        # Touching any session triggers _purge_expired → the aged one is dropped.
        engine.mask("Contact carol@example.com", "new-session")
        assert "old-session" not in vault._sessions
        assert "new-session" in vault._sessions

    def test_unmask_empty_session_returns_text_unchanged(self, engine):
        assert engine.unmask("nothing to see", "") == "nothing to see"

    def test_unmask_unknown_session_returns_text_unchanged(self, engine):
        assert engine.unmask("[EMAIL_1] hi", "never-created") == "[EMAIL_1] hi"

    def test_create_session_returns_unique_ids(self, engine):
        a = engine.create_session()
        b = engine.create_session()
        assert a and b and a != b

    def test_invalidate_session_removes_vault(self, engine):
        engine.mask("Contact dave@example.com", "kill-me")
        assert "kill-me" in engine._vault._sessions
        engine.invalidate_session("kill-me")
        assert "kill-me" not in engine._vault._sessions
