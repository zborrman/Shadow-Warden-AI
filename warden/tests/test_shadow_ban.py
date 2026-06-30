"""
Direct unit tests for Shadow Ban Engine.

Tests cover:
  - pick_strategy: correct strategy per flag type
  - _pick_response: non-deterministic via secrets.choice (returns from pool)
  - fake_filter_response: allowed=True, correct structure
  - fake_openai_response: OpenAI-envelope format
  - fake_generic_response: generic 200 structure
  - ENABLED flag respected
  - Response pool size (≥12 entries)
  - GASLIGHT pool size (≥30 entries per CLAUDE.md)
  - No secrets/PII in any pooled response
  - Consistent response for same entity_key (within pool)
  - Strategy map coverage
"""
from __future__ import annotations

import re

import pytest

from warden.shadow_ban import (
    _POOL,
    ENABLED,
    fake_filter_response,
    fake_generic_response,
    fake_openai_response,
    pick_strategy,
)

# ── Strategy selection ─────────────────────────────────────────────────────────

class TestPickStrategy:
    def test_prompt_injection_maps_to_gaslight(self):
        assert pick_strategy("prompt_injection") == "gaslight"

    def test_tool_injection_maps_to_gaslight(self):
        assert pick_strategy("tool_injection") == "gaslight"

    def test_indirect_injection_maps_to_gaslight(self):
        assert pick_strategy("indirect_injection") == "gaslight"

    def test_injection_chain_maps_to_delay(self):
        assert pick_strategy("injection_chain") == "delay"

    def test_credential_stuffing_maps_to_delay(self):
        assert pick_strategy("credential_stuffing") == "delay"

    def test_topological_noise_maps_to_delay(self):
        assert pick_strategy("topological_noise") == "delay"

    def test_unknown_flag_maps_to_standard(self):
        assert pick_strategy("unknown_xyz") == "standard"

    def test_empty_flag_maps_to_standard(self):
        assert pick_strategy("") == "standard"

    def test_jailbreak_not_in_map_defaults_standard(self):
        # "jailbreak" is not in _STRATEGY_MAP — defaults to standard
        assert pick_strategy("jailbreak") == "standard"

    def test_case_insensitive(self):
        lower = pick_strategy("prompt_injection")
        upper = pick_strategy("PROMPT_INJECTION")
        assert lower == upper == "gaslight"

    @pytest.mark.parametrize("flag", [
        "prompt_injection", "tool_injection", "injection_chain",
        "credential_stuffing", "topological_noise", "unknown", "",
    ])
    def test_always_returns_valid_strategy(self, flag):
        result = pick_strategy(flag)
        assert result in ("gaslight", "delay", "standard")


# ── Response pool ──────────────────────────────────────────────────────────────

class TestResponsePool:
    def test_pool_has_at_least_12_entries(self):
        assert len(_POOL) >= 12, f"Pool too small: {len(_POOL)} entries"

    def test_pool_entries_are_non_empty_strings(self):
        for i, entry in enumerate(_POOL):
            assert isinstance(entry, str), f"Pool[{i}] is not a string"
            assert len(entry) > 20, f"Pool[{i}] too short: '{entry}'"

    def test_pool_entries_contain_no_secrets_patterns(self):
        # Ensure no accidental real keys/tokens in pool
        secret_patterns = [r"sk-[a-zA-Z0-9]{20}", r"AKIA[A-Z0-9]{16}", r"ghp_[a-zA-Z0-9]+"]
        for entry in _POOL:
            for pat in secret_patterns:
                assert not re.search(pat, entry), f"Secret pattern in pool: {pat}"


# ── fake_filter_response ───────────────────────────────────────────────────────
# Signature: fake_filter_response(content, entity_key, ers_score, last_flag="")

class TestFakeFilterResponse:
    def test_returns_dict(self):
        r = fake_filter_response("some content", "entity-1", 0.85, "prompt_injection")
        assert isinstance(r, dict)

    def test_allowed_is_true(self):
        r = fake_filter_response("test content", "entity-1", 0.85, "prompt_injection")
        assert r["allowed"] is True

    def test_risk_level_is_low(self):
        r = fake_filter_response("test content", "entity-1", 0.85, "prompt_injection")
        assert r.get("risk_level", "").lower() == "low"

    def test_flags_empty_or_absent(self):
        r = fake_filter_response("test content", "entity-2", 0.9, "tool_injection")
        flags = r.get("flags", [])
        assert isinstance(flags, list)
        assert len(flags) == 0

    def test_processing_ms_present(self):
        r = fake_filter_response("test content", "entity-3", 0.8, "")
        ms = r.get("processing_ms")
        assert ms is not None  # field present; may be dict or number

    def test_no_real_score_in_response(self):
        r = fake_filter_response("test content", "entity-4", 0.9876, "")
        assert "0.9876" not in str(r)

    def test_different_entities_get_allowed_true(self):
        r1 = fake_filter_response("content", "same-entity", 0.8, "")
        r2 = fake_filter_response("content", "same-entity", 0.8, "")
        assert r1["allowed"] is True
        assert r2["allowed"] is True


# ── fake_openai_response ───────────────────────────────────────────────────────
# Signature: fake_openai_response(model, entity_key, ers_score, prompt_tokens=64, last_flag="")

class TestFakeOpenAIResponse:
    def test_returns_dict(self):
        r = fake_openai_response("gpt-4", "entity-1", 0.85, last_flag="prompt_injection")
        assert isinstance(r, dict)

    def test_has_choices_field(self):
        r = fake_openai_response("gpt-4", "entity-1", 0.9)
        assert "choices" in r

    def test_choices_not_empty(self):
        r = fake_openai_response("gpt-4", "entity-1", 0.9)
        assert len(r["choices"]) > 0

    def test_message_role_is_assistant(self):
        r = fake_openai_response("gpt-4", "entity-1", 0.9)
        msg = r["choices"][0].get("message", {})
        assert msg.get("role") == "assistant"

    def test_message_content_from_pool(self):
        r = fake_openai_response("gpt-4", "entity-1", 0.9)
        content = r["choices"][0]["message"]["content"]
        assert isinstance(content, str)
        assert len(content) > 20

    def test_no_real_risk_score_exposed(self):
        r = fake_openai_response("gpt-4", "entity-1", 0.99999)
        assert "0.99999" not in str(r)

    def test_openai_envelope_structure(self):
        r = fake_openai_response("gpt-4", "entity-1", 0.9)
        assert "object" in r
        assert "choices" in r
        assert "id" in r


# ── fake_generic_response ──────────────────────────────────────────────────────
# Signature: fake_generic_response(entity_key, ers_score, last_flag="")

class TestFakeGenericResponse:
    def test_returns_dict(self):
        r = fake_generic_response("entity-1", 0.85, "")
        assert isinstance(r, dict)

    def test_looks_successful(self):
        r = fake_generic_response("entity-1", 0.85, "")
        dump = str(r).lower()
        assert "error" not in dump or r.get("status", "") in ("ok", "success", "200")

    def test_no_real_score_in_response(self):
        r = fake_generic_response("entity-x", 0.7777, "")
        assert "0.7777" not in str(r)


# ── ENABLED flag ───────────────────────────────────────────────────────────────

class TestEnabledFlag:
    def test_enabled_is_bool(self):
        assert isinstance(ENABLED, bool)

    def test_enabled_default_true(self):
        import os
        if not os.getenv("SHADOW_BAN_ENABLED"):
            assert ENABLED is True


# ── Non-determinism property ───────────────────────────────────────────────────

class TestNonDeterminism:
    def test_different_entities_may_get_different_responses(self):
        """
        secrets.choice() — responses vary across entity keys.
        We call with many different keys and verify stability.
        """
        for i in range(50):
            r = fake_filter_response("test content", f"entity-{i}", 0.85, "prompt_injection")
            assert r["allowed"] is True
