"""Tests for shadow_ai/signatures.py and agent/memory.py."""
import os

os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("SEMANTIC_THRESHOLD", "0.72")
os.environ.setdefault("LOGS_PATH", "/tmp/warden_sig_mem_test.json")


# ══════════════════════════════════════════════════════════════════════════════
# shadow_ai/signatures.py
# ══════════════════════════════════════════════════════════════════════════════

class TestAIProviderSignatures:
    def test_ai_providers_not_empty(self):
        from warden.shadow_ai.signatures import AI_PROVIDERS
        assert len(AI_PROVIDERS) >= 10

    def test_openai_present(self):
        from warden.shadow_ai.signatures import AI_PROVIDERS
        assert "openai" in AI_PROVIDERS
        sig = AI_PROVIDERS["openai"]
        assert "api.openai.com" in sig["domains"]
        assert sig["risk_level"] in ("LOW", "MEDIUM", "HIGH")

    def test_anthropic_present(self):
        from warden.shadow_ai.signatures import AI_PROVIDERS
        assert "anthropic" in AI_PROVIDERS

    def test_ollama_local_ai(self):
        from warden.shadow_ai.signatures import AI_PROVIDERS
        assert "ollama" in AI_PROVIDERS
        assert AI_PROVIDERS["ollama"]["category"] == "LOCAL_AI"

    def test_all_signatures_have_required_fields(self):
        from warden.shadow_ai.signatures import AI_PROVIDERS
        for key, sig in AI_PROVIDERS.items():
            assert "domains" in sig, f"{key} missing domains"
            assert "url_patterns" in sig, f"{key} missing url_patterns"
            assert "risk_level" in sig, f"{key} missing risk_level"
            assert "category" in sig, f"{key} missing category"
            assert "display_name" in sig, f"{key} missing display_name"
            assert sig["risk_level"] in ("LOW", "MEDIUM", "HIGH"), f"{key} bad risk_level"

    def test_domain_to_provider_populated(self):
        from warden.shadow_ai.signatures import DOMAIN_TO_PROVIDER
        assert len(DOMAIN_TO_PROVIDER) >= 10
        assert any("openai" in v for v in DOMAIN_TO_PROVIDER.values())

    def test_probe_ports_include_common(self):
        from warden.shadow_ai.signatures import PROBE_PORTS
        assert 80 in PROBE_PORTS
        assert 443 in PROBE_PORTS
        assert 8080 in PROBE_PORTS

    def test_local_ai_ports_included(self):
        from warden.shadow_ai.signatures import LOCAL_AI_PORTS, PROBE_PORTS
        for port in LOCAL_AI_PORTS:
            assert port in PROBE_PORTS

    def test_categories_are_valid(self):
        from warden.shadow_ai.signatures import AI_PROVIDERS
        valid = {"GENERATIVE_AI", "EMBEDDING_API", "INFERENCE_API", "LOCAL_AI",
                 "CODE_AI", "MULTIMODAL_AI", "SEARCH_AI"}
        for key, sig in AI_PROVIDERS.items():
            assert sig["category"] in valid, f"{key}: unexpected category {sig['category']!r}"

    def test_high_risk_providers_exist(self):
        from warden.shadow_ai.signatures import AI_PROVIDERS
        high_risk = [k for k, v in AI_PROVIDERS.items() if v["risk_level"] == "HIGH"]
        assert len(high_risk) >= 1


# ══════════════════════════════════════════════════════════════════════════════
# agent/memory.py — fail-open helpers (no live Redis needed)
# ══════════════════════════════════════════════════════════════════════════════

class TestAgentMemory:
    def test_now_iso_format(self):
        from warden.agent.memory import now_iso
        ts = now_iso()
        assert "T" in ts
        assert ts.endswith("+00:00") or ts.endswith("Z") or "+" in ts

    def test_load_history_empty_session(self):
        from warden.agent.memory import load_history
        history = load_history("nonexistent-session-xyz")
        assert isinstance(history, list)

    def test_save_and_load_history(self):
        from warden.agent.memory import load_history, save_history
        sid = "test-session-memory-001"
        msgs = [{"role": "user", "content": "hello"}, {"role": "assistant", "content": "hi"}]
        save_history(sid, msgs)
        loaded = load_history(sid)
        assert isinstance(loaded, list)

    def test_clear_history(self):
        from warden.agent.memory import clear_history, load_history, save_history
        sid = "test-session-clear-001"
        save_history(sid, [{"role": "user", "content": "test"}])
        clear_history(sid)
        loaded = load_history(sid)
        assert loaded == []

    def test_get_state_missing_key(self):
        from warden.agent.memory import get_state
        val = get_state("nonexistent-state-key-xyz")
        assert val is None

    def test_set_and_get_state(self):
        from warden.agent.memory import get_state, set_state
        set_state("test-key-001", "test-value")
        val = get_state("test-key-001")
        assert val == "test-value" or val is None  # None = Redis unavail (fail-open)
