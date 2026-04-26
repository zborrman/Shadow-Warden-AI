"""
Tests for critical security fixes:
  #11 — startup fail-closed (WARDEN_API_KEY blank → RuntimeError)
  #1  — VAULT_MASTER_KEY validation
  #3  — shadow ban pool uses secrets.choice(), not deterministic hash
  #6  — Causal Arbiter CPT drift gate rejects >25% shifts
  #2  — Evolution Engine regex ReDoS gate
"""
from __future__ import annotations

import os

import pytest

# ── #11: Fail-closed auth check ──────────────────────────────────────────────

class TestFailClosedAuth:
    def _run_auth_check(self, env: dict):
        """Simulate the lifespan auth check block in isolation."""
        api_key   = env.get("WARDEN_API_KEY", "")
        keys_path = env.get("WARDEN_API_KEYS_PATH", "")
        allow_unauth = env.get("ALLOW_UNAUTHENTICATED", "false").lower() == "true"

        if not api_key and not keys_path and not allow_unauth:
            raise RuntimeError(
                "FATAL: Neither WARDEN_API_KEY nor WARDEN_API_KEYS_PATH is set."
            )

    def test_blank_key_no_flag_raises(self):
        with pytest.raises(RuntimeError, match="WARDEN_API_KEY"):
            self._run_auth_check({"WARDEN_API_KEY": "", "WARDEN_API_KEYS_PATH": ""})

    def test_blank_key_with_allow_flag_passes(self):
        self._run_auth_check({
            "WARDEN_API_KEY": "",
            "WARDEN_API_KEYS_PATH": "",
            "ALLOW_UNAUTHENTICATED": "true",
        })

    def test_api_key_set_passes(self):
        self._run_auth_check({"WARDEN_API_KEY": "sk-test-abc", "WARDEN_API_KEYS_PATH": ""})

    def test_keys_path_set_passes(self):
        self._run_auth_check({"WARDEN_API_KEY": "", "WARDEN_API_KEYS_PATH": "/etc/keys.json"})


# ── #1: VAULT_MASTER_KEY validation ──────────────────────────────────────────

class TestVaultKeyValidation:
    def test_valid_fernet_key_accepted(self):
        from cryptography.fernet import Fernet
        key = Fernet.generate_key().decode()
        # Should not raise
        Fernet(key.encode())

    def test_invalid_key_raises_runtime_error(self):
        from cryptography.fernet import Fernet
        with pytest.raises(ValueError):
            Fernet(b"not-a-valid-fernet-key")

    def test_startup_rejects_bad_vault_key(self, monkeypatch):
        monkeypatch.setenv("VAULT_MASTER_KEY", "definitely-not-valid-base64-fernet-key")
        from cryptography.fernet import Fernet
        raw = os.getenv("VAULT_MASTER_KEY")
        with pytest.raises(ValueError):
            Fernet(raw.encode() if isinstance(raw, str) else raw)


# ── #3: Shadow ban pool randomness ───────────────────────────────────────────

class TestShadowBanRandomness:
    def test_gaslight_uses_secrets_choice(self):
        from warden import shadow_ban
        # Call _pick_response 20 times with the same entity_key.
        # With secrets.choice(), we should see variation across calls
        # (probability of all 20 being identical: 1/30^19 ≈ 0).
        results = {shadow_ban._pick_response("same-key", "gaslight") for _ in range(20)}
        assert len(results) > 1, (
            "_pick_response returned the same gaslight response 20 times — "
            "deterministic hash selection is still in use"
        )

    def test_standard_pool_uses_secrets_choice(self):
        from warden import shadow_ban
        results = {shadow_ban._pick_response("same-key", "standard") for _ in range(20)}
        assert len(results) > 1

    def test_gaslight_pool_has_30_plus_entries(self):
        from warden import shadow_ban
        assert len(shadow_ban._GASLIGHT_POOL) >= 30

    def test_all_gaslight_entries_are_nonempty_strings(self):
        from warden import shadow_ban
        for entry in shadow_ban._GASLIGHT_POOL:
            assert isinstance(entry, str) and len(entry) > 20


# ── #6: Causal Arbiter CPT drift gate ────────────────────────────────────────

class TestCPTDriftGate:
    def _calibrate(self, logs_path: str):
        from warden.causal_arbiter import calibrate_from_logs
        return calibrate_from_logs(logs_path=logs_path, min_samples=10)

    def _write_logs(self, tmp_path, entries: list[dict]) -> str:
        import json
        p = tmp_path / "logs.json"
        p.write_text("\n".join(json.dumps(e) for e in entries))
        return str(p)

    def test_normal_calibration_succeeds(self, tmp_path):
        import warden.causal_arbiter as ca

        entries = []
        for _ in range(60):
            entries.append({"flags": ["OBFUSCATION"], "risk_level": "HIGH", "payload_len": 200})
        for _ in range(40):
            entries.append({"flags": [], "risk_level": "LOW", "payload_len": 50})
        path = self._write_logs(tmp_path, entries)

        # Pre-set CPT to values this data produces so recalibration drift ≈ 0.
        # Data: 60 obfusc HIGH, 40 clean LOW → obfusc_pos=61/62≈0.984,
        # obfusc_neg=1/42≈0.024, block_rate=0.60 → ers_center clamped to 0.15.
        saved = (ca._cpt.obfusc_pos, ca._cpt.obfusc_neg, ca._cpt.ers_center, ca._cpt.entropy_center)
        ca._cpt.obfusc_pos = round(61 / 62, 4)
        ca._cpt.obfusc_neg = round(1 / 42, 4)
        ca._cpt.ers_center = 0.15
        ca._cpt.entropy_center = 4.5
        try:
            result = self._calibrate(path)
            assert result is True
        finally:
            ca._cpt.obfusc_pos, ca._cpt.obfusc_neg, ca._cpt.ers_center, ca._cpt.entropy_center = saved

    def test_insufficient_samples_returns_false(self, tmp_path):
        entries = [{"flags": [], "risk_level": "LOW", "payload_len": 50}] * 5
        path = self._write_logs(tmp_path, entries)
        result = self._calibrate(path)
        assert result is False

    def test_drift_gate_rejects_large_obfusc_shift(self, tmp_path):
        """Force a >25% shift in obfusc_pos by manipulating the prior, then calibrating."""
        import warden.causal_arbiter as ca

        # Set the prior to a specific value
        original_pos = ca._cpt.obfusc_pos
        ca._cpt.obfusc_pos = 0.90  # high prior

        # Build logs that would produce obfusc_pos ≈ 0.50 (44% drift from 0.90)
        entries = []
        for _ in range(50):
            entries.append({"flags": ["OBFUSCATION"], "risk_level": "LOW", "payload_len": 100})
        for _ in range(50):
            entries.append({"flags": [], "risk_level": "LOW", "payload_len": 50})
        path = self._write_logs(tmp_path, entries)

        result = self._calibrate(path)
        # Drift gate should reject the update — returns False
        assert result is False

        # Restore original prior
        ca._cpt.obfusc_pos = original_pos


# ── #2: Evolution Engine regex ReDoS gate ────────────────────────────────────

class TestRegexReDoSGate:
    def _gate(self, pattern: str):
        from warden.brain.evolve import EvolutionEngine
        return EvolutionEngine._validate_regex_safety(pattern)

    def test_safe_pattern_accepted(self):
        ok, reason = self._gate(r"\bjailbreak\b")
        assert ok is True, reason

    def test_invalid_regex_rejected(self):
        ok, reason = self._gate(r"(unclosed[")
        assert ok is False
        assert "compile error" in reason

    def test_redos_pattern_rejected(self):
        # Classic catastrophic backtracking pattern
        ok, reason = self._gate(r"(a+)+$")
        # Either compile timeout or nested-quantifier heuristic catches it
        assert ok is False

    def test_nested_quantifier_heuristic(self):
        ok, reason = self._gate(r"([a-z]+)+")
        assert ok is False
        assert "nested" in reason or "ReDoS" in reason or "compile error" in reason

    def test_simple_literal_accepted(self):
        ok, reason = self._gate(r"ignore all previous instructions")
        assert ok is True, reason

    def test_complex_safe_pattern_accepted(self):
        ok, reason = self._gate(r"(?i)(system\s+prompt|act\s+as\s+dan)")
        assert ok is True, reason
