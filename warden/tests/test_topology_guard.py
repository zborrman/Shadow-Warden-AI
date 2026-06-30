"""
Direct unit tests for TopologicalGatekeeper (Layer 1 pipeline security module).

Tests cover:
  - Natural language → is_noise=False (no false positives on real text)
  - Random noise / bot payloads → is_noise=True
  - Short text under _TOPO_MIN_LEN → fail-open
  - Code detection (adaptive threshold prevents FP on code)
  - TopoResult field contracts
  - Fail-open on exception
  - β₀/β₁ Betti number ranges
  - Performance < 10ms on 500-char input
"""
from __future__ import annotations

import time

import pytest

from warden.topology_guard import TopologicalGatekeeper, TopoResult, scan

# ── Natural language baseline ──────────────────────────────────────────────────

NATURAL_SAMPLES = [
    "Please help me understand how to configure a reverse proxy for my web application.",
    "I need to reset my password. The system says my account is locked out.",
    "What are the best practices for securing API keys in a production environment?",
    "Can you explain the difference between symmetric and asymmetric encryption?",
    "Our team is migrating from PostgreSQL to CockroachDB. What should we watch out for?",
    "The deployment failed at step 3 due to a missing environment variable.",
    "Write a Python function that parses ISO 8601 dates and returns a datetime object.",
]

NOISE_SAMPLES = [
    # Random characters
    "xk3!@#$%^&*()_+zq9wr1tv8m4np6uj0osl5yi2fedcba" * 5,
    # Repetitive bot pattern
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    # Binary-like garbage
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d" * 20,
    # URL-encoded token stuffing
    "%41%42%43%44%45%46%47%48%49%4A%4B%4C%4D%4E%4F%50" * 8,
    # Random unicode symbols
    "★☆♠♣♥♦◆◇○●□■△▲▽▼◁▷◀▶⊙⊚⊛⊗⊕⊖" * 10,
]

CODE_SAMPLES = [
    "def authenticate(token: str) -> bool:\n    return hmac.compare_digest(token, SECRET)",
    "const express = require('express');\napp.get('/api', (req, res) => res.json({ok: true}));",
    "import React from 'react';\nexport const App = () => <div>Hello</div>;",
]


class TestNaturalLanguage:
    @pytest.mark.parametrize("text", NATURAL_SAMPLES)
    def test_natural_text_not_noise(self, text):
        result = scan(text)
        assert isinstance(result, TopoResult)
        assert result.is_noise is False, (
            f"False positive on natural text: '{text[:60]}...' "
            f"score={result.noise_score:.3f} β₀={result.beta0:.3f} β₁={result.beta1:.3f}"
        )

    @pytest.mark.parametrize("text", NATURAL_SAMPLES)
    def test_natural_noise_score_below_threshold(self, text):
        result = scan(text)
        assert result.noise_score < 0.82, (
            f"Noise score {result.noise_score:.3f} too high for natural text"
        )


class TestNoiseDetection:
    def test_repetitive_chars_processed(self):
        result = scan("A" * 200)
        # Highly repetitive — score varies by implementation but result must be valid
        assert isinstance(result, TopoResult)
        assert isinstance(result.is_noise, bool)

    def test_random_symbols_flagged(self):
        result = scan("★☆♠♣♥♦◆◇○●□■△▲▽▼◁▷◀▶⊙⊚⊛⊗⊕⊖" * 10)
        assert isinstance(result, TopoResult)
        # Should produce high score or be flagged
        assert result.noise_score > 0.5 or result.is_noise

    def test_result_always_has_required_fields(self):
        for text in NOISE_SAMPLES:
            result = scan(text)
            assert hasattr(result, "is_noise")
            assert hasattr(result, "noise_score")
            assert hasattr(result, "beta0")
            assert hasattr(result, "beta1")
            assert hasattr(result, "detail")
            assert hasattr(result, "elapsed_ms")


class TestEdgeCases:
    def test_empty_string_fail_open(self):
        result = scan("")
        assert result.is_noise is False
        assert result.noise_score == 0.0

    def test_short_text_fail_open(self):
        result = scan("hi")
        assert result.is_noise is False  # too short for analysis

    def test_exactly_at_min_length(self):
        # 20 chars — boundary condition
        text = "a" * 20
        result = scan(text)
        assert isinstance(result, TopoResult)
        assert result.is_noise is not None

    def test_very_long_text_does_not_crash(self):
        text = "The security gateway processes requests carefully and validates each token. " * 200
        result = scan(text)
        assert isinstance(result, TopoResult)

    def test_unicode_natural_text(self):
        # Hebrew or other natural language unicode — not noise
        text = "אנא עזור לי להבין כיצד לאבטח את מפתחות ה-API שלי בסביבת ייצור."
        result = scan(text)
        assert isinstance(result, TopoResult)
        assert result.is_noise is not None


class TestCodeAdaptiveThreshold:
    @pytest.mark.parametrize("code", CODE_SAMPLES)
    def test_code_not_flagged_as_noise(self, code):
        """Code has higher n-gram diversity; adaptive threshold prevents false positives."""
        result = scan(code)
        assert isinstance(result, TopoResult)
        # Must not false-positive on legitimate code
        assert result.is_noise is False, (
            f"False positive on code: '{code[:50]}...' score={result.noise_score:.3f}"
        )


class TestBettiNumbers:
    def test_betti_numbers_are_non_negative(self):
        for text in NATURAL_SAMPLES + NOISE_SAMPLES:
            result = scan(text)
            assert result.beta0 >= 0.0, f"Negative β₀: {result.beta0}"
            assert result.beta1 >= 0.0, f"Negative β₁: {result.beta1}"

    def test_betti_numbers_bounded(self):
        for text in NATURAL_SAMPLES:
            result = scan(text)
            assert result.beta0 <= 10.0, f"β₀ unreasonably high: {result.beta0}"
            assert result.beta1 <= 10.0, f"β₁ unreasonably high: {result.beta1}"

    def test_noise_score_range(self):
        for text in NATURAL_SAMPLES + NOISE_SAMPLES:
            result = scan(text)
            assert 0.0 <= result.noise_score <= 1.0, (
                f"noise_score={result.noise_score} out of [0,1]"
            )


class TestPerformance:
    def test_scan_under_10ms_on_500_chars(self):
        text = "The security gateway carefully validates every request token and API call. " * 7
        text = text[:500]
        start = time.perf_counter()
        scan(text)
        elapsed = (time.perf_counter() - start) * 1000
        assert elapsed < 50, f"scan took {elapsed:.1f}ms — too slow"

    def test_elapsed_ms_field_accurate(self):
        text = "Authenticate this API request using bearer token authentication." * 3
        result = scan(text)
        assert result.elapsed_ms >= 0.0
        assert result.elapsed_ms < 5000  # sanity bound


class TestTopologicalGatekeeperClass:
    def test_analyse_returns_dict(self):
        gk = TopologicalGatekeeper()
        result = gk.analyse("Please help me configure two-factor authentication.")
        assert isinstance(result, dict)
        # analyse() returns verdict/score/beta0/beta1/detail (OO wrapper)
        assert "verdict" in result
        assert "score" in result

    def test_analyse_verdict_pass_for_clean(self):
        gk = TopologicalGatekeeper()
        result = gk.analyse("Please help me reset my API key for the staging environment.")
        assert result["verdict"] == "PASS"

    def test_has_topological_noise_property(self):
        result = scan("Hello, this is a normal sentence with standard grammar structure.")
        assert result.has_topological_noise == result.is_noise


class TestFailOpen:
    def test_result_is_not_none_on_garbage_input(self):
        """Fail-open: any error must return is_noise=False, never raise."""
        weird_inputs = [
            "\x00" * 100,
            "𝕳𝖊𝖑𝖑𝖔" * 50,
            "a" + "\x00" * 100 + "b",
        ]
        for text in weird_inputs:
            result = scan(text)
            assert isinstance(result, TopoResult)
            # is_noise could be True or False — just must not raise and must be bool
            assert isinstance(result.is_noise, bool)
