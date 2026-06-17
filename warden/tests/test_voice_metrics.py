"""Tests for Voice-Commerce Prometheus metrics (VC-02 / B.6)."""
from __future__ import annotations

import pytest


class TestSessionDurationHistogram:
    def test_session_duration_records(self):
        from warden.voice.metrics import VOICE_SESSION_DURATION

        before = VOICE_SESSION_DURATION._sum.get()
        VOICE_SESSION_DURATION.observe(45.0)
        after = VOICE_SESSION_DURATION._sum.get()
        assert after - before == pytest.approx(45.0, abs=0.01)


class TestLatencyHistogram:
    def test_latency_histogram_records(self):
        from warden.voice.metrics import VOICE_LATENCY

        before = VOICE_LATENCY._sum.get()
        VOICE_LATENCY.observe(250.0)
        after = VOICE_LATENCY._sum.get()
        assert after - before == pytest.approx(250.0, abs=0.01)


class TestConversionCounter:
    def test_conversion_counter_increments(self):
        from warden.voice.metrics import VOICE_CONVERSIONS

        before = VOICE_CONVERSIONS._value.get()
        VOICE_CONVERSIONS.inc()
        after = VOICE_CONVERSIONS._value.get()
        assert after - before == 1.0


class TestErrorCounter:
    def test_error_counter_increments_on_asr_failure(self):
        from warden.voice.metrics import VOICE_ERRORS

        before = VOICE_ERRORS.labels(stage="asr")._value.get()
        VOICE_ERRORS.labels(stage="asr").inc()
        after = VOICE_ERRORS.labels(stage="asr")._value.get()
        assert after - before == 1.0

    def test_error_counter_separates_stages(self):
        from warden.voice.metrics import VOICE_ERRORS

        VOICE_ERRORS.labels(stage="nlu").inc()
        VOICE_ERRORS.labels(stage="tts").inc()
        nlu_val = VOICE_ERRORS.labels(stage="nlu")._value.get()
        tts_val = VOICE_ERRORS.labels(stage="tts")._value.get()
        # Different labels tracked independently
        assert nlu_val >= 1.0
        assert tts_val >= 1.0


