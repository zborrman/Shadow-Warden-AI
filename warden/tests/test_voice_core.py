"""
warden/tests/test_voice_core.py
Phase 1 — Streaming ASR + TTS + NLU (8 tests).
"""
from __future__ import annotations

import asyncio
import os
import struct

import pytest

os.environ.setdefault("ANTHROPIC_API_KEY", "")       # disable LLM in NLU
os.environ.setdefault("VOICE_ASR_PROVIDER", "whisper")
os.environ.setdefault("REDIS_URL", "memory://")


# ── Helpers ────────────────────────────────────────────────────────────────────

def _pcm_bytes(duration_ms: int = 200, sample_rate: int = 16_000, amplitude: int = 1000) -> bytes:
    """Synthetic PCM 16-bit mono audio."""
    import math
    n      = int(sample_rate * duration_ms / 1000)
    frames = [int(amplitude * math.sin(2 * math.pi * 440 * i / sample_rate)) for i in range(n)]
    return struct.pack(f"<{n}h", *frames)


def _mulaw_bytes(duration_ms: int = 200) -> bytes:
    """Minimal 8kHz mulaw bytes for provider compat test."""
    n = int(8000 * duration_ms / 1000)
    return bytes([127] * n)


# ── ASR tests ──────────────────────────────────────────────────────────────────

class TestStreamingASR:
    def test_result_dataclass_defaults(self):
        from warden.voice.asr import ASRResult
        r = ASRResult()
        assert r.transcript == ""
        assert r.confidence == 1.0
        assert not r.partial
        assert r.error == ""

    def test_stream_audio_returns_asr_result(self):
        """stream_audio always returns ASRResult — never raises even if model unavailable."""
        from warden.voice.asr import ASRResult, StreamingASR
        asr = StreamingASR(provider="whisper")
        # With no faster-whisper the finalize returns ASRResult with error field
        result = asyncio.run(asr.finalize())
        assert isinstance(result, ASRResult)

    def test_mulaw_bytes_accepted(self):
        """StreamingASR accepts 8kHz mulaw bytes without raising at construction."""
        from warden.voice.asr import StreamingASR
        asr = StreamingASR(provider="whisper")
        assert asr.provider == "whisper"
        buf = _mulaw_bytes(100)
        asr._buffer.append(buf)
        assert len(asr._buffer) == 1

    def test_finalize_empty_buffer(self):
        from warden.voice.asr import ASRResult, StreamingASR
        asr    = StreamingASR(provider="whisper")
        result = asyncio.run(asr.finalize())
        assert isinstance(result, ASRResult)
        assert result.transcript == ""

    @pytest.mark.asyncio
    async def test_decode_pcm_fallback(self):
        from warden.voice.asr import _decode_pcm
        audio = _pcm_bytes()
        arr   = _decode_pcm(audio)
        # Should return a non-empty numpy-like array
        assert len(arr) > 0


# ── TTS tests ──────────────────────────────────────────────────────────────────

class TestTTSEngine:
    def test_silent_pcm_fallback(self):
        from warden.voice.tts import _silent_pcm
        audio = _silent_pcm(100)
        assert isinstance(audio, bytes)
        assert len(audio) > 0

    def test_engine_edge_provider_fallback(self):
        """Edge TTS falls back to silent PCM if edge_tts not installed."""
        from warden.voice.tts import TTSEngine
        engine = TTSEngine(provider="edge")
        result = asyncio.run(engine.synthesize("hello"))
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_stream_yields_chunks(self):
        from warden.voice.tts import TTSEngine

        async def collect():
            engine  = TTSEngine(provider="edge")
            chunks  = []
            async for chunk in engine.synthesize_stream("hi"):
                chunks.append(chunk)
            return chunks

        chunks = asyncio.run(collect())
        assert isinstance(chunks, list)
        assert len(chunks) >= 1


# ── NLU tests ──────────────────────────────────────────────────────────────────

class TestVoiceNLU:
    def test_search_intent(self):
        from warden.voice.nlu import _rule_parse
        intent = _rule_parse("find me a blue widget for under $50", {})
        assert intent.intent_type == "search"
        assert "product" in intent.entities
        assert intent.entities.get("max_price") == 50.0

    def test_buy_intent_with_product(self):
        from warden.voice.nlu import _rule_parse
        intent = _rule_parse("I want to buy 3 units of cloud storage", {})
        assert intent.intent_type == "buy"
        assert intent.entities.get("quantity") == 3

    def test_negotiate_intent(self):
        from warden.voice.nlu import _rule_parse
        intent = _rule_parse("how about $40 instead?", {})
        assert intent.intent_type == "negotiate"

    def test_cancel_intent(self):
        from warden.voice.nlu import _rule_parse
        intent = _rule_parse("cancel that, forget it", {})
        assert intent.intent_type == "cancel"

    def test_rule_parse_returns_voice_intent(self):
        from warden.voice.nlu import _rule_parse, VoiceIntent
        intent = _rule_parse("hello", {})
        assert isinstance(intent, VoiceIntent)
        assert intent.source == "rule"
        assert 0.0 <= intent.confidence <= 1.0

    @pytest.mark.asyncio
    async def test_parse_intent_no_key_uses_rules(self):
        """Without ANTHROPIC_API_KEY, parse_intent() falls back to rule_parse."""
        from warden.voice.nlu import parse_intent
        intent = await parse_intent("search for notebooks under $100")
        assert intent.intent_type == "search"
        assert intent.source == "rule"

    @pytest.mark.asyncio
    async def test_nlu_stateful_history(self):
        from warden.voice.nlu import VoiceNLU
        nlu = VoiceNLU()
        i1  = await nlu.parse("find blue widget")
        i2  = await nlu.parse("buy the first one")
        assert i1.intent_type == "search"
        assert i2.intent_type == "buy"
        assert len(nlu._history) == 2

    @pytest.mark.asyncio
    async def test_integration_transcript_to_intent(self):
        """Full path: transcript string → VoiceNLU.parse → VoiceIntent with entities."""
        from warden.voice.nlu import VoiceNLU
        nlu    = VoiceNLU()
        intent = await nlu.parse("I want to find a laptop for under $800")
        assert intent.intent_type == "search"
        assert intent.entities.get("max_price") == 800.0
