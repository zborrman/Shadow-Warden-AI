"""
warden/voice/tts.py
Text-to-Speech engine — ElevenLabs (emotion-rich), Azure (cost-effective), Edge (free local).

Target: synthesis completes within VOICE_TTS_LATENCY_MS (default 200ms) for natural dialogue.
Falls back to silent PCM stub when provider unavailable.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor

from warden.config import settings

log = logging.getLogger("warden.voice.tts")

_PROVIDER      = settings.voice_tts_provider
_ELEVENLABS    = settings.elevenlabs_api_key
_AZURE_KEY     = settings.azure_speech_key
_AZURE_REGION  = settings.azure_speech_region
_LATENCY_MS    = settings.voice_tts_latency_ms
_CHUNK_SIZE    = 8192

_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="voice-tts")


def _silent_pcm(duration_ms: int = 200, sample_rate: int = 16_000) -> bytes:
    """Return silent PCM 16-bit mono — used as fallback."""
    return b"\x00\x00" * int(sample_rate * duration_ms / 1000)


class TTSEngine:
    """Text-to-Speech with streaming chunked output."""

    def __init__(self, provider: str = _PROVIDER) -> None:
        self.provider = provider

    async def synthesize(self, text: str, voice_config: dict | None = None) -> bytes:
        """Return complete PCM audio bytes."""
        config = voice_config or {}
        loop   = asyncio.get_running_loop()
        return await loop.run_in_executor(_executor, self._synth_sync, text, config)

    async def synthesize_stream(self, text: str, voice_config: dict | None = None) -> AsyncIterator[bytes]:
        """Yield audio in chunks as they become available."""
        audio = await self.synthesize(text, voice_config)
        for i in range(0, max(len(audio), 1), _CHUNK_SIZE):
            yield audio[i:i + _CHUNK_SIZE]

    # ── Provider dispatch ──────────────────────────────────────────────────────

    def _synth_sync(self, text: str, config: dict) -> bytes:
        if self.provider == "elevenlabs":
            return self._elevenlabs(text, config)
        if self.provider == "azure":
            return self._azure(text, config)
        return self._edge(text, config)

    def _elevenlabs(self, text: str, config: dict) -> bytes:
        if not _ELEVENLABS:
            return _silent_pcm()
        try:
            import httpx  # noqa: PLC0415
            vid  = config.get("voice_id", "21m00Tcm4TlvDq8ikWAM")
            resp = httpx.post(
                f"https://api.elevenlabs.io/v1/text-to-speech/{vid}",
                headers={"xi-api-key": _ELEVENLABS, "Content-Type": "application/json"},
                json={
                    "text": text,
                    "model_id": "eleven_turbo_v2",
                    "voice_settings": {"stability": 0.5, "similarity_boost": 0.8},
                    "output_format": "pcm_16000",
                },
                timeout=10.0,
            )
            resp.raise_for_status()
            return resp.content
        except Exception as exc:
            log.warning("ElevenLabs TTS error: %s", exc)
            return _silent_pcm()

    def _azure(self, text: str, config: dict) -> bytes:
        if not _AZURE_KEY:
            return _silent_pcm()
        try:
            import azure.cognitiveservices.speech as speechsdk  # noqa: PLC0415
            cfg  = speechsdk.SpeechConfig(subscription=_AZURE_KEY, region=_AZURE_REGION)
            cfg.set_speech_synthesis_output_format(
                speechsdk.SpeechSynthesisOutputFormat.Raw16Khz16BitMonoPcm
            )
            synth  = speechsdk.SpeechSynthesizer(speech_config=cfg, audio_config=None)
            result = synth.speak_text_async(text).get()
            if result.reason.name == "SynthesizingAudioCompleted":
                return bytes(result.audio_data)
            return _silent_pcm()
        except Exception as exc:
            log.warning("Azure TTS error: %s", exc)
            return _silent_pcm()

    def _edge(self, text: str, config: dict) -> bytes:
        try:
            import edge_tts  # noqa: PLC0415

            async def _run() -> bytes:
                voice = config.get("voice", "en-US-AriaNeural")
                comm  = edge_tts.Communicate(text, voice)
                chunks: list[bytes] = []
                async for chunk in comm.stream():
                    if chunk["type"] == "audio":
                        chunks.append(chunk["data"])
                return b"".join(chunks)

            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(_run())
            finally:
                loop.close()
        except Exception as exc:
            log.warning("Edge TTS error: %s", exc)
            return _silent_pcm()
