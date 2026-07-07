"""
warden/voice/asr.py
Streaming ASR — faster-whisper (local), Deepgram, or AssemblyAI.

Providers
---------
  whisper   — local faster-whisper (reuses audio_guard model cache)
  deepgram  — cloud, ~307ms latency, 8kHz mulaw support
  assemblyai— cloud, batch upload + poll

Session model: create StreamingASR() per call, stream_audio() chunks, finalize().
"""
from __future__ import annotations

import asyncio
import io
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import lru_cache

from warden.config import settings

log = logging.getLogger("warden.voice.asr")

_PROVIDER      = settings.voice_asr_provider
_DEEPGRAM_KEY  = settings.deepgram_api_key
_AAIKEY        = settings.assemblyai_api_key
_CACHE_DIR     = settings.model_cache_dir
_MODEL_SIZE    = settings.voice_asr_model
_COMPUTE       = settings.voice_asr_compute
_SAMPLE_RATE   = 16_000
_MAX_WINDOW    = 10   # rolling buffer window in chunks

_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="voice-asr")


@lru_cache(maxsize=1)
def _load_whisper():
    from faster_whisper import WhisperModel  # noqa: PLC0415
    t0 = time.time()
    model = WhisperModel(_MODEL_SIZE, device="cpu", compute_type=_COMPUTE, download_root=_CACHE_DIR)
    log.info("VoiceASR: Whisper loaded in %.1fs model=%s", time.time() - t0, _MODEL_SIZE)
    return model


@dataclass
class ASRResult:
    transcript: str  = ""
    confidence: float = 1.0
    language:   str  = "en"
    elapsed_ms: float = 0.0
    partial:    bool = False
    error:      str  = ""


def _decode_pcm(audio_bytes: bytes):
    """Decode audio bytes → float32 numpy array at 16 kHz mono. Fail-open."""
    try:
        import librosa  # noqa: PLC0415
        import numpy as np  # noqa: PLC0415
        arr, _ = librosa.load(io.BytesIO(audio_bytes), sr=_SAMPLE_RATE, mono=True)
        return arr
    except Exception:
        pass
    try:
        import numpy as np  # noqa: PLC0415
        return np.frombuffer(audio_bytes, dtype=np.int16).astype(np.float32) / 32768.0
    except Exception:
        import numpy as np  # noqa: PLC0415
        return np.zeros(_SAMPLE_RATE // 10, dtype=np.float32)


class StreamingASR:
    """
    Chunked streaming speech recogniser.

    Usage::
        asr = StreamingASR(provider="whisper")
        partial = await asr.stream_audio(chunk_bytes)
        final   = await asr.finalize()
    """

    def __init__(self, provider: str = _PROVIDER) -> None:
        self.provider = provider
        self._buffer: list[bytes] = []

    async def stream_audio(self, audio_chunk: bytes, config: dict | None = None) -> ASRResult:
        """Process one audio chunk; returns partial transcript."""
        t0 = time.monotonic()
        self._buffer.append(audio_chunk)
        combined = b"".join(self._buffer[-_MAX_WINDOW:])
        try:
            loop   = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                _executor, self._transcribe_sync, combined, config or {}
            )
        except Exception as exc:
            log.warning("ASR stream chunk error: %s", exc)
            result = ASRResult(error=str(exc))
        result.elapsed_ms = (time.monotonic() - t0) * 1000
        result.partial    = True
        return result

    async def finalize(self) -> ASRResult:
        """Return complete transcript from all buffered audio."""
        if not self._buffer:
            return ASRResult()
        t0    = time.monotonic()
        audio = b"".join(self._buffer)
        self._buffer.clear()
        try:
            loop   = asyncio.get_running_loop()
            result = await loop.run_in_executor(_executor, self._transcribe_sync, audio, {})
        except Exception as exc:
            log.warning("ASR finalize error: %s", exc)
            result = ASRResult(error=str(exc))
        result.elapsed_ms = (time.monotonic() - t0) * 1000
        result.partial    = False
        return result

    # ── Provider dispatch ──────────────────────────────────────────────────────

    def _transcribe_sync(self, audio_bytes: bytes, config: dict) -> ASRResult:
        if self.provider == "whisper":
            return self._whisper(audio_bytes, config)
        if self.provider == "deepgram":
            return self._deepgram(audio_bytes, config)
        if self.provider == "assemblyai":
            return self._assemblyai(audio_bytes, config)
        return ASRResult(error=f"unknown provider: {self.provider}")

    def _whisper(self, audio_bytes: bytes, config: dict) -> ASRResult:
        try:
            model = _load_whisper()
            audio = _decode_pcm(audio_bytes)
            segments, info = model.transcribe(
                audio,
                beam_size=config.get("beam_size", 1),
                language=config.get("language", "en"),
                vad_filter=True,
            )
            text = " ".join(s.text.strip() for s in segments)
            return ASRResult(transcript=text, language=info.language or "en", confidence=0.95)
        except Exception as exc:
            log.debug("Whisper error: %s", exc)
            return ASRResult(error=str(exc))

    def _deepgram(self, audio_bytes: bytes, config: dict) -> ASRResult:
        try:
            import httpx  # noqa: PLC0415
            resp = httpx.post(
                "https://api.deepgram.com/v1/listen",
                headers={"Authorization": f"Token {_DEEPGRAM_KEY}", "Content-Type": "audio/wav"},
                content=audio_bytes,
                params={"model": "nova-2", "encoding": "linear16", "sample_rate": 8000},
                timeout=10.0,
            )
            resp.raise_for_status()
            alt = resp.json()["results"]["channels"][0]["alternatives"][0]
            return ASRResult(transcript=alt.get("transcript", ""), confidence=alt.get("confidence", 0.9))
        except Exception as exc:
            return ASRResult(error=str(exc))

    def _assemblyai(self, audio_bytes: bytes, config: dict) -> ASRResult:
        try:
            import httpx  # noqa: PLC0415
            hdrs = {"authorization": _AAIKEY}
            upload = httpx.post(
                "https://api.assemblyai.com/v2/upload",
                headers=hdrs, content=audio_bytes, timeout=30.0,
            )
            upload.raise_for_status()
            tx = httpx.post(
                "https://api.assemblyai.com/v2/transcript",
                headers=hdrs, json={"audio_url": upload.json()["upload_url"]}, timeout=30.0,
            )
            tx.raise_for_status()
            tid = tx.json()["id"]
            for _ in range(30):
                import time as _t  # noqa: PLC0415
                _t.sleep(1)
                poll = httpx.get(f"https://api.assemblyai.com/v2/transcript/{tid}", headers=hdrs, timeout=10.0)
                data = poll.json()
                if data["status"] == "completed":
                    return ASRResult(transcript=data.get("text", ""), confidence=0.9)
                if data["status"] == "error":
                    return ASRResult(error=data.get("error", "assemblyai error"))
            return ASRResult(error="AssemblyAI timeout")
        except Exception as exc:
            return ASRResult(error=str(exc))
