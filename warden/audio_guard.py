"""
warden/audio_guard.py
━━━━━━━━━━━━━━━━━━━━
Audio Guard — Steps 4/5 of v1.4 Multi-Modal Guard.

Detects hidden commands injected via audio:
  • Speech-to-text transcription via Whisper (faster-whisper, CPU-optimized)
  • Transcript routed through existing SemanticGuard for injection detection
  • Ultrasound / inaudible command detection (energy analysis in >16 kHz band)

Model
──────
  faster-whisper — CTranslate2-optimized Whisper port (2-4x faster than openai/whisper)
  Model: tiny.en  — lowest latency for English-only audio (~100 ms for 5 s clip on CPU)
  Quantization: int8  — halves memory + 30% speed improvement on CPU

Pipeline
─────────
  audio_bytes
    → Whisper transcription            (ThreadPoolExecutor, AUDIO_PIPELINE_TIMEOUT_MS)
    → Ultrasound energy check          (FFT, synchronous — < 1 ms)
    → SemanticGuard text check         (existing pipeline — async)
    → AudioGuardResult

Performance targets
────────────────────
  faster-whisper tiny.en int8 on CPU: ~80–150 ms per 5 s audio clip.
  AUDIO_PIPELINE_TIMEOUT_MS=3000 — generous for up to 30 s clips.
  Fail-open on timeout.

Environment variables
─────────────────────
  AUDIO_GUARD_ENABLED         "false" to disable (default: true)
  AUDIO_GUARD_MODEL           Whisper model size (default: tiny.en)
  AUDIO_GUARD_COMPUTE         Compute type: int8 | float32 (default: int8)
  AUDIO_PIPELINE_TIMEOUT_MS   Hard timeout per clip (default: 3000)
  AUDIO_ULTRASOUND_THRESHOLD  Energy ratio threshold for ultrasound detection (default: 0.15)
  MODEL_CACHE_DIR             Shared model cache dir (default: /warden/models)
  AUDIO_MAX_BYTES             Max audio size in bytes (default: 25 MB)
"""
from __future__ import annotations

import asyncio
import base64
import io
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from functools import lru_cache
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

log = logging.getLogger("warden.audio_guard")

# ── Config ────────────────────────────────────────────────────────────────────

ENABLED: bool          = os.getenv("AUDIO_GUARD_ENABLED", "true").lower() != "false"
MODEL_SIZE: str        = os.getenv("AUDIO_GUARD_MODEL", "tiny.en")
COMPUTE_TYPE: str      = os.getenv("AUDIO_GUARD_COMPUTE", "int8")
TIMEOUT_MS: int        = int(os.getenv("AUDIO_PIPELINE_TIMEOUT_MS", "3000"))
US_THRESHOLD: float    = float(os.getenv("AUDIO_ULTRASOUND_THRESHOLD", "0.15"))
CACHE_DIR: str         = os.getenv("MODEL_CACHE_DIR", "/warden/models")
MAX_BYTES: int         = int(os.getenv("AUDIO_MAX_BYTES", str(25 * 1024 * 1024)))  # 25 MB

_SAMPLE_RATE = 16_000   # Whisper expects 16 kHz mono

# ── Thread pool ───────────────────────────────────────────────────────────────

_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="audio-guard")


# ── Model singleton ───────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def _load_whisper():
    """Load faster-whisper model once.  Raises ImportError if not installed."""
    from faster_whisper import WhisperModel  # noqa: PLC0415
    t0 = time.time()
    model = WhisperModel(
        MODEL_SIZE,
        device="cpu",
        compute_type=COMPUTE_TYPE,
        download_root=CACHE_DIR,
    )
    log.info(
        "AudioGuard: Whisper model loaded in %.1fs — model=%s compute=%s",
        time.time() - t0, MODEL_SIZE, COMPUTE_TYPE,
    )
    return model


def prewarm() -> bool:
    """Pre-load Whisper model at startup.  Returns True on success."""
    if not ENABLED:
        return False
    try:
        _load_whisper()
        return True
    except Exception as exc:
        log.warning("AudioGuard: model pre-warm failed (non-fatal): %s", exc)
        return False


# ── Result ────────────────────────────────────────────────────────────────────

@dataclass
class AudioGuardResult:
    transcript:          str   = ""
    is_injection:        bool  = False
    ultrasound_detected: bool  = False
    ultrasound_energy:   float = 0.0
    semantic_flags:      list  = field(default_factory=list)
    language:            str   = ""
    elapsed_ms:          float = 0.0
    error:               str   = ""
    # Segment-level data for AudioRedactor (v1.5)
    # Each entry: {start: float, end: float, text: str, flagged: bool}
    segments:            list[dict] = field(default_factory=list)
    sample_rate:         int   = 16_000   # sample rate of decoded audio (for redactor)


# ── Ultrasound detection ──────────────────────────────────────────────────────

def _check_ultrasound(audio_array, sample_rate: int) -> tuple[bool, float]:
    """
    Check if audio contains significant energy above 16 kHz (ultrasound commands).

    Returns (detected: bool, energy_ratio: float).
    Energy ratio = power in [16 kHz, Nyquist] / total power.
    """
    try:
        import numpy as np  # noqa: PLC0415
        n = len(audio_array)
        spectrum = np.abs(np.fft.rfft(audio_array))
        freqs    = np.fft.rfftfreq(n, d=1.0 / sample_rate)
        us_mask  = freqs >= 16_000
        total_power = float(np.sum(spectrum ** 2)) + 1e-10
        us_power    = float(np.sum(spectrum[us_mask] ** 2))
        ratio = us_power / total_power
        return ratio >= US_THRESHOLD, round(ratio, 4)
    except Exception:
        return False, 0.0


# ── Core transcription ────────────────────────────────────────────────────────

def _decode_audio(audio_bytes: bytes) -> tuple:
    """Decode audio bytes to numpy float32 array at 16 kHz mono."""
    try:
        # Try librosa first (best format support)
        import librosa  # noqa: PLC0415
        import numpy as np  # noqa: PLC0415
        audio_array, _ = librosa.load(io.BytesIO(audio_bytes), sr=_SAMPLE_RATE, mono=True)
        return audio_array, _SAMPLE_RATE
    except ImportError:
        pass

    try:
        # Fallback: soundfile (handles WAV/FLAC/OGG)
        import numpy as np  # noqa: PLC0415
        import soundfile as sf  # noqa: PLC0415
        audio_array, sr = sf.read(io.BytesIO(audio_bytes), dtype="float32", always_2d=False)
        if sr != _SAMPLE_RATE:
            # Simple linear resample (crude but dependency-free)
            ratio = _SAMPLE_RATE / sr
            new_len = int(len(audio_array) * ratio)
            indices = (np.arange(new_len) / ratio).astype(int)
            indices = np.clip(indices, 0, len(audio_array) - 1)
            audio_array = audio_array[indices]
        return audio_array, _SAMPLE_RATE
    except ImportError:
        pass

    raise RuntimeError(
        "No audio decoding backend available. "
        "Install librosa (pip install librosa) or soundfile (pip install soundfile)."
    )


def _transcribe_sync(audio_bytes: bytes) -> AudioGuardResult:
    """Transcribe audio and run ultrasound check synchronously."""
    t0 = time.time()
    try:
        model = _load_whisper()
        audio_array, sr = _decode_audio(audio_bytes)
        us_detected, us_energy = _check_ultrasound(audio_array, sr)

        segments, info = model.transcribe(
            audio_array,
            language="en",
            beam_size=1,             # greedy — fastest
            vad_filter=True,         # skip silence
        )
        # Materialise generator — needed both for transcript and per-segment timestamps
        seg_list   = list(segments)
        transcript = " ".join(s.text.strip() for s in seg_list).strip()
        seg_dicts  = [
            {"start": s.start, "end": s.end, "text": s.text.strip(), "flagged": False}
            for s in seg_list
        ]
        elapsed = (time.time() - t0) * 1000

        return AudioGuardResult(
            transcript          = transcript,
            ultrasound_detected = us_detected,
            ultrasound_energy   = us_energy,
            language            = getattr(info, "language", "en"),
            elapsed_ms          = round(elapsed, 2),
            segments            = seg_dicts,
            sample_rate         = sr,
        )
    except ImportError as exc:
        log.warning("AudioGuard: missing dependency (%s) — skipping", exc)
        return AudioGuardResult(error=str(exc), elapsed_ms=(time.time() - t0) * 1000)
    except Exception as exc:
        log.warning("AudioGuard: transcription error: %s", exc)
        return AudioGuardResult(error=str(exc), elapsed_ms=(time.time() - t0) * 1000)


# ── Public API ────────────────────────────────────────────────────────────────

async def check_audio(audio_bytes: bytes, semantic_guard=None) -> AudioGuardResult:
    """
    Async entry point: transcribe audio, detect ultrasound, check transcript.

    Steps:
      1. Whisper transcription (ThreadPoolExecutor, AUDIO_PIPELINE_TIMEOUT_MS)
      2. Ultrasound energy check (done inside transcription thread)
      3. SemanticGuard on transcript (if semantic_guard provided)

    Fail-open on timeout — text pipeline runs in parallel regardless.
    """
    if not ENABLED:
        return AudioGuardResult(error="disabled")

    if len(audio_bytes) > MAX_BYTES:
        log.warning("AudioGuard: audio too large (%d bytes) — skipping", len(audio_bytes))
        return AudioGuardResult(error="audio_too_large")

    loop = asyncio.get_running_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(_executor, _transcribe_sync, audio_bytes),
            timeout=TIMEOUT_MS / 1000,
        )
    except TimeoutError:
        log.warning("AudioGuard: transcription timed out after %d ms — fail-open", TIMEOUT_MS)
        return AudioGuardResult(error="timeout", elapsed_ms=float(TIMEOUT_MS))

    if result.error:
        return result

    # ── Step 3: semantic check on transcript ──────────────────────────────────
    if result.transcript and semantic_guard is not None:
        try:
            sem_result = await semantic_guard.check_async(result.transcript)
            result.is_injection  = sem_result.is_jailbreak
            result.semantic_flags = [
                {"flag": f.flag.value, "score": f.score, "detail": f.detail}
                for f in (sem_result.flags or [])
            ]

            # ── Per-segment flagging for precise bleeping (v1.5) ──────────
            # Only run per-segment check when injection confirmed to save latency.
            # Segments are checked concurrently via asyncio.gather.
            if sem_result.is_jailbreak and result.segments:
                try:
                    import asyncio as _asyncio  # noqa: PLC0415
                    checks = await _asyncio.gather(*[
                        semantic_guard.check_async(s["text"])
                        for s in result.segments
                        if s["text"]
                    ], return_exceptions=True)
                    any_flagged = False
                    idx = 0
                    for seg in result.segments:
                        if not seg["text"]:
                            continue
                        chk = checks[idx]
                        idx += 1
                        if not isinstance(chk, Exception) and chk.is_jailbreak:
                            seg["flagged"] = True
                            any_flagged = True
                    # Conservative fallback: if no individual segment triggered,
                    # flag all segments (full transcript is injection but we can't
                    # pin it to a single chunk — bleep everything).
                    if not any_flagged:
                        for seg in result.segments:
                            seg["flagged"] = True
                except Exception as _seg_exc:
                    log.debug("AudioGuard: per-segment check failed: %s", _seg_exc)
                    for seg in result.segments:
                        seg["flagged"] = True
        except Exception as exc:
            log.debug("AudioGuard: semantic check skipped: %s", exc)

    # Ultrasound alone is an injection signal even without transcript
    if result.ultrasound_detected:
        result.is_injection = True
        log.info(
            "AudioGuard: ultrasound commands detected energy_ratio=%.3f",
            result.ultrasound_energy,
        )

    if result.is_injection:
        log.info(
            "AudioGuard: AUDIO_INJECTION detected transcript=%r elapsed=%.1fms",
            result.transcript[:80], result.elapsed_ms,
        )

    return result


async def check_audio_b64(b64_string: str, semantic_guard=None) -> AudioGuardResult:
    """Convenience wrapper that decodes a base64 audio string first."""
    try:
        audio_bytes = base64.b64decode(b64_string)
    except Exception as exc:
        return AudioGuardResult(error=f"base64_decode_error: {exc}")
    return await check_audio(audio_bytes, semantic_guard)
