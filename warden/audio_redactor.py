"""
warden/audio_redactor.py
━━━━━━━━━━━━━━━━━━━━━━━
Audio Redactor — Step 2 of v1.5 Redaction & Content Synthesis.

Cleans flagged audio before forwarding to LLMs or returning to callers:
  • Segment bleeping   — replaces Whisper-flagged time ranges with silence.
                         Timestamps come from AudioGuardResult.segments (set by v1.5 update
                         to audio_guard.py; each entry has {start, end, text, flagged}).
  • Ultrasound filter  — zeroes FFT components above 16 kHz (inaudible band).
                         Removes hidden ultrasound commands while preserving audible content.
  • Output format      — WAV PCM float32, 16 kHz mono (same as Whisper input).

Decision tree
──────────────
  audio_result.is_injection AND segments available
    → bleep flagged segments (silence replacement)
  audio_result.is_injection AND no segments (e.g. timeout mid-transcription)
    → bleep entire audio (conservative)
  audio_result.ultrasound_detected
    → strip >16 kHz band via FFT (applied on top of segment bleeping if both are true)
  clean
    → return original bytes unchanged

Performance
────────────
  FFT lowpass on 10 s @ 16 kHz: ~3–8 ms on CPU.
  Silence fill of N segments: < 1 ms.
  WAV encode via soundfile: ~5–15 ms.
  Hard timeout: AUDIO_REDACTION_TIMEOUT_MS=1000 (fail-open → returns original on timeout).

Environment variables
─────────────────────
  AUDIO_REDACTION_ENABLED        "false" to disable (default: true)
  AUDIO_REDACTION_TIMEOUT_MS     Hard timeout in ms (default: 1000)
  AUDIO_MAX_BYTES                Max audio bytes — shared with audio_guard (default: 25 MB)
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
from typing import TYPE_CHECKING

import numpy as np

if TYPE_CHECKING:
    from warden.audio_guard import AudioGuardResult

log = logging.getLogger("warden.audio_redactor")

# ── Config ────────────────────────────────────────────────────────────────────

ENABLED:    bool = os.getenv("AUDIO_REDACTION_ENABLED", "true").lower() != "false"
TIMEOUT_MS: int  = int(os.getenv("AUDIO_REDACTION_TIMEOUT_MS", "1000"))
MAX_BYTES:  int  = int(os.getenv("AUDIO_MAX_BYTES", str(25 * 1024 * 1024)))

_SAMPLE_RATE = 16_000   # Whisper canonical rate

_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="audio-redact")


# ── Result ────────────────────────────────────────────────────────────────────

@dataclass
class RedactedSegment:
    start:   float
    end:     float
    text:    str = ""


@dataclass
class AudioRedactorResult:
    redacted_bytes:      bytes                = b""
    segments_bleeped:    list[RedactedSegment] = field(default_factory=list)
    ultrasound_filtered: bool                 = False
    elapsed_ms:          float                = 0.0
    error:               str                  = ""


# ── Silence / ultrasound replacement ─────────────────────────────────────────

def _bleep_segments(
    audio: np.ndarray,
    sample_rate: int,
    flagged_segs: list[dict],
) -> np.ndarray:
    """
    Replace flagged time ranges with silence (zeros).

    Args:
        audio:        Float32 numpy array, shape (N,).
        sample_rate:  Samples per second.
        flagged_segs: List of {start: float, end: float} dicts (seconds).

    Returns modified copy of the array.
    """

    out = audio.copy()
    for seg in flagged_segs:
        s = int(seg["start"] * sample_rate)
        e = int(seg["end"]   * sample_rate)
        s = max(0, min(s, len(out)))
        e = max(0, min(e, len(out)))
        if e > s:
            out[s:e] = 0.0
    return out


def _filter_ultrasound(audio: np.ndarray, sample_rate: int) -> np.ndarray:
    """
    Zero out FFT components above 16 kHz (inaudible ultrasound band).

    Applies a hard spectral cutoff at 16 kHz via real FFT → zero mask → IFFT.
    Audible content (< 16 kHz) is preserved exactly.
    """
    import numpy as np  # noqa: PLC0415

    spectrum = np.fft.rfft(audio)
    freqs    = np.fft.rfftfreq(len(audio), d=1.0 / sample_rate)
    spectrum[freqs >= 16_000] = 0.0
    return np.fft.irfft(spectrum, n=len(audio)).astype(np.float32)


# ── WAV encoding ──────────────────────────────────────────────────────────────

def _encode_wav(audio: np.ndarray, sample_rate: int) -> bytes:
    """Encode float32 numpy array as WAV bytes using soundfile."""
    import soundfile as sf  # noqa: PLC0415

    buf = io.BytesIO()
    sf.write(buf, audio, sample_rate, format="WAV", subtype="FLOAT")
    return buf.getvalue()


# ── Core redaction (synchronous — runs in ThreadPoolExecutor) ─────────────────

def _redact_sync(audio_bytes: bytes, guard_result: AudioGuardResult) -> AudioRedactorResult:
    t0 = time.time()
    try:
        import numpy as np  # noqa: PLC0415

        from warden.audio_guard import _decode_audio  # noqa: PLC0415

        getattr(guard_result, "sample_rate", _SAMPLE_RATE)
        audio, sr   = _decode_audio(audio_bytes)

        bleeped:    list[RedactedSegment] = []
        us_filtered = False

        # ── Segment bleeping ──────────────────────────────────────────────
        if guard_result.is_injection:
            segments = getattr(guard_result, "segments", [])
            flagged  = [s for s in segments if s.get("flagged")]

            if flagged:
                audio = _bleep_segments(audio, sr, flagged)
                bleeped = [
                    RedactedSegment(start=s["start"], end=s["end"], text=s.get("text", ""))
                    for s in flagged
                ]
                log.info(
                    "AudioRedactor: %d segment(s) silenced (%.1fs–%.1fs)",
                    len(bleeped),
                    bleeped[0].start if bleeped else 0,
                    bleeped[-1].end  if bleeped else 0,
                )
            else:
                # No segment timestamps available — silence entire clip
                audio = np.zeros_like(audio)
                duration = len(audio) / sr
                bleeped  = [RedactedSegment(start=0.0, end=duration,
                                            text="[full clip — no segment timestamps]")]
                log.info("AudioRedactor: full clip silenced (no segment timestamps).")

        # ── Ultrasound band removal ───────────────────────────────────────
        if getattr(guard_result, "ultrasound_detected", False):
            audio       = _filter_ultrasound(audio, sr)
            us_filtered = True
            log.info("AudioRedactor: ultrasound band (>16 kHz) stripped.")

        # ── Re-encode to WAV ──────────────────────────────────────────────
        redacted_bytes = _encode_wav(audio, sr)
        elapsed        = round((time.time() - t0) * 1000, 2)

        log.info(
            "AudioRedactor: done — segments_bleeped=%d ultrasound_filtered=%s "
            "size_in=%d size_out=%d elapsed=%.1fms",
            len(bleeped), us_filtered,
            len(audio_bytes), len(redacted_bytes), elapsed,
        )
        return AudioRedactorResult(
            redacted_bytes      = redacted_bytes,
            segments_bleeped    = bleeped,
            ultrasound_filtered = us_filtered,
            elapsed_ms          = elapsed,
        )

    except ImportError as exc:
        log.warning("AudioRedactor: missing dependency (%s) — returning original", exc)
        return AudioRedactorResult(
            redacted_bytes = audio_bytes,
            error          = str(exc),
            elapsed_ms     = round((time.time() - t0) * 1000, 2),
        )
    except Exception as exc:
        log.warning("AudioRedactor: error — returning original: %s", exc)
        return AudioRedactorResult(
            redacted_bytes = audio_bytes,
            error          = str(exc),
            elapsed_ms     = round((time.time() - t0) * 1000, 2),
        )


# ── Public API ────────────────────────────────────────────────────────────────

async def redact_audio(
    audio_bytes: bytes,
    guard_result: AudioGuardResult,
) -> AudioRedactorResult:
    """
    Async entry point: silence injected segments + strip ultrasound band.

    Args:
        audio_bytes:  Raw audio bytes (WAV/MP3/OGG/FLAC).
        guard_result: AudioGuardResult from audio_guard.check_audio() — must have
                      .is_injection, .ultrasound_detected, and .segments populated.

    Returns AudioRedactorResult.  On timeout or error, redacted_bytes falls back
    to the original audio (fail-open).
    """
    if not ENABLED:
        return AudioRedactorResult(redacted_bytes=audio_bytes, error="disabled")
    if len(audio_bytes) > MAX_BYTES:
        return AudioRedactorResult(redacted_bytes=audio_bytes, error="audio_too_large")
    if not guard_result.is_injection and not guard_result.ultrasound_detected:
        # Nothing to redact — return original unchanged
        return AudioRedactorResult(redacted_bytes=audio_bytes)

    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(_executor, _redact_sync, audio_bytes, guard_result),
            timeout=TIMEOUT_MS / 1000,
        )
    except TimeoutError:
        log.warning("AudioRedactor: timed out after %d ms — returning original", TIMEOUT_MS)
        return AudioRedactorResult(
            redacted_bytes = audio_bytes,
            error          = "timeout",
            elapsed_ms     = float(TIMEOUT_MS),
        )


async def redact_audio_b64(
    b64_string: str,
    guard_result: AudioGuardResult,
) -> tuple[str, AudioRedactorResult]:
    """
    Convenience wrapper: decode base64 → redact → re-encode.

    Returns (redacted_b64, result).  On any error returns (original_b64, result).
    """
    try:
        audio_bytes = base64.b64decode(b64_string)
    except Exception as exc:
        empty = AudioRedactorResult(
            redacted_bytes = b"",
            error          = f"base64_decode_error: {exc}",
        )
        return b64_string, empty

    result       = await redact_audio(audio_bytes, guard_result)
    redacted_b64 = base64.b64encode(result.redacted_bytes).decode()
    return redacted_b64, result
