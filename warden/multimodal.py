"""
warden/multimodal.py
━━━━━━━━━━━━━━━━━━━
Multi-Modal Pipeline Coordinator — Step 6 of v1.4.

Orchestrates parallel execution of the text, image, and audio guard stages,
then merges individual risk scores into a unified verdict.

Pipeline (parallel streams)
────────────────────────────
  MultimodalRequest
    ├── text content  ──→ existing /filter pipeline (SemanticGuard + ThreatVault)
    ├── image_b64     ──→ ImageGuard (CLIP zero-shot)          ─┐
    └── audio_b64     ──→ AudioGuard (Whisper + SemanticGuard) ─┘
                                ↓  asyncio.gather
                         MultimodalResult
                           unified risk_level = max(text, image, audio)
                           flags += VISUAL_JAILBREAK | AUDIO_INJECTION

Risk merging rules
───────────────────
  • Final risk = max(text_risk, image_risk, audio_risk) by severity order
  • A VISUAL_JAILBREAK or AUDIO_INJECTION flag always escalates to HIGH
  • Ultrasound detection alone → HIGH (even with empty transcript)
  • PII in image → PII_DETECTED flag + MEDIUM escalation (for GDPR masking)

GDPR image masking (Step 7)
────────────────────────────
  If ImageGuard detects PII (is_pii=True), the image is NOT forwarded to
  downstream LLMs.  The response includes a masked placeholder and a
  'pii_redacted' boolean in the modalities field.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from warden.schemas import FlagType, RiskLevel, SemanticFlag

log = logging.getLogger("warden.multimodal")

_RISK_ORDER = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.BLOCK]


def _max_risk(*levels: RiskLevel) -> RiskLevel:
    return max(levels, key=lambda r: _RISK_ORDER.index(r))


# ── Result ────────────────────────────────────────────────────────────────────

@dataclass
class MultimodalResult:
    risk_level:          RiskLevel          = RiskLevel.LOW
    allowed:             bool               = True
    flags:               list[SemanticFlag] = field(default_factory=list)
    modalities:          dict[str, Any]     = field(default_factory=dict)
    processing_ms:       dict[str, float]   = field(default_factory=dict)
    pii_redacted:        bool               = False
    redacted_image_b64:  str | None         = None   # blurred PNG, base64 (set when PII found)
    redacted_audio_b64:  str | None         = None   # silenced WAV, base64 (set when injection found)
    image_description:   str | None         = None   # CLIP-generated safe description (synthesis proxy)


# ── Unified scoring ───────────────────────────────────────────────────────────

def _image_risk(image_result) -> RiskLevel:
    if image_result.error or not hasattr(image_result, "is_jailbreak"):
        return RiskLevel.LOW
    if image_result.is_jailbreak:
        return RiskLevel.HIGH
    if image_result.is_pii:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _audio_risk(audio_result) -> RiskLevel:
    if audio_result.error or not hasattr(audio_result, "is_injection"):
        return RiskLevel.LOW
    if audio_result.is_injection or audio_result.ultrasound_detected:
        return RiskLevel.HIGH
    return RiskLevel.LOW


# ── Main coordinator ──────────────────────────────────────────────────────────

async def run_multimodal(
    *,
    text_content:   str | None = None,
    image_b64:      str | None = None,
    audio_b64:      str | None = None,
    text_risk:      RiskLevel  = RiskLevel.LOW,
    text_flags:     list[SemanticFlag] | None = None,
    semantic_guard  = None,
    strict:         bool = False,
    redact_pii:       bool = True,    # auto-blur PII regions before returning image
    redact_audio:     bool = True,    # auto-silence injection segments before returning audio
    synthesize_proxy: bool = False,   # generate safe text description instead of forwarding image
) -> MultimodalResult:
    """
    Run image + audio guards in parallel, merge with existing text result.

    Args:
        text_content:   Raw text (already filtered by main pipeline).
        image_b64:      Base64-encoded image (PNG/JPEG/WebP).
        audio_b64:      Base64-encoded audio (WAV/MP3/OGG).
        text_risk:      Risk level already determined by text pipeline.
        text_flags:     Flags already raised by text pipeline.
        semantic_guard: BrainSemanticGuard instance for audio transcript check.
        strict:         If True, MEDIUM → block.

    Returns MultimodalResult with unified verdict.
    """
    t0 = time.time()
    all_flags = list(text_flags or [])
    modalities: dict[str, Any] = {"text": {"risk": text_risk.value}}

    # ── Parallel image + audio ────────────────────────────────────────────────
    tasks = []
    has_image = bool(image_b64)
    has_audio = bool(audio_b64)

    if has_image:
        from warden.image_guard import check_image_b64  # noqa: PLC0415
        tasks.append(check_image_b64(image_b64))
    else:
        tasks.append(asyncio.coroutine(lambda: None)() if False else _noop())

    if has_audio:
        from warden.audio_guard import check_audio_b64  # noqa: PLC0415
        tasks.append(check_audio_b64(audio_b64, semantic_guard))
    else:
        tasks.append(_noop())

    image_result, audio_result = await asyncio.gather(*tasks, return_exceptions=True)

    # ── Image result ──────────────────────────────────────────────────────────
    img_risk  = RiskLevel.LOW
    pii_found = False
    if has_image and not isinstance(image_result, Exception):
        img_risk  = _image_risk(image_result)
        pii_found = getattr(image_result, "is_pii", False)
        modalities["image"] = {
            "risk":            img_risk.value,
            "jailbreak_score": getattr(image_result, "jailbreak_score", 0.0),
            "pii_score":       getattr(image_result, "pii_score", 0.0),
            "elapsed_ms":      getattr(image_result, "elapsed_ms", 0.0),
            "error":           getattr(image_result, "error", ""),
        }
        if getattr(image_result, "is_jailbreak", False):
            all_flags.append(SemanticFlag(
                flag   = FlagType.VISUAL_JAILBREAK,
                score  = getattr(image_result, "jailbreak_score", 1.0),
                detail = "Visual jailbreak pattern detected by CLIP image analysis.",
            ))
        if pii_found:
            all_flags.append(SemanticFlag(
                flag   = FlagType.PII_DETECTED,
                score  = getattr(image_result, "pii_score", 0.8),
                detail = "PII detected in image (passport/ID/card) — GDPR: image not forwarded.",
            ))

    # ── Image PII redaction (v1.5) ────────────────────────────────────────────
    redacted_image_b64: str | None = None
    if has_image and pii_found and redact_pii and not isinstance(image_result, Exception):
        try:
            from warden.image_redactor import redact_image_b64 as _redact_b64  # noqa: PLC0415
            redacted_image_b64, _rr = await _redact_b64(image_b64, is_pii=True)
            modalities["image"]["redaction"] = {
                "regions_blurred": len(_rr.regions_blurred),
                "faces_found":     _rr.faces_found,
                "elapsed_ms":      _rr.elapsed_ms,
                "error":           _rr.error,
            }
            log.info(
                "ImageRedactor: %d region(s) blurred faces=%d elapsed=%.1fms",
                len(_rr.regions_blurred), _rr.faces_found, _rr.elapsed_ms,
            )
        except Exception as _re:
            log.debug("ImageRedactor: skipped (non-fatal): %s", _re)

    # ── Audio result ──────────────────────────────────────────────────────────
    aud_risk = RiskLevel.LOW
    if has_audio and not isinstance(audio_result, Exception):
        aud_risk = _audio_risk(audio_result)
        modalities["audio"] = {
            "risk":               aud_risk.value,
            "transcript":         getattr(audio_result, "transcript", ""),
            "ultrasound":         getattr(audio_result, "ultrasound_detected", False),
            "ultrasound_energy":  getattr(audio_result, "ultrasound_energy", 0.0),
            "elapsed_ms":         getattr(audio_result, "elapsed_ms", 0.0),
            "error":              getattr(audio_result, "error", ""),
        }
        if getattr(audio_result, "is_injection", False):
            all_flags.append(SemanticFlag(
                flag   = FlagType.AUDIO_INJECTION,
                score  = 1.0 if getattr(audio_result, "ultrasound_detected", False) else 0.85,
                detail = (
                    "Ultrasound command detected (inaudible frequency band)."
                    if getattr(audio_result, "ultrasound_detected", False)
                    else f"Audio injection in transcript: {getattr(audio_result, 'transcript', '')[:100]!r}"
                ),
            ))

    # ── Synthesis proxy (v1.5) ───────────────────────────────────────────────
    # Trigger: PII found + NOT a jailbreak + caller opts in via synthesize_proxy=True
    # Result: safe text description replaces image in downstream LLM context.
    image_description: str | None = None
    if (
        has_image
        and synthesize_proxy
        and pii_found
        and not getattr(image_result, "is_jailbreak", False)
        and not isinstance(image_result, Exception)
    ):
        try:
            from warden.image_synth import synthesize_b64 as _synth  # noqa: PLC0415
            synth_result = await _synth(image_b64)
            image_description = synth_result.description
            modalities["image"]["synthesis"] = {
                "scene":       synth_result.scene,
                "people":      synth_result.people,
                "sensitivity": synth_result.sensitivity,
                "elapsed_ms":  synth_result.elapsed_ms,
                "error":       synth_result.error,
            }
            log.info(
                "ImageSynth: description generated scene=%r people=%r elapsed=%.1fms",
                synth_result.scene, synth_result.people, synth_result.elapsed_ms,
            )
        except Exception as _se:
            log.debug("ImageSynth: skipped (non-fatal): %s", _se)

    # ── Audio redaction (v1.5) ────────────────────────────────────────────────
    redacted_audio_b64: str | None = None
    if (
        has_audio
        and redact_audio
        and not isinstance(audio_result, Exception)
        and audio_result is not None
        and (
            getattr(audio_result, "is_injection", False)
            or getattr(audio_result, "ultrasound_detected", False)
        )
    ):
        try:
            from warden.audio_redactor import redact_audio_b64 as _redact_aud  # noqa: PLC0415
            redacted_audio_b64, _ar = await _redact_aud(audio_b64, audio_result)
            modalities["audio"]["redaction"] = {
                "segments_bleeped":    len(_ar.segments_bleeped),
                "ultrasound_filtered": _ar.ultrasound_filtered,
                "elapsed_ms":          _ar.elapsed_ms,
                "error":               _ar.error,
            }
            log.info(
                "AudioRedactor: %d segment(s) bleeped ultrasound_filtered=%s elapsed=%.1fms",
                len(_ar.segments_bleeped), _ar.ultrasound_filtered, _ar.elapsed_ms,
            )
        except Exception as _are:
            log.debug("AudioRedactor: skipped (non-fatal): %s", _are)

    # ── Unified risk ──────────────────────────────────────────────────────────
    final_risk = _max_risk(text_risk, img_risk, aud_risk)
    if strict and final_risk == RiskLevel.MEDIUM:
        final_risk = RiskLevel.HIGH
    allowed = final_risk not in (RiskLevel.HIGH, RiskLevel.BLOCK)

    elapsed = round((time.time() - t0) * 1000, 2)
    modalities["unified"] = {"risk": final_risk.value, "allowed": allowed}

    log.info(
        "MultimodalPipeline: text=%s image=%s audio=%s → unified=%s allowed=%s elapsed=%.1fms",
        text_risk.value, img_risk.value, aud_risk.value,
        final_risk.value, allowed, elapsed,
    )

    return MultimodalResult(
        risk_level         = final_risk,
        allowed            = allowed,
        flags              = all_flags,
        modalities         = modalities,
        processing_ms      = {"multimodal_total": elapsed},
        pii_redacted       = pii_found,
        redacted_image_b64 = redacted_image_b64,
        redacted_audio_b64 = redacted_audio_b64,
        image_description  = image_description,
    )


async def _noop():
    """Placeholder for missing modality."""
    return None
