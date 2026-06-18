"""
warden/multimodal/_coordinator.py
───────────────────────────────────
Multi-Modal Pipeline Coordinator — moved from the legacy warden/multimodal.py
flat module so the warden/multimodal/ package can re-export it cleanly.

Original docstring: orchestrates parallel execution of the text, image, and
audio guard stages, then merges individual risk scores into a unified verdict.
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


@dataclass
class MultimodalResult:
    risk_level:          RiskLevel          = RiskLevel.LOW
    allowed:             bool               = True
    flags:               list[SemanticFlag] = field(default_factory=list)
    modalities:          dict[str, Any]     = field(default_factory=dict)
    processing_ms:       dict[str, float]   = field(default_factory=dict)
    pii_redacted:        bool               = False
    redacted_image_b64:  str | None         = None
    redacted_audio_b64:  str | None         = None
    image_description:   str | None         = None


def _image_risk(image_result: Any) -> RiskLevel:
    if getattr(image_result, "error", None) or not hasattr(image_result, "is_jailbreak"):
        return RiskLevel.LOW
    if image_result.is_jailbreak:
        return RiskLevel.HIGH
    if getattr(image_result, "is_pii", False):
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _audio_risk(audio_result: Any) -> RiskLevel:
    if getattr(audio_result, "error", None) or not hasattr(audio_result, "is_injection"):
        return RiskLevel.LOW
    if audio_result.is_injection or getattr(audio_result, "ultrasound_detected", False):
        return RiskLevel.HIGH
    return RiskLevel.LOW


async def _noop() -> None:
    return None


async def run_multimodal(
    *,
    text_content:    str | None                    = None,
    image_b64:       str | None                    = None,
    audio_b64:       str | None                    = None,
    text_risk:       RiskLevel                     = RiskLevel.LOW,
    text_flags:      list[SemanticFlag] | None     = None,
    semantic_guard:  Any                           = None,
    strict:          bool                          = False,
    redact_pii:      bool                          = True,
    redact_audio:    bool                          = True,
    synthesize_proxy: bool                         = False,
) -> MultimodalResult:
    """Run image + audio guards in parallel, merge with text risk result."""
    t0 = time.time()
    all_flags = list(text_flags or [])
    modalities: dict[str, Any] = {"text": {"risk": text_risk.value}}

    tasks: list[Any] = []
    has_image = bool(image_b64)
    has_audio = bool(audio_b64)

    if has_image:
        from warden.image_guard import check_image_b64  # noqa: PLC0415
        tasks.append(check_image_b64(image_b64))
    else:
        tasks.append(_noop())

    if has_audio:
        from warden.audio_guard import check_audio_b64  # noqa: PLC0415
        tasks.append(check_audio_b64(audio_b64, semantic_guard))
    else:
        tasks.append(_noop())

    image_result, audio_result = await asyncio.gather(*tasks, return_exceptions=True)

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
                detail = "PII detected in image — GDPR: image not forwarded.",
            ))

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
        except Exception as _re:
            log.debug("ImageRedactor: skipped (non-fatal): %s", _re)

    aud_risk = RiskLevel.LOW
    if has_audio and not isinstance(audio_result, Exception):
        aud_risk = _audio_risk(audio_result)
        modalities["audio"] = {
            "risk":              aud_risk.value,
            "transcript":        getattr(audio_result, "transcript", ""),
            "ultrasound":        getattr(audio_result, "ultrasound_detected", False),
            "ultrasound_energy": getattr(audio_result, "ultrasound_energy", 0.0),
            "elapsed_ms":        getattr(audio_result, "elapsed_ms", 0.0),
            "error":             getattr(audio_result, "error", ""),
        }
        if getattr(audio_result, "is_injection", False):
            all_flags.append(SemanticFlag(
                flag   = FlagType.AUDIO_INJECTION,
                score  = 1.0 if getattr(audio_result, "ultrasound_detected", False) else 0.85,
                detail = (
                    "Ultrasound command detected."
                    if getattr(audio_result, "ultrasound_detected", False)
                    else f"Audio injection: {getattr(audio_result, 'transcript', '')[:100]!r}"
                ),
            ))

    image_description: str | None = None
    if (
        has_image and synthesize_proxy and pii_found
        and not getattr(image_result, "is_jailbreak", False)
        and not isinstance(image_result, Exception)
    ):
        try:
            from warden.image_synth import synthesize_b64 as _synth  # noqa: PLC0415
            synth_result = await _synth(image_b64)
            image_description = synth_result.description
        except Exception as _se:
            log.debug("ImageSynth: skipped: %s", _se)

    redacted_audio_b64: str | None = None
    if (
        has_audio and redact_audio
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
        except Exception as _are:
            log.debug("AudioRedactor: skipped: %s", _are)

    final_risk = _max_risk(text_risk, img_risk, aud_risk)
    if strict and final_risk == RiskLevel.MEDIUM:
        final_risk = RiskLevel.HIGH
    allowed = final_risk not in (RiskLevel.HIGH, RiskLevel.BLOCK)

    elapsed = round((time.time() - t0) * 1000, 2)
    modalities["unified"] = {"risk": final_risk.value, "allowed": allowed}

    log.info(
        "MultimodalPipeline: text=%s image=%s audio=%s → unified=%s allowed=%s elapsed=%.1fms",
        text_risk.value, img_risk.value, aud_risk.value, final_risk.value, allowed, elapsed,
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
