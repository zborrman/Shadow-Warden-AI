"""
warden/image_synth.py
━━━━━━━━━━━━━━━━━━━━
Synthesis Proxy — Step 3 of v1.5 Redaction & Content Synthesis.

When ImageGuard flags MEDIUM risk (PII detected, no jailbreak), the image MUST NOT
be forwarded to the LLM.  This module generates a safe natural-language description
of the image instead, so the LLM still receives useful context without seeing PII.

The client uses `image_description` in place of the image bytes in its LLM prompt.

How it works
────────────
  Reuses the already-loaded CLIP-ViT-B/32 model from warden/image_guard.py
  (no second model download — same @lru_cache singleton).

  Three label sets are scored in a single CLIP forward pass:
    • Scene type  (10 labels) — outdoor / indoor / document / screen / …
    • People      (6 labels)  — none / one / group / child / …
    • Sensitivity (8 labels)  — general / ID doc / financial / medical / …

  Top label per category (above a confidence threshold) is assembled into a
  sentence like:
    "Safe image description (PII redacted): An indoor scene. One person visible.
     An identity document such as passport or ID card detected.
     [Original image not forwarded to AI model — GDPR Art. 25.]"

  If CLIP inference fails or times out, a conservative fallback string is returned.

Trigger condition
──────────────────
  synthesize_proxy=True in MultimodalRequest
  AND image_guard_result.is_pii = True
  AND image_guard_result.is_jailbreak = False  (jailbreak → block, no description needed)

Performance
────────────
  Single CLIP forward pass, 24 labels total: ~40–80 ms on CPU.
  Hard timeout: IMAGE_SYNTH_TIMEOUT_MS=2000 (fail-open → returns fallback string).

Environment variables
─────────────────────
  IMAGE_SYNTH_ENABLED        "false" to disable (default: true)
  IMAGE_SYNTH_TIMEOUT_MS     Hard timeout in ms (default: 2000)
  IMAGE_SYNTH_MIN_CONFIDENCE Minimum softmax score to include a label (default: 0.15)
"""
from __future__ import annotations

import asyncio
import io
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

log = logging.getLogger("warden.image_synth")

# ── Config ────────────────────────────────────────────────────────────────────

ENABLED:        bool  = os.getenv("IMAGE_SYNTH_ENABLED",  "true").lower() != "false"
TIMEOUT_MS:     int   = int(os.getenv("IMAGE_SYNTH_TIMEOUT_MS", "2000"))
MIN_CONFIDENCE: float = float(os.getenv("IMAGE_SYNTH_MIN_CONFIDENCE", "0.15"))

_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="img-synth")

# ── Label sets for zero-shot CLIP classification ──────────────────────────────
# All 24 labels are scored in a single forward pass — no extra latency.

_SCENE_LABELS = [
    "an outdoor scene",
    "an indoor scene",
    "an office or workplace",
    "a street or public space",
    "a document or form",
    "a web page or computer screen",
    "a natural landscape",
    "a medical or healthcare setting",
    "a vehicle or transportation",
    "a shopping or retail environment",
]

_PEOPLE_LABELS = [
    "no people in the image",
    "one person visible",
    "two people visible",
    "a small group of people",
    "a large crowd of people",
    "a child or infant",
]

_SENSITIVITY_LABELS = [
    "general everyday content",
    "an identity document such as passport or ID card",
    "a financial document such as bank statement or credit card",
    "a medical record or prescription",
    "a personal photograph or portrait",
    "a business or corporate document",
    "a handwritten note or letter",
    "a product or retail item",
]

_ALL_LABELS  = _SCENE_LABELS + _PEOPLE_LABELS + _SENSITIVITY_LABELS
_N_SCENE     = len(_SCENE_LABELS)
_N_PEOPLE    = len(_PEOPLE_LABELS)
_N_SENSITIVE = len(_SENSITIVITY_LABELS)

_FALLBACK = (
    "Safe image description (PII redacted): Image content could not be analysed. "
    "Original image not forwarded to AI model — GDPR Art. 25."
)


# ── Result ────────────────────────────────────────────────────────────────────

@dataclass
class SynthResult:
    description: str   = ""
    scene:       str   = ""
    people:      str   = ""
    sensitivity: str   = ""
    elapsed_ms:  float = 0.0
    error:       str   = ""


# ── Core classification (synchronous — runs in executor) ──────────────────────

def _classify_sync(image_bytes: bytes) -> SynthResult:
    t0 = time.time()
    try:
        from PIL import Image  # noqa: PLC0415

        from warden.image_guard import _load_model  # noqa: PLC0415

        model, processor = _load_model()
        pil_image = Image.open(io.BytesIO(image_bytes)).convert("RGB")

        import torch  # noqa: PLC0415

        inputs = processor(
            text   = _ALL_LABELS,
            images = pil_image,
            return_tensors = "pt",
            padding        = True,
        )
        with torch.no_grad():
            outputs = model(**inputs)
            probs   = outputs.logits_per_image.softmax(dim=1)[0].tolist()

        # ── Split probabilities per category ──────────────────────────────
        scene_probs = probs[:_N_SCENE]
        people_probs = probs[_N_SCENE:_N_SCENE + _N_PEOPLE]
        sens_probs  = probs[_N_SCENE + _N_PEOPLE:]

        def _top(labels, p_list):
            best_i = max(range(len(p_list)), key=lambda i: p_list[i])
            score  = p_list[best_i]
            return labels[best_i] if score >= MIN_CONFIDENCE else ""

        scene   = _top(_SCENE_LABELS,       scene_probs)
        people  = _top(_PEOPLE_LABELS,      people_probs)
        sens    = _top(_SENSITIVITY_LABELS, sens_probs)

        # ── Build natural-language description ────────────────────────────
        parts = ["Safe image description (PII redacted):"]
        if scene:
            # Capitalise first letter
            parts.append(scene[0].upper() + scene[1:] + ".")
        if people and people != "no people in the image":
            parts.append(people[0].upper() + people[1:] + ".")
        if sens and sens != "general everyday content":
            parts.append(sens[0].upper() + sens[1:] + " detected.")
        parts.append(
            "[Original image not forwarded to AI model — GDPR Art. 25 data minimisation.]"
        )
        description = " ".join(parts)

        elapsed = round((time.time() - t0) * 1000, 2)
        log.info(
            "ImageSynth: scene=%r people=%r sensitivity=%r elapsed=%.1fms",
            scene, people, sens, elapsed,
        )
        return SynthResult(
            description = description,
            scene       = scene,
            people      = people,
            sensitivity = sens,
            elapsed_ms  = elapsed,
        )

    except ImportError as exc:
        log.warning("ImageSynth: missing dependency (%s) — using fallback", exc)
        return SynthResult(
            description = _FALLBACK,
            error       = str(exc),
            elapsed_ms  = round((time.time() - t0) * 1000, 2),
        )
    except Exception as exc:
        log.warning("ImageSynth: classification error — using fallback: %s", exc)
        return SynthResult(
            description = _FALLBACK,
            error       = str(exc),
            elapsed_ms  = round((time.time() - t0) * 1000, 2),
        )


# ── Public API ────────────────────────────────────────────────────────────────

async def synthesize(image_bytes: bytes) -> SynthResult:
    """
    Generate a safe natural-language description of an image using CLIP.

    Reuses the CLIP model already loaded by ImageGuard — no extra download.
    Fail-open: on timeout or error, returns a conservative fallback string.

    Args:
        image_bytes: Raw image bytes (PNG/JPEG/WebP).

    Returns SynthResult with .description ready to inject into LLM context.
    """
    if not ENABLED:
        return SynthResult(description=_FALLBACK, error="disabled")

    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(_executor, _classify_sync, image_bytes),
            timeout=TIMEOUT_MS / 1000,
        )
    except TimeoutError:
        log.warning("ImageSynth: timed out after %d ms — using fallback", TIMEOUT_MS)
        return SynthResult(
            description = _FALLBACK,
            error       = "timeout",
            elapsed_ms  = float(TIMEOUT_MS),
        )


async def synthesize_b64(b64_string: str) -> SynthResult:
    """Convenience wrapper: decode base64 image then synthesize description."""
    import base64  # noqa: PLC0415
    try:
        image_bytes = base64.b64decode(b64_string)
    except Exception as exc:
        return SynthResult(
            description = _FALLBACK,
            error       = f"base64_decode_error: {exc}",
        )
    return await synthesize(image_bytes)
