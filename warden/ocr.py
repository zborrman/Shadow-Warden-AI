"""
warden/ocr.py
━━━━━━━━━━━━
OCR pre-check for multimodal prompt injection via screenshots.

Screenshots passed to Claude Vision (e.g. visual_diff tool) may contain
text-based prompt injection instructions that bypass all nine text-filter
layers. This module extracts visible text from a base64-encoded image before
it reaches Vision, allowing the full Warden pipeline to inspect it.

Backend selection (WARDEN_OCR_BACKEND env var):
  "tesseract"  — pytesseract (default, local, zero external calls)
  "vision"     — Claude Haiku vision (fallback when tesseract unavailable)
  "disabled"   — skip OCR entirely (not recommended)

If the selected backend fails at runtime, the module falls back silently to
the next option and logs a warning — never raising, so the caller's flow
is not interrupted.
"""
from __future__ import annotations

import base64
import logging
import os

log = logging.getLogger("warden.ocr")

_BACKEND = os.getenv("WARDEN_OCR_BACKEND", "tesseract").lower()

# Maximum image bytes to feed into OCR (5 MB). Larger images are skipped.
_MAX_IMAGE_BYTES = 5 * 1024 * 1024

# Maximum characters to return from OCR (downstream filter caps at 2 000 anyway).
_MAX_OCR_CHARS = 4_000

# Claude Haiku model used for Vision fallback — cheapest multimodal model.
_VISION_MODEL = "claude-haiku-4-5-20251001"
_VISION_PROMPT = (
    "Extract only the visible text from this image. "
    "Output the raw text verbatim, with no commentary, formatting, or analysis. "
    "If there is no text, output an empty string."
)


def _ocr_tesseract(image_bytes: bytes) -> str | None:
    """Run pytesseract on raw image bytes. Returns extracted text or None on error."""
    try:
        import io

        import pytesseract  # type: ignore[import-not-found]
        from PIL import Image  # type: ignore[import-not-found]

        img = Image.open(io.BytesIO(image_bytes))
        text: str = pytesseract.image_to_string(img)
        return text.strip()
    except ImportError:
        log.debug("OCR: pytesseract / Pillow not installed — skipping tesseract backend")
        return None
    except Exception as exc:
        log.warning("OCR: tesseract extraction failed — %s", exc)
        return None


def _ocr_vision(image_bytes: bytes, media_type: str = "image/png") -> str | None:
    """Ask Claude Haiku to extract text from the image. Returns text or None on error."""
    try:
        import anthropic

        client = anthropic.Anthropic()
        b64 = base64.b64encode(image_bytes).decode()
        msg = client.messages.create(
            model=_VISION_MODEL,
            max_tokens=1024,
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": media_type,
                                "data": b64,
                            },
                        },
                        {"type": "text", "text": _VISION_PROMPT},
                    ],
                }
            ],
        )
        block = msg.content[0] if msg.content else None
        if block and block.type == "text":
            return block.text.strip()  # type: ignore[union-attr]
        return None
    except ImportError:
        log.debug("OCR: anthropic SDK not available — Vision fallback skipped")
        return None
    except Exception as exc:
        log.warning("OCR: Vision extraction failed — %s", exc)
        return None


def extract_text_from_b64(b64_image: str, media_type: str = "image/png") -> str:
    """
    Extract visible text from a base64-encoded image using the configured backend.

    Returns the extracted text (may be empty string). Never raises — callers
    should treat an empty return as "no text found / OCR unavailable".

    The returned text is safe to pass directly into the Warden filter pipeline.
    """
    if _BACKEND == "disabled":
        return ""

    try:
        image_bytes = base64.b64decode(b64_image)
    except Exception:
        return ""

    if len(image_bytes) > _MAX_IMAGE_BYTES:
        log.debug("OCR: image too large (%d bytes) — skipped", len(image_bytes))
        return ""

    text: str | None = None

    if _BACKEND == "tesseract":
        text = _ocr_tesseract(image_bytes)
        if text is None:
            # Tesseract unavailable — fall through to Vision
            log.info("OCR: tesseract unavailable, falling back to Vision backend")
            text = _ocr_vision(image_bytes, media_type)
    elif _BACKEND == "vision":
        text = _ocr_vision(image_bytes, media_type)
    else:
        log.warning("OCR: unknown backend '%s' — OCR disabled", _BACKEND)
        return ""

    if not text:
        return ""

    return text[:_MAX_OCR_CHARS]
