"""
warden/image_redactor.py
━━━━━━━━━━━━━━━━━━━━━━━
Image PII Redactor — Step 1 of v1.5 Redaction & Content Synthesis.

Detects and blurs PII-bearing regions before forwarding images to LLMs:
  • Face detection   — OpenCV Haar cascade (haarcascade_frontalface_default.xml)
                       CPU-only, ~2 MB cascade file, ~5–15 ms per frame.
  • Text-dense zones — morphological close + contour analysis to find MRZ strips,
                       credit card number rows, and similar rectangular glyph blocks.
  • Fallback blur    — moderate full-image GaussianBlur when CLIP flagged PII but no
                       specific regions were found (e.g., handwritten doc).
  • EXIF strip       — GPS coords, device IDs, and author fields removed on every pass.

Pipeline
─────────
  image_bytes
    → PIL decode + EXIF strip
    → OpenCV face detection        (Haar cascade)
    → OpenCV text-region detection (morphology + contours, only when is_pii=True)
    → PIL GaussianBlur per region
    → PNG re-encode (no metadata)
    → ImageRedactorResult

Performance targets
────────────────────
  Haar cascade on 640×480: ~5–15 ms on CPU.
  Full pipeline incl. PIL encode: ~20–50 ms.
  Hard timeout: IMAGE_REDACTION_TIMEOUT_MS=500 (fail-open — returns original on timeout).

Environment variables
─────────────────────
  IMAGE_REDACTION_ENABLED       "false" to disable (default: true)
  IMAGE_REDACTION_BLUR_RADIUS   GaussianBlur radius for detected regions (default: 25)
  IMAGE_REDACTION_DOC_BLUR      Detect document text regions (default: true)
  IMAGE_REDACTION_FALLBACK_BLUR Full-image blur fallback when no region found (default: true)
  IMAGE_REDACTION_TIMEOUT_MS    Hard timeout in ms (default: 500)
  IMAGE_MAX_BYTES               Max image bytes — shared with image_guard (default: 10 MB)
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

log = logging.getLogger("warden.image_redactor")

# ── Config ────────────────────────────────────────────────────────────────────

ENABLED:      bool  = os.getenv("IMAGE_REDACTION_ENABLED",  "true").lower() != "false"
BLUR_RADIUS:  int   = int(os.getenv("IMAGE_REDACTION_BLUR_RADIUS", "25"))
DOC_BLUR:     bool  = os.getenv("IMAGE_REDACTION_DOC_BLUR",      "true").lower() != "false"
FALLBACK:     bool  = os.getenv("IMAGE_REDACTION_FALLBACK_BLUR",  "true").lower() != "false"
TIMEOUT_MS:   int   = int(os.getenv("IMAGE_REDACTION_TIMEOUT_MS", "500"))
MAX_BYTES:    int   = int(os.getenv("IMAGE_MAX_BYTES", str(10 * 1024 * 1024)))

_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="img-redact")


# ── Result ────────────────────────────────────────────────────────────────────

@dataclass
class RedactionRegion:
    kind: str    # "face" | "text_dense" | "full_image"
    x:    int = 0
    y:    int = 0
    w:    int = 0
    h:    int = 0


@dataclass
class ImageRedactorResult:
    redacted_bytes:  bytes                  = b""
    regions_blurred: list[RedactionRegion]  = field(default_factory=list)
    faces_found:     int                    = 0
    elapsed_ms:      float                  = 0.0
    error:           str                    = ""


# ── Model singleton ───────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def _load_face_cascade():
    """Load OpenCV Haar cascade once. Raises ImportError if opencv-python-headless missing."""
    import cv2  # noqa: PLC0415
    path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
    cascade = cv2.CascadeClassifier(path)
    if cascade.empty():
        raise RuntimeError(f"Failed to load Haar cascade from {path}")
    log.info("ImageRedactor: Haar cascade loaded.")
    return cascade


def prewarm() -> bool:
    """Pre-load cascade at FastAPI startup. Returns True on success."""
    if not ENABLED:
        return False
    try:
        _load_face_cascade()
        return True
    except Exception as exc:
        log.warning("ImageRedactor: prewarm failed (non-fatal): %s", exc)
        return False


# ── Face detection ────────────────────────────────────────────────────────────

def _detect_faces(np_array) -> list[tuple[int, int, int, int]]:
    """Run Haar cascade on a numpy RGB array. Returns (x, y, w, h) list."""
    import cv2  # noqa: PLC0415

    cascade = _load_face_cascade()
    gray = cv2.cvtColor(np_array, cv2.COLOR_RGB2GRAY)
    gray = cv2.equalizeHist(gray)   # improve detection on dark/bright images
    hits = cascade.detectMultiScale(
        gray,
        scaleFactor  = 1.1,
        minNeighbors = 5,
        minSize      = (30, 30),
        flags        = cv2.CASCADE_SCALE_IMAGE,
    )
    if len(hits) == 0:
        return []
    return [(int(x), int(y), int(w), int(h)) for x, y, w, h in hits]


# ── Document text-region detection ───────────────────────────────────────────

def _detect_text_regions(np_array) -> list[tuple[int, int, int, int]]:
    """
    Find text-dense rectangular zones (MRZ strips, card number rows).

    Strategy: morphological CLOSE with wide horizontal kernel merges adjacent
    character blobs into a solid rectangle; contour filtering keeps only
    wide, shallow bands typical of machine-readable text.
    """
    try:
        import cv2  # noqa: PLC0415

        gray = cv2.cvtColor(np_array, cv2.COLOR_RGB2GRAY)
        _, thresh = cv2.threshold(
            gray, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU
        )
        # Wide horizontal kernel merges glyphs on the same text line
        kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (20, 3))
        closed = cv2.morphologyEx(thresh, cv2.MORPH_CLOSE, kernel)

        contours, _ = cv2.findContours(
            closed, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE
        )

        img_area = np_array.shape[0] * np_array.shape[1]
        regions: list[tuple[int, int, int, int]] = []
        for cnt in contours:
            x, y, w, h = cv2.boundingRect(cnt)
            aspect = w / max(h, 1)
            area   = w * h
            # MRZ / card row: wide aspect ratio, medium absolute size
            if aspect > 4 and (img_area * 0.005) < area < (img_area * 0.30):
                regions.append((x, y, w, h))
        return regions
    except Exception:
        return []


# ── PIL blur application ──────────────────────────────────────────────────────

def _blur_regions(pil_image, boxes: list[tuple[int, int, int, int]], radius: int):
    """Gaussian-blur each (x, y, w, h) box in-place on the PIL image."""
    from PIL import ImageFilter  # noqa: PLC0415

    for (x, y, w, h) in boxes:
        # Add 10 % padding around detected region (catches hair/ears for faces)
        pad = int(min(w, h) * 0.10)
        x1 = max(0, x - pad)
        y1 = max(0, y - pad)
        x2 = min(pil_image.width,  x + w + pad)
        y2 = min(pil_image.height, y + h + pad)
        crop    = pil_image.crop((x1, y1, x2, y2))
        blurred = crop.filter(ImageFilter.GaussianBlur(radius=radius))
        pil_image.paste(blurred, (x1, y1))
    return pil_image


# ── Core redaction (synchronous — runs in ThreadPoolExecutor) ─────────────────

def _redact_sync(image_bytes: bytes, is_pii: bool) -> ImageRedactorResult:
    t0 = time.time()
    try:
        import numpy as np  # noqa: PLC0415
        from PIL import Image, ImageFilter  # noqa: PLC0415

        # ── Decode + EXIF strip ───────────────────────────────────────────
        src = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        # Paste onto a fresh Image to discard all EXIF/metadata
        pil_image = Image.new("RGB", src.size)
        pil_image.paste(src)
        np_array = np.array(pil_image)

        blur_boxes: list[tuple[int, int, int, int]] = []
        regions:    list[RedactionRegion]           = []

        # ── Face detection ────────────────────────────────────────────────
        try:
            for (x, y, w, h) in _detect_faces(np_array):
                blur_boxes.append((x, y, w, h))
                regions.append(RedactionRegion("face", x, y, w, h))
        except Exception as _fe:
            log.debug("ImageRedactor: face detection error: %s", _fe)

        # ── Document text-zone detection (only when CLIP flagged PII) ────
        if is_pii and DOC_BLUR:
            try:
                for (x, y, w, h) in _detect_text_regions(np_array):
                    blur_boxes.append((x, y, w, h))
                    regions.append(RedactionRegion("text_dense", x, y, w, h))
            except Exception as _te:
                log.debug("ImageRedactor: text region detection error: %s", _te)

        # ── Apply region blur ─────────────────────────────────────────────
        if blur_boxes:
            pil_image = _blur_regions(pil_image, blur_boxes, BLUR_RADIUS)
        elif is_pii and FALLBACK:
            # No specific regions found but image is flagged — moderate full blur
            pil_image = pil_image.filter(ImageFilter.GaussianBlur(radius=BLUR_RADIUS // 2))
            regions.append(RedactionRegion(
                "full_image", 0, 0, pil_image.width, pil_image.height
            ))

        # ── Re-encode as PNG (no metadata) ───────────────────────────────
        buf = io.BytesIO()
        pil_image.save(buf, format="PNG", optimize=False)
        redacted_bytes = buf.getvalue()

        elapsed = round((time.time() - t0) * 1000, 2)
        log.info(
            "ImageRedactor: %d region(s) blurred — faces=%d text_dense=%d fallback=%d elapsed=%.1fms",
            len(regions),
            sum(1 for r in regions if r.kind == "face"),
            sum(1 for r in regions if r.kind == "text_dense"),
            sum(1 for r in regions if r.kind == "full_image"),
            elapsed,
        )
        return ImageRedactorResult(
            redacted_bytes  = redacted_bytes,
            regions_blurred = regions,
            faces_found     = sum(1 for r in regions if r.kind == "face"),
            elapsed_ms      = elapsed,
        )

    except ImportError as exc:
        log.warning("ImageRedactor: missing dependency (%s) — returning original", exc)
        return ImageRedactorResult(
            redacted_bytes = image_bytes,
            error          = str(exc),
            elapsed_ms     = round((time.time() - t0) * 1000, 2),
        )
    except Exception as exc:
        log.warning("ImageRedactor: error — returning original: %s", exc)
        return ImageRedactorResult(
            redacted_bytes = image_bytes,
            error          = str(exc),
            elapsed_ms     = round((time.time() - t0) * 1000, 2),
        )


# ── Public API ────────────────────────────────────────────────────────────────

async def redact_image(image_bytes: bytes, is_pii: bool = True) -> ImageRedactorResult:
    """
    Async entry point: blur PII regions in image_bytes.

    Args:
        image_bytes: Raw image bytes (PNG/JPEG/WebP).
        is_pii:      True when ImageGuard already flagged PII — enables document
                     text-zone detection and fallback full-image blur.

    Always returns a valid ImageRedactorResult.  On timeout or error,
    redacted_bytes falls back to the original (fail-open).
    """
    if not ENABLED:
        return ImageRedactorResult(redacted_bytes=image_bytes, error="disabled")
    if len(image_bytes) > MAX_BYTES:
        return ImageRedactorResult(redacted_bytes=image_bytes, error="image_too_large")

    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(_executor, _redact_sync, image_bytes, is_pii),
            timeout=TIMEOUT_MS / 1000,
        )
    except TimeoutError:
        log.warning("ImageRedactor: timed out after %d ms — returning original", TIMEOUT_MS)
        return ImageRedactorResult(
            redacted_bytes = image_bytes,
            error          = "timeout",
            elapsed_ms     = float(TIMEOUT_MS),
        )


async def redact_image_b64(
    b64_string: str,
    is_pii: bool = True,
) -> tuple[str, ImageRedactorResult]:
    """
    Convenience wrapper: decode base64 → redact → re-encode.

    Returns (redacted_b64, result).  On any error returns (original_b64, result).
    """
    try:
        image_bytes = base64.b64decode(b64_string)
    except Exception as exc:
        empty = ImageRedactorResult(
            redacted_bytes = b"",
            error          = f"base64_decode_error: {exc}",
        )
        return b64_string, empty

    result       = await redact_image(image_bytes, is_pii=is_pii)
    redacted_b64 = base64.b64encode(result.redacted_bytes).decode()
    return redacted_b64, result
