"""
warden/image_guard.py
━━━━━━━━━━━━━━━━━━━━
Image Guard — Step 1/2 of v1.4 Multi-Modal Guard.

Detects visual jailbreaks embedded in images:
  • Text-in-image attacks   — "ignore previous instructions" rendered as PNG
  • Adversarial noise       — perturbations designed to override system prompt
  • PII in images           — passport scans, credit card photos (GDPR masking)

Detection method: CLIP-ViT-B/32 zero-shot classification
─────────────────────────────────────────────────────────
CLIP's joint text-image embedding space lets us compare an image against a set
of natural-language "jailbreak" and "safe" prompts without training a separate
classifier.  The jailbreak score is the softmax-normalized similarity of the
image against the jailbreak prompt set vs the safe prompt set.

Why zero-shot first?
  Training a supervised classifier (Step 2) requires a labelled dataset of
  jailbreak images.  Zero-shot gives useful signal immediately and can be
  replaced by a fine-tuned classifier head once the dataset is collected.

Loading
────────
  Model loaded once at startup via @lru_cache singleton.
  All inference runs in a ThreadPoolExecutor (non-blocking, same pattern as
  MiniLM in brain/semantic.py).

Performance targets
────────────────────
  CLIP-ViT-B/32 on CPU: ~60–90 ms per image (224×224).
  IMAGE_PIPELINE_TIMEOUT_MS=100 — hard deadline.  Fail-open on timeout.

Environment variables
─────────────────────
  IMAGE_GUARD_ENABLED         "false" to disable (default: true)
  IMAGE_GUARD_THRESHOLD       Jailbreak score threshold 0–1 (default: 0.28)
  IMAGE_PIPELINE_TIMEOUT_MS   Hard timeout per image (default: 100)
  IMAGE_GUARD_MODEL           CLIP model ID (default: openai/clip-vit-b-32)
  MODEL_CACHE_DIR             Shared model cache dir (default: /warden/models)
  IMAGE_MAX_BYTES             Max image size in bytes (default: 10 MB)
"""
from __future__ import annotations

import asyncio
import base64
import io
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import lru_cache

log = logging.getLogger("warden.image_guard")

# ── Config ────────────────────────────────────────────────────────────────────

ENABLED: bool        = os.getenv("IMAGE_GUARD_ENABLED", "true").lower() != "false"
THRESHOLD: float     = float(os.getenv("IMAGE_GUARD_THRESHOLD", "0.28"))
TIMEOUT_MS: int      = int(os.getenv("IMAGE_PIPELINE_TIMEOUT_MS", "100"))
MODEL_ID: str        = os.getenv("IMAGE_GUARD_MODEL", "openai/clip-vit-b-32")
CACHE_DIR: str       = os.getenv("MODEL_CACHE_DIR", "/warden/models")
MAX_BYTES: int       = int(os.getenv("IMAGE_MAX_BYTES", str(10 * 1024 * 1024)))  # 10 MB

# ── Jailbreak / safe prompt sets for zero-shot CLIP scoring ──────────────────

_JAILBREAK_PROMPTS = [
    "ignore all previous instructions",
    "jailbreak prompt attack",
    "harmful instructions hidden in image",
    "override safety guidelines",
    "disregard system prompt",
    "do anything now DAN mode",
    "text instructing AI to ignore rules",
    "adversarial prompt injection",
    "bypass content filter",
    "forget your instructions",
    # PhishGuard v3 — visual phishing / fake login portals
    "fake login portal with Microsoft logo",
    "phishing page imitating bank website login",
    "spoofed website with password input field",
    "counterfeit PayPal or Apple ID login screen",
    "brand impersonation credential harvesting form",
    "social engineering page requesting username and password",
    "fake security alert requiring immediate action",
    "urgent account verification popup overlay",
]

_SAFE_PROMPTS = [
    "normal photograph",
    "everyday safe image",
    "document with regular text",
    "a clean screenshot",
    "product photo",
    "landscape photography",
    "abstract graphic design",
]

# PII visual patterns — used for GDPR masking detection
_PII_PROMPTS = [
    "passport photograph document",
    "credit card with numbers",
    "national identity card",
    "social security card",
    "bank statement document",
    "medical record document",
    "driver's license photograph",
]

# ── Thread pool for non-blocking inference ────────────────────────────────────

_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="image-guard")


# ── Model singleton ───────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def _load_model():
    """Load CLIP model + processor once.  Raises ImportError if deps missing."""
    from transformers import CLIPModel, CLIPProcessor  # noqa: PLC0415
    t0 = time.time()
    processor = CLIPProcessor.from_pretrained(MODEL_ID, cache_dir=CACHE_DIR)
    model = CLIPModel.from_pretrained(MODEL_ID, cache_dir=CACHE_DIR)
    model.eval()
    log.info(
        "ImageGuard: CLIP model loaded in %.1fs — model=%s threshold=%.2f",
        time.time() - t0, MODEL_ID, THRESHOLD,
    )
    return model, processor


def prewarm() -> bool:
    """Pre-load CLIP model at startup.  Returns True on success."""
    if not ENABLED:
        return False
    try:
        _load_model()
        return True
    except Exception as exc:
        log.warning("ImageGuard: model pre-warm failed (non-fatal): %s", exc)
        return False


# ── Result ────────────────────────────────────────────────────────────────────

@dataclass
class ImageGuardResult:
    is_jailbreak: bool        = False
    jailbreak_score: float    = 0.0
    is_pii: bool              = False
    pii_score: float          = 0.0
    is_phishing_visual: bool  = False   # PhishGuard v3 — fake login portal / brand spoof
    phishing_score: float     = 0.0
    method: str               = "clip_zero_shot"
    elapsed_ms: float         = 0.0
    error: str                = ""


# ── Core inference ────────────────────────────────────────────────────────────

def _run_clip(image_bytes: bytes) -> ImageGuardResult:
    """Run CLIP inference synchronously — call via executor."""
    t0 = time.time()
    try:
        import torch  # noqa: PLC0415
        from PIL import Image  # noqa: PLC0415

        model, processor = _load_model()
        image = Image.open(io.BytesIO(image_bytes)).convert("RGB")

        # PhishGuard v3 — phishing visual prompts are the last 8 entries of
        # _JAILBREAK_PROMPTS (added after the original 10 jailbreak prompts).
        n_orig_jb   = 10   # original jailbreak prompt count
        n_phish_vis = len(_JAILBREAK_PROMPTS) - n_orig_jb

        all_prompts = _JAILBREAK_PROMPTS + _SAFE_PROMPTS + _PII_PROMPTS
        inputs = processor(
            text=all_prompts,
            images=image,
            return_tensors="pt",
            padding=True,
            truncation=True,
        )

        with torch.no_grad():
            outputs = model(**inputs)
            logits = outputs.logits_per_image  # shape: [1, num_prompts]
            probs   = logits.softmax(dim=1)[0].tolist()

        n_jb   = len(_JAILBREAK_PROMPTS)
        n_safe = len(_SAFE_PROMPTS)
        n_pii  = len(_PII_PROMPTS)

        # Original jailbreak prompts (indices 0..n_orig_jb)
        jb_score      = sum(probs[:n_orig_jb])
        # Phishing visual prompts (n_orig_jb..n_jb)
        phish_score   = sum(probs[n_orig_jb:n_jb]) if n_phish_vis > 0 else 0.0
        # PII prompts
        pii_score     = sum(probs[n_jb + n_safe: n_jb + n_safe + n_pii])

        elapsed = (time.time() - t0) * 1000
        return ImageGuardResult(
            is_jailbreak        = jb_score >= THRESHOLD,
            jailbreak_score     = round(jb_score, 4),
            is_pii              = pii_score >= THRESHOLD,
            pii_score           = round(pii_score, 4),
            is_phishing_visual  = phish_score >= THRESHOLD,
            phishing_score      = round(phish_score, 4),
            elapsed_ms          = round(elapsed, 2),
        )

    except ImportError as exc:
        log.warning("ImageGuard: missing dependency (%s) — skipping", exc)
        return ImageGuardResult(error=str(exc), elapsed_ms=(time.time() - t0) * 1000)
    except Exception as exc:
        log.warning("ImageGuard: inference error: %s", exc)
        return ImageGuardResult(error=str(exc), elapsed_ms=(time.time() - t0) * 1000)


# ── Public API ────────────────────────────────────────────────────────────────

async def check_image(image_bytes: bytes) -> ImageGuardResult:
    """
    Async entry point.  Runs CLIP in the thread pool with a hard timeout.

    Returns ImageGuardResult with is_jailbreak=False on timeout or error
    (fail-open — latency guarantee beats security for transient failures;
    the text pipeline still runs in parallel).
    """
    if not ENABLED:
        return ImageGuardResult(method="disabled")

    if len(image_bytes) > MAX_BYTES:
        log.warning("ImageGuard: image too large (%d bytes) — skipping", len(image_bytes))
        return ImageGuardResult(error="image_too_large")

    loop = asyncio.get_running_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(_executor, _run_clip, image_bytes),
            timeout=TIMEOUT_MS / 1000,
        )
    except TimeoutError:
        log.warning(
            "ImageGuard: inference timed out after %d ms — fail-open", TIMEOUT_MS
        )
        result = ImageGuardResult(error="timeout", elapsed_ms=float(TIMEOUT_MS))

    if result.is_jailbreak:
        log.info(
            "ImageGuard: VISUAL_JAILBREAK detected score=%.3f elapsed=%.1fms",
            result.jailbreak_score, result.elapsed_ms,
        )
    if result.is_pii:
        log.info(
            "ImageGuard: PII_IN_IMAGE detected score=%.3f elapsed=%.1fms",
            result.pii_score, result.elapsed_ms,
        )
    if result.is_phishing_visual:
        log.warning(
            "ImageGuard: PHISHING_VISUAL detected score=%.3f elapsed=%.1fms",
            result.phishing_score, result.elapsed_ms,
        )
    return result


async def check_image_b64(b64_string: str) -> ImageGuardResult:
    """Convenience wrapper that decodes a base64 image string first."""
    try:
        image_bytes = base64.b64decode(b64_string)
    except Exception as exc:
        return ImageGuardResult(error=f"base64_decode_error: {exc}")
    return await check_image(image_bytes)
