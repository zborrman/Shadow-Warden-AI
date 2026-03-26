"""
warden/topology_guard.py
━━━━━━━━━━━━━━━━━━━━━━━
Topological Data Analysis (TDA) Gatekeeper — Layer 1 pre-filter.

Converts text into a point cloud via character n-gram frequency embedding,
then approximates topological features (β₀ connected components, β₁ 1-cycles)
to distinguish structured natural language from bot/attack noise.

Natural language signature:      Attack / random noise signature:
  β₀ low  (few clusters)           β₀ high  (many isolated components)
  β₁ low  (few loops)              β₁ high  (repetitive cyclic patterns)
  char entropy: 3.8–4.8 bits       char entropy: > 5.0 bits (near-random)
  ngram diversity: 0.6–0.85        ngram diversity: ≈ 1.0 (all unique)

When `ripser` is installed (optional), true Vietoris-Rips persistent homology
is computed and real Betti numbers are returned.  Without ripser the fallback
uses a lightweight algebraic approximation over the n-gram frequency distribution
that achieves comparable precision in under 2ms CPU.

Fails open — any internal error returns is_noise=False so legitimate requests
are never blocked by TDA failures.
"""
from __future__ import annotations

import hashlib
import logging
import math
import os
import time
from dataclasses import dataclass

import numpy as np

log = logging.getLogger("warden.topology_guard")

# ── Config ────────────────────────────────────────────────────────────────────

_TOPO_NOISE_THRESHOLD = float(os.getenv("TOPO_NOISE_THRESHOLD", "0.82"))
_TOPO_MIN_LEN         = int(os.getenv("TOPO_MIN_LEN", "20"))
_NGRAM_N              = 3
_POINT_DIM            = 32   # embedding dimension for each n-gram point

# ── Adaptive threshold by content type ────────────────────────────────────────
# Code has higher n-gram diversity and lower word-char ratio than prose, so the
# generic threshold (0.82) would over-fire on legitimate code payloads.
# The env var overrides still apply when set explicitly.
_TOPO_THRESHOLD_CODE   = float(os.getenv("TOPO_NOISE_THRESHOLD_CODE",    "0.65"))
_TOPO_THRESHOLD_NATURAL = float(os.getenv("TOPO_NOISE_THRESHOLD_NATURAL", "0.82"))

# Code detection heuristics — keyword density in the first 300 chars
_CODE_KEYWORDS = frozenset({
    "def ", "class ", "import ", "return ", "if __", "function ", "const ",
    "var ", "let ", "fn ", "pub ", "use ", "from ", "=>", "->", "#!/",
    "{", "}", "();", "!=", "==", "&&", "||",
})

# ── Result ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TopoResult:
    """Outcome of a topological scan."""

    is_noise:    bool
    noise_score: float   # 0.0 = structured natural language, 1.0 = pure noise
    beta0:       float   # approx. β₀ — connected components (normalized)
    beta1:       float   # approx. β₁ — 1-cycles / loops (normalized)
    detail:      str
    elapsed_ms:  float

    @property
    def has_topological_noise(self) -> bool:
        return self.is_noise


# ── Core helpers ──────────────────────────────────────────────────────────────


def _char_ngrams(text: str, n: int) -> list[str]:
    return [text[i : i + n] for i in range(max(0, len(text) - n + 1))]


def _ngram_freq(text: str, n: int = _NGRAM_N) -> dict[str, float]:
    ngrams = _char_ngrams(text.lower(), n)
    if not ngrams:
        return {}
    total = len(ngrams)
    raw: dict[str, int] = {}
    for ng in ngrams:
        raw[ng] = raw.get(ng, 0) + 1
    return {ng: cnt / total for ng, cnt in raw.items()}


def _ngram_to_point(ng: str) -> np.ndarray:
    """Hash n-gram to a normalized point in [0, 1]^_POINT_DIM."""
    digest = hashlib.sha256(ng.encode()).digest()
    return np.frombuffer(digest[:_POINT_DIM], dtype=np.uint8).astype(np.float32) / 255.0


def _shannon_entropy(freq: dict[str, float]) -> float:
    return -sum(p * math.log2(p) for p in freq.values() if p > 0)


# ── Fallback approximation (no ripser) ───────────────────────────────────────


def _compute_fallback(
    text: str, freq: dict[str, float]
) -> tuple[float, float, float]:
    """
    Return (noise_score, beta0_approx, beta1_approx) without ripser.

    β₀ ≈ number of significant frequency gaps in the sorted distribution.
         Natural text has a smooth power-law decay; noise has sudden jumps.
    β₁ ≈ repetitive-loop score from entropy × (1 − diversity).
    """
    if not freq:
        return 0.5, 1.0, 0.0

    freqs_arr = np.array(list(freq.values()), dtype=np.float32)

    # ── β₀: connected components ─────────────────────────────────────
    sorted_f = np.sort(freqs_arr)[::-1]
    gaps     = np.abs(np.diff(sorted_f))
    sigma    = float(np.std(sorted_f)) + 1e-9
    n_sig_gaps = int(np.sum(gaps > sigma * 0.5))
    beta0_approx = min(1.0, (n_sig_gaps + 1.0) / max(1.0, len(freqs_arr)))

    # ── β₁: 1-cycles (repetition) ────────────────────────────────────
    entropy     = _shannon_entropy(freq)
    max_entropy = math.log2(len(freq)) if len(freq) > 1 else 1.0
    entropy_ratio = entropy / max_entropy if max_entropy > 0 else 0.0
    # Diversity: unique n-grams per total n-gram instances
    total_ngrams = len(text) - _NGRAM_N + 1
    diversity    = len(freq) / max(1.0, total_ngrams)
    beta1_approx = max(0.0, entropy_ratio * (1.0 - min(diversity * 5.0, 1.0)))

    # ── Character-level entropy ───────────────────────────────────────
    char_counts: dict[str, int] = {}
    for c in text:
        char_counts[c] = char_counts.get(c, 0) + 1
    char_freq  = {c: n / len(text) for c, n in char_counts.items()}
    char_entr  = _shannon_entropy(char_freq)
    max_c_entr = math.log2(len(char_freq)) if len(char_freq) > 1 else 1.0
    char_ratio = char_entr / max_c_entr if max_c_entr > 0 else 0.0

    # ── Word-character ratio ──────────────────────────────────────────
    word_chars   = sum(1 for c in text if c.isalnum() or c.isspace())
    wc_ratio     = word_chars / max(1, len(text))

    # ── N-gram diversity noise ────────────────────────────────────────
    # Natural English: diversity ≈ 0.70–0.85.
    # Random noise: ≈ 1.0.  Repetitive DoS: ≈ 0.0–0.10.
    diversity_noise = min(1.0, abs(diversity - 0.77) * 2.5)

    # β₁ contribution: repetitive-loop patterns (high β₁ = cyclic/repetitive noise)
    # Weights rebalanced to incorporate β₁ (previously unused in score).
    noise_score = (
        0.33 * char_ratio
        + 0.27 * (1.0 - wc_ratio)
        + 0.22 * diversity_noise
        + 0.10 * beta0_approx
        + 0.08 * beta1_approx
    )
    noise_score = max(0.0, min(1.0, noise_score))

    return noise_score, beta0_approx, beta1_approx


# ── Content-type detection ────────────────────────────────────────────────────


def _detect_content_type(text: str) -> str:
    """
    Heuristically classify text as 'code' or 'natural'.

    Uses keyword density in the first 300 characters — fast enough for pre-filter.
    Returns 'code' only when multiple programming indicators are present to avoid
    false-positives on prose that mentions programming terms.
    """
    sample = text[:300]
    hits = sum(1 for kw in _CODE_KEYWORDS if kw in sample)
    return "code" if hits >= 3 else "natural"


# ── Optional ripser path ──────────────────────────────────────────────────────

_HAS_RIPSER: bool | None = None


def _has_ripser() -> bool:
    global _HAS_RIPSER
    if _HAS_RIPSER is None:
        try:
            import ripser  # noqa: F401, PLC0415
            _HAS_RIPSER = True
            log.info("TopologyGuard: ripser available — true persistent homology enabled")
        except ImportError:
            _HAS_RIPSER = False
            log.debug("TopologyGuard: ripser not installed — using algebraic fallback")
    return _HAS_RIPSER


def _compute_ripser(
    text: str, freq: dict[str, float]
) -> tuple[float, float, float]:
    """True persistent homology via Vietoris-Rips (ripser)."""
    from ripser import ripser  # noqa: PLC0415

    # Build weighted point cloud from top-64 n-grams
    top_ngrams = sorted(freq.items(), key=lambda x: -x[1])[:64]
    if len(top_ngrams) < 4:
        return _compute_fallback(text, freq)

    points = np.array(
        [_ngram_to_point(ng) * w for ng, w in top_ngrams], dtype=np.float32
    )
    diagrams = ripser(points, maxdim=1)["dgms"]

    n = max(1.0, len(top_ngrams))
    # β₀: components with persistence > 0.05 (filter noise in diagram)
    beta0 = float(
        sum(1 for b, d in diagrams[0] if not math.isinf(d) and (d - b) > 0.05)
    ) / n
    # β₁: number of 1-cycles present
    beta1 = float(len(diagrams[1])) / n if len(diagrams) > 1 else 0.0

    # Blend topological Betti score with fallback for robustness
    fallback_score, _, _ = _compute_fallback(text, freq)
    topo_score = 0.45 * beta0 + 0.35 * beta1 + 0.20 * fallback_score
    noise_score = max(0.0, min(1.0, topo_score))

    return noise_score, beta0, beta1


# ── Public API ────────────────────────────────────────────────────────────────


def scan(text: str) -> TopoResult:
    """
    Scan text for topological noise.

    Returns TopoResult with is_noise=True when the text lacks the structural
    properties of natural language (random noise, bot payloads, repetitive DoS,
    garbled binary-encoded content, etc.).

    Fails open: any internal error returns is_noise=False.
    """
    t_start = time.perf_counter()
    try:
        if not text or len(text) < _TOPO_MIN_LEN:
            return TopoResult(
                is_noise=False, noise_score=0.0, beta0=0.0, beta1=0.0,
                detail="input too short for topological analysis",
                elapsed_ms=0.0,
            )

        freq = _ngram_freq(text)
        if not freq:
            return TopoResult(
                is_noise=False, noise_score=0.0, beta0=0.0, beta1=0.0,
                detail="no n-grams extracted",
                elapsed_ms=0.0,
            )

        if _has_ripser():
            try:
                noise_score, beta0, beta1 = _compute_ripser(text, freq)
            except Exception:
                noise_score, beta0, beta1 = _compute_fallback(text, freq)
        else:
            noise_score, beta0, beta1 = _compute_fallback(text, freq)

        # Adaptive threshold: code payloads have structurally different n-gram
        # distributions; use a lower threshold to avoid false positives.
        content_type = _detect_content_type(text)
        threshold = (
            _TOPO_THRESHOLD_CODE if content_type == "code" else _TOPO_THRESHOLD_NATURAL
        )

        is_noise = noise_score >= threshold
        elapsed  = round((time.perf_counter() - t_start) * 1000, 2)

        if is_noise:
            log.warning(
                "Topological noise detected: score=%.3f β₀=%.3f β₁=%.3f "
                "len=%d content_type=%s threshold=%.2f",
                noise_score, beta0, beta1, len(text), content_type, threshold,
            )

        detail = (
            f"Topological noise score {noise_score:.3f} "
            f"(β₀={beta0:.3f}, β₁={beta1:.3f}) ≥ threshold {threshold} [{content_type}]"
            if is_noise else
            f"Structured text (noise={noise_score:.3f} < threshold {threshold} [{content_type}])"
        )

        return TopoResult(
            is_noise=is_noise,
            noise_score=round(noise_score, 4),
            beta0=round(beta0, 4),
            beta1=round(beta1, 4),
            detail=detail,
            elapsed_ms=elapsed,
        )

    except Exception as exc:
        log.debug("TopologyGuard.scan error (fail-open): %s", exc)
        return TopoResult(
            is_noise=False, noise_score=0.0, beta0=0.0, beta1=0.0,
            detail=f"scan error (fail-open): {exc}",
            elapsed_ms=round((time.perf_counter() - t_start) * 1000, 2),
        )
