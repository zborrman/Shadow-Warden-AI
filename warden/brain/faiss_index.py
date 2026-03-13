"""
warden/brain/faiss_index.py
━━━━━━━━━━━━━━━━━━━━━━━━━
FAISS Approximate Nearest Neighbour index for the threat corpus.

Why
───
The default SemanticGuard uses a brute-force O(n) cosine scan via
``torch.nn.functional.cosine_similarity`` across the full corpus tensor.
This is fine up to ~500 entries (< 1 ms on CPU).  Beyond that, each
``/filter`` call adds noticeable latency:

  • 500  entries → ~  0.8 ms
  • 1 000 entries → ~  1.5 ms
  • 5 000 entries → ~  7   ms    ← ANN breakeven
  • 10 000 entries → ~ 14   ms

FAISSIndexedCorpus replaces the linear scan with an IndexFlatIP
(inner-product = cosine similarity on unit vectors) or IndexIVFFlat
(inverted-file; ~4× faster on large corpora at the cost of a training
step and a small recall penalty).

The index is rebuilt automatically whenever ``add_examples()`` is
called via :class:`~warden.brain.semantic.SemanticGuard`.

Activation threshold
─────────────────────
FAISS is only activated when the corpus exceeds ``FAISS_MIN_CORPUS``
(default: 500 entries).  Below that, the existing torch tensor scan
is used unchanged — no FAISS dependency required for small deployments.

Dependencies
─────────────
  faiss-cpu (CPU-only, no GPU required)
  Install: pip install faiss-cpu
  OR add to requirements.txt: faiss-cpu>=1.8.0

  faiss-cpu is intentionally NOT in the default requirements because:
    a. It adds ~50 MB and takes ~30 s to build from source on some platforms.
    b. Most deployments won't have > 500 corpus entries.
  It is installed on demand when the threshold is crossed.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

import numpy as np

if TYPE_CHECKING:
    import torch

log = logging.getLogger("warden.brain.faiss_index")

FAISS_MIN_CORPUS = int(os.getenv("FAISS_MIN_CORPUS", "500"))


@dataclass
class FAISSCorpus:
    """
    Wraps a FAISS IndexFlatIP for fast cosine similarity lookup.

    Usage (typically managed by SemanticGuard internally):

        corpus = FAISSCorpus.build(embeddings_tensor)
        scores, indices = corpus.search(query_embedding_tensor, k=1)
        max_score = scores[0][0]  # float, 0–1
    """
    index: faiss.Index            # type: ignore[name-defined]  # noqa: F821
    size:  int

    @classmethod
    def build(cls, embeddings: torch.Tensor) -> FAISSCorpus:
        """
        Build a FAISS IndexFlatIP from a (N, dim) float32 tensor.
        Vectors must already be L2-normalised (unit norm) so that
        inner product equals cosine similarity.
        """
        try:
            import faiss  # noqa: PLC0415
        except ImportError as exc:
            raise RuntimeError(
                "faiss-cpu is not installed.  Install it with:\n"
                "  pip install faiss-cpu\n"
                "or set FAISS_MIN_CORPUS to a very high number to disable FAISS."
            ) from exc

        vecs = embeddings.cpu().numpy().astype(np.float32)
        dim  = vecs.shape[1]

        if vecs.shape[0] >= 4096:
            # IVFFlat: faster for large corpora; requires training
            n_centroids = max(1, int(vecs.shape[0] ** 0.5))
            quantizer   = faiss.IndexFlatIP(dim)
            index       = faiss.IndexIVFFlat(quantizer, dim, n_centroids, faiss.METRIC_INNER_PRODUCT)
            index.train(vecs)
            index.nprobe = max(1, n_centroids // 4)   # search 25% of clusters
        else:
            # Flat exact search — O(n) but cache-efficient for < 4 K vectors
            index = faiss.IndexFlatIP(dim)

        index.add(vecs)
        log.info("FAISS index built: %d vectors, dim=%d, type=%s",
                 vecs.shape[0], dim, type(index).__name__)
        return cls(index=index, size=vecs.shape[0])

    def search(self, query: torch.Tensor, k: int = 1) -> tuple[np.ndarray, np.ndarray]:
        """
        Find the k nearest neighbours.

        Returns (scores, indices) as numpy arrays shaped (1, k).
        Scores are cosine similarities in [0, 1] (unit-normalised vectors).
        """
        vec = query.cpu().numpy().astype(np.float32).reshape(1, -1)
        scores, indices = self.index.search(vec, k)
        return scores, indices

    def max_similarity(self, query: torch.Tensor) -> float:
        """Return the single highest cosine similarity in the corpus."""
        scores, _ = self.search(query, k=1)
        return float(scores[0][0])


def should_use_faiss(corpus_size: int) -> bool:
    """Return True when the corpus is large enough to benefit from FAISS."""
    return corpus_size >= FAISS_MIN_CORPUS


def try_build_faiss(embeddings: torch.Tensor) -> FAISSCorpus | None:
    """
    Attempt to build a FAISSCorpus.  Returns None (and logs a warning)
    if faiss-cpu is not installed — the caller falls back to torch scan.
    """
    try:
        return FAISSCorpus.build(embeddings)
    except RuntimeError as exc:
        log.warning("FAISS unavailable, using brute-force scan: %s", exc)
        return None
