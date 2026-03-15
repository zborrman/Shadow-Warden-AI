"""
warden/brain/onnx_runner.py
━━━━━━━━━━━━━━━━━━━━━━━━━━
Optional ONNX Runtime inference path for the MiniLM sentence encoder.

Speed improvement: ~2-4x faster on CPU vs. pure PyTorch inference.
Memory improvement: ~40% smaller footprint (no autograd machinery).

When ONNX_MODEL_PATH is set, warden/brain/semantic.py automatically switches
to this backend for both corpus pre-computation and per-request inference.
If unset (default), semantic.py falls back to the standard PyTorch path.

Export your model once::

    python scripts/export_onnx.py

Then in .env::

    ONNX_MODEL_PATH=/warden/models/minilm-onnx

Configuration
─────────────
  ONNX_MODEL_PATH=         path to onnx model dir (empty = disabled)
  ONNX_THREADS=1           inter-op parallelism threads
  ONNX_INTRA_THREADS=4     intra-op threads (set to CPU core count)
"""
from __future__ import annotations

import logging
import os
from functools import lru_cache
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import numpy as np

log = logging.getLogger("warden.brain.onnx_runner")

_ONNX_MODEL_PATH = os.getenv("ONNX_MODEL_PATH", "")
_ONNX_THREADS    = int(os.getenv("ONNX_THREADS",       "1"))
_ONNX_INTRA      = int(os.getenv("ONNX_INTRA_THREADS", "4"))


class OnnxSentenceEncoder:
    """
    Sentence encoder backed by ONNX Runtime.

    Compatible with all-MiniLM-L6-v2 exported via scripts/export_onnx.py.
    Produces L2-normalised float32 embeddings identical to the PyTorch path.

    Usage::

        encoder = OnnxSentenceEncoder.load("/warden/models/minilm-onnx")
        vec = encoder.encode("This is a test sentence.")
        # vec: np.ndarray shape (384,) float32, L2-normalised

        vecs = encoder.encode_batch(["sentence one", "sentence two"])
        # vecs: np.ndarray shape (2, 384) float32, rows L2-normalised
    """

    def __init__(self, session, tokenizer, input_names: set[str]) -> None:
        self._session     = session
        self._tokenizer   = tokenizer
        self._input_names = input_names   # pre-computed set of model input names

    @classmethod
    def load(cls, model_dir: str) -> OnnxSentenceEncoder:
        """Load the ONNX session and tokenizer from *model_dir*."""
        import onnxruntime as ort
        from transformers import AutoTokenizer

        model_path = os.path.join(model_dir, "model.onnx")
        if not os.path.isfile(model_path):
            raise FileNotFoundError(
                f"ONNX model not found at {model_path}. "
                "Run: python scripts/export_onnx.py"
            )

        opts = ort.SessionOptions()
        opts.inter_op_num_threads    = _ONNX_THREADS
        opts.intra_op_num_threads    = _ONNX_INTRA
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL

        session     = ort.InferenceSession(model_path, sess_options=opts)
        tokenizer   = AutoTokenizer.from_pretrained(model_dir)
        input_names = {inp.name for inp in session.get_inputs()}

        log.info(
            "OnnxSentenceEncoder loaded: %s  inputs=%s  threads=%d/%d",
            model_path, input_names, _ONNX_THREADS, _ONNX_INTRA,
        )
        return cls(session, tokenizer, input_names)

    # ── Encoding ──────────────────────────────────────────────────────────────

    def encode(self, text: str) -> np.ndarray:
        """Encode one sentence → (384,) float32, L2-normalised."""
        return self.encode_batch([text])[0]

    def encode_batch(self, texts: list[str]) -> np.ndarray:
        """
        Encode multiple sentences in a single ONNX session.run() call.
        Returns (N, 384) float32 array, each row L2-normalised.

        Using batched tokenisation is ~3× faster than calling encode() N times
        because it avoids N separate ONNX graph executions.
        """
        import numpy as np

        enc = self._tokenizer(
            texts,
            return_tensors="np",
            truncation=True,
            max_length=128,
            padding="max_length",
        )

        feed: dict[str, np.ndarray] = {
            "input_ids":      enc["input_ids"].astype(np.int64),
            "attention_mask": enc["attention_mask"].astype(np.int64),
        }
        if "token_type_ids" in self._input_names:
            feed["token_type_ids"] = enc.get(
                "token_type_ids",
                np.zeros_like(enc["input_ids"]),
            ).astype(np.int64)

        # outputs[0]: (batch, seq_len, 384)  — last_hidden_state
        outputs    = self._session.run(None, feed)
        token_embs = outputs[0].astype(np.float32)           # (B, S, 384)
        mask       = feed["attention_mask"].astype(np.float32)  # (B, S)

        # Mean pooling: sum(token * mask) / sum(mask)  →  (B, 384)
        masked     = token_embs * mask[:, :, None]            # (B, S, 384)
        embeddings = masked.sum(axis=1) / mask.sum(axis=1, keepdims=True)  # (B, 384)

        # L2 normalise each row
        norms      = np.linalg.norm(embeddings, axis=1, keepdims=True)
        norms      = np.where(norms == 0, 1.0, norms)         # avoid div-by-zero
        return (embeddings / norms).astype(np.float32)


@lru_cache(maxsize=1)
def get_onnx_encoder() -> OnnxSentenceEncoder | None:
    """
    Return a cached OnnxSentenceEncoder when ONNX_MODEL_PATH is configured.
    Returns None when ONNX_MODEL_PATH is unset (PyTorch path active).

    Cached via @lru_cache — InferenceSession is loaded exactly once per process.
    """
    if not _ONNX_MODEL_PATH:
        return None
    try:
        enc = OnnxSentenceEncoder.load(_ONNX_MODEL_PATH)
        log.info("ONNX backend active — PyTorch path bypassed.")
        return enc
    except Exception as exc:
        log.warning("OnnxSentenceEncoder unavailable (%s). Falling back to PyTorch.", exc)
        return None
