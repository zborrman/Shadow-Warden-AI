#!/usr/bin/env python3
"""
scripts/export_onnx.py
━━━━━━━━━━━━━━━━━━━━━
Export all-MiniLM-L6-v2 to ONNX for use with warden/brain/onnx_runner.py.

Two export paths (tried in order):
  1. optimum[onnxruntime]  — preferred; preserves the full sentence-transformers
     pipeline including mean-pooling and L2 normalisation in the graph.
  2. torch.onnx.export     — fallback; raw transformer backbone only.
     Mean-pooling and L2 norm are applied at inference time in onnx_runner.py.

Usage::

    # Preferred (install optimum once):
    pip install optimum[onnxruntime]
    python scripts/export_onnx.py

    # Fallback (torch only, no extra deps):
    python scripts/export_onnx.py --torch

    # Custom output directory:
    python scripts/export_onnx.py --output /warden/models/minilm-onnx

Then set in .env:
    ONNX_MODEL_PATH=/warden/models/minilm-onnx
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys

MODEL_ID       = "sentence-transformers/all-MiniLM-L6-v2"
DEFAULT_OUTPUT = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "warden", "models", "minilm-onnx")
)


# ── Path 1: optimum ────────────────────────────────────────────────────────────

def export_via_optimum(output: str, cache_dir: str | None) -> None:
    """Export using HuggingFace Optimum — preserves mean-pooling in the graph."""
    from optimum.onnxruntime import ORTModelForFeatureExtraction
    from transformers import AutoTokenizer

    print(f"[optimum] Exporting {MODEL_ID} -> {output}")
    model = ORTModelForFeatureExtraction.from_pretrained(
        MODEL_ID, export=True, cache_dir=cache_dir
    )
    model.save_pretrained(output)

    # Normalise ONNX filename to model.onnx (optimum may use model_optimized.onnx)
    onnx_src = os.path.join(output, "model.onnx")
    if not os.path.isfile(onnx_src):
        for fname in os.listdir(output):
            if fname.endswith(".onnx"):
                shutil.copy(os.path.join(output, fname), onnx_src)
                print(f"[optimum] Renamed {fname} -> model.onnx")
                break

    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, cache_dir=cache_dir)
    tokenizer.save_pretrained(output)


# ── Path 2: torch.onnx.export ──────────────────────────────────────────────────

def export_via_torch(output: str, cache_dir: str | None) -> None:
    """
    Export the raw transformer backbone via torch.onnx.export.

    NOTE: This exports the encoder only — mean-pooling and L2 normalisation
    are NOT baked into the graph.  They are applied at inference time by
    OnnxSentenceEncoder in warden/brain/onnx_runner.py, so the final
    embeddings are numerically identical to the sentence-transformers output.
    """
    import torch
    from transformers import AutoModel, AutoTokenizer

    print(f"[torch] Exporting {MODEL_ID} -> {output}")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, cache_dir=cache_dir)
    model     = AutoModel.from_pretrained(MODEL_ID, cache_dir=cache_dir)
    model.eval()

    dummy   = tokenizer("shadow warden export", return_tensors="pt",
                        padding="max_length", truncation=True, max_length=128)
    inp_ids = dummy["input_ids"]
    attn    = dummy["attention_mask"]

    onnx_path = os.path.join(output, "model.onnx")
    with torch.no_grad():
        torch.onnx.export(
            model,
            (inp_ids, attn),
            onnx_path,
            input_names   = ["input_ids", "attention_mask"],
            output_names  = ["last_hidden_state", "pooler_output"],
            dynamic_axes  = {
                "input_ids":         {0: "batch", 1: "seq_len"},
                "attention_mask":    {0: "batch", 1: "seq_len"},
                "last_hidden_state": {0: "batch", 1: "seq_len"},
            },
            opset_version       = 17,
            do_constant_folding = True,
        )
    print(f"[torch] Saved {onnx_path}")

    tokenizer.save_pretrained(output)


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Export MiniLM to ONNX")
    parser.add_argument("--output",    default=DEFAULT_OUTPUT, help="Output directory")
    parser.add_argument("--cache-dir", default=None,           help="HuggingFace cache dir")
    parser.add_argument("--torch",     action="store_true",
                        help="Force torch.onnx.export (skip optimum)")
    args = parser.parse_args()

    output = os.path.abspath(args.output)
    os.makedirs(output, exist_ok=True)

    if not args.torch:
        try:
            export_via_optimum(output, args.cache_dir)
            method = "optimum"
        except ImportError:
            print("[optimum] not installed -- falling back to torch.onnx.export")
            print("          (pip install optimum[onnxruntime] for the preferred path)")
            export_via_torch(output, args.cache_dir)
            method = "torch"
    else:
        export_via_torch(output, args.cache_dir)
        method = "torch"

    onnx_path = os.path.join(output, "model.onnx")
    if not os.path.isfile(onnx_path):
        print("ERROR: model.onnx not found after export.", file=sys.stderr)
        sys.exit(1)

    size_mb = os.path.getsize(onnx_path) / 1024 / 1024
    print(f"\nExport complete [{method}]")
    print(f"  model.onnx : {size_mb:.1f} MB")
    print(f"  directory  : {output}")
    print(f"\nAdd to .env:  ONNX_MODEL_PATH={output}")


if __name__ == "__main__":
    main()
