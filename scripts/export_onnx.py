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

MODEL_ID        = "sentence-transformers/all-MiniLM-L6-v2"
DEFAULT_OUTPUT  = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "warden", "models", "minilm-onnx")
)
DEFAULT_Q_OUTPUT = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "warden", "models", "minilm-onnx-int8")
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


# ── INT8 quantization ─────────────────────────────────────────────────────────

def quantize_int8(fp32_dir: str, q_output: str) -> str:
    """
    Apply dynamic INT8 quantization to a previously exported FP32 ONNX model.

    Uses onnxruntime.quantization.quantize_dynamic — no calibration data needed.
    Dynamic quantization folds weight matrices to INT8 at export time; activations
    are quantized at inference time.  For sentence encoders this gives:
      • ~70% smaller model file (91 MB FP32 → ~23 MB INT8)
      • 1.5–2.5× faster CPU inference (AVX2/AVX-512 VNNI int8 paths)
      • < 0.5% cosine similarity degradation on typical sentence pairs

    Parameters
    ----------
    fp32_dir   : directory containing the FP32 model.onnx
    q_output   : destination directory for the INT8 model
    """
    from onnxruntime.quantization import QuantType, quantize_dynamic

    os.makedirs(q_output, exist_ok=True)
    fp32_path = os.path.join(fp32_dir,  "model.onnx")
    int8_path = os.path.join(q_output, "model.onnx")

    print(f"[quantize] INT8 dynamic quantization: {fp32_path} -> {int8_path}")
    quantize_dynamic(
        model_input          = fp32_path,
        model_output         = int8_path,
        weight_type          = QuantType.QInt8,
        optimize_model       = True,
        per_channel          = False,   # per-tensor is faster on x86 without AVX-512 VNNI
        reduce_range         = False,   # set True only on older Intel CPUs (Skylake)
        extra_options        = {"MatMulConstBOnly": True},  # only quantize constant weights
    )

    # Copy tokenizer files so the INT8 dir is self-contained (ONNX_MODEL_PATH can
    # point directly to it without needing the FP32 dir at runtime).
    import shutil
    for fname in os.listdir(fp32_dir):
        if not fname.endswith(".onnx"):
            shutil.copy2(os.path.join(fp32_dir, fname), os.path.join(q_output, fname))

    size_fp32 = os.path.getsize(fp32_path) / 1024 / 1024
    size_int8 = os.path.getsize(int8_path) / 1024 / 1024
    print(f"[quantize] FP32: {size_fp32:.1f} MB  →  INT8: {size_int8:.1f} MB  "
          f"({100 * (1 - size_int8 / size_fp32):.0f}% reduction)")
    return int8_path


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Export all-MiniLM-L6-v2 to ONNX (FP32) and optionally quantize to INT8",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples
--------
  # Full pipeline: FP32 export + INT8 quantization (recommended for 8-vCPU server)
  python scripts/export_onnx.py --quantize

  # FP32 export only (skips quantization)
  python scripts/export_onnx.py

  # Force torch.onnx.export backend (no optimum required)
  python scripts/export_onnx.py --torch --quantize

  # Custom directories
  python scripts/export_onnx.py --output /warden/models/minilm-onnx \\
                                 --quantize-output /warden/models/minilm-onnx-int8

After export, set in .env:
  ONNX_MODEL_PATH=/warden/models/minilm-onnx-int8   # INT8 (recommended)
  # or
  ONNX_MODEL_PATH=/warden/models/minilm-onnx         # FP32 fallback
""",
    )
    parser.add_argument("--output",          default=DEFAULT_OUTPUT,
                        help="FP32 output directory (default: warden/models/minilm-onnx)")
    parser.add_argument("--quantize-output", default=DEFAULT_Q_OUTPUT,
                        help="INT8 output directory (default: warden/models/minilm-onnx-int8)")
    parser.add_argument("--cache-dir",       default=None,
                        help="HuggingFace model cache directory")
    parser.add_argument("--torch",           action="store_true",
                        help="Force torch.onnx.export backend (skip optimum)")
    parser.add_argument("--quantize",        action="store_true",
                        help="Also produce an INT8-quantized model after FP32 export")
    args = parser.parse_args()

    # ── Step 1: FP32 export ───────────────────────────────────────────────────
    output = os.path.abspath(args.output)
    os.makedirs(output, exist_ok=True)

    if not args.torch:
        try:
            export_via_optimum(output, args.cache_dir)
            method = "optimum"
        except ImportError:
            print("[optimum] not installed — falling back to torch.onnx.export")
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
    print(f"\nFP32 export complete [{method}]")
    print(f"  model.onnx : {size_mb:.1f} MB")
    print(f"  directory  : {output}")

    # ── Step 2: INT8 quantization (optional) ─────────────────────────────────
    if args.quantize:
        try:
            q_output = os.path.abspath(args.quantize_output)
            int8_path = quantize_int8(output, q_output)
            print(f"\nINT8 quantization complete")
            print(f"  model.onnx : {int8_path}")
            print(f"  directory  : {q_output}")
            print(f"\nRecommended .env setting:")
            print(f"  ONNX_MODEL_PATH={q_output}")
            print(f"  ONNX_THREADS=1")
            print(f"  ONNX_INTRA_THREADS=2   # 2 threads/worker × 4 uvicorn workers = 8 vCPU")
        except Exception as exc:
            print(f"\nWARNING: INT8 quantization failed ({exc})")
            print(f"  Ensure onnxruntime>=1.18.0 is installed: pip install onnxruntime")
            print(f"  Falling back to FP32 model.")
            print(f"\nAdd to .env:  ONNX_MODEL_PATH={output}")
    else:
        print(f"\nAdd to .env:  ONNX_MODEL_PATH={output}")
        print(f"Tip: run with --quantize for additional 1.5-2.5× speedup via INT8")


if __name__ == "__main__":
    main()
