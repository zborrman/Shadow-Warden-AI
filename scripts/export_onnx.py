#!/usr/bin/env python3
"""
scripts/export_onnx.py
━━━━━━━━━━━━━━━━━━━━━
Export all-MiniLM-L6-v2 to ONNX format for use with warden/brain/onnx_runner.py.

Usage::

    pip install optimum[onnxruntime]
    python scripts/export_onnx.py [--output /warden/models/minilm-onnx]

The output directory will contain:
  model.onnx       -- the exported ONNX model (~23 MB)
  tokenizer.json   -- fast tokenizer config
  tokenizer_config.json
  vocab.txt
  special_tokens_map.json

Then set in .env::

    ONNX_MODEL_PATH=/warden/models/minilm-onnx
"""
import argparse
import os
import sys

MODEL_ID = "sentence-transformers/all-MiniLM-L6-v2"
DEFAULT_OUTPUT = os.path.join(os.path.dirname(__file__), "..", "warden", "models", "minilm-onnx")


def main() -> None:
    parser = argparse.ArgumentParser(description="Export MiniLM to ONNX")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Output directory")
    parser.add_argument("--cache-dir", default=None, help="HuggingFace cache dir")
    args = parser.parse_args()

    output = os.path.abspath(args.output)
    os.makedirs(output, exist_ok=True)

    try:
        from optimum.onnxruntime import ORTModelForFeatureExtraction
        from transformers import AutoTokenizer
    except ImportError:
        print("ERROR: optimum[onnxruntime] not installed.")
        print("Run: pip install optimum[onnxruntime]")
        sys.exit(1)

    print(f"Exporting {MODEL_ID} -> {output}")
    model = ORTModelForFeatureExtraction.from_pretrained(
        MODEL_ID,
        export=True,
        cache_dir=args.cache_dir,
    )
    model.save_pretrained(output)
    # Copy the ONNX file to expected name
    onnx_src = os.path.join(output, "model.onnx")
    if not os.path.isfile(onnx_src):
        for fname in os.listdir(output):
            if fname.endswith(".onnx"):
                import shutil
                shutil.copy(os.path.join(output, fname), onnx_src)
                break

    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, cache_dir=args.cache_dir)
    tokenizer.save_pretrained(output)

    size_mb = os.path.getsize(onnx_src) / 1024 / 1024
    print(f"Done. model.onnx = {size_mb:.1f} MB")
    print(f"Set in .env:  ONNX_MODEL_PATH={output}")


if __name__ == "__main__":
    main()
