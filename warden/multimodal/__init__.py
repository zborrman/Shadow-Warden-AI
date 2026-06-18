"""
warden/multimodal/__init__.py
─────────────────────────────
Package init — re-exports the pipeline coordinator and DET-01 pre-filter.
"""
from warden.multimodal._coordinator import MultimodalResult, run_multimodal
from warden.multimodal.handler import prefilter_multimodal

__all__ = ["run_multimodal", "MultimodalResult", "prefilter_multimodal"]
