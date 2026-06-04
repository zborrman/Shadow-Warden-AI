"""
warden/sdk — Shadow Warden AI client SDK components.

Public API
──────────
  WardenSpanProcessor       — sync OTel span processor (ThreadPoolExecutor)
  WardenAsyncSpanProcessor  — async OTel span processor (asyncio tasks)
  get_sdk_stats             — aggregate stats across all active processors

Version: 1.0.0  (IN-21 / Shadow Warden AI v5.2)
"""
from warden.sdk.otel import (
    WardenAsyncSpanProcessor,
    WardenSpanProcessor,
    get_sdk_stats,
)

__all__ = [
    "WardenSpanProcessor",
    "WardenAsyncSpanProcessor",
    "get_sdk_stats",
]

__version__ = "1.0.0"
