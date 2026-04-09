"""
warden/paddle_billing.py — DEPRECATED
──────────────────────────────────────
Paddle has been replaced by Lemon Squeezy.
This module is kept only for backwards compatibility and will be removed in v3.0.

All billing is now handled by warden/lemon_billing.py.
"""
from warden.lemon_billing import (  # noqa: F401  re-export
    LemonBilling as PaddleBilling,
)
