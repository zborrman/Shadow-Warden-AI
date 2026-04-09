"""
warden/paddle_billing.py — DEPRECATED
──────────────────────────────────────
Paddle has been replaced by Lemon Squeezy.
This module is kept only for backwards compatibility and will be removed in v3.0.

All billing is now handled by warden/lemon_billing.py.
"""
# ruff: noqa: F401  — every import here is a public re-export for backwards compat
from warden.lemon_billing import PLAN_QUOTAS
from warden.lemon_billing import LemonBilling as PaddleBilling
from warden.lemon_billing import get_lemon_billing as get_paddle_billing
