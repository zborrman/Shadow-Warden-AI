"""warden/billing/ — billing and quota enforcement helpers.

Re-exports from the legacy warden/billing.py flat module so that existing
imports (``from warden.billing import BillingStore, BILLING_AGG_INTERVAL``)
continue to work now that billing/ is a package (needed for quotas.py).
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

# Load billing.py directly by file path to avoid the package self-shadowing it.
_billing_py = Path(__file__).parent.parent / "billing.py"
_spec = importlib.util.spec_from_file_location("warden._billing_legacy", _billing_py)
_mod = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(_mod)  # type: ignore[union-attr]
sys.modules["warden._billing_legacy"] = _mod

BillingStore = _mod.BillingStore
BILLING_AGG_INTERVAL = _mod.BILLING_AGG_INTERVAL
BILLING_DB_PATH = _mod.BILLING_DB_PATH
LOGS_PATH = _mod.LOGS_PATH

__all__ = ["BillingStore", "BILLING_AGG_INTERVAL", "BILLING_DB_PATH", "LOGS_PATH"]
