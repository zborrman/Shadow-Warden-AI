"""
GSAM — Global Statistic Agentic Marketplace (GSAM-01).

Analytics + governance layer over the agentic marketplace:
  • wide denormalized observations stream (ClickHouse, fail-open spool)
  • market/economics math (session cost, ROI, drift index, anti-inflation score)
  • agent quarantine + JIT credential leasing

Import rule: this package must have zero import-time side effects — the
router is registered via app_factory.RouterSpec and every producer tap uses
a lazy import guarded by try/except.
"""
from __future__ import annotations

__all__ = ["gsam_emit"]


def gsam_emit(obs: dict) -> None:
    """Lazy proxy to the collector singleton — never raises."""
    try:
        from warden.gsam.collector import gsam_emit as _emit
        _emit(obs)
    except Exception as exc:
        from warden.observability import Reason, record_failopen
        record_failopen("gsam_collector", Reason.BACKEND_ERROR, exc)
