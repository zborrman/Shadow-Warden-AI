"""
warden/intel/ — Threat intelligence facade package.

Canonical import path for threat feeds, sync, storage, and Intel Bridge.
"""
from __future__ import annotations

from warden.corpus_sync import CorpusSyncWatcher  # noqa: F401
from warden.intel_bridge import WardenIntelBridge  # noqa: F401
from warden.intel_ops import WardenIntelOps  # noqa: F401
from warden.threat_feed import ThreatFeedClient  # noqa: F401
from warden.threat_store import ThreatStore  # noqa: F401
from warden.threat_sync import ThreatSyncClient  # noqa: F401
from warden.threat_vault import SEVERITY_RANK, ThreatVault  # noqa: F401

__all__ = [
    "CorpusSyncWatcher",
    "SEVERITY_RANK",
    "ThreatFeedClient",
    "ThreatStore",
    "ThreatSyncClient",
    "ThreatVault",
    "WardenIntelBridge",
    "WardenIntelOps",
]
