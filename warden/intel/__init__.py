"""
warden/intel/ — Threat intelligence facade package.

Canonical import path for threat feeds, sync, storage, and Intel Bridge.
"""
from __future__ import annotations

from warden.corpus_sync import CorpusSyncWatcher
from warden.intel_bridge import WardenIntelBridge
from warden.intel_ops import WardenIntelOps
from warden.threat_feed import ThreatFeedClient
from warden.threat_store import ThreatStore
from warden.threat_sync import ThreatSyncClient
from warden.threat_vault import SEVERITY_RANK, ThreatVault

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
