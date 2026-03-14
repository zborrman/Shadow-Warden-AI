"""
warden/threat_intel
━━━━━━━━━━━━━━━━━━
Continuous Threat Intelligence & Countermeasure Engine.

Proactively monitors external security sources (MITRE ATLAS, NVD, GitHub
Security Advisories, arXiv, OWASP LLM Top 10), analyzes each item with
Claude Haiku to determine relevance and extract detection patterns, then
synthesizes SemanticGuard rules and ML corpus examples that are hot-loaded
into the running system — without a restart.

This is the *proactive* intelligence layer.  It complements the *reactive*
Evolution Engine (brain/evolve.py) which watches live blocked traffic, and the
*collaborative* ThreatFeedClient (threat_feed.py) which shares rules between
Warden instances.

Pipeline
────────
  External Sources
    → ThreatIntelCollector  (HTTP / RSS pull, SHA-256 dedup, SQLite persist)
    → ThreatIntelAnalyzer   (Claude Haiku: relevance, OWASP category, pattern)
    → RuleFactory           (synthesize _Rule + ML examples, vet, activate)
    → ReviewQueue           (auto-approve or hold for manual review)
    → RuleLedger            (pending_review → active → retired lifecycle)
    → BrainSemanticGuard    (add_examples() hot-reload)

Opt-in
──────
  Set THREAT_INTEL_ENABLED=true to activate.
  The scheduler is registered in main.py lifespan() as an asyncio background
  task, running every THREAT_INTEL_SYNC_HRS hours (default: 6).
"""
from __future__ import annotations

from warden.threat_intel.analyzer import ThreatIntelAnalyzer
from warden.threat_intel.collector import ThreatIntelCollector
from warden.threat_intel.rule_factory import RuleFactory
from warden.threat_intel.scheduler import ThreatIntelScheduler
from warden.threat_intel.store import ThreatIntelStore

__all__ = [
    "ThreatIntelStore",
    "ThreatIntelCollector",
    "ThreatIntelAnalyzer",
    "RuleFactory",
    "ThreatIntelScheduler",
]
