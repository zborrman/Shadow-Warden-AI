"""
Shadow Warden AI — GDPR-compliant AI security gateway.

Public API surface (stable, versioned):

    from warden.core    import FilterRequest, FilterResponse, RiskLevel
    from warden.guards  import SemanticGuard, topology_scan
    from warden.redaction import SecretRedactor
    from warden.intel   import ThreatFeedClient, WardenIntelBridge

All legacy flat-module import paths remain available for backward
compatibility (e.g. ``from warden.semantic_guard import SemanticGuard``).
"""

#  ── THE version of record (P-1) ──────────────────────────────────────────────
#  This literal is the single source of truth for the product version.
#  pyproject.toml reads it (`[tool.setuptools.dynamic] version = {attr = ...}`)
#  and warden/tests/test_version_of_record.py asserts every documentation
#  surface agrees with it.
#
#  Before P-1 there were three answers: pyproject.toml said 5.3.0, this file
#  said 5.6.0, and every published document said 7.7 — so the built wheel, the
#  importable package and the product all disagreed, and anything keyed on the
#  package version (SBOM, support tickets, CVE correlation) was wrong.
#
#  Bumping the product: change this line, then update the `**Version:**` /
#  `Version X` headers the test enumerates. The test tells you which they are.
__version__ = "7.7.0"
__all__ = ["__version__"]
