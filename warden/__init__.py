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

__version__ = "4.30.0"
__all__ = ["__version__"]
