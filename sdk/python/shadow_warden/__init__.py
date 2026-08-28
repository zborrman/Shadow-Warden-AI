"""
shadow_warden
━━━━━━━━━━━━
Python SDK for the Shadow Warden AI gateway.

Quick start::

    from shadow_warden import WardenClient

    with WardenClient(gateway_url="http://localhost:8001", api_key="sk_...") as warden:
        result = warden.filter("Summarise the contract for client@example.com")
        if result.allowed:
            response = openai_client.chat.completions.create(...)

Async usage::

    from shadow_warden import AsyncWardenClient

    async with AsyncWardenClient(gateway_url="...", api_key="...") as warden:
        result = await warden.filter("user prompt")
"""
# Agentic-commerce surface. Merged in from the second Python SDK tree during the
# 2026-08-22 consolidation: three packages claimed to be "the" SDK and the site
# advertised three different install names, none of which resolved on PyPI.
# `ShadowWardenClient` and `SecureAgent` are what the homepage sells, so they
# move here rather than disappearing with the tree that held them.
from shadow_warden.agent import SecureAgent
from shadow_warden.client import AsyncWardenClient, WardenClient
from shadow_warden.commerce import ShadowWardenClient
from shadow_warden.errors import (
    WardenBlockedError,
    WardenError,
    WardenGatewayError,
    WardenTimeoutError,
)
from shadow_warden.models import FilterResult, ImpactReport, SecretFinding, SemanticFlag

__version__ = "1.1.0"

__all__ = [
    # Clients
    "WardenClient",
    "AsyncWardenClient",
    "ShadowWardenClient",
    # Agentic commerce
    "SecureAgent",
    # Models
    "FilterResult",
    "ImpactReport",
    "SecretFinding",
    "SemanticFlag",
    # Errors
    "WardenError",
    "WardenBlockedError",
    "WardenGatewayError",
    "WardenTimeoutError",
    # Meta
    "__version__",
]
