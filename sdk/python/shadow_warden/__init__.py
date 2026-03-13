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
from shadow_warden.client import AsyncWardenClient, WardenClient
from shadow_warden.errors import (
    WardenBlockedError,
    WardenError,
    WardenGatewayError,
    WardenTimeoutError,
)
from shadow_warden.models import FilterResult, SecretFinding, SemanticFlag

__version__ = "0.5.0"

__all__ = [
    # Clients
    "WardenClient",
    "AsyncWardenClient",
    # Models
    "FilterResult",
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
