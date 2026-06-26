"""
warden/protocols/a2a/agent_card.py
────────────────────────────────────
A2A v1.0 Agent Card — served at /.well-known/agent.json.

The Agent Card is the discovery document that external agents use to learn
about this Shadow Warden node: what it can do, how to authenticate, and
what A2A task types it accepts.

Spec: https://a2a.af (Linux Foundation A2A v1.0)
"""
from __future__ import annotations

import os
from typing import Any

_BASE_URL    = os.getenv("A2A_BASE_URL", "https://api.shadow-warden-ai.com")
_AGENT_NAME  = os.getenv("A2A_AGENT_NAME", "Shadow Warden AI")
_AGENT_DID   = os.getenv("A2A_AGENT_DID", "did:shadow:default")
_AGENT_VER   = "5.6.0"


def _e2e_pub_key() -> str:
    """Return the server's E2E public key lazily; empty string if unavailable."""
    try:
        from warden.protocols.a2a.task_lifecycle import get_server_e2e_pubkey
        return get_server_e2e_pubkey()
    except Exception:
        return ""


def build_agent_card() -> dict[str, Any]:
    """
    Return the A2A v1.0 Agent Card as a serialisable dict.

    Fields follow the A2A Agent Card JSON schema v1.0.
    """
    return {
        "schema_version": "a2a/v1.0",
        "name": _AGENT_NAME,
        "version": _AGENT_VER,
        "description": (
            "Shadow Warden AI — GDPR-compliant AI security gateway with "
            "autonomous threat detection, agentic marketplace, and sovereign "
            "data routing for enterprise M2M workloads."
        ),
        "did": _AGENT_DID,
        "endpoint": f"{_BASE_URL}/a2a",
        "well_known": f"{_BASE_URL}/.well-known/agent.json",
        "auth_schemes": [
            {
                "type": "api_key",
                "header": "X-API-Key",
                "description": "Shadow Warden per-tenant API key",
            },
            {
                "type": "bearer",
                "description": "W3C Verifiable Credential (Ed25519Signature2020)",
            },
        ],
        "capabilities": [
            "task:marketplace_search",
            "task:security_filter",
            "task:threat_analysis",
            "task:compliance_report",
            "task:escrow_management",
            "task:agent_registration",
            "payment:x402",
        ],
        "payment_schemes": [
            {
                "scheme": "x402/1.0",
                "description": "Per-call USDC nanopayments for search (x402 protocol)",
                "header_required": "PAYMENT-SIGNATURE",
                "header_response": "PAYMENT-REQUIRED",
                "endpoint": f"{_BASE_URL}/marketplace/action",
                "actions": ["search"],
                "amount_usd": os.getenv("MARKETPLACE_SEARCH_FEE_USD", "0.000001"),
                "network": "polygon-amoy",
                "enabled": os.getenv("X402_GATE_ENABLED", "false"),
            }
        ],
        "supported_content_types": [
            "application/json",
            "text/plain",
            "application/warden-a2a-encrypted",
        ],
        "e2e_encryption": {
            "supported": True,
            "algorithm": "X25519+HKDF-SHA256+AES-256-GCM",
            "pub_key": _e2e_pub_key(),
            "note": (
                "Encrypt task input with TunnelCrypto.encrypt(json, ECDH(caller_priv, pub_key)). "
                "Pass e2e_caller_pub_key + e2e_encrypted_input in the POST /a2a/tasks body."
            ),
        },
        "supported_task_types": [
            {
                "type": "marketplace_search",
                "description": "Search the agentic marketplace for listings, agents, or assets",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "asset_type": {"type": "string"},
                        "max_price": {"type": "number"},
                        "query": {"type": "string"},
                    },
                },
            },
            {
                "type": "security_filter",
                "description": "Submit content for 9-stage AI security filtering",
                "input_schema": {
                    "type": "object",
                    "required": ["content"],
                    "properties": {
                        "content": {"type": "string"},
                        "tenant_id": {"type": "string"},
                    },
                },
            },
            {
                "type": "threat_analysis",
                "description": "Analyse a threat or CVE report via SOVA agent",
                "input_schema": {
                    "type": "object",
                    "required": ["query"],
                    "properties": {
                        "query": {"type": "string"},
                        "session_id": {"type": "string"},
                    },
                },
            },
            {
                "type": "compliance_report",
                "description": "Generate a compliance posture report for a tenant",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "tenant_id": {"type": "string"},
                        "framework": {"type": "string", "enum": ["GDPR", "SOC2", "ISO27001", "HIPAA"]},
                    },
                },
            },
        ],
        "links": {
            "docs":       f"{_BASE_URL}/docs",
            "openapi":    f"{_BASE_URL}/openapi.json",
            "health":     f"{_BASE_URL}/health",
            "trust_graph": f"{_BASE_URL}/marketplace/trust/graph",
        },
        "jurisdiction": os.getenv("HOME_JURISDICTION", "EU"),
        "compliance_frameworks": ["GDPR", "SOC2", "ISO27001"],
    }
