"""The MCP 402 error told clients to send an UNSIGNED PAYMENT-SIGNATURE.

`x402_gate._verify_payment_identity` rejects any payload without a public key,
nonce, timestamp and Ed25519 signature, so a client following the published
instructions could never pay. The instructions must name every field the
verifier requires and the exact message it checks the signature against.
"""
from __future__ import annotations

from pathlib import Path

from warden.marketplace.x402_gate import _canonical_payment_msg

_SRC = (Path(__file__).resolve().parents[1] / "mcp" / "gateway.py").read_text(encoding="utf-8")


def test_instructions_never_describe_the_unsigned_format():
    assert 'base64({\\"agent_id\\": \\"<did>\\"})' not in _SRC
    assert 'base64({"agent_id": "..."})' not in _SRC


def test_instructions_name_every_field_the_verifier_requires():
    for field in ("public_key", "nonce", "issued_at", "signature"):
        assert f'\\"{field}\\"' in _SRC, f"402 instructions omit {field}"


def test_instructions_quote_the_message_the_verifier_signs():
    prefix = _canonical_payment_msg("A", "N", 0).decode().split(":")[0]
    assert f"{prefix}:<agent_id>:<nonce>:<issued_at>" in _SRC
