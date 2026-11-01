"""The MCP 402 error told clients to send an UNSIGNED PAYMENT-SIGNATURE.

`x402_gate._verify_payment_identity` rejects any payload without a public key,
nonce, timestamp and Ed25519 signature, so a client following the published
instructions could never pay. The instructions must name every field the
verifier requires, the exact message it checks the signature against, and how
agent_id is derived — and both 402 paths must publish the same text.
"""
from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path

from warden.marketplace.agent import _B62_ALPHA, pubkey_to_agent_id
from warden.marketplace.x402_gate import _canonical_payment_msg
from warden.mcp.gateway import _X402_SIGNED_RETRY

_SRC = (Path(__file__).resolve().parents[1] / "mcp" / "gateway.py").read_text(encoding="utf-8")


def test_instructions_never_describe_the_unsigned_format():
    assert 'base64({\\"agent_id\\": \\"<did>\\"})' not in _SRC
    assert 'base64({"agent_id": "..."})' not in _SRC


def test_both_402_paths_use_the_one_instruction_string():
    # Every "instructions" value in the gateway starts from the shared constant,
    # so the two paths cannot drift apart field by field.
    blocks = re.findall(r'"instructions":\s*\(\s*(\w+)', _SRC)
    assert len(blocks) == 2, blocks
    assert set(blocks) == {"_X402_SIGNED_RETRY"}


def test_instructions_show_every_field_as_a_key_value_pair():
    for field, placeholder in (
        ("agent_id", '"did:shadow:'),
        ("public_key", '"<base64'),
        ("nonce", '"<uuid4>"'),
        ("issued_at", "<unix seconds>"),
        ("signature", '"<base64>"'),
    ):
        assert f'"{field}": {placeholder}' in _X402_SIGNED_RETRY, field


def test_instructions_quote_the_full_message_the_verifier_signs():
    documented = "x402/1.0:<agent_id>:<nonce>:<issued_at>"
    rendered = _canonical_payment_msg("<agent_id>", "<nonce>", 0).decode()
    assert rendered.replace(":0", ":<issued_at>") == documented
    assert documented in _X402_SIGNED_RETRY


def test_documented_agent_id_derivation_matches_the_verifier():
    pub_b64 = base64.b64encode(bytes(range(32))).decode()
    n = int.from_bytes(hashlib.sha256(base64.b64decode(pub_b64)).digest(), "big")
    chars = []
    while n:
        chars.append(_B62_ALPHA[n % 62])
        n //= 62
    by_the_instructions = "did:shadow:" + "".join(reversed(chars))[:32]
    assert by_the_instructions == pubkey_to_agent_id(pub_b64)
    for phrase in ("did:shadow:", "first 32 base-62", "0-9A-Za-z", "SHA-256",
                   "base64-decoded public_key"):
        assert phrase in _X402_SIGNED_RETRY, phrase
