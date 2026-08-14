"""
x402 payer identity must be cryptographically proven (vuln-0004 / CWE-345).

Strix drained a victim's prepaid balance by sending base64({"agent_id": victim})
as PAYMENT-SIGNATURE — the gate trusted the claimed agent_id with no signature.
The gate now requires an Ed25519 signature over the payment intent AND that
agent_id == pubkey_to_agent_id(public_key) (self-authenticating did:shadow DID),
so knowing a public DID is no longer enough to spend its balance.
"""
from __future__ import annotations

import base64
import json
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from warden.marketplace.agent import pubkey_to_agent_id
from warden.marketplace.x402_gate import (
    _canonical_payment_msg,
    _extract_agent_id,
    _verify_payment_identity,
)


def _signed_header(priv: Ed25519PrivateKey, agent_id: str, pub_b64: str,
                   nonce: str | None = None, issued_at: int | None = None) -> str:
    nonce = nonce or str(uuid.uuid4())
    issued_at = issued_at if issued_at is not None else int(time.time())
    sig = priv.sign(_canonical_payment_msg(agent_id, nonce, issued_at))
    payload = {
        "agent_id":   agent_id,
        "public_key": pub_b64,
        "signature":  base64.b64encode(sig).decode(),
        "nonce":      nonce,
        "issued_at":  issued_at,
    }
    return base64.b64encode(json.dumps(payload).encode()).decode()


def _keypair():
    priv = Ed25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes_raw()
    pub_b64 = base64.b64encode(pub_raw).decode()
    return priv, pub_b64, pubkey_to_agent_id(pub_b64)


def test_forged_unsigned_agent_id_is_not_trusted():
    """The exact PoC: base64({'agent_id': victim}) with no signature."""
    forged = base64.b64encode(json.dumps({"agent_id": "did:shadow:victimAAA"}).encode()).decode()
    assert _extract_agent_id(forged) is None


def test_valid_signed_identity_is_accepted():
    priv, pub_b64, agent_id = _keypair()
    header = _signed_header(priv, agent_id, pub_b64)
    assert _extract_agent_id(header) == agent_id


def test_signature_over_mismatched_did_is_rejected():
    """A real signature, but agent_id claims a DID not derived from this key."""
    priv, pub_b64, _ = _keypair()
    header = _signed_header(priv, "did:shadow:someoneElse", pub_b64)
    assert _extract_agent_id(header) is None


def test_signature_from_wrong_key_is_rejected():
    """agent_id/public_key are the victim's, but signed by a different key."""
    _, victim_pub_b64, victim_agent = _keypair()
    attacker_priv = Ed25519PrivateKey.generate()
    header = _signed_header(attacker_priv, victim_agent, victim_pub_b64)
    assert _extract_agent_id(header) is None


def test_missing_signature_fields_rejected():
    payload = {"agent_id": "did:shadow:x", "nonce": "n", "issued_at": int(time.time())}
    assert _verify_payment_identity(payload) is None
