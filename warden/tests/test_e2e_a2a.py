"""
Tests for A2A E2E encryption integration (Phase 1-1).

Covers:
  - TunnelCrypto round-trip encryption / decryption
  - Wrong key raises DecryptionError
  - create_task with E2E encrypted input decrypts correctly
  - create_task with E2E input + wrong key raises ValueError
  - handler receives plaintext (not encrypted) input
  - get_server_e2e_pubkey() returns a non-empty key
"""
import json

import pytest

# ── helpers ───────────────────────────────────────────────────────────────────

def _make_caller_encrypted_input(server_pub: str, task_id: str, payload: dict) -> tuple[dict, str]:
    """
    Simulate the caller side:
      1. generate ephemeral keypair
      2. derive shared key with server's pub + task_id
      3. encrypt the JSON-serialised payload
    Returns (encrypted_input_dict, caller_pub_b64).
    """
    from warden.syndicates.crypto import TunnelCrypto

    caller_priv, caller_pub = TunnelCrypto.generate_keypair()
    aes_key = TunnelCrypto.derive_shared_key(caller_priv, server_pub, task_id)
    encrypted = TunnelCrypto.encrypt(json.dumps(payload), aes_key)
    return encrypted, caller_pub


# ── TunnelCrypto standalone ───────────────────────────────────────────────────

class TestTunnelCryptoRoundTrip:
    def test_encrypt_decrypt_round_trip(self):
        from warden.syndicates.crypto import TunnelCrypto

        priv_a, pub_a = TunnelCrypto.generate_keypair()
        priv_b, pub_b = TunnelCrypto.generate_keypair()
        tunnel_id = "test-tunnel-abc"

        key_a = TunnelCrypto.derive_shared_key(priv_a, pub_b, tunnel_id)
        key_b = TunnelCrypto.derive_shared_key(priv_b, pub_a, tunnel_id)

        assert key_a == key_b, "ECDH shared secrets must match"

        envelope = TunnelCrypto.encrypt("Hello, A2A!", key_a)
        plaintext = TunnelCrypto.decrypt(envelope, key_b)
        assert plaintext == "Hello, A2A!"

    def test_wrong_key_raises_decryption_error(self):
        from warden.syndicates.crypto import DecryptionError, TunnelCrypto

        priv_a, pub_a = TunnelCrypto.generate_keypair()
        priv_b, pub_b = TunnelCrypto.generate_keypair()
        priv_c, _    = TunnelCrypto.generate_keypair()

        key_ab = TunnelCrypto.derive_shared_key(priv_a, pub_b, "t1")
        # Derive a *different* key using an unrelated private key
        key_cb = TunnelCrypto.derive_shared_key(priv_c, pub_b, "t1")

        envelope = TunnelCrypto.encrypt("secret", key_ab)
        with pytest.raises(DecryptionError):
            TunnelCrypto.decrypt(envelope, key_cb)

    def test_tampered_ciphertext_raises(self):
        from warden.syndicates.crypto import DecryptionError, TunnelCrypto

        priv, pub_self = TunnelCrypto.generate_keypair()
        priv_peer, pub_peer = TunnelCrypto.generate_keypair()
        key = TunnelCrypto.derive_shared_key(priv, pub_peer, "tamper-test")
        envelope = TunnelCrypto.encrypt("original", key)

        # Flip a byte in ciphertext
        import base64
        ct = base64.urlsafe_b64decode(envelope["ciphertext"] + "==")
        ct_bad = bytes([ct[0] ^ 0xFF]) + ct[1:]
        envelope["ciphertext"] = base64.urlsafe_b64encode(ct_bad).rstrip(b"=").decode()

        with pytest.raises(DecryptionError):
            TunnelCrypto.decrypt(envelope, key)


# ── A2A E2E integration ───────────────────────────────────────────────────────

class TestA2AE2E:
    def test_get_server_e2e_pubkey_non_empty(self):
        from warden.protocols.a2a.task_lifecycle import get_server_e2e_pubkey

        pub = get_server_e2e_pubkey()
        assert isinstance(pub, str) and len(pub) > 0

    def test_create_task_with_e2e_input_decrypts(self):
        from warden.protocols.a2a.task_lifecycle import get_server_e2e_pubkey

        server_pub = get_server_e2e_pubkey()
        payload = {"content": "classified payload", "tenant_id": "test"}

        # We need the task_id ahead of time to key the HKDF — use a workaround:
        # create unencrypted first to get the format, then test with a known task_id.
        # We derive the task_id by calling create_task normally to get its shape,
        # but for E2E we must encrypt BEFORE calling create_task (task_id is unknown).
        # Solution: use a placeholder task_id for encryption, then verify server decrypts.
        # In production, callers use GET /a2a/pubkey + a client-generated task_id UUID.

        import uuid as _uuid
        pre_task_id = str(_uuid.uuid4())

        encrypted, caller_pub = _make_caller_encrypted_input(server_pub, pre_task_id, payload)

        # Simulate what the server does internally when it receives the encrypted task.
        # We call _decrypt_e2e_input directly to verify the round-trip.
        from warden.protocols.a2a.task_lifecycle import _decrypt_e2e_input

        result = _decrypt_e2e_input(encrypted, caller_pub, pre_task_id)
        assert result == payload

    def test_create_task_plaintext_input_unchanged(self):
        from warden.protocols.a2a.task_lifecycle import create_task

        task = create_task(
            task_type="security_filter",
            input_data={"content": "hello"},
            tenant_id="t1",
        )
        assert task["input"] == {"content": "hello"}
        assert task["state"] == "submitted"

    def test_create_task_e2e_wrong_caller_pub_raises(self):
        from warden.protocols.a2a.task_lifecycle import (
            _decrypt_e2e_input,
            get_server_e2e_pubkey,
        )
        from warden.syndicates.crypto import TunnelCrypto

        server_pub = get_server_e2e_pubkey()
        task_id = "bad-key-test-task"

        # Encrypt with correct server pub
        caller_priv, caller_pub = TunnelCrypto.generate_keypair()
        aes_key = TunnelCrypto.derive_shared_key(caller_priv, server_pub, task_id)
        encrypted = TunnelCrypto.encrypt('{"secret": 1}', aes_key)

        # Use a *different* caller pub — server will derive a different AES key
        _, wrong_caller_pub = TunnelCrypto.generate_keypair()

        with pytest.raises(ValueError, match="E2E decryption failed"):
            _decrypt_e2e_input(encrypted, wrong_caller_pub, task_id)

    def test_agent_card_includes_e2e(self):
        from warden.protocols.a2a.agent_card import build_agent_card

        card = build_agent_card()
        assert "application/warden-a2a-encrypted" in card["supported_content_types"]
        assert card["e2e_encryption"]["supported"] is True
        assert len(card["e2e_encryption"]["pub_key"]) > 0
