"""Tests for quantum-safe hybrid asset signatures (SEC-08)."""
from __future__ import annotations

import base64


def _make_keypair():
    """Create a minimal CommunityKeypair stub for testing."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    priv = Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    class _Keypair:
        ed25519_pub_b64 = base64.b64encode(pub_bytes).decode()
        is_hybrid = False

        def sign(self, data: bytes) -> bytes:
            return priv.sign(data)

    return _Keypair()


class TestHybridSignatureCreation:
    def test_classical_signature_created(self, tmp_path):
        from warden.marketplace.tokenizer import AssetTokenizer

        keypair = _make_keypair()
        tokenizer = AssetTokenizer()
        rule = {"keyword": "malware", "risk": "high"}
        container = tokenizer.tokenize_rule(rule, keypair, "agent-1", "comm-1")

        assert "signature" in container
        sig = base64.b64decode(container["signature"])
        assert len(sig) == 64  # Ed25519 signature is always 64 bytes

    def test_pqc_signature_field_present_but_empty_without_pqc(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PQC_ENABLED", "false")
        from warden.marketplace.tokenizer import AssetTokenizer

        keypair = _make_keypair()
        container = AssetTokenizer().tokenize_rule({"keyword": "test"}, keypair, "a", "c")
        assert container["pqc_signature"] == ""


class TestSignatureVerification:
    def test_classical_signature_verifies(self):
        from warden.marketplace.tokenizer import AssetTokenizer, verify_asset_signature

        keypair = _make_keypair()
        container = AssetTokenizer().tokenize_rule({"keyword": "x"}, keypair, "a", "c")
        assert verify_asset_signature(container)

    def test_tampered_signature_fails(self):
        from warden.marketplace.tokenizer import AssetTokenizer, verify_asset_signature

        keypair = _make_keypair()
        container = AssetTokenizer().tokenize_rule({"keyword": "y"}, keypair, "a", "c")
        container["signature"] = base64.b64encode(b"\x00" * 64).decode()
        assert not verify_asset_signature(container)

    def test_missing_signature_fails(self):
        from warden.marketplace.tokenizer import verify_asset_signature

        container = {"sha256": "abc", "signer_public_key": "", "signature": ""}
        assert not verify_asset_signature(container)


class TestClassicalOnlyStillWorks:
    def test_non_hybrid_keypair_tokenizes(self):
        from warden.marketplace.tokenizer import AssetTokenizer, verify_asset_signature

        keypair = _make_keypair()
        keypair.is_hybrid = False
        container = AssetTokenizer().tokenize_signals(
            [{"threat": "xss", "score": 0.9}], keypair, "ag", "co"
        )
        assert container["asset_type"] == "signals"
        assert verify_asset_signature(container)
