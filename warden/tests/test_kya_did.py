"""Tests for KYA DID module and profile store."""
from __future__ import annotations

from warden.kya.did import (
    did_from_seed,
    ephemeral_did,
    generate_keypair,
    is_valid_did,
    sign_challenge,
    sign_trust_assertion,
    verify_signature,
)


class TestDIDFormat:
    def test_valid_did_format(self):
        _, pub, did = generate_keypair()
        assert is_valid_did(did)
        assert did.startswith("did:shadow:")
        tail = did[len("did:shadow:"):]
        assert len(tail) == 22

    def test_invalid_did_too_short(self):
        assert not is_valid_did("did:shadow:abc")

    def test_invalid_did_wrong_prefix(self):
        assert not is_valid_did("did:eth:abc123456789012345678901")

    def test_invalid_did_bad_chars(self):
        assert not is_valid_did("did:shadow:" + "!" * 22)

    def test_ephemeral_did_is_valid(self):
        assert is_valid_did(ephemeral_did())

    def test_did_from_seed_deterministic(self):
        seed = b"test-seed-32-bytes-padded-to-32b"
        d1 = did_from_seed(seed)
        d2 = did_from_seed(seed)
        assert d1 == d2

    def test_different_keys_different_dids(self):
        _, _, did1 = generate_keypair()
        _, _, did2 = generate_keypair()
        assert did1 != did2


class TestSigning:
    def test_sign_verify_roundtrip(self):
        priv, pub, _ = generate_keypair()
        sig = sign_challenge(priv, "hello-world")
        assert verify_signature(pub, "hello-world", sig)

    def test_wrong_challenge_fails(self):
        priv, pub, _ = generate_keypair()
        sig = sign_challenge(priv, "hello")
        assert not verify_signature(pub, "world", sig)

    def test_wrong_key_fails(self):
        priv, _,   _ = generate_keypair()
        _,    pub2, _ = generate_keypair()
        sig = sign_challenge(priv, "hello")
        assert not verify_signature(pub2, "hello", sig)

    def test_trust_assertion_hmac(self):
        _, _, did = generate_keypair()
        sig = sign_trust_assertion(did, 0.85, "2026-01-01T00:00:00+00:00")
        assert len(sig) == 64  # hex SHA256


class TestProfileStore:
    def test_register_and_get(self, tmp_path):
        db = str(tmp_path / "kya.db")
        from warden.kya.profile import get_profile, register_did
        _, pub, did = generate_keypair()
        profile = register_did(did, pub, "tenant-1", db_path=db)
        assert profile.did == did
        assert profile.trust_score == 0.5
        assert profile.kya_status == "PENDING"

        fetched = get_profile(did, db_path=db)
        assert fetched is not None
        assert fetched.did == did

    def test_unknown_did_returns_none(self, tmp_path):
        db = str(tmp_path / "kya.db")
        from warden.kya.profile import get_profile
        assert get_profile("did:shadow:" + "A" * 22, db_path=db) is None

    def test_trust_update_clamps(self, tmp_path):
        db = str(tmp_path / "kya.db")
        from warden.kya.profile import register_did, update_trust
        _, pub, did = generate_keypair()
        register_did(did, pub, db_path=db)
        # Clamp at 1.0
        new = update_trust(did, 10.0, db_path=db)
        assert new == 1.0
        # Clamp at 0.0
        new2 = update_trust(did, -100.0, db_path=db)
        assert new2 == 0.0

    def test_promote_status(self, tmp_path):
        db = str(tmp_path / "kya.db")
        from warden.kya.profile import get_profile, promote_status, register_did
        _, pub, did = generate_keypair()
        register_did(did, pub, db_path=db)
        promote_status(did, "VERIFIED", db_path=db)
        p = get_profile(did, db_path=db)
        assert p is not None and p.kya_status == "VERIFIED"

    def test_list_profiles_owner_filter(self, tmp_path):
        db = str(tmp_path / "kya.db")
        from warden.kya.profile import list_profiles, register_did
        _, pub1, did1 = generate_keypair()
        _, pub2, did2 = generate_keypair()
        register_did(did1, pub1, "owner-A", db_path=db)
        register_did(did2, pub2, "owner-B", db_path=db)
        results = list_profiles("owner-A", db_path=db)
        dids = [p.did for p in results]
        assert did1 in dids
        assert did2 not in dids

    def test_upsert_updates_pubkey(self, tmp_path):
        db = str(tmp_path / "kya.db")
        from warden.kya.profile import get_profile, register_did
        _, pub1, did = generate_keypair()
        _, pub2, _   = generate_keypair()
        register_did(did, pub1, db_path=db)
        register_did(did, pub2, db_path=db)  # upsert
        p = get_profile(did, db_path=db)
        assert p is not None and p.pubkey_b64 == pub2
