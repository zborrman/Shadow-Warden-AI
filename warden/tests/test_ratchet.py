"""
warden/tests/test_ratchet.py
──────────────────────────────
Tests for warden/syndicates/ratchet.py — Signal Double Ratchet.

Coverage
────────
  MessageKeysCache  — put/pop, eviction, TTL, size limit
  RatchetSession    — encrypt/decrypt in-order, out-of-order, tier intervals,
                      DH ratchet advancement, serialization roundtrip
"""
from __future__ import annotations

import os
import time
import unittest

os.environ.setdefault("RATCHET_CACHE_SIZE", "100")
os.environ.setdefault("RATCHET_CACHE_TTL_S", "60")


# ── Shared secret helper ──────────────────────────────────────────────────────

def _make_sessions(tier="business"):
    """
    Create a symmetric Alice/Bob ratchet pair from the same shared secret.

    Key agreement requires:
      alice.send_chain == bob.recv_chain
      alice.recv_chain == bob.send_chain

    `from_shared_secret` derives:
      send_chain = hkdf(root, "warden:ratchet:send:{sid}")
      recv_chain = hkdf(root, "warden:ratchet:recv:{sid}")

    So Bob must have his chains swapped relative to Alice.
    """
    from warden.syndicates.ratchet import MessageKeysCache, RatchetSession
    secret = os.urandom(32)
    sid    = "test-session-" + os.urandom(4).hex()
    alice  = RatchetSession.from_shared_secret(secret, sid, tier=tier)
    bob    = RatchetSession.from_shared_secret(secret, sid, tier=tier)
    # Swap Bob's chains so alice.send == bob.recv
    bob.send_chain, bob.recv_chain = bob.recv_chain, bob.send_chain
    cache  = MessageKeysCache(max_size=100, ttl_s=60)
    return alice, bob, cache


class TestMessageKeysCache(unittest.TestCase):

    def test_put_and_pop(self):
        from warden.syndicates.ratchet import MessageKeysCache
        cache = MessageKeysCache(max_size=10, ttl_s=60)
        key   = os.urandom(32)
        cache.put("sess-1", 0, key)
        self.assertEqual(cache.pop("sess-1", 0), key)

    def test_pop_nonexistent_returns_none(self):
        from warden.syndicates.ratchet import MessageKeysCache
        cache = MessageKeysCache()
        self.assertIsNone(cache.pop("noexist", 99))

    def test_pop_twice_returns_none(self):
        from warden.syndicates.ratchet import MessageKeysCache
        cache = MessageKeysCache()
        key   = os.urandom(32)
        cache.put("s", 1, key)
        cache.pop("s", 1)
        self.assertIsNone(cache.pop("s", 1))

    def test_max_size_evicts_oldest(self):
        from warden.syndicates.ratchet import MessageKeysCache
        cache = MessageKeysCache(max_size=3, ttl_s=60)
        for i in range(4):
            cache.put("s", i, os.urandom(32))
        self.assertEqual(len(cache), 3)

    def test_len(self):
        from warden.syndicates.ratchet import MessageKeysCache
        cache = MessageKeysCache(max_size=50)
        for i in range(5):
            cache.put("s", i, os.urandom(32))
        self.assertEqual(len(cache), 5)


class TestRatchetEncryptDecrypt(unittest.TestCase):

    def test_in_order_roundtrip(self):
        alice, bob, cache = _make_sessions()
        plaintext = b"Hello, Bob!"
        env = alice.encrypt(plaintext)
        recovered = bob.decrypt(env, cache=cache)
        self.assertEqual(recovered, plaintext)

    def test_multiple_messages_in_order(self):
        alice, bob, cache = _make_sessions()
        messages = [f"Message {i}".encode() for i in range(20)]
        envelopes = [alice.encrypt(m) for m in messages]
        for env, expected in zip(envelopes, messages):
            self.assertEqual(bob.decrypt(env, cache=cache), expected)

    def test_step_increments(self):
        alice, bob, cache = _make_sessions()
        env0 = alice.encrypt(b"first")
        env1 = alice.encrypt(b"second")
        self.assertEqual(env0.step, 0)
        self.assertEqual(env1.step, 1)

    def test_out_of_order_delivery(self):
        alice, bob, cache = _make_sessions()
        env0 = alice.encrypt(b"first")
        env1 = alice.encrypt(b"second")
        env2 = alice.encrypt(b"third")

        # Deliver in reverse order: 2, 1, 0
        self.assertEqual(bob.decrypt(env2, cache=cache), b"third")
        self.assertEqual(bob.decrypt(env1, cache=cache), b"second")
        self.assertEqual(bob.decrypt(env0, cache=cache), b"first")

    def test_each_envelope_is_unique(self):
        alice, bob, cache = _make_sessions()
        e1 = alice.encrypt(b"same content")
        e2 = alice.encrypt(b"same content")
        self.assertNotEqual(e1.ciphertext_b64, e2.ciphertext_b64)
        self.assertNotEqual(e1.nonce_b64, e2.nonce_b64)

    def test_tampered_ciphertext_raises(self):
        import base64 as b64
        from cryptography.exceptions import InvalidTag
        alice, bob, cache = _make_sessions()
        env = alice.encrypt(b"secret")
        bad_ct = b64.b64encode(b"\x00" * 32).decode()
        env.ciphertext_b64 = bad_ct
        with self.assertRaises(InvalidTag):
            bob.decrypt(env, cache=cache)

    def test_envelope_json_roundtrip(self):
        from warden.syndicates.ratchet import RatchetEnvelope
        alice, bob, cache = _make_sessions()
        env = alice.encrypt(b"json test")
        j   = env.to_json()
        env2 = RatchetEnvelope.from_json(j)
        self.assertEqual(bob.decrypt(env2, cache=cache), b"json test")


class TestRatchetTierInterval(unittest.TestCase):

    def test_individual_interval_is_1(self):
        from warden.syndicates.ratchet import _get_ratchet_interval
        self.assertEqual(_get_ratchet_interval("individual"), 1)

    def test_business_interval_is_10(self):
        from warden.syndicates.ratchet import _get_ratchet_interval
        self.assertEqual(_get_ratchet_interval("business"), 10)

    def test_mcp_interval_is_50(self):
        from warden.syndicates.ratchet import _get_ratchet_interval
        self.assertEqual(_get_ratchet_interval("mcp"), 50)

    def test_dh_ratchet_fires_at_interval(self):
        """Root key should change at send_step = ratchet_interval."""
        alice, bob, cache = _make_sessions(tier="business")  # interval=10
        root_before = bytes(alice.root_key)
        # Send 10 messages (step 0..9)
        envelopes = [alice.encrypt(f"msg{i}".encode()) for i in range(10)]
        # At step 10, the DH ratchet should have advanced
        alice.encrypt(b"trigger")  # step 10
        root_after = bytes(alice.root_key)
        self.assertNotEqual(root_before, root_after, "Root key should advance at ratchet interval")


class TestRatchetSerialization(unittest.TestCase):

    def test_to_from_dict(self):
        from warden.syndicates.ratchet import RatchetSession
        secret = os.urandom(32)
        sid    = "ser-test"
        s1     = RatchetSession.from_shared_secret(secret, sid)
        # Encrypt some messages to advance state
        e1 = s1.encrypt(b"hello")
        e2 = s1.encrypt(b"world")

        d  = s1.to_dict()
        s2 = RatchetSession.from_dict(d)
        self.assertEqual(s2.session_id, s1.session_id)
        self.assertEqual(s2.send_step,  s1.send_step)
        self.assertEqual(s2.tier,       s1.tier)


if __name__ == "__main__":
    unittest.main(verbosity=2)
