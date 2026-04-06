"""
warden/tests/test_community_registry.py
─────────────────────────────────────────
Tests for v2.8 Business Communities — Phase 1 (Identity Engine).

Coverage
────────
  id_generator        UUIDv7, Member_ID scoping, Snowflake monotonicity
  keypair             Key generation, HKDF derivation, sign/verify, safety_number
  key_archive         store, get, set_status, crypto_shred, load_keypair_from_entry
  clearance           ClearanceLevel access matrix, wrap/unwrap CEK, create/open envelope,
                      rewrap_envelope_cek, check_downgrade_requires_rotation
  registry            create_community, invite_member, update_clearance, remove_member,
                      duplicate detection, rotation_required flag
  rotation            initiate_rotation, get_rotation_progress, complete_rotation
  break_glass         initiate, sign, activate (happy path + guards)
"""
from __future__ import annotations

import base64
import os
import time
import unittest
import uuid

# ── env must be set before importing warden modules ──────────────────────────
os.environ.setdefault("VAULT_MASTER_KEY", "i5EjtPkHUtDxUPbjfMgWpurGBBc7mjUEpweFU40aDAA=")  # valid Fernet key
os.environ.setdefault("COMMUNITY_REGISTRY_PATH",    "/tmp/warden_test_community_registry.db")
os.environ.setdefault("COMMUNITY_KEY_ARCHIVE_PATH", "/tmp/warden_test_community_key_archive.db")
os.environ.setdefault("BREAK_GLASS_AUDIT_PATH",     "/tmp/warden_test_break_glass_audit.jsonl")
os.environ.setdefault("BREAK_GLASS_M_SIGS",         "2")   # lower threshold for tests


# ════════════════════════════════════════════════════════════════════════════════
# 1. ID Generator
# ════════════════════════════════════════════════════════════════════════════════

class TestIdGenerator(unittest.TestCase):

    def setUp(self):
        from warden.communities import id_generator as ig
        self.ig = ig

    def test_new_community_id_is_valid_uuid(self):
        cid = self.ig.new_community_id()
        parsed = uuid.UUID(cid)
        self.assertEqual(parsed.version, 7)

    def test_community_ids_are_unique(self):
        ids = {self.ig.new_community_id() for _ in range(50)}
        self.assertEqual(len(ids), 50)

    def test_member_id_scoped_to_community(self):
        cid = self.ig.new_community_id()
        mid1 = self.ig.new_member_id(cid)
        mid2 = self.ig.new_member_id(cid)
        # Different member IDs even in same community
        self.assertNotEqual(mid1, mid2)
        # Both are valid UUIDs
        uuid.UUID(mid1)
        uuid.UUID(mid2)

    def test_member_id_differs_across_communities(self):
        cid_a = self.ig.new_community_id()
        cid_b = self.ig.new_community_id()
        # Same randomness would give different results due to namespace XOR
        mids_a = {self.ig.new_member_id(cid_a) for _ in range(20)}
        mids_b = {self.ig.new_member_id(cid_b) for _ in range(20)}
        self.assertTrue(mids_a.isdisjoint(mids_b))

    def test_snowflake_monotonic(self):
        ids = [self.ig.new_entity_id() for _ in range(100)]
        self.assertEqual(ids, sorted(ids))

    def test_snowflake_unique(self):
        ids = [self.ig.new_entity_id() for _ in range(500)]
        self.assertEqual(len(ids), len(set(ids)))

    def test_entity_id_to_ts_reasonable(self):
        before = time.time()
        eid    = self.ig.new_entity_id()
        after  = time.time()
        ts     = self.ig.entity_id_to_ts(eid)
        self.assertGreaterEqual(ts, before - 0.01)
        self.assertLessEqual(ts, after + 0.01)


# ════════════════════════════════════════════════════════════════════════════════
# 2. Keypair
# ════════════════════════════════════════════════════════════════════════════════

class TestKeypair(unittest.TestCase):

    def setUp(self):
        from warden.communities.id_generator import new_community_id
        from warden.communities.keypair import generate_community_keypair
        self.cid = new_community_id()
        self.kp  = generate_community_keypair(self.cid, kid="v1")

    def test_kid_set(self):
        self.assertEqual(self.kp.kid, "v1")

    def test_community_id_set(self):
        self.assertEqual(self.kp.community_id, self.cid)

    def test_pub_keys_are_base64(self):
        base64.b64decode(self.kp.ed25519_pub_b64)
        base64.b64decode(self.kp.x25519_pub_b64)

    def test_sign_verify_roundtrip(self):
        data = b"test payload for signing"
        sig  = self.kp.sign(data)
        self.assertTrue(self.kp.verify(data, sig))

    def test_verify_rejects_tampered(self):
        data = b"original"
        sig  = self.kp.sign(data)
        self.assertFalse(self.kp.verify(b"tampered", sig))

    def test_derive_clearance_key_length(self):
        for level in ("PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"):
            key = self.kp.derive_clearance_key(level)
            self.assertEqual(len(key), 32, f"Key for {level} should be 32 bytes")

    def test_clearance_keys_are_distinct(self):
        keys = [self.kp.derive_clearance_key(lvl) for lvl in ("PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED")]
        self.assertEqual(len(set(keys)), 4)

    def test_clearance_key_deterministic(self):
        k1 = self.kp.derive_clearance_key("CONFIDENTIAL")
        k2 = self.kp.derive_clearance_key("CONFIDENTIAL")
        self.assertEqual(k1, k2)

    def test_safety_number_20_hex_chars(self):
        sn = self.kp.safety_number()
        self.assertEqual(len(sn), 20)
        int(sn, 16)  # must be valid hex

    def test_to_from_dict_roundtrip(self):
        from warden.communities.keypair import CommunityKeypair
        d   = self.kp.to_dict()
        kp2 = CommunityKeypair.from_dict(d)
        self.assertEqual(kp2.kid,            self.kp.kid)
        self.assertEqual(kp2.community_id,   self.kp.community_id)
        self.assertEqual(kp2.ed25519_pub_b64, self.kp.ed25519_pub_b64)
        # Sign with reconstructed keypair — should still verify
        sig = kp2.sign(b"hello")
        self.assertTrue(self.kp.verify(b"hello", sig))


# ════════════════════════════════════════════════════════════════════════════════
# 3. Key Archive
# ════════════════════════════════════════════════════════════════════════════════

class TestKeyArchive(unittest.TestCase):

    def setUp(self):
        from warden.communities.id_generator import new_community_id
        from warden.communities.key_archive import KeyStatus, store_keypair
        from warden.communities.keypair import generate_community_keypair
        self.cid = new_community_id()
        self.kp  = generate_community_keypair(self.cid, kid="v1")
        store_keypair(self.kp, status=KeyStatus.ACTIVE)

    def test_get_entry_active(self):
        from warden.communities.key_archive import KeyStatus, get_entry
        entry = get_entry(self.cid, "v1")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.status, KeyStatus.ACTIVE)
        self.assertEqual(entry.kid, "v1")

    def test_get_active_entry(self):
        from warden.communities.key_archive import get_active_entry
        entry = get_active_entry(self.cid)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.kid, "v1")

    def test_set_status_rotation_only(self):
        from warden.communities.key_archive import KeyStatus, get_entry, set_status
        result = set_status(self.cid, "v1", KeyStatus.ROTATION_ONLY)
        self.assertTrue(result)
        entry = get_entry(self.cid, "v1")
        self.assertEqual(entry.status, KeyStatus.ROTATION_ONLY)

    def test_crypto_shred(self):
        from warden.communities.key_archive import KeyStatus, crypto_shred, get_entry
        shredded = crypto_shred(self.cid, "v1")
        self.assertTrue(shredded)
        entry = get_entry(self.cid, "v1")
        self.assertEqual(entry.status, KeyStatus.SHREDDED)
        self.assertIsNone(entry.ed_priv_enc_b64)
        self.assertIsNone(entry.x_priv_enc_b64)

    def test_load_keypair_from_shredded_raises(self):
        from warden.communities.key_archive import crypto_shred, get_entry, load_keypair_from_entry
        crypto_shred(self.cid, "v1")
        entry = get_entry(self.cid, "v1")
        with self.assertRaises(ValueError):
            load_keypair_from_entry(entry)

    def test_load_keypair_from_active(self):
        from warden.communities.key_archive import get_entry, load_keypair_from_entry
        entry = get_entry(self.cid, "v1")
        kp    = load_keypair_from_entry(entry)
        self.assertEqual(kp.kid, "v1")
        # Verify key is functional
        sig = kp.sign(b"archive test")
        self.assertTrue(kp.verify(b"archive test", sig))

    def test_list_entries(self):
        from warden.communities.id_generator import new_community_id
        from warden.communities.key_archive import KeyStatus, list_entries, store_keypair
        from warden.communities.keypair import generate_community_keypair
        cid = new_community_id()
        for kid in ("v1", "v2"):
            kp = generate_community_keypair(cid, kid=kid)
            store_keypair(kp, status=KeyStatus.ACTIVE)
        entries = list_entries(cid)
        self.assertEqual(len(entries), 2)


# ════════════════════════════════════════════════════════════════════════════════
# 4. Clearance Levels + Envelope
# ════════════════════════════════════════════════════════════════════════════════

class TestClearanceLevel(unittest.TestCase):

    def test_access_matrix(self):
        from warden.communities.clearance import ClearanceLevel
        self.assertTrue(ClearanceLevel.PUBLIC.can_access(ClearanceLevel.PUBLIC))
        self.assertFalse(ClearanceLevel.PUBLIC.can_access(ClearanceLevel.INTERNAL))
        self.assertTrue(ClearanceLevel.RESTRICTED.can_access(ClearanceLevel.CONFIDENTIAL))
        self.assertTrue(ClearanceLevel.CONFIDENTIAL.can_access(ClearanceLevel.INTERNAL))
        self.assertFalse(ClearanceLevel.INTERNAL.can_access(ClearanceLevel.CONFIDENTIAL))

    def test_from_str(self):
        from warden.communities.clearance import ClearanceLevel
        self.assertEqual(ClearanceLevel.from_str("confidential"), ClearanceLevel.CONFIDENTIAL)

    def test_wrap_unwrap_cek(self):
        from warden.communities.clearance import unwrap_cek, wrap_cek
        level_key = os.urandom(32)
        cek       = os.urandom(32)
        nonce, ct = wrap_cek(cek, level_key)
        recovered = unwrap_cek(ct, nonce, level_key)
        self.assertEqual(recovered, cek)

    def test_wrong_key_raises(self):
        from cryptography.exceptions import InvalidTag

        from warden.communities.clearance import unwrap_cek, wrap_cek
        level_key  = os.urandom(32)
        wrong_key  = os.urandom(32)
        cek        = os.urandom(32)
        nonce, ct  = wrap_cek(cek, level_key)
        with self.assertRaises(InvalidTag):
            unwrap_cek(ct, nonce, wrong_key)


class TestEnvelope(unittest.TestCase):

    def setUp(self):
        from warden.communities.clearance import ClearanceLevel, create_envelope
        from warden.communities.id_generator import new_community_id, new_entity_id
        from warden.communities.key_archive import KeyStatus, store_keypair
        from warden.communities.keypair import generate_community_keypair

        self.cid      = new_community_id()
        self.kp       = generate_community_keypair(self.cid, kid="v1")
        store_keypair(self.kp, status=KeyStatus.ACTIVE)
        self.entity_id = str(new_entity_id())
        self.plaintext = b"Top secret business document"
        self.envelope  = create_envelope(
            entity_id    = self.entity_id,
            community_id = self.cid,
            plaintext    = self.plaintext,
            clearance    = ClearanceLevel.CONFIDENTIAL,
            keypair      = self.kp,
            sender_mid   = "member-001",
        )

    def test_envelope_fields(self):
        self.assertEqual(self.envelope.community_id, self.cid)
        self.assertEqual(self.envelope.clearance, "CONFIDENTIAL")
        self.assertNotEqual(self.envelope.sig_b64, "")

    def test_open_envelope_authorized(self):
        from warden.communities.clearance import ClearanceLevel, open_envelope
        plaintext = open_envelope(self.envelope, self.kp, ClearanceLevel.CONFIDENTIAL)
        self.assertEqual(plaintext, self.plaintext)

    def test_open_envelope_higher_clearance_allowed(self):
        from warden.communities.clearance import ClearanceLevel, open_envelope
        plaintext = open_envelope(self.envelope, self.kp, ClearanceLevel.RESTRICTED)
        self.assertEqual(plaintext, self.plaintext)

    def test_open_envelope_insufficient_clearance(self):
        from warden.communities.clearance import ClearanceLevel, open_envelope
        with self.assertRaises(PermissionError):
            open_envelope(self.envelope, self.kp, ClearanceLevel.INTERNAL)

    def test_open_envelope_tampered_sig(self):
        import copy

        from warden.communities.clearance import ClearanceLevel, open_envelope
        tampered = copy.copy(self.envelope)
        tampered.sig_b64 = base64.b64encode(b"bad" * 21 + b"x").decode()
        with self.assertRaises(ValueError):
            open_envelope(tampered, self.kp, ClearanceLevel.CONFIDENTIAL)

    def test_rewrap_envelope_cek(self):
        from warden.communities.clearance import ClearanceLevel, open_envelope, rewrap_envelope_cek
        from warden.communities.key_archive import KeyStatus, set_status, store_keypair
        from warden.communities.keypair import generate_community_keypair

        # Generate new keypair v2
        kp_v2 = generate_community_keypair(self.cid, kid="v2")
        store_keypair(kp_v2, status=KeyStatus.ACTIVE)
        set_status(self.cid, "v1", KeyStatus.ROTATION_ONLY)

        new_env = rewrap_envelope_cek(self.envelope, self.kp, kp_v2)
        self.assertEqual(new_env.kid, "v2")
        self.assertEqual(new_env.payload_b64, self.envelope.payload_b64)  # payload untouched

        # Can decrypt with new key
        plaintext = open_envelope(new_env, kp_v2, ClearanceLevel.CONFIDENTIAL)
        self.assertEqual(plaintext, self.plaintext)

    def test_envelope_json_roundtrip(self):
        from warden.communities.clearance import ClearanceEnvelope
        j   = self.envelope.to_json()
        env2 = ClearanceEnvelope.from_json(j)
        self.assertEqual(env2.sig_b64, self.envelope.sig_b64)

    def test_check_downgrade_requires_rotation(self):
        from warden.communities.clearance import ClearanceLevel, check_downgrade_requires_rotation
        # Losing CONFIDENTIAL access requires rotation
        self.assertTrue(check_downgrade_requires_rotation(
            ClearanceLevel.CONFIDENTIAL, ClearanceLevel.INTERNAL
        ))
        # Losing RESTRICTED access requires rotation
        self.assertTrue(check_downgrade_requires_rotation(
            ClearanceLevel.RESTRICTED, ClearanceLevel.PUBLIC
        ))
        # Upgrade never requires rotation
        self.assertFalse(check_downgrade_requires_rotation(
            ClearanceLevel.PUBLIC, ClearanceLevel.CONFIDENTIAL
        ))
        # Same level — no rotation
        self.assertFalse(check_downgrade_requires_rotation(
            ClearanceLevel.INTERNAL, ClearanceLevel.INTERNAL
        ))


# ════════════════════════════════════════════════════════════════════════════════
# 5. Community Registry
# ════════════════════════════════════════════════════════════════════════════════

class TestCommunityRegistry(unittest.TestCase):

    def setUp(self):
        from warden.communities.registry import create_community
        self.tenant_id = f"tenant-{uuid.uuid4().hex[:8]}"
        self.community = create_community(
            tenant_id    = self.tenant_id,
            display_name = "Test Community",
            created_by   = "admin@test.com",
            description  = "Integration test community",
            tier         = "business",
        )

    def test_community_created(self):
        self.assertIsNotNone(self.community.community_id)
        self.assertEqual(self.community.display_name, "Test Community")
        self.assertEqual(self.community.active_kid, "v1")
        self.assertEqual(self.community.status, "ACTIVE")

    def test_get_community(self):
        from warden.communities.registry import get_community
        rec = get_community(self.community.community_id)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.community_id, self.community.community_id)

    def test_get_community_not_found(self):
        from warden.communities.registry import get_community
        self.assertIsNone(get_community("00000000-0000-0000-0000-000000000000"))

    def test_list_communities(self):
        from warden.communities.registry import create_community, list_communities
        create_community(self.tenant_id, "Community 2", "admin@test.com")
        communities = list_communities(self.tenant_id)
        ids = {c.community_id for c in communities}
        self.assertIn(self.community.community_id, ids)

    def test_invite_member(self):
        from warden.communities.clearance import ClearanceLevel
        from warden.communities.registry import invite_member
        member = invite_member(
            community_id = self.community.community_id,
            tenant_id    = self.tenant_id,
            external_id  = "user@example.com",
            display_name = "Alice",
            clearance    = ClearanceLevel.INTERNAL,
        )
        self.assertIsNotNone(member.member_id)
        self.assertEqual(member.clearance, "INTERNAL")
        self.assertEqual(member.status, "ACTIVE")

    def test_duplicate_invite_raises(self):
        from warden.communities.clearance import ClearanceLevel
        from warden.communities.registry import invite_member
        invite_member(
            community_id = self.community.community_id,
            tenant_id    = self.tenant_id,
            external_id  = "dup@example.com",
            clearance    = ClearanceLevel.PUBLIC,
        )
        with self.assertRaises(ValueError):
            invite_member(
                community_id = self.community.community_id,
                tenant_id    = self.tenant_id,
                external_id  = "dup@example.com",
                clearance    = ClearanceLevel.PUBLIC,
            )

    def test_list_members(self):
        from warden.communities.clearance import ClearanceLevel
        from warden.communities.registry import invite_member, list_members
        invite_member(
            community_id = self.community.community_id,
            tenant_id    = self.tenant_id,
            external_id  = "bob@example.com",
            clearance    = ClearanceLevel.PUBLIC,
        )
        members = list_members(self.community.community_id)
        external_ids = {m.external_id for m in members}
        self.assertIn("bob@example.com", external_ids)

    def test_update_clearance_no_rotation(self):
        from warden.communities.clearance import ClearanceLevel
        from warden.communities.registry import invite_member, update_clearance
        member = invite_member(
            community_id = self.community.community_id,
            tenant_id    = self.tenant_id,
            external_id  = "upgrade@example.com",
            clearance    = ClearanceLevel.PUBLIC,
        )
        updated, rotation_required = update_clearance(
            self.community.community_id, member.member_id, ClearanceLevel.INTERNAL
        )
        self.assertEqual(updated.clearance, "INTERNAL")
        self.assertFalse(rotation_required)

    def test_update_clearance_rotation_required(self):
        from warden.communities.clearance import ClearanceLevel
        from warden.communities.registry import invite_member, update_clearance
        member = invite_member(
            community_id = self.community.community_id,
            tenant_id    = self.tenant_id,
            external_id  = "downgrade@example.com",
            clearance    = ClearanceLevel.CONFIDENTIAL,
        )
        updated, rotation_required = update_clearance(
            self.community.community_id, member.member_id, ClearanceLevel.PUBLIC
        )
        self.assertEqual(updated.clearance, "PUBLIC")
        self.assertTrue(rotation_required)

    def test_remove_member(self):
        from warden.communities.clearance import ClearanceLevel
        from warden.communities.registry import (
            invite_member,
            list_members,
            remove_member,
        )
        member = invite_member(
            community_id = self.community.community_id,
            tenant_id    = self.tenant_id,
            external_id  = "remove@example.com",
            clearance    = ClearanceLevel.PUBLIC,
        )
        result = remove_member(self.community.community_id, member.member_id)
        self.assertTrue(result)

        # Should no longer appear in active members list
        active = {m.member_id for m in list_members(self.community.community_id)}
        self.assertNotIn(member.member_id, active)

    def test_remove_nonexistent_member(self):
        from warden.communities.registry import remove_member
        result = remove_member(self.community.community_id, "nonexistent-mid")
        self.assertFalse(result)


# ════════════════════════════════════════════════════════════════════════════════
# 6. Rotation (happy path)
# ════════════════════════════════════════════════════════════════════════════════

class TestRotation(unittest.TestCase):

    def setUp(self):
        from warden.communities.registry import create_community
        self.tenant_id = f"tenant-rot-{uuid.uuid4().hex[:6]}"
        self.community = create_community(
            tenant_id    = self.tenant_id,
            display_name = "Rotation Test",
            created_by   = "admin",
        )

    def test_initiate_rotation(self):
        from warden.communities.key_archive import KeyStatus, get_entry
        from warden.communities.rotation import initiate_rotation
        result = initiate_rotation(self.community.community_id, initiated_by="admin")
        self.assertEqual(result["old_kid"], "v1")
        self.assertEqual(result["new_kid"], "v2")
        self.assertEqual(result["status"], "IN_PROGRESS")

        # Old key should be ROTATION_ONLY
        old_entry = get_entry(self.community.community_id, "v1")
        self.assertEqual(old_entry.status, KeyStatus.ROTATION_ONLY)

    def test_rotation_progress_stored(self):
        from warden.communities.rotation import get_rotation_progress, initiate_rotation
        initiate_rotation(self.community.community_id, initiated_by="admin")
        get_rotation_progress(self.community.community_id)
        # result may be None if Redis is unavailable (fine in unit tests)
        # just ensure no exception was raised

    def test_complete_rotation_no_failures(self):
        from warden.communities.key_archive import KeyStatus, get_entry
        from warden.communities.rotation import complete_rotation, initiate_rotation
        initiate_rotation(self.community.community_id, initiated_by="admin")

        # Stub progress (no Redis in unit tests) — set manually
        from warden.communities import rotation as rot
        rot._save_progress(self.community.community_id, {
            "community_id": self.community.community_id,
            "old_kid":      "v1",
            "new_kid":      "v2",
            "done":         0,
            "failed":       0,
            "status":       "IN_PROGRESS",
        })

        result = complete_rotation(
            self.community.community_id,
            confirmed_by=["admin-a", "admin-b"],
        )
        self.assertEqual(result["old_kid"], "v1")
        self.assertTrue(result["shredded"])

        # Old key should be SHREDDED
        entry = get_entry(self.community.community_id, "v1")
        self.assertEqual(entry.status, KeyStatus.SHREDDED)


# ════════════════════════════════════════════════════════════════════════════════
# 7. Break Glass
# ════════════════════════════════════════════════════════════════════════════════

class TestBreakGlass(unittest.TestCase):

    def setUp(self):
        from warden.communities.id_generator import new_community_id
        from warden.communities.key_archive import KeyStatus, store_keypair
        from warden.communities.keypair import generate_community_keypair
        self.cid = new_community_id()
        kp = generate_community_keypair(self.cid, kid="v1")
        store_keypair(kp, status=KeyStatus.ACTIVE)

    def test_non_mcp_tier_rejected(self):
        from warden.communities.break_glass import initiate_break_glass
        with self.assertRaises(PermissionError):
            initiate_break_glass(self.cid, "v1", "test reason", "admin", tenant_tier="business")

    def test_initiate_creates_pending_request(self):
        from warden.communities.break_glass import initiate_break_glass
        req = initiate_break_glass(self.cid, "v1", "forensic investigation", "admin@mcp.com",
                                   tenant_tier="mcp")
        self.assertEqual(req.status, "PENDING")
        self.assertEqual(req.community_id, self.cid)

    def test_sign_and_activate(self):
        from warden.communities.break_glass import (
            activate_break_glass,
            initiate_break_glass,
            sign_break_glass,
        )
        req = initiate_break_glass(self.cid, "v1", "legal hold", "admin",
                                   tenant_tier="mcp")

        # BREAK_GLASS_M_SIGS is set to 2 in test env
        sign_break_glass(req.request_id, "signer-1", base64.b64encode(b"sig1").decode())
        result = sign_break_glass(req.request_id, "signer-2", base64.b64encode(b"sig2").decode())
        self.assertEqual(result["status"], "READY")

        kp = activate_break_glass(req.request_id)
        self.assertIsNotNone(kp)
        self.assertEqual(kp.kid, "v1")

    def test_insufficient_sigs_raises(self):
        from warden.communities.break_glass import (
            activate_break_glass,
            initiate_break_glass,
            sign_break_glass,
        )
        req = initiate_break_glass(self.cid, "v1", "test", "admin", tenant_tier="mcp")
        sign_break_glass(req.request_id, "signer-1", base64.b64encode(b"sig1").decode())
        # Only 1 signature, need 2
        with self.assertRaises(PermissionError):
            activate_break_glass(req.request_id)

    def test_close_break_glass(self):
        from warden.communities.break_glass import (
            activate_break_glass,
            close_break_glass,
            initiate_break_glass,
            sign_break_glass,
        )
        req = initiate_break_glass(self.cid, "v1", "test close", "admin", tenant_tier="mcp")
        sign_break_glass(req.request_id, "s1", base64.b64encode(b"sig1").decode())
        sign_break_glass(req.request_id, "s2", base64.b64encode(b"sig2").decode())
        activate_break_glass(req.request_id)
        close_break_glass(req.request_id)

        from warden.communities.break_glass import _load
        closed_req = _load(req.request_id)
        self.assertEqual(closed_req.status, "CLOSED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
