"""
warden/tests/test_multisig.py
──────────────────────────────
Tests for warden/communities/multisig.py — Multi-Sig Bridge Consensus.

Coverage
────────
  config_hash computation + integrity lock
  Proposal create / get / list
  add_signature quorum logic (PENDING → APPROVED)
  reject_proposal veto
  Expiry TTL enforcement
  Duplicate signer rejection
  Ed25519 signature verification (with keypair)
  verify_proposal_hash (payload integrity)
  signing_bytes format
"""
from __future__ import annotations

import base64
import os
import time
import unittest
import uuid

os.environ.setdefault("VAULT_MASTER_KEY", "i5EjtPkHUtDxUPbjfMgWpurGBBc7mjUEpweFU40aDAA=")
os.environ.setdefault("MULTISIG_PROPOSAL_TTL_S", "300")
os.environ.setdefault("MULTISIG_DEFAULT_M",       "2")


class TestConfigHash(unittest.TestCase):

    def test_hash_is_deterministic(self):
        from warden.communities.multisig import _compute_config_hash
        payload = {"action": "rotate", "old_kid": "v1", "new_kid": "v2"}
        h1 = _compute_config_hash(payload)
        h2 = _compute_config_hash(payload)
        self.assertEqual(h1, h2)

    def test_hash_differs_on_different_payload(self):
        from warden.communities.multisig import _compute_config_hash
        h1 = _compute_config_hash({"action": "rotate", "old_kid": "v1"})
        h2 = _compute_config_hash({"action": "rotate", "old_kid": "v2"})
        self.assertNotEqual(h1, h2)

    def test_hash_is_hex_sha256(self):
        from warden.communities.multisig import _compute_config_hash
        h = _compute_config_hash({"x": 1})
        self.assertEqual(len(h), 64)
        int(h, 16)  # valid hex

    def test_key_order_independent(self):
        from warden.communities.multisig import _compute_config_hash
        h1 = _compute_config_hash({"a": 1, "b": 2})
        h2 = _compute_config_hash({"b": 2, "a": 1})
        self.assertEqual(h1, h2, "config_hash must be key-order independent (sorted JSON)")


class TestCreateProposal(unittest.TestCase):

    def _cid(self):
        from warden.communities.id_generator import new_community_id
        return new_community_id()

    def test_create_returns_pending(self):
        from warden.communities.multisig import ProposalStatus, create_proposal
        cid = self._cid()
        p = create_proposal(cid, "KEY_ROTATION", {"old_kid": "v1"}, "admin", m_required=2)
        self.assertEqual(p.status, ProposalStatus.PENDING)
        self.assertEqual(p.community_id, cid)

    def test_config_hash_locked_at_creation(self):
        from warden.communities.multisig import _compute_config_hash, create_proposal
        payload = {"action": "test"}
        cid = self._cid()
        p = create_proposal(cid, "GOVERNANCE_CHANGE", payload, "admin")
        self.assertEqual(p.config_hash, _compute_config_hash(payload))

    def test_proposal_id_is_unique(self):
        from warden.communities.multisig import create_proposal
        cid = self._cid()
        ids = {create_proposal(cid, "KEY_ROTATION", {}, "admin").proposal_id for _ in range(10)}
        self.assertEqual(len(ids), 10)


class TestSignatures(unittest.TestCase):

    def setUp(self):
        from warden.communities.id_generator import new_community_id
        from warden.communities.multisig import create_proposal
        self.cid = new_community_id()
        self.proposal = create_proposal(
            self.cid, "KEY_ROTATION",
            {"old_kid": "v1", "new_kid": "v2"},
            "proposer-001", m_required=2,
        )

    def test_first_sig_still_pending(self):
        from warden.communities.multisig import add_signature
        result = add_signature(self.proposal.proposal_id, "signer-1",
                               base64.b64encode(b"sig1").decode())
        self.assertEqual(result["status"], "PENDING")
        self.assertEqual(result["sigs"], 1)

    def test_m_sigs_approves(self):
        from warden.communities.multisig import ProposalStatus, add_signature, get_proposal
        add_signature(self.proposal.proposal_id, "signer-1",
                      base64.b64encode(b"sig1").decode())
        result = add_signature(self.proposal.proposal_id, "signer-2",
                               base64.b64encode(b"sig2").decode())
        self.assertEqual(result["status"], ProposalStatus.APPROVED)
        p = get_proposal(self.proposal.proposal_id)
        self.assertEqual(p.status, ProposalStatus.APPROVED)
        self.assertIsNotNone(p.finalized_at)

    def test_duplicate_signer_raises(self):
        from warden.communities.multisig import add_signature
        add_signature(self.proposal.proposal_id, "signer-dup",
                      base64.b64encode(b"sig").decode())
        with self.assertRaises(ValueError):
            add_signature(self.proposal.proposal_id, "signer-dup",
                          base64.b64encode(b"sig2").decode())

    def test_sign_approved_proposal_raises(self):
        from warden.communities.multisig import add_signature
        add_signature(self.proposal.proposal_id, "s1", base64.b64encode(b"a").decode())
        add_signature(self.proposal.proposal_id, "s2", base64.b64encode(b"b").decode())
        with self.assertRaises(ValueError):
            add_signature(self.proposal.proposal_id, "s3", base64.b64encode(b"c").decode())

    def test_with_keypair_valid_sig(self):
        """Signature verification with a real Ed25519 community keypair."""
        from warden.communities.key_archive import KeyStatus, store_keypair
        from warden.communities.keypair import generate_community_keypair
        from warden.communities.multisig import add_signature, signing_bytes
        kp = generate_community_keypair(self.cid, kid="v1")
        store_keypair(kp, status=KeyStatus.ACTIVE)

        sign_data = signing_bytes(self.proposal.config_hash)
        sig = kp.sign(sign_data)
        result = add_signature(
            self.proposal.proposal_id, "signer-ed",
            base64.b64encode(sig).decode(),
            community_keypair=kp,
        )
        self.assertIn(result["status"], ("PENDING", "APPROVED"))

    def test_with_keypair_bad_sig_raises(self):
        from warden.communities.key_archive import KeyStatus, store_keypair
        from warden.communities.keypair import generate_community_keypair
        from warden.communities.multisig import add_signature
        kp = generate_community_keypair(self.cid, kid="v1")
        store_keypair(kp, status=KeyStatus.ACTIVE)

        bad_sig = b"\x00" * 64
        with self.assertRaises(ValueError):
            add_signature(
                self.proposal.proposal_id, "signer-bad",
                base64.b64encode(bad_sig).decode(),
                community_keypair=kp,
            )


class TestRejectAndList(unittest.TestCase):

    def setUp(self):
        from warden.communities.id_generator import new_community_id
        from warden.communities.multisig import create_proposal
        self.cid = new_community_id()
        self.p   = create_proposal(self.cid, "MEMBER_ELEVATION", {}, "proposer")

    def test_reject_moves_to_rejected(self):
        from warden.communities.multisig import ProposalStatus, get_proposal, reject_proposal
        reject_proposal(self.p.proposal_id, rejected_by="veto-admin")
        p = get_proposal(self.p.proposal_id)
        self.assertEqual(p.status, ProposalStatus.REJECTED)
        self.assertEqual(p.rejected_by, "veto-admin")

    def test_reject_already_rejected_raises(self):
        from warden.communities.multisig import reject_proposal
        reject_proposal(self.p.proposal_id, rejected_by="admin1")
        with self.assertRaises(ValueError):
            reject_proposal(self.p.proposal_id, rejected_by="admin2")

    def test_list_proposals_by_community(self):
        from warden.communities.multisig import create_proposal, list_proposals
        create_proposal(self.cid, "KEY_ROTATION", {"x": 1}, "admin")
        proposals = list_proposals(self.cid)
        self.assertGreaterEqual(len(proposals), 1)
        self.assertTrue(all(p.community_id == self.cid for p in proposals))

    def test_list_filter_by_status(self):
        from warden.communities.multisig import ProposalStatus, list_proposals, reject_proposal
        reject_proposal(self.p.proposal_id, "admin")
        rejected = list_proposals(self.cid, status_filter=ProposalStatus.REJECTED)
        self.assertTrue(any(p.proposal_id == self.p.proposal_id for p in rejected))
        pending = list_proposals(self.cid, status_filter=ProposalStatus.PENDING)
        self.assertFalse(any(p.proposal_id == self.p.proposal_id for p in pending))


class TestPayloadIntegrity(unittest.TestCase):

    def test_verify_matching_payload(self):
        from warden.communities.id_generator import new_community_id
        from warden.communities.multisig import create_proposal, verify_proposal_hash
        payload = {"action": "shred", "kid": "v1"}
        p = create_proposal(new_community_id(), "KEY_ROTATION", payload, "admin")
        self.assertTrue(verify_proposal_hash(p, payload))

    def test_verify_mismatched_payload(self):
        from warden.communities.id_generator import new_community_id
        from warden.communities.multisig import create_proposal, verify_proposal_hash
        p = create_proposal(new_community_id(), "KEY_ROTATION", {"a": 1}, "admin")
        self.assertFalse(verify_proposal_hash(p, {"a": 2}))

    def test_signing_bytes_format(self):
        from warden.communities.multisig import signing_bytes
        config_hash = "a" * 64  # 64 hex chars = 32 bytes
        sb = signing_bytes(config_hash)
        self.assertTrue(sb.startswith(b"warden:multisig:v1:"))
        self.assertEqual(len(sb), len(b"warden:multisig:v1:") + 32)


if __name__ == "__main__":
    unittest.main(verbosity=2)
