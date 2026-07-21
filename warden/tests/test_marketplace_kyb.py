"""
Tests for warden/marketplace/kyb.py — Know Your Business (KYB), FT-5.

KYB is never self-triggered here (that wiring is covered in
test_marketplace_kya.py's escalation tests) — this file exercises the KYB
state machine directly: require -> submit -> verify/reject, draft-only
(the system never self-verifies), and idempotency of require_kyb().
"""
from __future__ import annotations

import pytest

from warden.marketplace import kyb


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(kyb, "_DB_PATH", str(tmp_path / "kyb_test.db"))


class TestRequireKyb:
    def test_creates_required_record(self):
        rec = kyb.require_kyb("tenant-A", reason="kya_flagged:HIGH_VELOCITY")
        assert rec.owner_tenant_id == "tenant-A"
        assert rec.kyb_status == "REQUIRED"
        assert rec.triggered_by == "kya_flagged:HIGH_VELOCITY"

    def test_idempotent_does_not_downgrade_submitted(self):
        kyb.require_kyb("tenant-B", reason="first_trigger")
        kyb.submit_kyb("tenant-B", business_name="Acme Corp")
        rec = kyb.require_kyb("tenant-B", reason="second_trigger")
        assert rec.kyb_status == "SUBMITTED"
        assert rec.triggered_by == "first_trigger"  # unchanged

    def test_idempotent_does_not_downgrade_verified(self):
        kyb.require_kyb("tenant-C", reason="trigger")
        kyb.submit_kyb("tenant-C", business_name="Acme Corp")
        kyb.verify_kyb("tenant-C", reviewed_by="officer-1", approved=True)
        rec = kyb.require_kyb("tenant-C", reason="another_trigger")
        assert rec.kyb_status == "VERIFIED"


class TestSubmitKyb:
    def test_submit_moves_to_submitted(self):
        kyb.require_kyb("tenant-D", reason="trigger")
        rec = kyb.submit_kyb("tenant-D", business_name="Acme LLC", jurisdiction="US-DE",
                              registration_number="123456")
        assert rec.kyb_status == "SUBMITTED"
        assert rec.business_name == "Acme LLC"
        assert rec.jurisdiction == "US-DE"
        assert rec.registration_number == "123456"
        assert rec.submitted_at

    def test_submit_without_prior_requirement_raises(self):
        with pytest.raises(ValueError):
            kyb.submit_kyb("tenant-nonexistent", business_name="Ghost Inc")

    def test_resubmit_after_rejection_allowed(self):
        kyb.require_kyb("tenant-E", reason="trigger")
        kyb.submit_kyb("tenant-E", business_name="Bad Name")
        kyb.verify_kyb("tenant-E", reviewed_by="officer-1", approved=False)
        rec = kyb.submit_kyb("tenant-E", business_name="Corrected Name")
        assert rec.kyb_status == "SUBMITTED"
        assert rec.business_name == "Corrected Name"

    def test_resubmit_when_already_submitted_is_noop(self):
        kyb.require_kyb("tenant-F", reason="trigger")
        kyb.submit_kyb("tenant-F", business_name="First Name")
        rec = kyb.submit_kyb("tenant-F", business_name="Second Name")
        assert rec.business_name == "First Name"  # unchanged — no-op

    def test_resubmit_when_verified_is_noop(self):
        kyb.require_kyb("tenant-G", reason="trigger")
        kyb.submit_kyb("tenant-G", business_name="Verified Co")
        kyb.verify_kyb("tenant-G", reviewed_by="officer-1", approved=True)
        rec = kyb.submit_kyb("tenant-G", business_name="Attempted Change")
        assert rec.kyb_status == "VERIFIED"
        assert rec.business_name == "Verified Co"


class TestVerifyKyb:
    def test_verify_approve_sets_verified(self):
        kyb.require_kyb("tenant-H", reason="trigger")
        kyb.submit_kyb("tenant-H", business_name="Good Co")
        rec = kyb.verify_kyb("tenant-H", reviewed_by="officer-2", approved=True)
        assert rec.kyb_status == "VERIFIED"
        assert rec.reviewed_by == "officer-2"
        assert rec.verified_at

    def test_verify_reject_sets_rejected(self):
        kyb.require_kyb("tenant-I", reason="trigger")
        kyb.submit_kyb("tenant-I", business_name="Bad Co")
        rec = kyb.verify_kyb("tenant-I", reviewed_by="officer-2", approved=False)
        assert rec.kyb_status == "REJECTED"

    def test_verify_without_submission_raises(self):
        kyb.require_kyb("tenant-J", reason="trigger")
        with pytest.raises(ValueError):
            kyb.verify_kyb("tenant-J", reviewed_by="officer-2", approved=True)

    def test_verify_nonexistent_tenant_raises(self):
        with pytest.raises(ValueError):
            kyb.verify_kyb("tenant-ghost", reviewed_by="officer-2", approved=True)

    def test_verify_already_verified_raises(self):
        kyb.require_kyb("tenant-K", reason="trigger")
        kyb.submit_kyb("tenant-K", business_name="Co")
        kyb.verify_kyb("tenant-K", reviewed_by="officer-2", approved=True)
        with pytest.raises(ValueError):
            kyb.verify_kyb("tenant-K", reviewed_by="officer-3", approved=True)


class TestStatusReads:
    def test_get_status_not_required_when_untouched(self):
        assert kyb.get_kyb_status("tenant-untouched") == "NOT_REQUIRED"

    def test_get_status_tracks_lifecycle(self):
        kyb.require_kyb("tenant-L", reason="trigger")
        assert kyb.get_kyb_status("tenant-L") == "REQUIRED"
        kyb.submit_kyb("tenant-L", business_name="Co")
        assert kyb.get_kyb_status("tenant-L") == "SUBMITTED"
        kyb.verify_kyb("tenant-L", reviewed_by="officer-1", approved=True)
        assert kyb.get_kyb_status("tenant-L") == "VERIFIED"

    def test_get_record_unknown_returns_none(self):
        assert kyb.get_kyb_record("tenant-unknown") is None

    def test_get_record_returns_full_record(self):
        kyb.require_kyb("tenant-M", reason="trigger")
        rec = kyb.get_kyb_record("tenant-M")
        assert rec is not None
        assert rec.owner_tenant_id == "tenant-M"


class TestKybBlocksParticipation:
    def test_not_required_does_not_block(self):
        assert kyb.kyb_blocks_participation("tenant-never-flagged") is False

    def test_required_blocks(self):
        kyb.require_kyb("tenant-N", reason="trigger")
        assert kyb.kyb_blocks_participation("tenant-N") is True

    def test_submitted_blocks(self):
        kyb.require_kyb("tenant-O", reason="trigger")
        kyb.submit_kyb("tenant-O", business_name="Co")
        assert kyb.kyb_blocks_participation("tenant-O") is True

    def test_verified_does_not_block(self):
        kyb.require_kyb("tenant-P", reason="trigger")
        kyb.submit_kyb("tenant-P", business_name="Co")
        kyb.verify_kyb("tenant-P", reviewed_by="officer-1", approved=True)
        assert kyb.kyb_blocks_participation("tenant-P") is False

    def test_rejected_blocks(self):
        kyb.require_kyb("tenant-Q", reason="trigger")
        kyb.submit_kyb("tenant-Q", business_name="Co")
        kyb.verify_kyb("tenant-Q", reviewed_by="officer-1", approved=False)
        assert kyb.kyb_blocks_participation("tenant-Q") is True


class TestToDict:
    def test_to_dict_returns_dict(self):
        rec = kyb.require_kyb("tenant-R", reason="trigger")
        d = rec.to_dict()
        assert isinstance(d, dict)
        assert d["owner_tenant_id"] == "tenant-R"
        assert d["kyb_status"] == "REQUIRED"
