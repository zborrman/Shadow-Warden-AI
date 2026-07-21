"""Tests for warden/marketplace/kyb.py — KYB (Know Your Business), sits behind KYA."""
import os

import pytest


@pytest.fixture(autouse=True)
def _isolate_kyb(tmp_path):
    """Each test gets its own SQLite DB and no Redis."""
    os.environ["MARKETPLACE_DB_PATH"] = str(tmp_path / "kyb_test.db")
    os.environ["REDIS_URL"] = "memory://"
    yield
    os.environ.pop("MARKETPLACE_DB_PATH", None)
    os.environ.pop("REDIS_URL", None)


class TestSubmission:
    def test_submit_creates_pending_record(self):
        from warden.marketplace.kyb import submit_for_review
        rec = submit_for_review("tenant-A", business_name="Acme Corp")
        assert rec.tenant_id == "tenant-A"
        assert rec.business_name == "Acme Corp"
        assert rec.kyb_status == "PENDING"
        assert rec.provider == "manual"

    def test_manual_provider_never_auto_decides(self):
        """v1's only provider always defers to a human — never auto-VERIFIED/REJECTED."""
        from warden.marketplace.kyb import submit_for_review
        for _ in range(5):
            rec = submit_for_review("tenant-repeat", business_name="Repeat Co")
            assert rec.kyb_status == "PENDING"

    def test_resubmit_is_idempotent_refresh(self):
        from warden.marketplace.kyb import get_kyb_record, submit_for_review
        submit_for_review("tenant-B", business_name="First Name")
        submit_for_review("tenant-B", business_name="Updated Name")
        rec = get_kyb_record("tenant-B")
        assert rec is not None
        assert rec.business_name == "Updated Name"
        assert rec.kyb_status == "PENDING"

    def test_get_kyb_record_unknown_returns_none(self):
        from warden.marketplace.kyb import get_kyb_record
        assert get_kyb_record("tenant-nonexistent") is None

    def test_get_kyb_status_unknown_returns_pending(self):
        from warden.marketplace.kyb import get_kyb_status
        assert get_kyb_status("tenant-unknown") == "PENDING"

    def test_get_kyb_status_empty_tenant_returns_pending(self):
        from warden.marketplace.kyb import get_kyb_status
        assert get_kyb_status("") == "PENDING"


class TestReview:
    def test_approve_sets_verified(self):
        from warden.marketplace.kyb import approve_kyb, get_kyb_status, submit_for_review
        submit_for_review("tenant-approve", business_name="Good Co")
        rec = approve_kyb("tenant-approve", reviewer="ops-1")
        assert rec.kyb_status == "VERIFIED"
        assert rec.reviewer == "ops-1"
        assert get_kyb_status("tenant-approve") == "VERIFIED"

    def test_reject_sets_rejected_with_reason(self):
        from warden.marketplace.kyb import get_kyb_record, reject_kyb, submit_for_review
        submit_for_review("tenant-reject", business_name="Bad Co")
        reject_kyb("tenant-reject", reviewer="ops-2", reason="sanctions_hit")
        rec = get_kyb_record("tenant-reject")
        assert rec.kyb_status == "REJECTED"
        assert any("sanctions_hit" in n for n in rec.notes)

    def test_flag_sets_flagged(self):
        from warden.marketplace.kyb import flag_kyb, submit_for_review
        submit_for_review("tenant-flag", business_name="Maybe Co")
        rec = flag_kyb("tenant-flag", reviewer="ops-3", reason="needs_docs")
        assert rec.kyb_status == "FLAGGED"

    def test_approve_without_submission_raises(self):
        from warden.marketplace.kyb import approve_kyb
        with pytest.raises(ValueError, match="no KYB submission"):
            approve_kyb("tenant-never-submitted", reviewer="ops-4")

    def test_approve_then_reject_overrides(self):
        from warden.marketplace.kyb import (
            approve_kyb,
            get_kyb_status,
            reject_kyb,
            submit_for_review,
        )
        submit_for_review("tenant-flip", business_name="Flip Co")
        approve_kyb("tenant-flip", reviewer="ops-5")
        reject_kyb("tenant-flip", reviewer="ops-6", reason="later_sanctions_hit")
        assert get_kyb_status("tenant-flip") == "REJECTED"

    def test_notes_accumulate_across_reviews(self):
        from warden.marketplace.kyb import flag_kyb, get_kyb_record, submit_for_review
        submit_for_review("tenant-notes", business_name="Notes Co")
        flag_kyb("tenant-notes", reviewer="ops-7", reason="first_pass")
        flag_kyb("tenant-notes", reviewer="ops-8", reason="second_pass")
        rec = get_kyb_record("tenant-notes")
        assert len(rec.notes) == 2


class TestEnforcementFlag:
    def test_enforcement_disabled_by_default(self):
        from warden.marketplace.kyb import enforcement_enabled
        assert enforcement_enabled() is False

    def test_enforcement_enabled_via_env(self, monkeypatch):
        from warden.marketplace.kyb import enforcement_enabled
        monkeypatch.setenv("KYB_ENFORCEMENT_ENABLED", "true")
        assert enforcement_enabled() is True


class TestToDict:
    def test_to_dict_returns_dict(self):
        from warden.marketplace.kyb import submit_for_review
        rec = submit_for_review("tenant-dict", business_name="Dict Co")
        d = rec.to_dict()
        assert isinstance(d, dict)
        assert d["tenant_id"] == "tenant-dict"
        assert "kyb_status" in d
