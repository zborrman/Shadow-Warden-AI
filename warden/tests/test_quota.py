"""
warden/tests/test_quota.py
───────────────────────────
Tests for warden/communities/quota.py — storage/bandwidth quota enforcement.

Coverage
────────
  check_entity_size()        — within / over per-tier max
  check_storage_quota()      — within / QuotaExceeded / OverageRequired
  check_bandwidth_quota()    — within / QuotaExceeded / OverageRequired
  record_upload/download()   — counter increments
  release_storage()          — floor-at-zero behaviour
  apply_referral_bonus()     — bonus added to effective quota
  get_usage()                — summary dict structure
"""
from __future__ import annotations

import os
import tempfile
import unittest

# Redirect DB paths for tests
os.environ.setdefault("QUOTA_DB_PATH", "/tmp/warden_test_quota_unit.db")


class _QuotaBase(unittest.TestCase):
    """Base class: reset counters between tests via fresh SQLite DB per test."""

    def setUp(self):
        # Use a unique DB per test to avoid cross-test counter pollution
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        os.environ["QUOTA_DB_PATH"] = self._tmp.name
        # Patch module-level path that was already imported
        import warden.communities.quota as q
        q._QUOTA_DB_PATH = self._tmp.name

    def tearDown(self):
        try:
            os.unlink(self._tmp.name)
        except OSError:
            pass


_MB = 1024 * 1024
_GB = 1024 ** 3


class TestCheckEntitySize(_QuotaBase):

    def test_individual_within_limit(self):
        from warden.communities.quota import check_entity_size
        check_entity_size("individual", 50 * _MB)   # limit=100 MB — no raise

    def test_individual_over_limit_raises(self):
        from warden.communities.quota import check_entity_size
        with self.assertRaises(ValueError) as ctx:
            check_entity_size("individual", 101 * _MB)
        self.assertIn("100", str(ctx.exception))

    def test_business_allows_1gb(self):
        from warden.communities.quota import check_entity_size
        check_entity_size("business", 1 * _GB)   # exactly at limit — OK

    def test_business_over_1gb_raises(self):
        from warden.communities.quota import check_entity_size
        with self.assertRaises(ValueError):
            check_entity_size("business", 1 * _GB + 1)

    def test_mcp_allows_5gb(self):
        from warden.communities.quota import check_entity_size
        check_entity_size("mcp", 5 * _GB)   # no raise

    def test_unknown_tier_falls_back_to_individual(self):
        from warden.communities.quota import check_entity_size
        with self.assertRaises(ValueError):
            check_entity_size("enterprise-gold", 200 * _MB)


class TestCheckStorageQuota(_QuotaBase):

    def test_empty_community_always_passes(self):
        from warden.communities.quota import check_storage_quota
        result = check_storage_quota("cid-empty", "individual", 1 * _MB)
        self.assertTrue(result)

    def test_individual_at_limit_raises_quota_exceeded(self):
        from warden.communities.quota import (
            QuotaExceeded, _incr_counter, check_storage_quota,
        )
        cid = "cid-ind-full"
        # Fill storage to limit
        _incr_counter(cid, "storage_bytes", 10 * _GB)
        with self.assertRaises(QuotaExceeded) as ctx:
            check_storage_quota(cid, "individual", 1 * _MB)
        self.assertEqual(ctx.exception.metric, "storage")
        self.assertIn("business", ctx.exception.upgrade_tier.lower())

    def test_business_overage_raises_overage_required(self):
        from warden.communities.quota import (
            OverageRequired, _incr_counter, check_storage_quota,
        )
        cid = "cid-biz-full"
        _incr_counter(cid, "storage_bytes", 100 * _GB)
        with self.assertRaises(OverageRequired) as ctx:
            check_storage_quota(cid, "business", 1 * _MB)
        self.assertEqual(ctx.exception.metric, "storage")

    def test_bonus_bytes_expand_effective_quota(self):
        from warden.communities.quota import (
            QuotaExceeded, _incr_counter, check_storage_quota,
        )
        cid = "cid-bonus"
        # Fill to exactly the base 10 GB limit
        _incr_counter(cid, "storage_bytes", 10 * _GB)
        # Without bonus, adding 1 byte would exceed
        with self.assertRaises(QuotaExceeded):
            check_storage_quota(cid, "individual", 1)
        # Add a 2 GB referral bonus
        _incr_counter(cid, "bonus_bytes", 2 * _GB)
        # Now 1 MB should fit
        result = check_storage_quota(cid, "individual", 1 * _MB)
        self.assertTrue(result)


class TestCheckBandwidthQuota(_QuotaBase):

    def test_within_bw_passes(self):
        from warden.communities.quota import check_bandwidth_quota
        result = check_bandwidth_quota("bw-cid-ok", "individual", 1 * _GB)
        self.assertTrue(result)

    def test_individual_bw_exceeded_raises_quota_exceeded(self):
        from warden.communities.quota import (
            QuotaExceeded, _bw_metric, _incr_counter, check_bandwidth_quota,
        )
        cid = "bw-cid-full"
        _incr_counter(cid, _bw_metric(), 50 * _GB)
        with self.assertRaises(QuotaExceeded):
            check_bandwidth_quota(cid, "individual", 1 * _MB)

    def test_business_bw_exceeded_raises_overage_required(self):
        from warden.communities.quota import (
            OverageRequired, _bw_metric, _incr_counter, check_bandwidth_quota,
        )
        cid = "bw-biz-full"
        _incr_counter(cid, _bw_metric(), 500 * _GB)
        with self.assertRaises(OverageRequired):
            check_bandwidth_quota(cid, "business", 1 * _MB)


class TestRecordAndRelease(_QuotaBase):

    def test_record_upload_increments_storage(self):
        from warden.communities.quota import get_storage_used, record_upload
        cid = "rec-upload-cid"
        record_upload(cid, 10 * _MB)
        self.assertEqual(get_storage_used(cid), 10 * _MB)

    def test_record_upload_increments_bandwidth(self):
        from warden.communities.quota import get_bandwidth_used, record_upload
        cid = "rec-bw-cid"
        record_upload(cid, 5 * _MB)
        self.assertEqual(get_bandwidth_used(cid), 5 * _MB)

    def test_record_download_increments_bandwidth_only(self):
        from warden.communities.quota import (
            get_bandwidth_used, get_storage_used, record_download,
        )
        cid = "dl-cid"
        record_download(cid, 3 * _MB)
        self.assertEqual(get_bandwidth_used(cid), 3 * _MB)
        self.assertEqual(get_storage_used(cid), 0)   # storage unchanged

    def test_release_storage_decrements_counter(self):
        from warden.communities.quota import (
            get_storage_used, record_upload, release_storage,
        )
        cid = "rel-cid"
        record_upload(cid, 20 * _MB)
        release_storage(cid, 10 * _MB)
        self.assertEqual(get_storage_used(cid), 10 * _MB)

    def test_release_storage_floors_at_zero(self):
        from warden.communities.quota import get_storage_used, release_storage
        cid = "rel-floor-cid"
        release_storage(cid, 999 * _GB)   # nothing stored — should not go negative
        self.assertEqual(get_storage_used(cid), 0)


class TestReferralBonus(_QuotaBase):

    def test_referral_bonus_increases_effective_quota(self):
        from warden.communities.quota import apply_referral_bonus, get_usage
        cid = "ref-bonus-cid"
        total = apply_referral_bonus(cid, "referrer-id-123")
        usage = get_usage(cid)
        self.assertGreater(total, 0)
        self.assertEqual(usage["bonus_bytes"], total)

    def test_multiple_referrals_accumulate(self):
        from warden.communities.quota import apply_referral_bonus
        cid = "ref-multi-cid"
        b1 = apply_referral_bonus(cid, "ref-A")
        b2 = apply_referral_bonus(cid, "ref-B")
        self.assertEqual(b2, b1 * 2)


class TestGetUsage(_QuotaBase):

    def test_usage_dict_keys(self):
        from warden.communities.quota import get_usage
        usage = get_usage("usage-cid")
        for key in (
            "community_id", "storage_bytes", "storage_human",
            "bandwidth_bytes", "bandwidth_human", "bonus_bytes",
            "bonus_human", "period",
        ):
            self.assertIn(key, usage)

    def test_period_is_current_month(self):
        from datetime import UTC, datetime

        from warden.communities.quota import get_usage
        usage = get_usage("period-cid")
        expected = datetime.now(UTC).strftime("%Y-%m")
        self.assertEqual(usage["period"], expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
