"""
warden/tests/test_feature_gate.py
───────────────────────────────────
Tests for warden/billing/feature_gate.py — tier-based Feature Gating.

Coverage
────────
  TIER_LIMITS correctness (all tiers, all features)
  FeatureGate.require()          — enabled/disabled + error messages
  FeatureGate.require_capacity() — within / at / over limit
  FeatureGate.is_enabled()
  FeatureGate.meets_minimum()
  _min_tier_for / _min_tier_for_capacity
  FeatureGateMiddleware          — ASGI 403 for gated routes
"""
from __future__ import annotations

import unittest


class TestTierLimits(unittest.TestCase):

    def test_individual_no_communities(self):
        from warden.billing.feature_gate import TIER_LIMITS
        limits = TIER_LIMITS["individual"]
        self.assertFalse(limits["communities_enabled"])
        self.assertEqual(limits["max_communities"], 0)

    def test_business_communities_enabled(self):
        from warden.billing.feature_gate import TIER_LIMITS
        limits = TIER_LIMITS["business"]
        self.assertTrue(limits["communities_enabled"])
        self.assertEqual(limits["max_communities"], 5)
        self.assertTrue(limits["multisig_enabled"])
        self.assertFalse(limits["break_glass_enabled"])

    def test_mcp_all_enabled(self):
        from warden.billing.feature_gate import TIER_LIMITS, _UNLIMITED
        limits = TIER_LIMITS["mcp"]
        self.assertTrue(limits["communities_enabled"])
        self.assertTrue(limits["break_glass_enabled"])
        self.assertTrue(limits["byok_enabled"])
        self.assertEqual(limits["max_communities"], _UNLIMITED)

    def test_ratchet_intervals(self):
        from warden.billing.feature_gate import TIER_LIMITS
        self.assertIsNone(TIER_LIMITS["individual"]["ratchet_interval"])
        self.assertEqual(TIER_LIMITS["business"]["ratchet_interval"], 10)
        self.assertEqual(TIER_LIMITS["mcp"]["ratchet_interval"], 50)


class TestFeatureGateRequire(unittest.TestCase):

    def test_enabled_feature_passes(self):
        from warden.billing.feature_gate import FeatureGate
        gate = FeatureGate.for_tier("business")
        gate.require("communities_enabled")   # should not raise

    def test_disabled_feature_raises(self):
        from warden.billing.feature_gate import FeatureGate
        gate = FeatureGate.for_tier("individual")
        with self.assertRaises(PermissionError) as ctx:
            gate.require("communities_enabled")
        self.assertIn("INDIVIDUAL", str(ctx.exception).upper())

    def test_break_glass_requires_mcp(self):
        from warden.billing.feature_gate import FeatureGate
        biz_gate = FeatureGate.for_tier("business")
        with self.assertRaises(PermissionError):
            biz_gate.require("break_glass_enabled")

        mcp_gate = FeatureGate.for_tier("mcp")
        mcp_gate.require("break_glass_enabled")   # should not raise

    def test_byok_requires_mcp(self):
        from warden.billing.feature_gate import FeatureGate
        with self.assertRaises(PermissionError):
            FeatureGate.for_tier("business").require("byok_enabled")
        FeatureGate.for_tier("mcp").require("byok_enabled")


class TestFeatureGateCapacity(unittest.TestCase):

    def test_within_limit_passes(self):
        from warden.billing.feature_gate import FeatureGate
        gate = FeatureGate.for_tier("business")
        gate.require_capacity("max_communities", 4)   # limit=5, count=4 → OK

    def test_at_limit_raises(self):
        from warden.billing.feature_gate import FeatureGate
        gate = FeatureGate.for_tier("business")
        with self.assertRaises(PermissionError):
            gate.require_capacity("max_communities", 5)  # count=5 >= limit=5

    def test_zero_limit_raises(self):
        from warden.billing.feature_gate import FeatureGate
        gate = FeatureGate.for_tier("individual")
        with self.assertRaises(PermissionError):
            gate.require_capacity("max_communities", 0)

    def test_unlimited_never_raises(self):
        from warden.billing.feature_gate import FeatureGate, _UNLIMITED
        gate = FeatureGate.for_tier("mcp")
        gate.require_capacity("max_communities", _UNLIMITED - 1)   # no raise


class TestFeatureGateMeetsMinimum(unittest.TestCase):

    def test_individual_below_business(self):
        from warden.billing.feature_gate import FeatureGate
        self.assertFalse(FeatureGate.for_tier("individual").meets_minimum("business"))

    def test_business_meets_business(self):
        from warden.billing.feature_gate import FeatureGate
        self.assertTrue(FeatureGate.for_tier("business").meets_minimum("business"))

    def test_mcp_meets_all(self):
        from warden.billing.feature_gate import FeatureGate
        gate = FeatureGate.for_tier("mcp")
        for t in ("individual", "business", "mcp"):
            self.assertTrue(gate.meets_minimum(t))

    def test_unknown_tier_defaults_to_individual(self):
        from warden.billing.feature_gate import FeatureGate
        gate = FeatureGate.for_tier("enterprise-plus")
        self.assertEqual(gate.tier, "individual")


class TestMinTierHelpers(unittest.TestCase):

    def test_communities_enabled_min_tier_is_business(self):
        from warden.billing.feature_gate import _min_tier_for
        self.assertEqual(_min_tier_for("communities_enabled"), "business")

    def test_break_glass_min_tier_is_mcp(self):
        from warden.billing.feature_gate import _min_tier_for
        self.assertEqual(_min_tier_for("break_glass_enabled"), "mcp")

    def test_capacity_min_tier_for_communities(self):
        from warden.billing.feature_gate import _min_tier_for_capacity
        self.assertEqual(_min_tier_for_capacity("max_communities"), "business")


class TestFeatureGateMiddleware(unittest.IsolatedAsyncioTestCase):
    """ASGI middleware unit tests using minimal scope/receive/send mocks."""

    async def test_community_route_individual_tier_403(self):
        from warden.billing.feature_gate import FeatureGateMiddleware

        received_status = []

        async def dummy_app(scope, receive, send):
            received_status.append("app_called")

        async def send(event):
            if event["type"] == "http.response.start":
                received_status.append(event["status"])

        middleware = FeatureGateMiddleware(dummy_app)
        scope = {
            "type":    "http",
            "path":    "/communities",
            "headers": [(b"x-tenant-tier", b"individual")],
        }
        await middleware(scope, None, send)
        self.assertIn(403, received_status)
        self.assertNotIn("app_called", received_status)

    async def test_community_route_business_tier_passes(self):
        from warden.billing.feature_gate import FeatureGateMiddleware

        app_called = []

        async def dummy_app(scope, receive, send):
            app_called.append(True)

        middleware = FeatureGateMiddleware(dummy_app)
        scope = {
            "type":    "http",
            "path":    "/communities",
            "headers": [(b"x-tenant-tier", b"business")],
        }
        await middleware(scope, None, lambda e: None)
        self.assertTrue(app_called)

    async def test_non_gated_route_passes_for_individual(self):
        from warden.billing.feature_gate import FeatureGateMiddleware

        app_called = []

        async def dummy_app(scope, receive, send):
            app_called.append(True)

        middleware = FeatureGateMiddleware(dummy_app)
        scope = {
            "type":    "http",
            "path":    "/filter",
            "headers": [(b"x-tenant-tier", b"individual")],
        }
        await middleware(scope, None, lambda e: None)
        self.assertTrue(app_called)

    async def test_break_glass_route_requires_mcp(self):
        from warden.billing.feature_gate import FeatureGateMiddleware

        blocked = []

        async def dummy_app(scope, receive, send):
            blocked.append("not_blocked")

        async def send(event):
            if event["type"] == "http.response.start":
                blocked.append(event["status"])

        middleware = FeatureGateMiddleware(dummy_app)
        scope = {
            "type":    "http",
            "path":    "/communities/break-glass",
            "headers": [(b"x-tenant-tier", b"business")],
        }
        await middleware(scope, None, send)
        self.assertIn(403, blocked)
        self.assertNotIn("not_blocked", blocked)


if __name__ == "__main__":
    unittest.main(verbosity=2)
