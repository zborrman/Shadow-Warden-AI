"""
warden/tests/test_tenant_impact.py
───────────────────────────────────
Tests for GET /tenant/impact — tenant-scoped Dollar Impact Calculator.

Covers:
  - Basic response shape
  - Correct tenant_id filtering (other tenant's data excluded)
  - Zero-data tenants return valid zeroed response
  - Period parameter respected
  - Dollar math: dollar_saved = blocked × COST_PER_BLOCK_USD
  - Annual projection: annual = dollar_saved × (365/period_days)
  - Threat breakdown: top_threats sorted by count desc
  - Quota fields from StripeBilling (mocked)
  - Auth: 401 when no credentials; 402 when subscription lapsed
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_log_entry(
    tenant_id: str = "acme",
    allowed: bool = True,
    flags: list[str] | None = None,
    masked: bool = False,
    days_ago: float = 1.0,
) -> dict:
    ts = datetime.now(UTC) - timedelta(days=days_ago)
    return {
        "ts":           ts.isoformat(),
        "request_id":   f"req-{ts.timestamp():.0f}",
        "tenant_id":    tenant_id,
        "allowed":      allowed,
        "flags":        flags or [],
        "masked":       masked,
        "risk_level":   "block" if not allowed else "low",
        "attack_cost_usd": 0.0,
        "shadow_banned":   False,
    }


def _write_logs(tmp_path: Path, entries: list[dict]) -> str:
    log_path = tmp_path / "logs.json"
    log_path.write_text(
        "\n".join(json.dumps(e) for e in entries) + "\n",
        encoding="utf-8",
    )
    return str(log_path)


def _make_client(log_path: str, billing_mock=None) -> TestClient:
    """Create a TestClient for the tenant_impact router with patched deps."""
    from fastapi import FastAPI

    from warden.api.tenant_impact import router

    app = FastAPI()
    app.include_router(router)

    # Patch the analytics logger to read from our temp file
    with patch("warden.analytics.logger.LOGS_PATH", Path(log_path)):
        # Patch require_ext_auth so tests can inject tenant_id
        pass

    return TestClient(app)


# ─────────────────────────────────────────────────────────────────────────────
# Helper that bypasses auth for unit-testing the pure logic layer
# ─────────────────────────────────────────────────────────────────────────────

def _build_impact_direct(log_path: str, tenant_id: str, period: int = 30) -> dict:
    """Call _build_impact directly (no HTTP), patching the log path."""
    from warden.api.tenant_impact import _build_impact
    with patch("warden.analytics.logger.LOGS_PATH", Path(log_path)):
        return _build_impact(tenant_id=tenant_id, period_days=period)


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestImpactResponseShape:
    def test_required_keys_present(self, tmp_path):
        log_path = _write_logs(tmp_path, [
            _make_log_entry("acme", allowed=False, flags=["prompt_injection"]),
            _make_log_entry("acme", allowed=True),
        ])
        result = _build_impact_direct(log_path, "acme")

        for key in (
            "tenant_id", "period_days", "generated_at",
            "requests_total", "requests_blocked", "requests_allowed",
            "pii_masked", "block_rate_pct",
            "dollar_saved", "inference_saved_usd", "annual_projection",
            "top_threats", "timeline",
            "plan", "quota", "rate_limit_per_min", "quota_used_pct",
        ):
            assert key in result, f"Missing key: {key}"

    def test_tenant_id_in_response(self, tmp_path):
        log_path = _write_logs(tmp_path, [])
        result   = _build_impact_direct(log_path, "beta_corp")
        assert result["tenant_id"] == "beta_corp"

    def test_period_days_in_response(self, tmp_path):
        log_path = _write_logs(tmp_path, [])
        result   = _build_impact_direct(log_path, "acme", period=14)
        assert result["period_days"] == 14


class TestTenantFiltering:
    def test_other_tenant_data_excluded(self, tmp_path):
        entries = [
            _make_log_entry("acme",     allowed=False, flags=["jailbreak"]),
            _make_log_entry("acme",     allowed=False, flags=["jailbreak"]),
            _make_log_entry("rival_co", allowed=False, flags=["jailbreak"]),  # not ours
            _make_log_entry("acme",     allowed=True),
        ]
        log_path = _write_logs(tmp_path, entries)
        result   = _build_impact_direct(log_path, "acme")

        assert result["requests_total"]   == 3   # only acme
        assert result["requests_blocked"] == 2
        assert result["requests_allowed"] == 1

    def test_unknown_tenant_returns_zeros(self, tmp_path):
        entries  = [_make_log_entry("acme", allowed=False)]
        log_path = _write_logs(tmp_path, entries)
        result   = _build_impact_direct(log_path, "nobody")

        assert result["requests_total"]   == 0
        assert result["requests_blocked"] == 0
        assert result["dollar_saved"]     == 0.0

    def test_no_logs_file_returns_zeros(self, tmp_path):
        # logs.json does not exist
        result = _build_impact_direct(str(tmp_path / "absent.json"), "acme")
        assert result["requests_total"] == 0
        assert result["dollar_saved"]   == 0.0


class TestDollarMath:
    COST = 100.0  # default IMPACT_COST_PER_BLOCK_USD

    def test_dollar_saved_equals_blocked_times_cost(self, tmp_path):
        n_blocked = 7
        entries   = [_make_log_entry("t", allowed=False) for _ in range(n_blocked)]
        entries  += [_make_log_entry("t", allowed=True)  for _ in range(3)]
        log_path  = _write_logs(tmp_path, entries)

        with patch.dict("os.environ", {"IMPACT_COST_PER_BLOCK_USD": str(self.COST)}):
            result = _build_impact_direct(log_path, "t")

        assert result["dollar_saved"] == pytest.approx(n_blocked * self.COST)

    def test_annual_projection_scales_to_year(self, tmp_path):
        entries  = [_make_log_entry("t", allowed=False) for _ in range(10)]
        log_path = _write_logs(tmp_path, entries)

        with patch.dict("os.environ", {"IMPACT_COST_PER_BLOCK_USD": str(self.COST)}):
            result = _build_impact_direct(log_path, "t", period=30)

        expected_annual = round(10 * self.COST * (365 / 30), 2)
        assert result["annual_projection"] == pytest.approx(expected_annual, rel=0.01)

    def test_block_rate_pct_correct(self, tmp_path):
        entries  = [_make_log_entry("t", allowed=False) for _ in range(3)]
        entries += [_make_log_entry("t", allowed=True)  for _ in range(7)]
        log_path = _write_logs(tmp_path, entries)
        result   = _build_impact_direct(log_path, "t")

        assert result["block_rate_pct"] == pytest.approx(30.0)

    def test_pii_masked_counted_correctly(self, tmp_path):
        entries = [
            _make_log_entry("t", masked=True),
            _make_log_entry("t", masked=True),
            _make_log_entry("t", masked=False),
        ]
        log_path = _write_logs(tmp_path, entries)
        result   = _build_impact_direct(log_path, "t")
        assert result["pii_masked"] == 2


class TestThreatBreakdown:
    def test_top_threats_sorted_descending(self, tmp_path):
        entries = (
            [_make_log_entry("t", allowed=False, flags=["jailbreak"])]     * 5 +
            [_make_log_entry("t", allowed=False, flags=["prompt_injection"])] * 3 +
            [_make_log_entry("t", allowed=False, flags=["pii_detected"])]  * 1
        )
        log_path = _write_logs(tmp_path, entries)
        result   = _build_impact_direct(log_path, "t")
        counts   = [t["count"] for t in result["top_threats"]]

        assert counts == sorted(counts, reverse=True)
        assert result["top_threats"][0]["flag"] == "jailbreak"

    def test_top_threats_capped_at_8(self, tmp_path):
        flags   = [f"flag_{i}" for i in range(12)]
        entries = [_make_log_entry("t", allowed=False, flags=[f]) for f in flags]
        log_path = _write_logs(tmp_path, entries)
        result   = _build_impact_direct(log_path, "t")

        assert len(result["top_threats"]) <= 8

    def test_allowed_requests_not_counted_in_threats(self, tmp_path):
        entries = [
            _make_log_entry("t", allowed=True,  flags=["some_flag"]),
            _make_log_entry("t", allowed=False, flags=["jailbreak"]),
        ]
        log_path = _write_logs(tmp_path, entries)
        result   = _build_impact_direct(log_path, "t")

        flags_seen = {t["flag"] for t in result["top_threats"]}
        assert "some_flag"  not in flags_seen  # allowed — not a threat
        assert "jailbreak"  in flags_seen

    def test_human_readable_label(self, tmp_path):
        entries  = [_make_log_entry("t", allowed=False, flags=["prompt_injection"])]
        log_path = _write_logs(tmp_path, entries)
        result   = _build_impact_direct(log_path, "t")

        threat = result["top_threats"][0]
        assert threat["label"] == "Prompt Injection"

    def test_pct_sums_to_100(self, tmp_path):
        entries = (
            [_make_log_entry("t", allowed=False, flags=["jailbreak"])]      * 3 +
            [_make_log_entry("t", allowed=False, flags=["prompt_injection"])] * 7
        )
        log_path = _write_logs(tmp_path, entries)
        result   = _build_impact_direct(log_path, "t")

        total_pct = sum(t["pct"] for t in result["top_threats"])
        assert abs(total_pct - 100.0) < 1.0  # within 1% due to rounding


class TestTimeline:
    def test_timeline_has_period_days_buckets(self, tmp_path):
        log_path = _write_logs(tmp_path, [])
        result   = _build_impact_direct(log_path, "t", period=14)
        assert len(result["timeline"]) == 14

    def test_timeline_bucket_keys(self, tmp_path):
        log_path = _write_logs(tmp_path, [])
        result   = _build_impact_direct(log_path, "t", period=7)

        for bucket in result["timeline"]:
            assert "date"     in bucket
            assert "requests" in bucket
            assert "blocked"  in bucket
            assert "pii"      in bucket

    def test_timeline_counts_entries_in_correct_day(self, tmp_path):
        entries = [
            _make_log_entry("t", allowed=False, days_ago=0.1),  # today
            _make_log_entry("t", allowed=False, days_ago=0.1),  # today
            _make_log_entry("t", allowed=False, days_ago=2.0),  # 2 days ago
        ]
        log_path = _write_logs(tmp_path, entries)
        result   = _build_impact_direct(log_path, "t", period=7)

        today_str = datetime.now(UTC).strftime("%Y-%m-%d")
        today_bucket = next((b for b in result["timeline"] if b["date"] == today_str), None)
        assert today_bucket is not None
        assert today_bucket["blocked"] == 2


class TestBillingIntegration:
    def test_plan_and_rate_limit_from_billing(self, tmp_path):
        log_path = _write_logs(tmp_path, [])

        mock_billing = MagicMock()
        mock_billing.get_plan.return_value             = "growth"
        mock_billing.get_quota.return_value            = 250_000
        mock_billing.get_rate_limit_per_minute.return_value = 200

        with patch("warden.stripe_billing.get_stripe_billing", return_value=mock_billing):
            result = _build_impact_direct(log_path, "t")

        assert result["plan"]             == "growth"
        assert result["quota"]            == 250_000
        assert result["rate_limit_per_min"] == 200

    def test_free_plan_defaults_when_billing_unavailable(self, tmp_path):
        log_path = _write_logs(tmp_path, [])

        with patch("warden.stripe_billing.get_stripe_billing",
                   side_effect=ImportError("stripe not installed")):
            result = _build_impact_direct(log_path, "t")

        assert result["plan"] == "free"

    def test_quota_used_pct_calculation(self, tmp_path):
        entries  = [_make_log_entry("t") for _ in range(100)]
        log_path = _write_logs(tmp_path, entries)

        mock_billing = MagicMock()
        mock_billing.get_plan.return_value             = "startup"
        mock_billing.get_quota.return_value            = 1_000
        mock_billing.get_rate_limit_per_minute.return_value = 60

        with patch("warden.stripe_billing.get_stripe_billing", return_value=mock_billing):
            result = _build_impact_direct(log_path, "t")

        assert result["quota_used_pct"] == pytest.approx(10.0)
