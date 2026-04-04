"""
warden/tests/test_weekly_report.py
───────────────────────────────────
Tests for the Weekly ROI Impact Report ARQ task.

Covers:
  - HTML rendering: required sections, metric placeholders, CTA link
  - Plain-text rendering: required fields present
  - build_report_for_tenant: dry-run (no SMTP), delivery called with right args
  - send_weekly_reports ARQ task: iterates only active paid tenants,
    skips free / cancelled, handles per-tenant failures gracefully
  - admin_email captured from checkout session
  - StripeBilling._upsert preserves existing admin_email on conflict
"""
from __future__ import annotations

import json
import sqlite3
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_impact_data(
    blocked: int = 12,
    pii: int = 5,
    dollar_saved: float = 1200.0,
    total: int = 200,
    plan: str = "startup",
) -> dict:
    return {
        "tenant_id":          "acme",
        "period_days":        7,
        "generated_at":       datetime.now(UTC).isoformat(),
        "requests_total":     total,
        "requests_blocked":   blocked,
        "requests_allowed":   total - blocked,
        "pii_masked":         pii,
        "block_rate_pct":     round(blocked / max(total, 1) * 100, 2),
        "dollar_saved":       dollar_saved,
        "inference_saved_usd": 0.0,
        "annual_projection":  round(dollar_saved * 365 / 7, 2),
        "top_threats":        [
            {"flag": "prompt_injection", "label": "Prompt Injection", "count": 8, "pct": 66.7},
            {"flag": "jailbreak",        "label": "Jailbreak Attempt",  "count": 4, "pct": 33.3},
        ],
        "timeline":           [],
        "plan":               plan,
        "quota":              50_000,
        "rate_limit_per_min": 60,
        "quota_used_pct":     0.4,
    }


# ── HTML rendering ────────────────────────────────────────────────────────────

class TestRenderHtml:
    def _render(self, **kwargs) -> str:
        from warden.workers.weekly_report import _render_html
        return _render_html(_make_impact_data(**kwargs), "acme")

    def test_returns_string(self):
        assert isinstance(self._render(), str)

    def test_doctype_present(self):
        html = self._render()
        assert "<!DOCTYPE html>" in html

    def test_dollar_saved_in_html(self):
        html = self._render(dollar_saved=1200.0)
        # $1.2K formatted
        assert "$1.2K" in html

    def test_blocked_count_in_html(self):
        html = self._render(blocked=42)
        assert "42" in html

    def test_pii_count_in_html(self):
        html = self._render(pii=17)
        assert "17" in html

    def test_tenant_id_in_html(self):
        html = self._render()
        assert "acme" in html

    def test_cta_link_present(self):
        html = self._render()
        assert "/impact" in html
        assert "View Full Impact Dashboard" in html

    def test_top_threats_rendered(self):
        html = self._render()
        assert "Prompt Injection" in html
        assert "Jailbreak Attempt" in html

    def test_unsubscribe_link_present(self):
        html = self._render()
        assert "unsubscribe" in html.lower()

    def test_annual_projection_shown(self):
        # $1200 * 365/7 ≈ $62.6K
        html = self._render(dollar_saved=1200.0)
        assert "/ yr" in html

    def test_zero_threats_shows_quiet_message(self):
        from warden.workers.weekly_report import _render_html
        data = _make_impact_data()
        data["top_threats"] = []
        html = _render_html(data, "acme")
        assert "quiet week" in html.lower() or "No threats" in html

    def test_large_numbers_formatted(self):
        html = self._render(blocked=5500, total=100_000)
        assert "5.5K" in html

    def test_dark_mode_media_query_present(self):
        html = self._render()
        assert "prefers-color-scheme" in html

    def test_inline_css_no_external_stylesheets(self):
        html = self._render()
        # Should not reference any external CSS file
        assert '<link rel="stylesheet"' not in html


# ── Plain-text rendering ──────────────────────────────────────────────────────

class TestRenderPlaintext:
    def _render(self) -> str:
        from warden.workers.weekly_report import _render_plaintext
        return _render_plaintext(_make_impact_data(), "acme")

    def test_dollar_saved_present(self):
        assert "$1,200.00" in self._render()

    def test_tenant_id_present(self):
        assert "acme" in self._render()

    def test_blocked_count_present(self):
        assert "12" in self._render()

    def test_portal_link_present(self):
        plain = self._render()
        assert "/impact" in plain

    def test_unsubscribe_link_present(self):
        assert "unsubscribe" in self._render().lower()


# ── build_report_for_tenant ───────────────────────────────────────────────────

class TestBuildReportForTenant:
    def test_dry_run_when_smtp_not_configured(self, caplog):
        """No SMTP → logs warning but returns True (non-fatal)."""
        import logging
        with patch("warden.api.tenant_impact._build_impact", return_value=_make_impact_data()):
            with patch.dict("os.environ", {"SMTP_HOST": "", "SMTP_USER": ""}):
                from importlib import reload
                import warden.workers.weekly_report as wr
                reload(wr)  # pick up cleared env
                with caplog.at_level(logging.INFO, logger="warden.workers.weekly_report"):
                    result = wr.build_report_for_tenant("acme", "admin@acme.com")

        assert result is True
        assert any("DRY RUN" in r.message or "would send" in r.message.lower()
                   for r in caplog.records)

    def test_smtp_send_called_with_correct_address(self):
        with patch("warden.api.tenant_impact._build_impact", return_value=_make_impact_data()), \
             patch.dict("os.environ", {"SMTP_HOST": "smtp.test.com", "SMTP_USER": "u", "SMTP_PASS": "p"}):
            from importlib import reload
            import warden.workers.weekly_report as wr
            reload(wr)

            with patch.object(wr, "_send_report_email") as mock_send:
                result = wr.build_report_for_tenant("acme", "admin@acme.com")

        mock_send.assert_called_once()
        args = mock_send.call_args[0]
        assert args[0] == "admin@acme.com"
        assert args[1] == "acme"
        assert result is True

    def test_smtp_failure_returns_false(self):
        with patch("warden.api.tenant_impact._build_impact", return_value=_make_impact_data()), \
             patch.dict("os.environ", {"SMTP_HOST": "smtp.test.com", "SMTP_USER": "u", "SMTP_PASS": "p"}):
            from importlib import reload
            import warden.workers.weekly_report as wr
            reload(wr)

            with patch.object(wr, "_send_report_email", side_effect=ConnectionError("timeout")):
                result = wr.build_report_for_tenant("acme", "admin@acme.com")

        assert result is False

    def test_impact_fetch_failure_returns_false(self):
        with patch("warden.api.tenant_impact._build_impact",
                   side_effect=RuntimeError("DB offline")):
            from warden.workers.weekly_report import build_report_for_tenant
            result = build_report_for_tenant("acme", "admin@acme.com")

        assert result is False


# ── send_weekly_reports ARQ task ──────────────────────────────────────────────

class TestSendWeeklyReports:
    def _make_billing(self, rows: list[dict]) -> MagicMock:
        """Build a minimal StripeBilling mock with the given subscription rows."""
        billing = MagicMock()
        billing._lock = __import__("threading").Lock()

        # Simulate SQLite rows
        mock_rows = []
        for r in rows:
            row = MagicMock()
            row.__getitem__ = lambda self, k, _r=r: _r[k]
            mock_rows.append(row)

        billing._conn.execute.return_value.fetchall.return_value = mock_rows
        return billing

    @pytest.mark.asyncio
    async def test_sends_to_all_active_paid_tenants(self):
        rows = [
            {"tenant_id": "acme",   "admin_email": "a@acme.com",   "plan": "startup"},
            {"tenant_id": "betaco", "admin_email": "b@betaco.com",  "plan": "growth"},
        ]
        billing = self._make_billing(rows)

        with patch("warden.stripe_billing.get_stripe_billing", return_value=billing), \
             patch("warden.workers.weekly_report.build_report_for_tenant", return_value=True) as mock_build:
            from warden.workers.weekly_report import send_weekly_reports
            result = await send_weekly_reports({})

        assert result["sent"] == 2
        assert result["failed"] == 0
        assert "acme" in result["tenant_ids_sent"]
        assert "betaco" in result["tenant_ids_sent"]

    @pytest.mark.asyncio
    async def test_failed_tenant_does_not_block_others(self):
        rows = [
            {"tenant_id": "ok_co",   "admin_email": "ok@ok.com",   "plan": "startup"},
            {"tenant_id": "fail_co", "admin_email": "f@fail.com",  "plan": "startup"},
        ]
        billing = self._make_billing(rows)

        def _build_side(tenant_id, admin_email, **kw):
            return tenant_id != "fail_co"

        with patch("warden.stripe_billing.get_stripe_billing", return_value=billing), \
             patch("warden.workers.weekly_report.build_report_for_tenant",
                   side_effect=_build_side):
            from warden.workers.weekly_report import send_weekly_reports
            result = await send_weekly_reports({})

        assert result["sent"]   == 1
        assert result["failed"] == 1
        assert "ok_co" in result["tenant_ids_sent"]

    @pytest.mark.asyncio
    async def test_no_tenants_returns_zeroes(self):
        billing = self._make_billing([])

        with patch("warden.stripe_billing.get_stripe_billing", return_value=billing):
            from warden.workers.weekly_report import send_weekly_reports
            result = await send_weekly_reports({})

        assert result["sent"]   == 0
        assert result["failed"] == 0

    @pytest.mark.asyncio
    async def test_billing_unavailable_returns_error(self):
        with patch("warden.stripe_billing.get_stripe_billing",
                   side_effect=RuntimeError("DB locked")):
            from warden.workers.weekly_report import send_weekly_reports
            result = await send_weekly_reports({})

        assert "error" in result
        assert result["sent"] == 0

    @pytest.mark.asyncio
    async def test_result_includes_generated_at(self):
        billing = self._make_billing([])
        with patch("warden.stripe_billing.get_stripe_billing", return_value=billing):
            from warden.workers.weekly_report import send_weekly_reports
            result = await send_weekly_reports({})

        assert "generated_at" in result
        # Should be a valid ISO timestamp
        datetime.fromisoformat(result["generated_at"])


# ── StripeBilling admin_email persistence ─────────────────────────────────────

class TestAdminEmailPersistence:
    def _make_billing(self, tmp_path: Path):
        from warden.stripe_billing import StripeBilling
        return StripeBilling(db_path=tmp_path / "stripe_test.db")

    def test_admin_email_stored_on_upsert(self, tmp_path):
        b = self._make_billing(tmp_path)
        b._upsert("t1", "cus_1", "sub_1", "startup", "active", None,
                  admin_email="owner@acme.com")
        row = b._conn.execute(
            "SELECT admin_email FROM subscriptions WHERE tenant_id='t1'"
        ).fetchone()
        assert row["admin_email"] == "owner@acme.com"

    def test_admin_email_preserved_on_plan_update(self, tmp_path):
        """Upgrading plan must not wipe the admin_email."""
        b = self._make_billing(tmp_path)
        b._upsert("t2", "cus_2", "sub_2", "startup", "active", None,
                  admin_email="owner@co.com")
        # Upgrade to growth (no email in this upsert call)
        b._upsert("t2", "cus_2", "sub_2", "growth", "active", None,
                  admin_email=None)
        row = b._conn.execute(
            "SELECT admin_email FROM subscriptions WHERE tenant_id='t2'"
        ).fetchone()
        assert row["admin_email"] == "owner@co.com"  # COALESCE preserved it

    def test_admin_email_captured_from_checkout_session(self, tmp_path):
        b = self._make_billing(tmp_path)
        b._enabled = True

        session = {
            "metadata":       {"tenant_id": "acme"},
            "customer":       "cus_x",
            "subscription":   "",
            "customer_email": "ceo@acme.com",
        }

        mock_sub = MagicMock()
        mock_sub.get = lambda k, d=None: {
            "status": "active", "items": {"data": []},
            "current_period_end": None, "customer": "cus_x",
            "id": "", "metadata": {},
        }.get(k, d)

        with patch("stripe.Subscription.retrieve", return_value=mock_sub), \
             patch("warden.cache._get_client", return_value=MagicMock(
                 set=lambda k, v: None, delete=lambda k: None, get=lambda k: None
             )):
            b._on_checkout_completed(session)

        row = b._conn.execute(
            "SELECT admin_email FROM subscriptions WHERE tenant_id='acme'"
        ).fetchone()
        assert row["admin_email"] == "ceo@acme.com"
