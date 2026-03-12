"""
warden/tests/test_report.py
━━━━━━━━━━━━━━━━━━━━━━━━━━
Tests for the Compliance Report Generator (warden/analytics/report.py).

Coverage:
  • ReportEngine.build()  — aggregation from log entries
  • render_html()         — valid HTML, expected strings present
  • render_json()         — schema completeness
  • Posture thresholds    — GREEN / YELLOW / RED
  • _recommendations()    — correct triggers
  • GET /msp/report/{id}  — HTML and JSON endpoints via TestClient
  • Empty tenant          — no data gracefully handled
"""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from warden.analytics.report import ReportData, ReportEngine, _recommendations

# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_entries(
    tenant_id: str = "acme",
    month: str = "2026-02",
    n_allowed: int = 80,
    n_blocked: int = 10,
    flags: list[str] | None = None,
    entities: list[str] | None = None,
) -> list[dict]:
    """Build synthetic NDJSON-style log entries for testing."""
    flags    = flags    or ["prompt_injection"]
    entities = entities or ["EMAIL", "PHONE"]
    entries: list[dict] = []

    for i in range(n_allowed):
        entries.append({
            "ts":             f"{month}-{(i % 28) + 1:02d}T12:00:00+00:00",
            "request_id":     f"allow-{i}",
            "allowed":        True,
            "risk_level":     "low",
            "flags":          [],
            "secrets_found":  [],
            "payload_len":    50,
            "payload_tokens": 12,
            "attack_cost_usd": 0.0,
            "elapsed_ms":     8.0,
            "strict":         False,
            "tenant_id":      tenant_id,
            "entity_count":   2 if i < 5 else 0,
            "entities_detected": entities if i < 5 else [],
        })

    for i in range(n_blocked):
        entries.append({
            "ts":             f"{month}-{(i % 28) + 1:02d}T14:00:00+00:00",
            "request_id":     f"block-{i}",
            "allowed":        False,
            "risk_level":     "high",
            "flags":          flags,
            "secrets_found":  [],
            "payload_len":    200,
            "payload_tokens": 50,
            "attack_cost_usd": 0.0000075,
            "elapsed_ms":     12.0,
            "strict":         False,
            "tenant_id":      tenant_id,
        })

    return entries


# ── ReportEngine.build() ──────────────────────────────────────────────────────

class TestReportEngineBuild:
    def _engine_with(self, entries: list[dict]) -> ReportEngine:
        engine = ReportEngine()
        with patch("warden.analytics.report.load_entries", return_value=entries):
            self._data = engine.build("acme", "2026-02")
        return engine

    def test_totals(self) -> None:
        entries = _make_entries(n_allowed=80, n_blocked=10)
        engine  = ReportEngine()
        with patch("warden.analytics.report.load_entries", return_value=entries):
            data = engine.build("acme", "2026-02")
        assert data.total_requests == 90
        assert data.total_blocked  == 10
        assert data.total_allowed  == 80

    def test_block_rate(self) -> None:
        entries = _make_entries(n_allowed=90, n_blocked=10)
        engine  = ReportEngine()
        with patch("warden.analytics.report.load_entries", return_value=entries):
            data = engine.build("acme", "2026-02")
        assert data.block_rate_pct == pytest.approx(10.0)

    def test_masked_entities_counted(self) -> None:
        entries = _make_entries(n_allowed=80, n_blocked=0, entities=["EMAIL", "PHONE"])
        engine  = ReportEngine()
        with patch("warden.analytics.report.load_entries", return_value=entries):
            data = engine.build("acme", "2026-02")
        # 5 entries have entity_count=2 each
        assert data.total_masked == 10
        assert "EMAIL" in data.entity_counts
        assert "PHONE" in data.entity_counts

    def test_attack_cost_summed(self) -> None:
        entries = _make_entries(n_allowed=0, n_blocked=10)
        engine  = ReportEngine()
        with patch("warden.analytics.report.load_entries", return_value=entries):
            data = engine.build("acme", "2026-02")
        # round(..., 4) rounds 10 * 0.0000075 = 0.000075 → 0.0001
        assert data.attack_cost_usd == pytest.approx(0.0001, rel=1e-4)

    def test_tenant_isolation(self) -> None:
        """Entries for a different tenant must NOT be counted."""
        own   = _make_entries(tenant_id="acme",  n_allowed=5, n_blocked=0)
        other = _make_entries(tenant_id="other", n_allowed=100, n_blocked=50)
        engine = ReportEngine()
        with patch("warden.analytics.report.load_entries", return_value=own + other):
            data = engine.build("acme", "2026-02")
        assert data.total_requests == 5

    def test_month_isolation(self) -> None:
        """Entries from a different month must NOT be counted."""
        feb = _make_entries(month="2026-02", n_allowed=10, n_blocked=0)
        mar = _make_entries(month="2026-03", n_allowed=999, n_blocked=0)
        engine = ReportEngine()
        with patch("warden.analytics.report.load_entries", return_value=feb + mar):
            data = engine.build("acme", "2026-02")
        assert data.total_requests == 10

    def test_empty_tenant(self) -> None:
        """No entries → all counts are zero, no crash."""
        engine = ReportEngine()
        with patch("warden.analytics.report.load_entries", return_value=[]):
            data = engine.build("nobody", "2026-02")
        assert data.total_requests == 0
        assert data.block_rate_pct == 0.0
        assert data.posture == "GREEN"

    def test_daily_buckets_filled(self) -> None:
        """daily list must have exactly 28 entries for February 2026."""
        entries = _make_entries(n_allowed=5)
        engine  = ReportEngine()
        with patch("warden.analytics.report.load_entries", return_value=entries):
            data = engine.build("acme", "2026-02")
        assert len(data.daily) == 28    # Feb 2026 has 28 days

    def test_flag_counts(self) -> None:
        entries = _make_entries(n_blocked=5, flags=["prompt_injection", "secret_detected"])
        engine  = ReportEngine()
        with patch("warden.analytics.report.load_entries", return_value=entries):
            data = engine.build("acme", "2026-02")
        # Each blocked entry has both flags
        assert data.flag_counts.get("prompt_injection", 0) == 5
        assert data.flag_counts.get("secret_detected",  0) == 5


# ── Posture thresholds ────────────────────────────────────────────────────────

class TestPosture:
    def _data_with_rate(self, reqs: int, blocked: int) -> ReportData:
        from warden.analytics.report import ReportData
        return ReportData(
            tenant_id="t", month="2026-02", month_label="Feb",
            generated_at="", total_requests=reqs, total_blocked=blocked,
        )

    def test_green_below_2pct(self) -> None:
        assert self._data_with_rate(100, 1).posture == "GREEN"

    def test_yellow_2_to_8pct(self) -> None:
        assert self._data_with_rate(100, 5).posture == "YELLOW"

    def test_red_above_8pct(self) -> None:
        assert self._data_with_rate(100, 9).posture == "RED"

    def test_green_zero_requests(self) -> None:
        assert self._data_with_rate(0, 0).posture == "GREEN"


# ── Recommendations ───────────────────────────────────────────────────────────

class TestRecommendations:
    def _data(self, **kwargs) -> ReportData:
        from warden.analytics.report import ReportData
        d = ReportData(
            tenant_id="t", month="2026-02", month_label="Feb", generated_at="",
            total_requests=kwargs.get("total_requests", 100),
            total_blocked=kwargs.get("total_blocked", 0),
            flag_counts=kwargs.get("flag_counts", {}),
            entity_counts=kwargs.get("entity_counts", {}),
        )
        return d

    def test_healthy_gives_default_rec(self) -> None:
        recs = _recommendations(self._data())
        assert len(recs) == 1
        assert "healthy" in recs[0].lower()

    def test_high_block_rate_rec(self) -> None:
        recs = _recommendations(self._data(total_requests=100, total_blocked=9))
        assert any("strict mode" in r.lower() for r in recs)

    def test_injection_rec(self) -> None:
        recs = _recommendations(self._data(flag_counts={"prompt_injection": 6}))
        assert any("prompt injection" in r.lower() for r in recs)

    def test_secret_leak_rec(self) -> None:
        recs = _recommendations(self._data(flag_counts={"secret_detected": 1}))
        assert any("credential" in r.lower() or "secret" in r.lower() for r in recs)

    def test_phone_rec(self) -> None:
        recs = _recommendations(self._data(entity_counts={"PHONE": 11}))
        assert any("phone" in r.lower() for r in recs)

    def test_multiple_recs_returned(self) -> None:
        recs = _recommendations(self._data(
            total_requests=100, total_blocked=9,
            flag_counts={"prompt_injection": 6, "secret_detected": 2},
        ))
        assert len(recs) >= 3


# ── render_html() ─────────────────────────────────────────────────────────────

class TestRenderHtml:
    def _html(self, **kwargs) -> str:
        entries = _make_entries(**kwargs)
        engine  = ReportEngine()
        with patch("warden.analytics.report.load_entries", return_value=entries):
            return engine.render_html("acme", "2026-02")

    def test_returns_string(self) -> None:
        assert isinstance(self._html(), str)

    def test_valid_html_structure(self) -> None:
        h = self._html()
        assert "<!DOCTYPE html>" in h
        assert "<html" in h
        assert "</html>" in h

    def test_tenant_id_in_output(self) -> None:
        assert "acme" in self._html()

    def test_month_label_in_output(self) -> None:
        assert "February 2026" in self._html()

    def test_posture_green_in_healthy_run(self) -> None:
        h = self._html(n_allowed=100, n_blocked=0)
        assert "GREEN" in h

    def test_posture_red_when_high_block(self) -> None:
        h = self._html(n_allowed=80, n_blocked=20)
        assert "RED" in h

    def test_section_headings_present(self) -> None:
        h = self._html()
        assert "Executive Summary"     in h
        assert "Threat Intelligence"   in h
        assert "Data Protection"       in h
        assert "Risk Level Breakdown"  in h
        assert "Daily Activity"        in h
        assert "Recommendations"       in h

    def test_print_css_present(self) -> None:
        assert "@media print" in self._html()

    def test_no_raw_script_injection(self) -> None:
        """tenant_id is HTML-escaped — no XSS via crafted tenant id."""
        entries = _make_entries(tenant_id="acme")
        engine  = ReportEngine()
        with patch("warden.analytics.report.load_entries", return_value=entries):
            html = engine.render_html('<script>alert(1)</script>', "2026-02")
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html


# ── render_json() ─────────────────────────────────────────────────────────────

class TestRenderJson:
    def _json(self, **kwargs) -> dict:
        entries = _make_entries(**kwargs)
        engine  = ReportEngine()
        with patch("warden.analytics.report.load_entries", return_value=entries):
            return engine.render_json("acme", "2026-02")

    def test_top_level_keys(self) -> None:
        d = self._json()
        for key in ("tenant_id", "month", "month_label", "generated_at",
                    "summary", "risk_breakdown", "threat_flags",
                    "entity_types", "daily", "recommendations"):
            assert key in d, f"Missing key: {key}"

    def test_summary_keys(self) -> None:
        s = self._json()["summary"]
        for key in ("total_requests", "total_blocked", "total_allowed",
                    "total_masked", "block_rate_pct", "attack_cost_usd",
                    "posture", "posture_label"):
            assert key in s, f"Missing summary key: {key}"

    def test_daily_list_length(self) -> None:
        d = self._json()
        assert len(d["daily"]) == 28    # Feb 2026

    def test_daily_row_keys(self) -> None:
        row = self._json()["daily"][0]
        for key in ("date", "requests", "blocked", "masked"):
            assert key in row

    def test_serialisable(self) -> None:
        """Must not raise when JSON-serialised."""
        d = self._json()
        json.dumps(d)   # should not raise

    def test_tenant_isolation_json(self) -> None:
        own   = _make_entries(tenant_id="acme",  n_allowed=3,   n_blocked=0)
        other = _make_entries(tenant_id="rival", n_allowed=999, n_blocked=0)
        engine = ReportEngine()
        with patch("warden.analytics.report.load_entries", return_value=own + other):
            d = engine.render_json("acme", "2026-02")
        assert d["summary"]["total_requests"] == 3


# ── HTTP endpoint ─────────────────────────────────────────────────────────────

class TestReportEndpoint:
    """Smoke tests via FastAPI TestClient — no model, no Redis."""

    @pytest.fixture(autouse=True)
    def _client(self):
        from fastapi.testclient import TestClient

        from warden.main import app
        self.client = TestClient(app, raise_server_exceptions=True)

    def _entries(self) -> list[dict]:
        return _make_entries(n_allowed=5, n_blocked=1)

    def test_html_report_returns_200(self) -> None:
        with patch("warden.analytics.report.load_entries", return_value=self._entries()):
            resp = self.client.get(
                "/msp/report/acme?month=2026-02&fmt=html",
                follow_redirects=True,
            )
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")
        assert "<!DOCTYPE html>" in resp.text

    def test_json_report_returns_200(self) -> None:
        with patch("warden.analytics.report.load_entries", return_value=self._entries()):
            resp = self.client.get(
                "/msp/report/acme?month=2026-02&fmt=json",
                follow_redirects=True,
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["tenant_id"] == "acme"
        assert data["month"] == "2026-02"
        assert "summary" in data

    def test_invalid_month_returns_400(self) -> None:
        resp = self.client.get("/msp/report/acme?month=not-a-month")
        assert resp.status_code == 400

    def test_default_month_is_current(self) -> None:
        from datetime import UTC, datetime
        current = datetime.now(UTC).strftime("%Y-%m")
        with patch("warden.analytics.report.load_entries", return_value=[]):
            resp = self.client.get("/msp/report/acme?fmt=json")
        assert resp.status_code == 200
        assert resp.json()["month"] == current

    def test_html_content_disposition_header(self) -> None:
        with patch("warden.analytics.report.load_entries", return_value=self._entries()):
            resp = self.client.get(
                "/msp/report/acme?month=2026-02&fmt=html",
                follow_redirects=True,
            )
        cd = resp.headers.get("content-disposition", "")
        assert "attachment" in cd
        assert "warden-report-acme-2026-02.html" in cd
