"""
warden/tests/test_error_budget_alert.py  (FM-5)
Pure-logic tests for the multiwindow SLA error-budget burn-rate alert job.
The DB read is not exercised here (no Postgres); the decision + formatting
helpers are pure and take already-fetched monitor rows.
"""
from __future__ import annotations

from warden.agent.scheduler import (
    _burn_windows_from_row,
    _evaluate_monitor_burns,
    _format_burn_slack,
)

_PRO_SLA = 0.999  # 99.9% → 0.1% error budget


def _row(mid: str, name: str, **windows) -> dict:
    """Build a monitor row with the up_* columns; unset windows default to 100%."""
    base = {"id": mid, "name": name, "url": f"https://{name}"}
    for col in ("up_5m", "up_30m", "up_1h", "up_2h", "up_6h", "up_1d", "up_3d"):
        base[col] = windows.get(col, 100.0)
    return base


# ── window mapping ────────────────────────────────────────────────────────────

class TestBurnWindowsFromRow:
    def test_maps_columns_to_labels(self):
        w = _burn_windows_from_row(_row("m1", "api", up_5m=90.0, up_1h=95.0))
        assert w["5m"] == 90.0
        assert w["1h"] == 95.0
        assert set(w) == {"5m", "30m", "1h", "2h", "6h", "1d", "3d"}

    def test_none_column_treated_as_perfect(self):
        row = _row("m1", "api")
        row["up_5m"] = None  # no probes in that window yet
        w = _burn_windows_from_row(row)
        assert w["5m"] == 100.0  # missing data is not a breach

    def test_decimal_like_values_floated(self):
        # ROUND(numeric) can arrive as Decimal — must not raise
        from decimal import Decimal
        row = _row("m1", "api")
        row["up_1h"] = Decimal("99.5")
        w = _burn_windows_from_row(row)
        assert w["1h"] == 99.5


# ── firing evaluation ─────────────────────────────────────────────────────────

class TestEvaluateMonitorBurns:
    def test_healthy_monitor_does_not_fire(self):
        rows = [_row("m1", "api")]  # all windows 100%
        assert _evaluate_monitor_burns(rows, _PRO_SLA) == []

    def test_sustained_outage_pages(self):
        # 1h at 90% and 5m at 0% → both burn far past the 14.4× page threshold
        rows = [_row("m1", "api", up_5m=0.0, up_1h=90.0)]
        firing = _evaluate_monitor_burns(rows, _PRO_SLA)
        assert len(firing) == 1
        assert firing[0]["severity"] == "page"
        assert firing[0]["name"] == "api"

    def test_single_blip_does_not_page(self):
        # 5m window fully down but every longer window still healthy → no page
        rows = [_row("m1", "api", up_5m=0.0)]
        assert _evaluate_monitor_burns(rows, _PRO_SLA) == []

    def test_slow_burn_tickets_not_pages(self):
        # 1d and 2h burning ~3× but the fast page windows healthy → ticket tier
        # error_rate for 3× at 0.999 SLA = 3*0.001 = 0.003 → uptime 99.7%
        rows = [_row("m1", "api", up_1d=99.6, up_2h=99.6)]
        firing = _evaluate_monitor_burns(rows, _PRO_SLA)
        assert len(firing) == 1
        assert firing[0]["severity"] == "ticket"

    def test_multiple_monitors_mixed(self):
        rows = [
            _row("m1", "api", up_5m=0.0, up_1h=90.0),   # pages
            _row("m2", "dash"),                          # healthy
            _row("m3", "app", up_1d=99.6, up_2h=99.6),  # tickets
        ]
        firing = _evaluate_monitor_burns(rows, _PRO_SLA)
        names = {f["name"]: f["severity"] for f in firing}
        assert names == {"api": "page", "app": "ticket"}

    def test_empty_rows(self):
        assert _evaluate_monitor_burns([], _PRO_SLA) == []


# ── slack formatting ──────────────────────────────────────────────────────────

class TestFormatBurnSlack:
    def test_pages_ranked_before_tickets(self):
        firing = [
            {"monitor_id": "m3", "name": "app", "url": "u", "severity": "ticket",
             "long_window": "1d", "short_window": "2h", "long_burn": 3.0, "short_burn": 3.0,
             "label": "10% of budget in 1d"},
            {"monitor_id": "m1", "name": "api", "url": "u", "severity": "page",
             "long_window": "1h", "short_window": "5m", "long_burn": 100.0, "short_burn": 1000.0,
             "label": "2% of budget in 1h"},
        ]
        msg = _format_burn_slack(firing, "2026-07-16 12:00 UTC", "pro")
        # page line comes before ticket line
        assert msg.index("api") < msg.index("app")
        assert msg.startswith("🔴")  # a page is present
        assert "PAGE" in msg and "TICKET" in msg
        assert "tier `pro`" in msg

    def test_ticket_only_uses_orange_icon(self):
        firing = [
            {"monitor_id": "m3", "name": "app", "url": "u", "severity": "ticket",
             "long_window": "1d", "short_window": "2h", "long_burn": 3.0, "short_burn": 3.0,
             "label": "10% of budget in 1d"},
        ]
        msg = _format_burn_slack(firing, "ts", "enterprise")
        assert msg.startswith("🟠")
        assert "tier `enterprise`" in msg
