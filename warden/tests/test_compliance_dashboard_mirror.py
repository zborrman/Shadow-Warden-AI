"""
warden/tests/test_compliance_dashboard_mirror.py — D-3 phase 1c.

`ComplianceDashboard.get_metrics()` pulled a 30-day window into memory and made
eight passes over it in Python. It now asks the `filter_events` mirror for the
same eight aggregates in one round trip, and falls back to the scan when the
mirror cannot answer.

The property that matters is not "SQL is used" — it is that **both paths return
the same numbers**, because either may answer any given call depending on
whether the mirror is on, still filling, or older than the window asked for. A
reader that quietly changes its arithmetic when a feature flag flips is worse
than the scan it replaced.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from warden.analytics import logger as lg
from warden.compliance.dashboard import ComplianceDashboard

# One fixed window of traffic, exercising every aggregate the dashboard reads.
_ENTRIES = [
    # allowed, low risk, no flags, no secrets
    {"allowed": True,  "risk_level": "low",   "flags": [],
     "secrets_found": [], "attack_cost_usd": 0.0,  "payload_tokens": 10},
    # blocked, lower-case "block" exactly as the journal writes it
    {"allowed": False, "risk_level": "block", "flags": ["prompt_injection"],
     "secrets_found": ["aws_key"], "attack_cost_usd": 0.5, "payload_tokens": 20},
    # allowed but HIGH — still an averted incident for the ROI arithmetic
    {"allowed": True,  "risk_level": "high",  "flags": ["ml_uncertain", "prompt_injection"],
     "secrets_found": [], "attack_cost_usd": 0.25, "payload_tokens": 30},
    # shadow-banned
    {"allowed": False, "risk_level": "block", "flags": ["shadow_ban"],
     "secrets_found": ["stripe_key", "aws_key"], "attack_cost_usd": 1.0, "payload_tokens": 40},
]

_EXPECTED = {
    "total": 4,
    "blocked": 2,
    "high_blocks": 3,          # two BLOCK + one HIGH
    "shadow_ban": 1,
    "attack_cost_usd": 1.75,
    "payload_tokens": 100,
    "secrets_total": 3,        # aws_key, stripe_key, aws_key
    "flag_counts": {"prompt_injection": 2, "ml_uncertain": 1, "shadow_ban": 1},
    "secret_counts": {"aws_key": 2, "stripe_key": 1},
}


@pytest.fixture
def journal(tmp_path, monkeypatch):
    now = datetime.now(UTC)
    path = tmp_path / "logs.json"
    path.write_text(
        "".join(
            json.dumps({**e, "ts": (now - timedelta(hours=i + 1)).isoformat(),
                        "request_id": f"r{i}"}) + "\n"
            for i, e in enumerate(_ENTRIES)
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(lg, "LOGS_PATH", path, raising=False)
    return path


def test_the_journal_path_computes_the_documented_aggregates(journal):
    got = ComplianceDashboard._metrics_from_journal(days=30)
    assert got == _EXPECTED


def test_high_blocks_counts_high_and_block_together(journal):
    """The ROI arithmetic treats both as one averted incident.

    Not the `summary()` split, where HIGH and BLOCK are separate columns — a
    detail easy to get wrong when porting the filter to SQL.
    """
    assert ComplianceDashboard._metrics_from_journal(days=30)["high_blocks"] == 3


def test_journal_path_is_case_insensitive_on_risk_level(journal, tmp_path, monkeypatch):
    """The journal writes lower-case, revision 0014 stores upper-case.

    Both spellings must count, or the number changes depending on which build
    wrote the row.
    """
    now = datetime.now(UTC)
    path = tmp_path / "mixed.json"
    path.write_text(
        json.dumps({"ts": now.isoformat(), "request_id": "a", "risk_level": "BLOCK",
                    "allowed": False, "flags": [], "secrets_found": []}) + "\n"
        + json.dumps({"ts": now.isoformat(), "request_id": "b", "risk_level": "block",
                      "allowed": False, "flags": [], "secrets_found": []}) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(lg, "LOGS_PATH", path, raising=False)
    assert ComplianceDashboard._metrics_from_journal(days=30)["high_blocks"] == 2


def test_get_metrics_prefers_the_mirror(journal, monkeypatch):
    """When the mirror answers, the scan must not run at all — that is the point."""
    scanned: list[int] = []
    monkeypatch.setattr(
        ComplianceDashboard, "_metrics_from_journal",
        staticmethod(lambda days: scanned.append(1) or _EXPECTED),
    )
    monkeypatch.setattr(
        ComplianceDashboard, "_metrics_from_mirror", staticmethod(lambda since: _EXPECTED)
    )
    out = ComplianceDashboard().get_metrics(days=30)
    assert scanned == [], "the mirror answered, yet the journal was scanned anyway"
    assert out["traffic"]["total_requests"] == 4


def test_get_metrics_falls_back_when_the_mirror_declines(journal, monkeypatch):
    monkeypatch.setattr(
        ComplianceDashboard, "_metrics_from_mirror", staticmethod(lambda since: None)
    )
    out = ComplianceDashboard().get_metrics(days=30)
    assert out["traffic"]["total_requests"] == 4
    assert out["threat_mitigation"]["high_block_events"] == 3


def test_both_paths_produce_the_same_report(journal, monkeypatch):
    """The report must not depend on which path answered."""
    monkeypatch.setattr(
        ComplianceDashboard, "_metrics_from_mirror", staticmethod(lambda since: None)
    )
    from_journal = ComplianceDashboard().get_metrics(days=30)

    monkeypatch.setattr(
        ComplianceDashboard, "_metrics_from_mirror", staticmethod(lambda since: _EXPECTED)
    )
    from_mirror = ComplianceDashboard().get_metrics(days=30)

    for section in ("traffic", "shadow_ban", "threat_mitigation", "secret_protection"):
        assert from_journal[section] == from_mirror[section], f"{section} diverged"


def test_a_mirror_error_never_breaks_the_report(journal, monkeypatch):
    """The mirror is best-effort; the journal is the authority."""
    def _boom(since):
        raise RuntimeError("postgres is down")

    monkeypatch.setattr(
        "warden.analytics.events_store.compliance_metrics", _boom, raising=False
    )
    out = ComplianceDashboard().get_metrics(days=30)
    assert out["traffic"]["total_requests"] == 4


def test_compliance_metrics_refuses_an_uncovered_window(monkeypatch):
    from warden.analytics import events_store

    monkeypatch.setattr("warden.db.connection.DATABASE_URL", "postgresql://x/y", raising=False)
    monkeypatch.setattr(
        events_store, "coverage_start", lambda: datetime.now(UTC) - timedelta(hours=1)
    )
    assert events_store.compliance_metrics(datetime.now(UTC) - timedelta(days=30)) is None
