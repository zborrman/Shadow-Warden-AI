"""
warden/tests/test_evidence_declares_absence.py

Two audit-facing surfaces render missing data as a finding:

  * the SOC 2 collector reads 17 fields off journal entries and 15 do not
    exist. `timestamp` is the decisive one — `_iter_log_window()` filters on it,
    so it yields nothing and every control reports zero. A bundle of zeroes is
    indistinguishable from a quiet, clean day, which is the reading an auditor
    would prefer and the worst failure mode an evidence artifact can have.
  * `/xai/dashboard` reports SKIP on `topology`, `brain`, `causal` and `ers`
    for every record ever explained, because `build_chain()` reads 27 fields
    and the journal writes 7.

Making them work is a separate decision — record the fields, or drop the
claims. What is pinned here is narrower and non-negotiable in the meantime:
**neither surface may present absence of data as absence of events.**
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from warden.compliance import soc2_collector as sc


@pytest.fixture
def journal(tmp_path, monkeypatch):
    def _write(rows: list[dict]) -> None:
        path = tmp_path / "logs.json"
        path.write_text(
            "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8"
        )
        monkeypatch.setattr(sc, "_logs_path", lambda: path)
    return _write


def _window(hours_back: float = 1.0) -> tuple[float, float]:
    now = datetime.now(UTC)
    return (now - timedelta(hours=hours_back)).timestamp(), (now + timedelta(hours=1)).timestamp()


def test_traffic_the_collectors_cannot_read_is_reported_as_unavailable(journal):
    now = datetime.now(UTC).isoformat()
    journal([
        {"ts": now, "request_id": "r1", "allowed": False, "risk_level": "block"},
        {"ts": now, "request_id": "r2", "allowed": True, "risk_level": "low"},
    ])
    cov = sc._journal_coverage(*_window())
    assert cov["status"] == "unavailable"
    assert cov["entries_in_window"] == 2
    assert cov["entries_visible_to_collectors"] == 0
    assert "timestamp" in cov["missing_entry_fields"]


def test_an_empty_window_is_not_reported_as_a_defect(journal):
    """No traffic is a real, honest zero — it must not cry wolf."""
    old = (datetime.now(UTC) - timedelta(days=30)).isoformat()
    journal([{"ts": old, "request_id": "r1"}])
    assert sc._journal_coverage(*_window())["status"] == "no_traffic"


def test_a_missing_journal_is_unavailable_not_clean(journal, tmp_path, monkeypatch):
    monkeypatch.setattr(sc, "_logs_path", lambda: tmp_path / "absent.json")
    cov = sc._journal_coverage(*_window())
    assert cov["status"] == "unavailable"
    assert cov["entries_in_window"] == 0


def test_the_bundle_carries_the_verdict_where_an_auditor_will_see_it(journal, tmp_path, monkeypatch):
    now = datetime.now(UTC)
    journal([{"ts": now.isoformat(), "request_id": "r1", "allowed": False, "risk_level": "block"}])
    monkeypatch.setattr(sc, "_archive_dir", lambda: tmp_path / "arch")
    bundle = sc.collect_daily_evidence(date=now)
    assert bundle["evidence_status"] == "unavailable"
    assert bundle["evidence_coverage"]["reason"]
    assert bundle["schema_version"] == "SOC2Collector-v2", (
        "the bundle gained a field an auditor must read — bump the schema version"
    )


def test_full_evidence_would_read_as_ok(journal):
    """The probe must be able to say yes, or it is just a constant."""
    now = datetime.now(UTC).isoformat()
    complete = {"ts": now, "request_id": "r1"}
    complete.update(dict.fromkeys(sc._REQUIRED_ENTRY_FIELDS, ""))
    complete["timestamp"] = now          # what _iter_log_window filters on
    journal([complete])
    cov = sc._journal_coverage(*_window())
    assert cov["status"] == "ok", cov
    assert cov["missing_entry_fields"] == []


# ── /xai/dashboard ────────────────────────────────────────────────────────────

def test_dashboard_flags_stages_that_are_skip_on_every_record():
    from warden.api import xai

    src = __import__("inspect").getsource(xai)
    assert "stages_without_evidence" in src and "data_quality" in src, (
        "the XAI dashboard no longer declares which stages have no evidence"
    )
