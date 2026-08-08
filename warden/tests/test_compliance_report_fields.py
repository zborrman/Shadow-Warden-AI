"""
warden/tests/test_compliance_report_fields.py

`api/compliance_report.py::_aggregate_logs()` read three fields the journal has
never written, so the report handed to a regulator said:

    blocked 0 · allowed = total · injection hits 0 · avg latency 0.0 ms

Measured against 3 377 production entries on 2026-08-08, the truth for the same
window was blocked 3 100, allowed 277, injection 3 100, avg 652.4 ms. The report
described a gateway that blocked nothing, and offered that as evidence of
compliance.

The failure is not arithmetic — every count was computed correctly, over a key
that does not exist. `dict.get()` returns a default rather than raising, so the
figures were plausible instead of absent. These tests pin the field names
against `build_entry()`, which is the authority, and pin the numbers the
aggregation must produce.
"""
from __future__ import annotations

import inspect
import json
from datetime import UTC, datetime, timedelta

import pytest

from warden.analytics import logger as lg
from warden.api import compliance_report as cr

# Captured before any fixture stubs it out, so the fallback test can put the
# real seam back without undoing the fixture's LOGS_PATH patch as well.
_REAL_MIRROR_SEAM = cr._aggregate_from_mirror

# The journal as it is actually written: lower-case risk levels, lower-case
# flags, `elapsed_ms`, and no `verdict` key anywhere.
_ENTRIES = [
    {"allowed": True,  "risk_level": "low",   "flags": [],
     "secrets_found": [],          "elapsed_ms": 100},
    {"allowed": False, "risk_level": "block", "flags": ["prompt_injection"],
     "secrets_found": ["aws_key"], "elapsed_ms": 200},
    {"allowed": True,  "risk_level": "high",  "flags": ["ml_uncertain"],
     "secrets_found": [],          "elapsed_ms": 300},
    {"allowed": False, "risk_level": "block", "flags": ["prompt_injection", "obfuscation"],
     "secrets_found": [],          "elapsed_ms": 400},
]


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
    # Force the journal path: the mirror is exercised separately.
    monkeypatch.setattr(cr, "_aggregate_from_mirror", lambda since: None)
    return path


def test_the_report_no_longer_claims_nothing_was_blocked(journal):
    stats = cr._aggregate_logs(days=30)
    assert stats["total"] == 4
    assert stats["blocked"] == 3, "two BLOCK + one HIGH — was 0 while it read `verdict`"
    assert stats["allowed"] == 1


def test_injection_hits_are_counted_against_lower_case_flags(journal):
    """Flags are `prompt_injection`; the old test was for `\"INJECTION\"`."""
    assert cr._aggregate_logs(days=30)["inj_hits"] == 2


def test_average_latency_reads_elapsed_ms(journal):
    assert cr._aggregate_logs(days=30)["avg_ms"] == 250.0


def test_pii_and_categories_were_already_correct(journal):
    stats = cr._aggregate_logs(days=30)
    assert stats["pii_hits"] == 1
    assert stats["anon_rate"] == 25.0
    assert stats["categories"]["prompt_injection"] == 2


def test_aggregation_reads_only_keys_build_entry_writes():
    """The guard that would have caught this on the day it was written.

    `dict.get()` on a key that does not exist returns a default instead of
    raising, so a typo in a field name produces a confident zero. The journal's
    schema is `build_entry()`; nothing downstream may invent a key.
    """
    written = set(inspect.getsource(lg.build_entry).split('"')[1::2])
    read = inspect.getsource(cr._aggregate_logs)
    for ghost in ("verdict", "latency_ms", "timestamp"):
        if ghost in written:
            continue
        assert f'"{ghost}"' not in read or ghost in ("timestamp",), (
            f"_aggregate_logs reads `{ghost}`, which build_entry never writes — "
            "it will silently report zero"
        )


def test_build_entry_still_writes_the_names_this_module_depends_on():
    """If the journal renames a field, this fails here rather than in a report."""
    src = inspect.getsource(lg.build_entry)
    for name in ("risk_level", "elapsed_ms", "flags", "secrets_found", "allowed"):
        assert f'"{name}"' in src, f"build_entry no longer writes `{name}`"


def test_the_scan_is_windowed(journal, monkeypatch):
    """It called load_entries() with no window on a request path, then filtered."""
    seen: list = []
    real = lg.load_entries

    def _spy(days=None):
        seen.append(days)
        return real(days=days)

    monkeypatch.setattr(lg, "load_entries", _spy)
    cr._aggregate_logs(days=7)
    assert seen == [7], f"load_entries was called with {seen}, not a 7-day window"


def test_mirror_result_is_used_when_it_answers(journal, monkeypatch):
    canned = {
        "total": 99, "blocked": 9, "allowed": 90, "pii_hits": 1,
        "inj_hits": 2, "avg_ms": 3.5, "anon_rate": 1.0, "categories": {},
    }
    monkeypatch.setattr(cr, "_aggregate_from_mirror", lambda since: canned)
    assert cr._aggregate_logs(days=30) == canned


def test_a_mirror_error_falls_back_to_the_journal(journal, monkeypatch):
    """The mirror is best-effort; the journal is the authority."""
    def _boom(since):
        raise RuntimeError("postgres is down")

    # Put the real seam back — the fixture stubs it out — then make the reader
    # underneath it raise, which is the case being tested.
    monkeypatch.setattr(cr, "_aggregate_from_mirror", _REAL_MIRROR_SEAM)
    monkeypatch.setattr(
        "warden.analytics.events_store.compliance_report_stats", _boom, raising=False
    )
    stats = cr._aggregate_logs(days=30)
    assert stats["total"] == 4 and stats["blocked"] == 3
