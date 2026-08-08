"""
warden/tests/test_bi_usage_summary.py — D-3 phase 1c, BI usage summary.

`get_usage_summary()` reported zero traffic in production, always. Four
independent defects were stacked, and the first alone was fatal:

  1. it resolved its own journal path — `data_path("warden_logs.json",
     "LOGS_PATH")`. With `LOGS_PATH` unset, as it is in production, that is
     `warden_logs.json`, a name the journal has never had (`logs.json`). The
     `except FileNotFoundError: pass` turned the miss into zeros.
  2. `timestamp` — the key is `ts`, so every row would have failed the month
     filter even if the file had been found.
  3. `verdict` — the key is `risk_level`, so `blocked` would have stayed 0.
  4. `processing_ms` — the key is `elapsed_ms`, so latency would have stayed 0.

Fixing only the filename would still have produced zeros. These tests pin the
numbers and, more usefully, pin the two structural rules that would have
prevented all four: this module resolves no journal path of its own, and it
reads no key `build_entry()` does not write.
"""
from __future__ import annotations

import ast
import inspect
import json
from datetime import UTC, datetime, timedelta

import pytest

from warden.analytics import logger as lg
from warden.business_intelligence import service as bi


@pytest.fixture(autouse=True)
def _no_cache(monkeypatch):
    monkeypatch.setattr(bi, "cache_get", lambda *a, **k: None)
    monkeypatch.setattr(bi, "cache_set", lambda *a, **k: None)
    # Force the journal path; the mirror is covered separately.
    monkeypatch.setattr(bi, "_usage_from_mirror", lambda tenant_id, period_month: None)


@pytest.fixture
def journal(tmp_path, monkeypatch):
    now = datetime.now(UTC).replace(day=15, hour=12, minute=0, second=0, microsecond=0)
    rows = [
        {"allowed": True,  "risk_level": "low",   "flags": [],                  "elapsed_ms": 100},
        {"allowed": False, "risk_level": "block", "flags": ["prompt_injection"], "elapsed_ms": 300},
        {"allowed": True,  "risk_level": "high",  "flags": ["prompt_injection"], "elapsed_ms": 200},
    ]
    path = tmp_path / "logs.json"
    path.write_text(
        "".join(
            json.dumps({**r, "ts": (now - timedelta(hours=i)).isoformat(),
                        "request_id": f"r{i}", "tenant_id": "acme"}) + "\n"
            for i, r in enumerate(rows)
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(lg, "LOGS_PATH", path, raising=False)
    return now.strftime("%Y-%m")


def test_usage_is_no_longer_always_zero(journal):
    out = bi.get_usage_summary("acme", period_month=journal)
    assert out["total_requests"] == 3
    assert out["blocked_requests"] == 2      # one BLOCK + one HIGH
    assert out["allowed_requests"] == 1
    assert out["avg_latency_ms"] == 200.0
    assert out["block_rate_pct"] == 66.67


def test_categories_come_from_flags(journal):
    """`category` and `type` were read; the journal writes neither."""
    cats = bi.get_usage_summary("acme", period_month=journal)["top_categories"]
    assert cats == [{"category": "prompt_injection", "count": 2}]


def test_daily_trend_is_populated(journal):
    trend = bi.get_usage_summary("acme", period_month=journal)["daily_trend"]
    assert trend and sum(d["count"] for d in trend) == 3


def test_another_tenant_sees_nothing(journal):
    assert bi.get_usage_summary("other", period_month=journal)["total_requests"] == 0


def test_module_resolves_no_journal_path_of_its_own():
    """The defect that made the other three unreachable.

    A second resolver for a file another module owns is how BI ended up
    reading `warden_logs.json` while the gateway wrote `logs.json`.
    """
    # Read the AST, not the text. The module documents the old path on purpose,
    # and a guard that trips on its own rationale is a guard someone deletes.
    tree = ast.parse(inspect.getsource(bi))
    offenders = [
        ast.unparse(node)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and getattr(node.func, "id", "") == "data_path"
        and any(
            isinstance(a, ast.Constant) and isinstance(a.value, str)
            and ("log" in a.value.lower())
            for a in node.args
        )
    ]
    assert not offenders, (
        "business_intelligence resolves its own journal path again "
        f"({offenders}) — warden.analytics.logger owns where the journal lives"
    )


def test_reads_no_key_build_entry_does_not_write():
    """`dict.get()` on a ghost key returns a default, not an error."""
    written = set(inspect.getsource(lg.build_entry).split('"')[1::2])
    read = inspect.getsource(bi._usage_from_journal)
    for ghost in ("timestamp", "verdict", "processing_ms", "category"):
        assert ghost not in written, f"build_entry now writes {ghost}; update this guard"
        assert f'"{ghost}"' not in read, (
            f"_usage_from_journal reads `{ghost}`, which build_entry never writes — "
            "it will silently report zero"
        )


def test_month_bounds_cover_december():
    """The next-month rollover is the easy one to get wrong."""
    start, end = bi._month_bounds("2026-12")
    assert start == datetime(2026, 12, 1, tzinfo=UTC)
    assert end == datetime(2027, 1, 1, tzinfo=UTC)


def test_mirror_result_is_used_when_it_answers(journal, monkeypatch):
    canned = {"total": 42, "blocked": 7, "avg_ms": 1.5,
              "categories": [("x", 1)], "daily": [("2026-08-01", 42)]}
    monkeypatch.setattr(bi, "_usage_from_mirror", lambda tenant_id, period_month: canned)
    out = bi.get_usage_summary("acme", period_month=journal)
    assert out["total_requests"] == 42 and out["blocked_requests"] == 7


def test_a_mirror_error_falls_back_to_the_journal(journal, monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError("postgres is down")

    monkeypatch.setattr(bi, "_usage_from_mirror", bi.__dict__["_usage_from_mirror"])
    monkeypatch.setattr(
        "warden.analytics.events_store.usage_summary", _boom, raising=False
    )
    assert bi.get_usage_summary("acme", period_month=journal)["total_requests"] == 3
