"""
warden/tests/test_shadow_ban_is_a_flag.py

Two money-facing readers counted shadow bans off `entry["shadow_banned"]`, a
key `build_entry()` has never written:

  * `financial/metrics_reader.shadow_banned_count()` — its Redis path is
    primary, but the journal fallback always returned 0;
  * `api/tenant_impact` — `inference_saved` summed `attack_cost_usd` over
    shadow-banned entries, so the saving it reports to a tenant was always
    $0.00.

Both are the quiet kind: zero is also what "no shadow bans" looks like.
A shadow ban is recorded as a detection **flag**, which is how
`compliance/dashboard.py` has always counted it.
"""
from __future__ import annotations

import os

# Warden's auth is fail-closed: importing the app modules with a blank
# WARDEN_API_KEY raises unless this is set. The suite conftest does it, but
# these tests import warden modules inside their own bodies, so set it here too
# rather than depend on collection order.
os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")


def _entry(flags: list[str], cost: float = 0.5) -> dict:
    return {
        "ts": "2026-08-09T12:00:00+00:00", "request_id": "r", "allowed": False,
        "risk_level": "block", "flags": flags, "secrets_found": [],
        "attack_cost_usd": cost, "payload_tokens": 10, "elapsed_ms": 5.0,
    }


def test_metrics_reader_counts_the_flag(monkeypatch):
    from warden.financial import metrics_reader as mr

    reader = mr.MetricsReader()
    monkeypatch.setattr(reader, "_redis_shadow_ban_count", lambda: 0)
    monkeypatch.setattr(reader, "_load_entries", lambda: [
        _entry(["shadow_ban"]), _entry(["prompt_injection"]), _entry(["shadow_ban"]),
    ])
    assert reader.shadow_banned_count() == 2


def test_metrics_reader_still_reports_zero_when_there_are_none(monkeypatch):
    """The fix must not turn every blocked request into a shadow ban."""
    from warden.financial import metrics_reader as mr

    reader = mr.MetricsReader()
    monkeypatch.setattr(reader, "_redis_shadow_ban_count", lambda: 0)
    monkeypatch.setattr(reader, "_load_entries", lambda: [_entry(["prompt_injection"])])
    assert reader.shadow_banned_count() == 0


def test_tenant_impact_credits_only_shadow_banned_requests(monkeypatch):
    """The saving reported to a tenant, executed rather than grepped.

    `inference_saved` summed `attack_cost_usd` over `e.get("shadow_banned")`,
    a key that does not exist, so the figure was always $0.00 — and a
    source-text assertion alone would not have caught a wrong *predicate*.
    """
    from warden.analytics import logger as event_logger
    from warden.api import tenant_impact as ti

    monkeypatch.setattr(event_logger, "load_entries", lambda days=None: [
        _entry(["shadow_ban"], cost=0.25),
        _entry(["prompt_injection"], cost=9.99),   # must not be credited
        _entry(["shadow_ban"], cost=0.75),
    ])
    out = ti._build_impact("default", 30)
    assert out["inference_saved_usd"] == 1.0, out


def test_tenant_impact_reports_zero_when_nothing_was_shadow_banned(monkeypatch):
    from warden.analytics import logger as event_logger
    from warden.api import tenant_impact as ti

    monkeypatch.setattr(event_logger, "load_entries", lambda days=None: [
        _entry(["prompt_injection"], cost=9.99),
    ])
    assert ti._build_impact("default", 30)["inference_saved_usd"] == 0.0


def test_neither_module_reads_the_key_that_does_not_exist():
    import inspect

    from warden.api import tenant_impact
    from warden.financial import metrics_reader as mr

    for mod in (mr, tenant_impact):
        code = "\n".join(
            ln for ln in inspect.getsource(mod).splitlines()
            if not ln.lstrip().startswith("#")
        )
        assert 'get("shadow_banned")' not in code, (
            f"{mod.__name__} reads `shadow_banned` again — build_entry never writes it"
        )
