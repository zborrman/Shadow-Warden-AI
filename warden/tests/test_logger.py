"""
warden/tests/test_logger.py
━━━━━━━━━━━━━━━━━━━━━━━━━━
Unit tests for the GDPR-safe analytics logger.

Uses a temporary file path to avoid touching production logs.
"""
from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta

import pytest


@pytest.fixture(autouse=True)
def tmp_log(monkeypatch, tmp_path):
    """Override LOGS_PATH to use a temp file for each test."""
    log_file = tmp_path / "test_logs.json"
    monkeypatch.setenv("LOGS_PATH", str(log_file))
    # Re-import to pick up the new env var
    import importlib

    import warden.analytics.logger as logger_mod
    importlib.reload(logger_mod)
    monkeypatch.setattr("warden.analytics.logger.LOGS_PATH", log_file)
    yield log_file


# ── Helpers ───────────────────────────────────────────────────────────────────

def _entry(**overrides):
    """Return a minimal valid build_entry() kwargs dict with all required fields."""
    defaults = {
        "request_id": "req-1",
        "allowed": True,
        "risk_level": "low",
        "flags": [],
        "secrets_found": [],
        "payload_len": 40,
        "payload_tokens": 10,
        "attack_cost_usd": 0.0000015,
        "elapsed_ms": 5.0,
        "strict": False,
    }
    defaults.update(overrides)
    return defaults


# ── build_entry() structure ───────────────────────────────────────────────────

def test_build_entry_structure() -> None:
    from warden.analytics import logger as event_logger
    entry = event_logger.build_entry(**_entry(request_id="req-123", allowed=True,
                                              risk_level="low", payload_len=42))
    assert entry["request_id"] == "req-123"
    assert entry["allowed"] is True
    assert entry["risk_level"] == "low"
    assert "ts" in entry
    # Content must NEVER appear in log entries
    assert "content" not in entry


def test_build_entry_contains_cost_fields() -> None:
    from warden.analytics import logger as event_logger
    entry = event_logger.build_entry(**_entry(payload_tokens=80, attack_cost_usd=0.000012))
    assert entry["payload_tokens"] == 80
    assert entry["attack_cost_usd"] == pytest.approx(0.000012)


def test_build_entry_cost_fields_present_even_when_zero() -> None:
    from warden.analytics import logger as event_logger
    entry = event_logger.build_entry(**_entry(payload_tokens=0, attack_cost_usd=0.0))
    assert "payload_tokens" in entry
    assert "attack_cost_usd" in entry
    assert entry["payload_tokens"] == 0
    assert entry["attack_cost_usd"] == 0.0


# ── estimate_tokens() ─────────────────────────────────────────────────────────

def test_estimate_tokens_basic() -> None:
    from warden.analytics.logger import estimate_tokens
    # 40-char string → 40 // 4 = 10 tokens
    assert estimate_tokens("a" * 40) == 10


def test_estimate_tokens_minimum_one() -> None:
    from warden.analytics.logger import estimate_tokens
    # Empty or very short strings must return at least 1
    assert estimate_tokens("") == 1
    assert estimate_tokens("hi") == 1


def test_estimate_tokens_large() -> None:
    from warden.analytics.logger import estimate_tokens
    # 4000 chars → 1000 tokens
    assert estimate_tokens("x" * 4000) == 1000


# ── token_cost_usd() ──────────────────────────────────────────────────────────

def test_token_cost_zero_tokens() -> None:
    from warden.analytics.logger import token_cost_usd
    assert token_cost_usd(0) == 0.0


def test_token_cost_one_million_tokens() -> None:
    from warden.analytics.logger import token_cost_usd
    # Default $0.15/1M tokens → 1M tokens = $0.15
    cost = token_cost_usd(1_000_000)
    assert cost == pytest.approx(0.15, rel=1e-3)


def test_token_cost_scales_linearly() -> None:
    from warden.analytics.logger import token_cost_usd
    assert token_cost_usd(100) * 10 == pytest.approx(token_cost_usd(1000), rel=1e-6)


# ── append / load ─────────────────────────────────────────────────────────────

def test_append_creates_file(tmp_log) -> None:
    from warden.analytics import logger as event_logger
    event_logger.append(event_logger.build_entry(**_entry()))
    assert tmp_log.exists()


def test_append_is_valid_ndjson(tmp_log) -> None:
    from warden.analytics import logger as event_logger
    for i in range(3):
        event_logger.append(event_logger.build_entry(**_entry(request_id=f"r{i}")))
    lines = tmp_log.read_text().strip().split("\n")
    assert len(lines) == 3
    for line in lines:
        parsed = json.loads(line)
        assert "ts" in parsed


def test_load_entries_returns_all(tmp_log) -> None:
    from warden.analytics import logger as event_logger
    event_logger.append(event_logger.build_entry(**_entry(
        request_id="r1", allowed=False, risk_level="high",
        flags=["prompt_injection"],
    )))
    entries = event_logger.load_entries()
    assert len(entries) == 1
    assert entries[0]["risk_level"] == "high"


def test_load_entries_include_cost_fields(tmp_log) -> None:
    from warden.analytics import logger as event_logger
    event_logger.append(event_logger.build_entry(**_entry(
        payload_tokens=200, attack_cost_usd=0.00003,
    )))
    entries = event_logger.load_entries()
    assert entries[0]["payload_tokens"] == 200
    assert entries[0]["attack_cost_usd"] == pytest.approx(0.00003)


def test_load_entries_day_filter(tmp_log) -> None:
    from warden.analytics import logger as event_logger
    # Write an entry dated 2 days ago
    old_entry = event_logger.build_entry(**_entry(request_id="old"))
    old_entry["ts"] = (datetime.now(UTC) - timedelta(days=2)).isoformat()
    event_logger.append(old_entry)

    # Write a fresh entry
    fresh = event_logger.build_entry(**_entry(request_id="fresh"))
    event_logger.append(fresh)

    # Filter to last 1 day — only fresh entry should appear
    entries = event_logger.load_entries(days=1)
    assert len(entries) == 1
    assert entries[0]["request_id"] == "fresh"


# ── GDPR helpers ──────────────────────────────────────────────────────────────

def test_purge_old_entries(tmp_log) -> None:
    import importlib

    from warden.analytics import logger as event_logger
    # Set retention to 7 days
    os.environ["GDPR_LOG_RETENTION_DAYS"] = "7"
    importlib.reload(event_logger)
    event_logger.LOGS_PATH = tmp_log

    # Write old entry
    old = event_logger.build_entry(**_entry(request_id="old"))
    old["ts"] = (datetime.now(UTC) - timedelta(days=10)).isoformat()
    event_logger.append(old)

    # Write current entry
    current = event_logger.build_entry(**_entry(request_id="current"))
    event_logger.append(current)

    removed = event_logger.purge_old_entries()
    assert removed == 1
    remaining = event_logger.load_entries()
    assert len(remaining) == 1
    assert remaining[0]["request_id"] == "current"


def test_no_content_in_log_entries() -> None:
    """GDPR compliance: content must never appear in the logger schema."""
    import inspect

    from warden.analytics import logger as event_logger
    src = inspect.getsource(event_logger.build_entry)
    assert "content" not in src.split("return")[1], (
        "build_entry must not include the content field in its return value"
    )
