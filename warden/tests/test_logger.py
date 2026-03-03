"""
warden/tests/test_logger.py
━━━━━━━━━━━━━━━━━━━━━━━━━━
Unit tests for the GDPR-safe analytics logger.

Uses a temporary file path to avoid touching production logs.
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

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


def test_build_entry_structure() -> None:
    from warden.analytics import logger as event_logger
    entry = event_logger.build_entry(
        request_id="req-123",
        allowed=True,
        risk_level="low",
        flags=[],
        secrets_found=[],
        content_len=42,
        elapsed_ms=12.5,
        strict=False,
    )
    assert entry["request_id"] == "req-123"
    assert entry["allowed"] is True
    assert entry["risk_level"] == "low"
    assert "ts" in entry
    # Content must NEVER appear in log entries
    assert "content" not in entry


def test_append_creates_file(tmp_log) -> None:
    from warden.analytics import logger as event_logger
    entry = event_logger.build_entry(
        request_id="r1", allowed=True, risk_level="low",
        flags=[], secrets_found=[], content_len=10, elapsed_ms=5.0, strict=False,
    )
    event_logger.append(entry)
    assert tmp_log.exists()


def test_append_is_valid_ndjson(tmp_log) -> None:
    from warden.analytics import logger as event_logger
    for i in range(3):
        event_logger.append(event_logger.build_entry(
            request_id=f"r{i}", allowed=True, risk_level="low",
            flags=[], secrets_found=[], content_len=i, elapsed_ms=1.0, strict=False,
        ))
    lines = tmp_log.read_text().strip().split("\n")
    assert len(lines) == 3
    for line in lines:
        parsed = json.loads(line)
        assert "ts" in parsed


def test_load_entries_returns_all(tmp_log) -> None:
    from warden.analytics import logger as event_logger
    event_logger.append(event_logger.build_entry(
        request_id="r1", allowed=False, risk_level="high",
        flags=["prompt_injection"], secrets_found=[], content_len=50,
        elapsed_ms=10.0, strict=False,
    ))
    entries = event_logger.load_entries()
    assert len(entries) == 1
    assert entries[0]["risk_level"] == "high"


def test_load_entries_day_filter(tmp_log) -> None:
    from warden.analytics import logger as event_logger
    # Write an entry dated 2 days ago
    old_entry = event_logger.build_entry(
        request_id="old", allowed=True, risk_level="low",
        flags=[], secrets_found=[], content_len=1, elapsed_ms=1.0, strict=False,
    )
    old_entry["ts"] = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    event_logger.append(old_entry)

    # Write a fresh entry
    fresh = event_logger.build_entry(
        request_id="fresh", allowed=True, risk_level="low",
        flags=[], secrets_found=[], content_len=1, elapsed_ms=1.0, strict=False,
    )
    event_logger.append(fresh)

    # Filter to last 1 day — only fresh entry should appear
    entries = event_logger.load_entries(days=1)
    assert len(entries) == 1
    assert entries[0]["request_id"] == "fresh"


def test_purge_old_entries(tmp_log) -> None:
    from warden.analytics import logger as event_logger
    import importlib
    # Set retention to 7 days
    os.environ["GDPR_LOG_RETENTION_DAYS"] = "7"
    importlib.reload(event_logger)
    event_logger.LOGS_PATH = tmp_log

    # Write old entry
    old = event_logger.build_entry(
        request_id="old", allowed=True, risk_level="low",
        flags=[], secrets_found=[], content_len=1, elapsed_ms=1.0, strict=False,
    )
    old["ts"] = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    event_logger.append(old)

    # Write current entry
    current = event_logger.build_entry(
        request_id="current", allowed=True, risk_level="low",
        flags=[], secrets_found=[], content_len=1, elapsed_ms=1.0, strict=False,
    )
    event_logger.append(current)

    removed = event_logger.purge_old_entries()
    assert removed == 1
    remaining = event_logger.load_entries()
    assert len(remaining) == 1
    assert remaining[0]["request_id"] == "current"


def test_no_content_in_log_entries() -> None:
    """GDPR compliance: content must never appear in the logger schema."""
    from warden.analytics import logger as event_logger
    import inspect
    src = inspect.getsource(event_logger.build_entry)
    assert "content" not in src.split("return")[1], (
        "build_entry must not include the content field in its return value"
    )
