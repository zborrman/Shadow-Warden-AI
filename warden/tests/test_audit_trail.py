"""
Tests for warden/audit_trail.py — Cryptographic Audit Trail.

Covers:
  • AuditTrail.record()         — basic write + return hash
  • AuditTrail.count()          — correct entry count
  • AuditTrail.verify_chain()   — valid chain, empty chain, tampered hash,
                                   broken prev_hash link
  • AuditTrail.export_range()   — all entries, date range filter, limit
  • Chaining invariants          — each entry's hash includes prev_hash
  • Thread-safety sanity         — concurrent writes do not corrupt the chain
  • AUDIT_TRAIL_ENABLED=false    — record() is a no-op
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

import pytest

from warden.audit_trail import AuditTrail, _GENESIS_HASH


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def trail(tmp_path: Path) -> AuditTrail:
    """Fresh AuditTrail backed by a temp SQLite file."""
    return AuditTrail(db_path=tmp_path / "test_audit.db")


def _record(trail: AuditTrail, *, n: int = 1, action: str = "allowed") -> list[str]:
    """Helper: write *n* entries and return their hashes."""
    hashes = []
    for i in range(n):
        h = trail.record(
            request_id    = f"req-{i:04d}",
            tenant_id     = "default",
            risk_level    = "low",
            action        = action,
            reason        = f"reason-{i}",
            flags         = ["FLAG_A"] if i % 2 == 0 else [],
            processing_ms = float(i * 10),
        )
        hashes.append(h)
    return hashes


# ── Basic write ───────────────────────────────────────────────────────────────

class TestRecord:
    def test_returns_nonempty_hash(self, trail):
        h = trail.record(
            request_id="r1", tenant_id="t1",
            risk_level="medium", action="blocked",
        )
        assert isinstance(h, str)
        assert len(h) == 64    # SHA-256 hex

    def test_count_increments(self, trail):
        assert trail.count() == 0
        _record(trail, n=3)
        assert trail.count() == 3

    def test_each_hash_is_unique(self, trail):
        hashes = _record(trail, n=5)
        assert len(set(hashes)) == 5

    def test_empty_flags_default(self, trail):
        trail.record(request_id="r", tenant_id="t",
                     risk_level="low", action="allowed")
        entries = trail.export_range()
        assert entries[0]["flags"] == []

    def test_flags_stored_as_list(self, trail):
        trail.record(
            request_id="r", tenant_id="t",
            risk_level="high", action="blocked",
            flags=["PROMPT_INJECTION", "JAILBREAK"],
        )
        entries = trail.export_range()
        assert entries[0]["flags"] == ["PROMPT_INJECTION", "JAILBREAK"]

    def test_all_fields_stored(self, trail):
        trail.record(
            request_id    = "req-abc",
            tenant_id     = "acme",
            risk_level    = "high",
            action        = "blocked",
            reason        = "jailbreak attempt",
            flags         = ["JAILBREAK"],
            processing_ms = 42.7,
        )
        entries = trail.export_range()
        e = entries[0]
        assert e["request_id"]    == "req-abc"
        assert e["tenant_id"]     == "acme"
        assert e["risk_level"]    == "high"
        assert e["action"]        == "blocked"
        assert e["reason"]        == "jailbreak attempt"
        assert e["flags"]         == ["JAILBREAK"]
        assert e["processing_ms"] == pytest.approx(42.7, abs=0.01)


# ── Chain verification ────────────────────────────────────────────────────────

class TestVerifyChain:
    def test_empty_chain_is_valid(self, trail):
        valid, count = trail.verify_chain()
        assert valid is True
        assert count == 0

    def test_single_entry_chain_valid(self, trail):
        _record(trail, n=1)
        valid, count = trail.verify_chain()
        assert valid is True
        assert count == 1

    def test_multi_entry_chain_valid(self, trail):
        _record(trail, n=20)
        valid, count = trail.verify_chain()
        assert valid is True
        assert count == 20

    def test_first_entry_chains_from_genesis(self, trail):
        _record(trail, n=1)
        entries = trail.export_range()
        assert entries[0]["prev_hash"] == _GENESIS_HASH

    def test_subsequent_entries_chain_correctly(self, trail):
        hashes = _record(trail, n=3)
        entries = trail.export_range()
        assert entries[1]["prev_hash"] == hashes[0]
        assert entries[2]["prev_hash"] == hashes[1]

    def test_tampered_entry_hash_detected(self, trail, tmp_path):
        _record(trail, n=5)
        # Directly corrupt row 3's entry_hash in the DB
        conn = sqlite3.connect(str(tmp_path / "test_audit.db"))
        conn.execute(
            "UPDATE audit_chain SET entry_hash = 'deadbeef' || entry_hash "
            "WHERE seq = 3"
        )
        conn.commit()
        conn.close()

        valid, broken_at = trail.verify_chain()
        assert valid is False
        assert broken_at == 3

    def test_tampered_prev_hash_detected(self, trail, tmp_path):
        _record(trail, n=5)
        conn = sqlite3.connect(str(tmp_path / "test_audit.db"))
        conn.execute(
            "UPDATE audit_chain SET prev_hash = 'aaaa' || prev_hash "
            "WHERE seq = 2"
        )
        conn.commit()
        conn.close()

        valid, broken_at = trail.verify_chain()
        assert valid is False
        assert broken_at == 2

    def test_deleted_row_breaks_chain(self, trail, tmp_path):
        _record(trail, n=5)
        conn = sqlite3.connect(str(tmp_path / "test_audit.db"))
        conn.execute("DELETE FROM audit_chain WHERE seq = 3")
        conn.commit()
        conn.close()

        # After deletion, row 4's prev_hash no longer matches row 2's entry_hash
        valid, _ = trail.verify_chain()
        assert valid is False


# ── Export ────────────────────────────────────────────────────────────────────

class TestExportRange:
    def test_export_all(self, trail):
        _record(trail, n=10)
        entries = trail.export_range()
        assert len(entries) == 10

    def test_export_respects_limit(self, trail):
        _record(trail, n=20)
        entries = trail.export_range(limit=5)
        assert len(entries) == 5

    def test_export_empty_chain(self, trail):
        entries = trail.export_range()
        assert entries == []

    def test_export_ordered_by_seq(self, trail):
        _record(trail, n=5)
        entries = trail.export_range()
        seqs = [e["seq"] for e in entries]
        assert seqs == sorted(seqs)

    def test_export_contains_entry_hash(self, trail):
        hashes = _record(trail, n=3)
        entries = trail.export_range()
        stored_hashes = [e["entry_hash"] for e in entries]
        assert stored_hashes == hashes

    def test_export_date_range_start(self, trail):
        _record(trail, n=3)
        entries = trail.export_range()
        # Use the second entry's timestamp as start — should return entries 2 and 3
        start_ts = entries[1]["recorded_at"]
        filtered = trail.export_range(start=start_ts)
        assert len(filtered) >= 2
        assert all(e["recorded_at"] >= start_ts for e in filtered)

    def test_export_date_range_end(self, trail):
        _record(trail, n=3)
        entries = trail.export_range()
        end_ts = entries[1]["recorded_at"]
        filtered = trail.export_range(end=end_ts)
        assert len(filtered) >= 1
        assert all(e["recorded_at"] <= end_ts for e in filtered)


# ── Chaining invariants ───────────────────────────────────────────────────────

class TestChainingInvariants:
    def test_hash_depends_on_content(self, trail, tmp_path):
        """Two entries with different content must produce different hashes."""
        h1 = trail.record(
            request_id="r1", tenant_id="t", risk_level="low",
            action="allowed", reason="ok",
        )
        h2 = trail.record(
            request_id="r2", tenant_id="t", risk_level="high",
            action="blocked", reason="threat",
        )
        assert h1 != h2

    def test_changing_reason_changes_hash(self, tmp_path):
        """Same structural entry but different reason → different hash."""
        trail1 = AuditTrail(db_path=tmp_path / "a.db")
        trail2 = AuditTrail(db_path=tmp_path / "b.db")
        h1 = trail1.record(
            request_id="r", tenant_id="t", risk_level="low",
            action="allowed", reason="reason-A",
        )
        h2 = trail2.record(
            request_id="r", tenant_id="t", risk_level="low",
            action="allowed", reason="reason-B",
        )
        assert h1 != h2


# ── Thread safety ─────────────────────────────────────────────────────────────

class TestThreadSafety:
    def test_concurrent_writes_produce_valid_chain(self, trail):
        errors: list[Exception] = []

        def _write(i: int) -> None:
            try:
                trail.record(
                    request_id    = f"req-{i:04d}",
                    tenant_id     = "default",
                    risk_level    = "low",
                    action        = "allowed",
                    processing_ms = float(i),
                )
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=_write, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread errors: {errors}"
        assert trail.count() == 50
        valid, count = trail.verify_chain()
        assert valid is True
        assert count == 50


# ── AUDIT_TRAIL_ENABLED=false ─────────────────────────────────────────────────

class TestDisabledMode:
    def test_record_returns_empty_string_when_disabled(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AUDIT_TRAIL_ENABLED", "false")
        # Re-import to pick up the env var
        import importlib
        import warden.audit_trail as _at_mod
        importlib.reload(_at_mod)

        trail = _at_mod.AuditTrail(db_path=tmp_path / "disabled.db")
        h = trail.record(
            request_id="r", tenant_id="t",
            risk_level="low", action="allowed",
        )
        assert h == ""
        assert trail.count() == 0

        # Restore
        importlib.reload(_at_mod)
