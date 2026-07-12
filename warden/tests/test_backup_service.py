"""
Phase 6 — nightly encrypted DB backup (warden/backup/service.py).

Covers:
  - discovery of warden_*.db under WARDEN_DATA_DIR
  - encrypted round-trip (backup → restore) integrity
  - fail-CLOSED when VAULT_MASTER_KEY is unset (no plaintext written)
  - empty data dir → no-op (no crash)
  - rotation keeps last SNAPSHOT_KEEP directories
  - ship_backup is fail-open when S3 disabled
"""
from __future__ import annotations

import importlib
import sqlite3

import pytest
from cryptography.fernet import Fernet


def _mk_db(path, rows):
    con = sqlite3.connect(str(path))
    con.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
    con.executemany("INSERT INTO t (v) VALUES (?)", [(r,) for r in rows])
    con.commit()
    con.close()


@pytest.fixture
def svc(monkeypatch, tmp_path):
    """Reload the service with WARDEN_DATA_DIR + SNAPSHOT_DIR + a Fernet key."""
    data = tmp_path / "data"
    data.mkdir()
    snaps = tmp_path / "snaps"
    monkeypatch.setenv("WARDEN_DATA_DIR", str(data))
    monkeypatch.setenv("SNAPSHOT_DIR", str(snaps))
    monkeypatch.setenv("SNAPSHOT_KEEP", "3")
    monkeypatch.setenv("VAULT_MASTER_KEY", Fernet.generate_key().decode())
    # Clear per-module DB overrides so discovery uses data_dir only.
    for v in ("MARKETPLACE_DB_PATH", "SEP_DB_PATH", "BI_DB_PATH", "GSAM_DB_PATH",
              "AUTH_DB_PATH", "VENDOR_GOV_DB_PATH", "COST_ALLOC_DB_PATH",
              "MARKETPLACE_X402_DB_PATH", "SAC_WALLET_DB_PATH", "BILLING_AUDIT_DB_PATH"):
        monkeypatch.delenv(v, raising=False)
    import warden.config as cfg
    importlib.reload(cfg)
    import warden.backup.service as s
    mod = importlib.reload(s)
    yield mod, data, snaps
    monkeypatch.delenv("WARDEN_DATA_DIR", raising=False)
    importlib.reload(cfg)


class TestDiscovery:
    def test_finds_warden_dbs(self, svc):
        s, data, _ = svc
        _mk_db(data / "warden_marketplace.db", ["a"])
        _mk_db(data / "warden_custom.db", ["b"])
        found = s.discover_dbs()
        assert "marketplace" in found
        assert "custom" in found

    def test_ignores_non_warden_and_non_db(self, svc):
        s, data, _ = svc
        _mk_db(data / "other.db", ["x"])          # not warden_*
        (data / "warden_notes.txt").write_text("x")  # not *.db
        found = s.discover_dbs()
        assert "other" not in found
        assert all(not v.name.endswith(".txt") for v in found.values())


class TestRoundTrip:
    def test_backup_then_restore_integrity(self, svc):
        s, data, _ = svc
        db = data / "warden_sep.db"
        _mk_db(db, ["alpha", "beta", "gamma"])
        snap = s.run_backup(label="test")
        enc = snap / "sep.db.enc"
        assert enc.exists()
        # Corrupt the live DB, then restore.
        db.write_bytes(b"corrupted")
        n = s.restore(str(snap), db_name="sep")
        assert n == 1
        con = sqlite3.connect(str(db))
        vals = [r[0] for r in con.execute("SELECT v FROM t ORDER BY id")]
        con.close()
        assert vals == ["alpha", "beta", "gamma"]

    def test_snapshot_file_is_encrypted(self, svc):
        s, data, _ = svc
        _mk_db(data / "warden_sep.db", ["secret_value"])
        snap = s.run_backup()
        blob = (snap / "sep.db.enc").read_bytes()
        assert b"secret_value" not in blob         # ciphertext, not plaintext
        assert b"SQLite format 3" not in blob


class TestFailClosed:
    def test_missing_key_raises_and_writes_no_plaintext(self, svc, monkeypatch):
        s, data, snaps = svc
        _mk_db(data / "warden_sep.db", ["x"])
        monkeypatch.delenv("VAULT_MASTER_KEY", raising=False)
        with pytest.raises(RuntimeError):
            s.run_backup()
        # No unencrypted .db files leaked into the snapshot tree.
        if snaps.exists():
            assert not list(snaps.rglob("*.db"))


class TestEmptyAndRotation:
    def test_empty_dir_is_noop(self, svc):
        s, _, _ = svc
        snap = s.run_backup()          # no DBs present
        assert snap.exists()
        assert list(snap.glob("*.db.enc")) == []

    def test_rotation_keeps_last_k(self, svc):
        s, data, snaps = svc
        _mk_db(data / "warden_sep.db", ["x"])
        made = []
        for i in range(5):
            # Distinct timestamps by forcing unique dir names.
            d = snaps / f"2026010{i}T000000Z"
            d.mkdir(parents=True)
            (d / "sep.db.enc").write_bytes(b"x")
            made.append(d)
        s.purge()  # keep last 3 (SNAPSHOT_KEEP=3)
        remaining = sorted(p.name for p in snaps.iterdir() if p.is_dir())
        assert len(remaining) == 3
        assert remaining == ["20260102T000000Z", "20260103T000000Z", "20260104T000000Z"]


class TestShipFailOpen:
    def test_ship_returns_zero_when_s3_disabled(self, svc, monkeypatch):
        s, data, _ = svc
        monkeypatch.setenv("S3_ENABLED", "false")
        _mk_db(data / "warden_sep.db", ["x"])
        snap = s.run_backup()
        assert s.ship_backup(snap) == 0   # never raises
