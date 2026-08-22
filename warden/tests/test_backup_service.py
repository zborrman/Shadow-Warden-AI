"""
Phase 6 — nightly encrypted DB backup (warden/backup/service.py).

Covers:
  - discovery of warden_*.db under WARDEN_DATA_DIR
  - encrypted round-trip (backup → restore) integrity
  - fail-CLOSED when VAULT_MASTER_KEY is unset (no plaintext written)
  - empty data dir → no-op (no crash)
  - rotation keeps last SNAPSHOT_KEEP directories
  - ship_backup is fail-open when S3 disabled
  - R1: pg_dump artifact (encrypted, fail-open vs SQLite), pg restore, offsite ship
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
              "MARKETPLACE_X402_DB_PATH", "SAC_WALLET_DB_PATH", "BILLING_AUDIT_DB_PATH",
              # R1 — keep pg + offsite paths inert unless a test opts in.
              "DATABASE_URL", "PG_BACKUP_ENABLED", "OFFSITE_S3_ENDPOINT",
              "OFFSITE_S3_ACCESS_KEY", "OFFSITE_S3_SECRET_KEY", "OFFSITE_S3_BUCKET"):
        monkeypatch.delenv(v, raising=False)
    # NB: do NOT reload warden.config here. config.data_dir()/data_path() read env
    # at call time, so a reload is unnecessary — and it would mint new class objects
    # (e.g. ConfigValidationError), breaking isinstance/pytest.raises in any test
    # module that imported them earlier in the session. Only the backup service
    # needs reloading, because it snapshots SNAPSHOT_DIR/SNAPSHOT_KEEP at import.
    import warden.backup.service as s
    mod = importlib.reload(s)
    yield mod, data, snaps
    monkeypatch.delenv("WARDEN_DATA_DIR", raising=False)


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


class TestPostgres:
    _URL = "postgresql+asyncpg://u:p@h:5432/db"

    def test_pg_url_strips_sqlalchemy_driver(self, svc, monkeypatch):
        s, _, _ = svc
        monkeypatch.setenv("DATABASE_URL", self._URL)
        assert s._pg_url() == "postgresql://u:p@h:5432/db"

    def test_pg_url_empty_when_unset_or_disabled(self, svc, monkeypatch):
        s, _, _ = svc
        assert s._pg_url() == ""                      # DATABASE_URL unset (fixture)
        monkeypatch.setenv("DATABASE_URL", self._URL)
        monkeypatch.setenv("PG_BACKUP_ENABLED", "false")
        assert s._pg_url() == ""                      # opt-out flag wins

    def test_backup_writes_encrypted_pg_artifact(self, svc, monkeypatch):
        import os
        s, data, _ = svc
        monkeypatch.setenv("DATABASE_URL", self._URL)
        monkeypatch.setattr(s, "_pg_dump_bytes", lambda url: b"PGDMP-fake-dump-bytes")
        snap = s.run_backup()
        blob = (snap / "postgres.pgdump.enc").read_bytes()
        assert b"PGDMP" not in blob                   # ciphertext, not plaintext
        f = Fernet(os.environ["VAULT_MASTER_KEY"].encode())
        assert f.decrypt(blob) == b"PGDMP-fake-dump-bytes"

    def test_pg_failure_never_loses_sqlite_snapshots(self, svc, monkeypatch):
        s, data, _ = svc
        _mk_db(data / "warden_sep.db", ["x"])
        monkeypatch.setenv("DATABASE_URL", self._URL)

        def _boom(url):
            raise RuntimeError("pg_dump rc=1: connection refused")

        monkeypatch.setattr(s, "_pg_dump_bytes", _boom)
        snap = s.run_backup()                          # must not raise
        assert (snap / "sep.db.enc").exists()
        assert not (snap / "postgres.pgdump.enc").exists()

    def test_restore_invokes_pg_restore_with_decrypted_dump(self, svc, monkeypatch):
        s, data, _ = svc
        monkeypatch.setenv("DATABASE_URL", self._URL)
        monkeypatch.setattr(s, "_pg_dump_bytes", lambda url: b"PGDMP-round-trip")
        snap = s.run_backup()

        calls = []
        monkeypatch.setattr(s, "_pg_restore_bytes", lambda url, dump: calls.append((url, dump)))
        n = s.restore(str(snap), db_name="postgres")
        assert n == 1
        assert calls == [("postgresql://u:p@h:5432/db", b"PGDMP-round-trip")]

    def test_restore_skips_pg_without_database_url(self, svc, monkeypatch):
        s, data, _ = svc
        monkeypatch.setenv("DATABASE_URL", self._URL)
        monkeypatch.setattr(s, "_pg_dump_bytes", lambda url: b"PGDMP-x")
        snap = s.run_backup()
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.setattr(s, "_pg_restore_bytes",
                            lambda url, dump: pytest.fail("must not be called"))
        assert s.restore(str(snap), db_name="postgres") == 0


class _StubS3:
    def __init__(self):
        self.keys: list[str] = []

    def put_object(self, Bucket, Key, Body, ContentType):  # noqa: N803 — boto3 API
        self.keys.append(Key)


class TestOffsiteShip:
    def test_offsite_ships_every_enc_file(self, svc, monkeypatch):
        s, data, _ = svc
        monkeypatch.setenv("S3_ENABLED", "false")      # local target off
        _mk_db(data / "warden_sep.db", ["x"])
        monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@h/db")
        monkeypatch.setattr(s, "_pg_dump_bytes", lambda url: b"PGDMP-x")
        snap = s.run_backup()

        stub = _StubS3()
        monkeypatch.setattr(s, "_offsite_client", lambda: (stub, "warden-backups"))
        assert s.ship_backup(snap) == 2                # sep.db.enc + postgres.pgdump.enc
        assert sorted(k.rsplit("/", 1)[-1] for k in stub.keys) == [
            "postgres.pgdump.enc", "sep.db.enc",
        ]

    def test_offsite_failure_never_raises(self, svc, monkeypatch):
        s, data, _ = svc
        monkeypatch.setenv("S3_ENABLED", "false")
        _mk_db(data / "warden_sep.db", ["x"])
        snap = s.run_backup()

        def _boom():
            raise RuntimeError("offsite endpoint unreachable")

        monkeypatch.setattr(s, "_offsite_client", _boom)
        assert s.ship_backup(snap) == 0                # fail-open, counted

    def test_offsite_unconfigured_is_none(self, svc):
        s, _, _ = svc
        client, bucket = s._offsite_client()
        assert client is None and bucket == ""


class _StubVault:
    """Both ends of the mirror: a local Evidence Vault and an offsite bucket."""

    def __init__(self, bundles: dict[str, bytes], offsite: dict[str, bytes] | None = None):
        self.bundles = bundles                      # key → body, as in MinIO
        self.offsite: dict[str, bytes] = offsite or {}
        self.pages = 1                              # >1 forces pagination
        self.get_calls: list[str] = []

    # ── local side ────────────────────────────────────────────────────────
    def list_objects_v2(self, Bucket, Prefix, ContinuationToken=None):  # noqa: N803
        if Prefix.startswith("evidence-bundles/"):
            keys = sorted(k for k in self.offsite if k.startswith(Prefix))
        else:
            keys = sorted(k for k in self.bundles if k.startswith(Prefix))
        if self.pages > 1 and ContinuationToken is None and keys:
            return {"Contents": [{"Key": keys[0]}], "IsTruncated": True,
                    "NextContinuationToken": "page-2"}
        rest = keys[1:] if (self.pages > 1 and ContinuationToken) else keys
        return {"Contents": [{"Key": k} for k in rest], "IsTruncated": False}

    def get_object(self, Bucket, Key):  # noqa: N803
        self.get_calls.append(Key)
        return {"Body": _Body(self.bundles[Key])}

    # ── offsite side ──────────────────────────────────────────────────────
    def put_object(self, Bucket, Key, Body, ContentType):  # noqa: N803
        self.offsite[Key] = Body


class _Body:
    def __init__(self, raw: bytes):
        self._raw = raw

    def read(self) -> bytes:
        return self._raw


class TestEvidenceBundleReplication:
    """P0: the vault's bundles lived on one box while SOC 2 material cited them."""

    def _wire(self, s, monkeypatch, stub):
        monkeypatch.setattr("warden.storage.s3._get_client", lambda: stub)
        monkeypatch.setattr(s, "_offsite_client", lambda: (stub, "warden-offsite"))

    def test_bundles_are_mirrored_encrypted(self, svc, monkeypatch):
        s, _, _ = svc
        stub = _StubVault({"bundles/sess-1.json": b'{"bundle_hash":"sha256:aa"}'})
        self._wire(s, monkeypatch, stub)

        assert s.ship_evidence_bundles() == 1
        assert list(stub.offsite) == ["evidence-bundles/sess-1.json.enc"]
        stored = stub.offsite["evidence-bundles/sess-1.json.enc"]
        assert b"bundle_hash" not in stored, "bundle shipped offsite in plaintext"
        assert s._fernet().decrypt(stored) == b'{"bundle_hash":"sha256:aa"}'

    def test_replication_is_incremental(self, svc, monkeypatch):
        s, _, _ = svc
        stub = _StubVault({"bundles/sess-1.json": b"{}"})
        self._wire(s, monkeypatch, stub)

        assert s.ship_evidence_bundles() == 1
        assert s.ship_evidence_bundles() == 0, "re-uploaded a bundle already offsite"
        assert stub.get_calls == ["bundles/sess-1.json"]

    def test_every_page_is_replicated(self, svc, monkeypatch):
        """list_objects_v2 caps at 1000 keys; a job that stops there loses evidence."""
        s, _, _ = svc
        stub = _StubVault({f"bundles/sess-{i}.json": b"{}" for i in range(3)})
        stub.pages = 2
        self._wire(s, monkeypatch, stub)

        assert s.ship_evidence_bundles() == 3

    def test_offsite_listing_is_paginated_too(self, svc, monkeypatch):
        """The skip-set must span pages, or page 2 gets re-uploaded every night."""
        s, _, _ = svc
        stub = _StubVault(
            {f"bundles/sess-{i}.json": b"{}" for i in range(2)},
            offsite={f"evidence-bundles/sess-{i}.json.enc": b"x" for i in range(2)},
        )
        stub.pages = 2
        self._wire(s, monkeypatch, stub)

        assert s.ship_evidence_bundles() == 0, "re-shipped bundles found on offsite page 2"
        assert stub.get_calls == [], "read a bundle that was already offsite"

    def test_unconfigured_storage_is_counted_not_silent(self, svc, monkeypatch):
        """An un-counted early return is the fail-open the docstring denies."""
        s, _, _ = svc
        seen: list[tuple[str, str]] = []
        monkeypatch.setattr(s, "record_failopen",
                            lambda stage, reason, exc=None: seen.append((stage, reason)))
        monkeypatch.setattr("warden.storage.s3._get_client", lambda: None)
        monkeypatch.setattr(s, "_offsite_client", lambda: (None, ""))

        assert s.ship_evidence_bundles() == 0
        assert seen and seen[0][0] == "evidence_ship_offsite"

    def test_unconfigured_offsite_is_a_no_op(self, svc, monkeypatch):
        s, _, _ = svc
        stub = _StubVault({"bundles/sess-1.json": b"{}"})
        monkeypatch.setattr("warden.storage.s3._get_client", lambda: stub)
        monkeypatch.setattr(s, "_offsite_client", lambda: (None, ""))
        assert s.ship_evidence_bundles() == 0
        assert stub.offsite == {}

    def test_missing_key_refuses_to_ship_plaintext(self, svc, monkeypatch):
        """Fail-CLOSED: no VAULT_MASTER_KEY must mean no copy, not a plaintext copy."""
        s, _, _ = svc
        stub = _StubVault({"bundles/sess-1.json": b"{}"})
        self._wire(s, monkeypatch, stub)
        monkeypatch.delenv("VAULT_MASTER_KEY", raising=False)
        assert s.ship_evidence_bundles() == 0
        assert stub.offsite == {}

    def test_one_bad_bundle_does_not_stop_the_rest(self, svc, monkeypatch):
        s, _, _ = svc
        stub = _StubVault({"bundles/ok.json": b"{}", "bundles/bad.json": b"{}"})
        self._wire(s, monkeypatch, stub)
        real_get = stub.get_object

        def _flaky(Bucket, Key):  # noqa: N803
            if Key.endswith("bad.json"):
                raise RuntimeError("read failed")
            return real_get(Bucket=Bucket, Key=Key)

        monkeypatch.setattr(stub, "get_object", _flaky)
        assert s.ship_evidence_bundles() == 1
        assert list(stub.offsite) == ["evidence-bundles/ok.json.enc"]
