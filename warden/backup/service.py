"""
warden/backup/service.py
─────────────────────────
Nightly encrypted DB backup — Fernet-encrypted point-in-time snapshots of every
SQLite database under ``WARDEN_DATA_DIR`` (the Phase-6 data-layer consolidation).

Single source of truth for:
  • scripts/db_snapshot.py           — CLI + autonomous-loop Step 1b (subprocess)
  • sova_nightly_backup ARQ cron     — 03:30 UTC daily (warden/workers/settings.py)

Design
──────
  • Discovery: walk ``config.data_dir()`` for ``warden_*.db`` (our naming
    convention — avoids scooping unrelated DBs when the base dir is /tmp), unioned
    with the explicit env-var map for back-compat restore names.
  • Consistent snapshot: SQLite online-backup API (``src.backup(dst)``), never a
    raw file copy — safe while the DB is being written.
  • Encryption: Fernet (AES-128-CBC + HMAC-SHA256) via ``VAULT_MASTER_KEY``.
    **Fail-CLOSED**: no key → RuntimeError, no plaintext ever written to disk.
  • Rotation: keep the last ``SNAPSHOT_KEEP`` snapshot directories (default 7).
  • Postgres (R1): when ``DATABASE_URL`` is set, ``pg_dump --format=custom`` of the
    application database is encrypted into the same snapshot dir as
    ``postgres.pgdump.enc``. A pg failure never loses the SQLite snapshots (counted
    via ``record_failopen``); the Fernet key stays fail-CLOSED for both.
  • Optional off-box ship to S3/MinIO — degrades without blocking the backup, and
    every such degradation emits a ``record_failopen`` counter (FAILOPEN-01).
  • Offsite ship (R1): ``OFFSITE_S3_ENDPOINT/ACCESS_KEY/SECRET_KEY/BUCKET`` point at
    an S3 target on *different hardware* (Backblaze/Wasabi/Storage Box gateway…) —
    the same-host MinIO copy does not survive loss of the VPS. Fail-OPEN, counted.

GDPR: snapshots contain application DBs only (never prompt/response content, which
is never persisted). Encrypted at rest with the same key class as the vault.
"""
from __future__ import annotations

import contextlib
import logging
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from warden.config import data_dir, data_path
from warden.observability import Reason, record_failopen

log = logging.getLogger("warden.backup")

_SNAPSHOT_DIR = Path(os.getenv("SNAPSHOT_DIR", "data/snapshots"))
_KEEP = int(os.getenv("SNAPSHOT_KEEP", "7"))

# Explicit env-var map — resolved through data_path so overrides still win and
# names stay stable for restore even if the file is not under data_dir().
_DB_VARS: dict[str, tuple[str, str]] = {
    "marketplace": ("MARKETPLACE_DB_PATH",       "warden_marketplace.db"),
    "sep":         ("SEP_DB_PATH",               "warden_sep.db"),
    "bi":          ("BI_DB_PATH",                "warden_bi.db"),
    "vendor_gov":  ("VENDOR_GOV_DB_PATH",        "warden_vendor_gov.db"),
    "cost_alloc":  ("COST_ALLOC_DB_PATH",        "warden_costs.db"),
    "x402":        ("MARKETPLACE_X402_DB_PATH",  "warden_x402_marketplace.db"),
    "auth":        ("AUTH_DB_PATH",              "warden_auth.db"),
    "gsam":        ("GSAM_DB_PATH",              "warden_gsam.db"),
    "sac_wallet":  ("SAC_WALLET_DB_PATH",        "warden_sac_wallet.db"),
    "billing_audit": ("BILLING_AUDIT_DB_PATH",   "warden_billing_audit.db"),
}


# Postgres dump artifact name inside a snapshot dir (not warden_*.db — it must
# never collide with the SQLite restore loop, which only globs *.db.enc).
_PG_ARTIFACT = "postgres.pgdump.enc"
_PG_TIMEOUT_S = int(os.getenv("PG_BACKUP_TIMEOUT_S", "300"))


def _fernet() -> Any:
    """Return a Fernet cipher from VAULT_MASTER_KEY. Fail-CLOSED if unset.

    Returns ``Any`` because ``cryptography`` is imported lazily (it is an optional
    dep at import time); annotating rather than suppressing keeps the no-new-
    ``type: ignore`` ratchet honest.
    """
    key = os.getenv("VAULT_MASTER_KEY", "")
    if not key:
        raise RuntimeError("VAULT_MASTER_KEY not set — refusing to write unencrypted backups")
    from cryptography.fernet import Fernet
    return Fernet(key.encode() if isinstance(key, str) else key)


def _name_from_file(path: Path) -> str:
    """warden_marketplace.db → marketplace (strip prefix + suffix)."""
    stem = path.name
    if stem.endswith(".db"):
        stem = stem[:-3]
    if stem.startswith("warden_"):
        stem = stem[len("warden_"):]
    return stem


def discover_dbs() -> dict[str, Path]:
    """
    Return {name: path} for every existing SQLite DB to back up.

    Union of (a) the explicit env-var map and (b) all ``warden_*.db`` files under
    ``data_dir()``. De-duplicated by resolved absolute path; only existing files.
    """
    found: dict[str, Path] = {}
    seen: set[str] = set()

    def _add(name: str, path: Path) -> None:
        try:
            if not path.exists():
                return
            key = str(path.resolve())
            if key in seen:
                return
            seen.add(key)
            found[name] = path
        except OSError:
            return

    # (a) explicit, override-aware
    for name, (env, filename) in _DB_VARS.items():
        _add(name, Path(data_path(filename, env)))

    # (b) directory sweep of the consolidated data dir
    base = Path(data_dir())
    try:
        for f in sorted(base.glob("warden_*.db")):
            _add(_name_from_file(f), f)
    except OSError as exc:
        log.debug("backup: data_dir glob failed (%s): %s", base, exc)

    return found


# ── Postgres (R1) ─────────────────────────────────────────────────────────────

def _pg_url() -> str:
    """
    DATABASE_URL normalised for libpq tools: the SQLAlchemy driver suffix
    (``postgresql+asyncpg://``) is stripped to ``postgresql://``. Empty string
    when unset/malformed, or when PG_BACKUP_ENABLED=false.
    """
    if os.getenv("PG_BACKUP_ENABLED", "true").strip().lower() in ("false", "0", "no"):
        return ""
    url = os.getenv("DATABASE_URL", "").strip()
    if "://" not in url:
        return ""
    scheme, rest = url.split("://", 1)
    return f"{scheme.split('+', 1)[0]}://{rest}"


def _pg_dump_bytes(url: str) -> bytes:
    """``pg_dump --format=custom`` → bytes. Raises on any failure."""
    exe = shutil.which("pg_dump")
    if exe is None:
        raise RuntimeError("pg_dump not found on PATH (install postgresql-client-16)")
    proc = subprocess.run(  # noqa: S603 — fixed argv, no shell
        [exe, "--format=custom", "--no-password", f"--dbname={url}"],
        capture_output=True,
        timeout=_PG_TIMEOUT_S,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"pg_dump rc={proc.returncode}: {proc.stderr.decode(errors='replace')[:400]}"
        )
    return proc.stdout


def _pg_restore_bytes(url: str, dump: bytes) -> None:
    """``pg_restore --clean --if-exists`` a custom-format dump. Raises on failure."""
    exe = shutil.which("pg_restore")
    if exe is None:
        raise RuntimeError("pg_restore not found on PATH (install postgresql-client-16)")
    tmp_fd, tmp_name = tempfile.mkstemp(suffix=".pgdump")
    try:
        try:
            os.write(tmp_fd, dump)
        finally:
            os.close(tmp_fd)
        proc = subprocess.run(  # noqa: S603 — fixed argv, no shell
            [exe, "--clean", "--if-exists", "--no-password", f"--dbname={url}", tmp_name],
            capture_output=True,
            timeout=_PG_TIMEOUT_S,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"pg_restore rc={proc.returncode}: {proc.stderr.decode(errors='replace')[:400]}"
            )
    finally:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)


def run_backup(label: str = "", *, ship: bool = False) -> Path:
    """
    Take Fernet-encrypted snapshots of all discovered SQLite DBs.

    Returns the snapshot directory. Fail-CLOSED on the encryption key; a single DB
    that cannot be snapshotted is skipped (and counted) rather than losing the whole
    run. When ``ship`` is True, also pushes the encrypted files off-box.
    """
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    snap_dir = _SNAPSHOT_DIR / ts
    snap_dir.mkdir(parents=True, exist_ok=True)

    f = _fernet()  # fail-closed before touching any DB
    dbs = discover_dbs()
    pg_url = _pg_url()

    if not dbs and not pg_url:
        log.info("backup: no SQLite databases found under %s — nothing to do", data_dir())
        return snap_dir

    ok = 0
    for name, db_path in dbs.items():
        try:
            tmp_fd, tmp_name = tempfile.mkstemp(suffix=".db")
            os.close(tmp_fd)
            try:
                src = sqlite3.connect(str(db_path))
                dst = sqlite3.connect(tmp_name)
                with dst:
                    src.backup(dst)
                src.close()
                dst.close()
                plaintext = Path(tmp_name).read_bytes()
            finally:
                os.unlink(tmp_name)

            (snap_dir / f"{name}.db.enc").write_bytes(f.encrypt(plaintext))
            ok += 1
            log.debug("backup: %s (%s) → %d bytes", name, db_path, len(plaintext))
        except Exception as exc:  # noqa: BLE001
            log.warning("backup: %s failed — %s", name, exc)
            record_failopen("backup_snapshot", Reason.BACKEND_ERROR, exc)

    # Postgres — a pg failure must never cost the SQLite snapshots above.
    if pg_url:
        try:
            dump = _pg_dump_bytes(pg_url)
            (snap_dir / _PG_ARTIFACT).write_bytes(f.encrypt(dump))
            ok += 1
            log.info("backup: postgres pg_dump → %d bytes (encrypted)", len(dump))
        except Exception as exc:  # noqa: BLE001
            log.warning("backup: postgres dump failed — %s", exc)
            record_failopen("backup_pg_dump", Reason.BACKEND_ERROR, exc)

    if label:
        (snap_dir / "label.txt").write_text(label)

    _rotate()
    log.info("backup: %d/%d DBs snapshotted → %s", ok, len(dbs) + (1 if pg_url else 0), snap_dir)

    if ship:
        ship_backup(snap_dir)
    return snap_dir


def _offsite_client() -> tuple[Any | None, str]:
    """
    boto3 client for the OFFSITE_S3_* target (R1) — an S3 endpoint on different
    hardware than this VPS. Returns (None, "") when not configured; raises only
    inside ``ship_backup``'s fail-open envelope.
    """
    endpoint = os.getenv("OFFSITE_S3_ENDPOINT", "").strip()
    access = os.getenv("OFFSITE_S3_ACCESS_KEY", "").strip()
    secret = os.getenv("OFFSITE_S3_SECRET_KEY", "").strip()
    if not (endpoint and access and secret):
        return None, ""
    bucket = os.getenv("OFFSITE_S3_BUCKET", "warden-backups").strip()
    import boto3  # noqa: PLC0415 — optional dep, lazy like warden.storage.s3
    client = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=access,
        aws_secret_access_key=secret,
        region_name=os.getenv("OFFSITE_S3_REGION", "us-east-1"),
    )
    return client, bucket


def _put_all(client: Any, bucket: str, snap_dir: Path, target: str) -> int:
    """Upload every *.enc in the snapshot dir; count successes, count failures."""
    shipped = 0
    for enc in sorted(Path(snap_dir).glob("*.enc")):
        key = f"backups/{snap_dir.name}/{enc.name}"
        try:
            client.put_object(
                Bucket=bucket,
                Key=key,
                Body=enc.read_bytes(),
                ContentType="application/octet-stream",
            )
            shipped += 1
        except Exception as exc:  # noqa: BLE001
            log.warning("backup: ship %s → %s failed — %s", key, target, exc)
            record_failopen("backup_ship", Reason.NETWORK_ERROR, exc)
    if shipped:
        log.info("backup: shipped %d encrypted files to %s (%s)", shipped, target, bucket)
    return shipped


def ship_backup(snap_dir: Path) -> int:
    """
    Best-effort off-box ship of encrypted snapshot files (``*.enc`` — SQLite and
    the Postgres dump) to two independent targets:

      1. the platform S3/MinIO (``S3_*`` — same host: fast, but shares the VPS's fate)
      2. the offsite S3 (``OFFSITE_S3_*`` — different hardware: survives host loss)

    The local encrypted snapshot is already durable, so a ship failure (disabled,
    boto3 missing, network) degrades instead of raising — but every degradation emits
    a ``record_failopen`` counter so the loss of off-box copies is alertable, never
    silent. Returns the total number of file-copies shipped across both targets.
    """
    shipped = 0
    try:
        from warden.storage.s3 import S3_BUCKET_EVIDENCE, _get_client  # noqa: PLC0415
        client = _get_client()
        if client is not None:
            shipped += _put_all(client, S3_BUCKET_EVIDENCE, snap_dir, "local S3/MinIO")
    except Exception as exc:  # noqa: BLE001
        log.debug("backup: S3 ship unavailable: %s", exc)
        record_failopen("backup_ship", Reason.BACKEND_ERROR, exc)

    try:
        off_client, off_bucket = _offsite_client()
        if off_client is not None:
            shipped += _put_all(off_client, off_bucket, snap_dir, "offsite S3")
    except Exception as exc:  # noqa: BLE001
        log.warning("backup: offsite ship unavailable: %s", exc)
        record_failopen("backup_ship_offsite", Reason.BACKEND_ERROR, exc)
    return shipped


def _rotate() -> None:
    """Keep only the last ``_KEEP`` snapshot directories."""
    if not _SNAPSHOT_DIR.exists():
        return
    dirs = sorted((d for d in _SNAPSHOT_DIR.iterdir() if d.is_dir()), key=lambda d: d.name)
    for old in dirs[:-_KEEP] if _KEEP > 0 else []:
        shutil.rmtree(old, ignore_errors=True)
        log.debug("backup: rotated old snapshot %s", old)


def list_snapshots() -> list[dict]:
    """Return metadata for each snapshot directory (newest last)."""
    if not _SNAPSHOT_DIR.exists():
        return []
    out: list[dict] = []
    for d in sorted(x for x in _SNAPSHOT_DIR.iterdir() if x.is_dir()):
        files = list(d.glob("*.enc"))
        label = (d / "label.txt").read_text().strip() if (d / "label.txt").exists() else ""
        out.append({"ts": d.name, "path": str(d), "dbs": len(files), "label": label})
    return out


def restore(snap_path: str, db_name: str | None = None) -> int:
    """
    Decrypt and atomically restore a snapshot. If ``db_name`` is given, restore
    only that DB (``postgres`` targets the pg dump). Returns the number of DBs
    restored. Fail-CLOSED on the key.
    """
    snap_dir = Path(snap_path)
    if not snap_dir.exists():
        raise FileNotFoundError(f"snapshot not found: {snap_dir}")

    f = _fernet()
    dbs = discover_dbs()
    restored = 0

    for enc_file in sorted(snap_dir.glob("*.db.enc")):
        name = enc_file.name[:-len(".db.enc")]
        if db_name and name != db_name:
            continue
        target = dbs.get(name)
        if target is None:
            env, filename = _DB_VARS.get(name, ("", f"warden_{name}.db"))
            target = Path(data_path(filename, env) if env else data_path(filename))
        try:
            plaintext = f.decrypt(enc_file.read_bytes())
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp_fd, tmp_name = tempfile.mkstemp(dir=str(target.parent), suffix=".db.tmp")
            try:
                os.write(tmp_fd, plaintext)
            finally:
                os.close(tmp_fd)
            os.replace(tmp_name, target)
            restored += 1
            log.info("backup: restored %s → %s", name, target)
        except Exception as exc:  # noqa: BLE001
            log.warning("backup: restore %s failed — %s", name, exc)

    # Postgres (R1) — restore the pg dump when present and requested.
    pg_enc = snap_dir / _PG_ARTIFACT
    if pg_enc.exists() and db_name in (None, "postgres"):
        pg_url = _pg_url()
        if not pg_url:
            log.warning("backup: %s present but DATABASE_URL unset — skipping pg restore",
                        _PG_ARTIFACT)
        else:
            try:
                _pg_restore_bytes(pg_url, f.decrypt(pg_enc.read_bytes()))
                restored += 1
                log.info("backup: restored postgres from %s", pg_enc.name)
            except Exception as exc:  # noqa: BLE001
                log.warning("backup: restore postgres failed — %s", exc)
    return restored


def purge() -> None:
    """Delete snapshot directories beyond the retention window."""
    _rotate()


# ── CLI (delegated to by scripts/db_snapshot.py) ─────────────────────────────

def _cli(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Shadow Warden encrypted DB backup")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--list", action="store_true", help="List existing snapshots")
    group.add_argument("--restore", metavar="SNAP_DIR", help="Restore from a snapshot directory")
    group.add_argument("--purge", action="store_true", help="Delete snapshots beyond retention")
    parser.add_argument("--db", metavar="NAME", help="Restrict restore to a single DB name")
    parser.add_argument("--label", default="", help="Label for this snapshot")
    parser.add_argument("--ship", action="store_true", help="Also ship encrypted files to S3/MinIO")
    args = parser.parse_args(argv)

    if args.list:
        snaps = list_snapshots()
        if not snaps:
            print("No snapshots found.")
        for s in snaps:
            tag = f"  [{s['label']}]" if s["label"] else ""
            print(f"  {s['ts']}  ({s['dbs']} DBs){tag}")
    elif args.restore:
        n = restore(args.restore, db_name=args.db)
        print(f"Restored {n} DB(s).")
    elif args.purge:
        purge()
        print("Purge complete.")
    else:
        try:
            snap = run_backup(label=args.label, ship=args.ship)
        except RuntimeError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        print(f"Snapshot complete: {snap}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
