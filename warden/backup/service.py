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
  • Optional off-box ship to S3/MinIO — **fail-OPEN** (never blocks the backup).

GDPR: snapshots contain application DBs only (never prompt/response content, which
is never persisted). Encrypted at rest with the same key class as the vault.
"""
from __future__ import annotations

import logging
import os
import shutil
import sqlite3
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from warden.config import data_dir, data_path

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


def _fernet():  # type: ignore[no-untyped-def]
    """Return a Fernet cipher from VAULT_MASTER_KEY. Fail-CLOSED if unset."""
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


def run_backup(label: str = "", *, ship: bool = False) -> Path:
    """
    Take Fernet-encrypted snapshots of all discovered SQLite DBs.

    Returns the snapshot directory. Fail-CLOSED on the encryption key; individual
    DB failures are logged and skipped (best-effort per DB). When ``ship`` is True,
    also pushes the encrypted files off-box (fail-OPEN).
    """
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    snap_dir = _SNAPSHOT_DIR / ts
    snap_dir.mkdir(parents=True, exist_ok=True)

    f = _fernet()  # fail-closed before touching any DB
    dbs = discover_dbs()

    if not dbs:
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

    if label:
        (snap_dir / "label.txt").write_text(label)

    _rotate()
    log.info("backup: %d/%d DBs snapshotted → %s", ok, len(dbs), snap_dir)

    if ship:
        ship_backup(snap_dir)
    return snap_dir


def ship_backup(snap_dir: Path) -> int:
    """
    Best-effort off-box ship of encrypted snapshot files to S3/MinIO.

    Fail-OPEN: any error (S3 disabled, boto3 missing, network) is logged and
    returns the count shipped so far. Never raises.
    """
    shipped = 0
    try:
        from warden.storage.s3 import S3_BUCKET_EVIDENCE, _get_client  # noqa: PLC0415
        client = _get_client()
        if client is None:
            return 0
        for enc in sorted(Path(snap_dir).glob("*.db.enc")):
            key = f"backups/{snap_dir.name}/{enc.name}"
            try:
                client.put_object(
                    Bucket=S3_BUCKET_EVIDENCE,
                    Key=key,
                    Body=enc.read_bytes(),
                    ContentType="application/octet-stream",
                )
                shipped += 1
            except Exception as exc:  # noqa: BLE001
                log.warning("backup: ship %s failed — %s", key, exc)
        if shipped:
            log.info("backup: shipped %d encrypted files to S3 (%s)", shipped, S3_BUCKET_EVIDENCE)
    except Exception as exc:  # noqa: BLE001
        log.debug("backup: S3 ship unavailable (fail-open): %s", exc)
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
        files = list(d.glob("*.db.enc"))
        label = (d / "label.txt").read_text().strip() if (d / "label.txt").exists() else ""
        out.append({"ts": d.name, "path": str(d), "dbs": len(files), "label": label})
    return out


def restore(snap_path: str, db_name: str | None = None) -> int:
    """
    Decrypt and atomically restore a snapshot. If ``db_name`` is given, restore
    only that DB. Returns the number of DBs restored. Fail-CLOSED on the key.
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
