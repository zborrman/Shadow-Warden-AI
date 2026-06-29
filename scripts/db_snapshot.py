"""
DB Snapshot — Fernet-encrypted SQLite snapshots before autonomous loop runs.

Creates encrypted point-in-time snapshots of all Shadow Warden SQLite databases.
Run before every Maker-Checker cycle to enable rollback if a fix corrupts data.

Usage:
    python scripts/db_snapshot.py                   # snapshot all known DBs
    python scripts/db_snapshot.py --list            # list existing snapshots
    python scripts/db_snapshot.py --restore <path>  # decrypt + restore snapshot
    python scripts/db_snapshot.py --purge           # delete snapshots older than 7 days

Encryption: Fernet (AES-128-CBC + HMAC-SHA256) using VAULT_MASTER_KEY env var.
Snapshots stored in: data/snapshots/{timestamp}/
Rotation: keeps last 7 snapshots per DB (configurable via SNAPSHOT_KEEP).
"""
from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import sys
import tempfile
from datetime import datetime
from pathlib import Path

_SNAPSHOT_DIR = Path(os.getenv("SNAPSHOT_DIR", "data/snapshots"))
_KEEP = int(os.getenv("SNAPSHOT_KEEP", "7"))

_DB_VARS = {
    "marketplace":   "MARKETPLACE_DB_PATH",
    "sep":           "SEP_DB_PATH",
    "bi":            "BI_DB_PATH",
    "vendor_gov":    "VENDOR_GOV_DB_PATH",
    "cost_alloc":    "COST_ALLOC_DB_PATH",
    "x402":          "MARKETPLACE_X402_DB_PATH",
}

_DB_DEFAULTS = {
    "marketplace":   "/tmp/warden_marketplace.db",
    "sep":           "/tmp/warden_sep.db",
    "bi":            "/tmp/warden_bi.db",
    "vendor_gov":    "/tmp/warden_vendor_gov.db",
    "cost_alloc":    "/tmp/warden_cost_alloc.db",
    "x402":          "/tmp/warden_x402_marketplace.db",
}


def _fernet():  # type: ignore[return]  # Fernet from optional dep
    key = os.getenv("VAULT_MASTER_KEY", "")
    if not key:
        raise RuntimeError("VAULT_MASTER_KEY not set — cannot encrypt snapshots")
    from cryptography.fernet import Fernet
    return Fernet(key.encode() if isinstance(key, str) else key)


def _resolve_dbs() -> dict[str, Path]:
    """Return {name: path} for all SQLite DBs that actually exist."""
    result = {}
    for name, var in _DB_VARS.items():
        path = Path(os.getenv(var, _DB_DEFAULTS[name]))
        if path.exists():
            result[name] = path
    return result


def snapshot(label: str = "") -> Path:
    """
    Take encrypted snapshots of all existing SQLite DBs.
    Returns the snapshot directory path.
    """
    ts = datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
    snap_dir = _SNAPSHOT_DIR / ts
    snap_dir.mkdir(parents=True, exist_ok=True)

    f = _fernet()
    dbs = _resolve_dbs()

    if not dbs:
        print("No SQLite databases found — nothing to snapshot.", file=sys.stderr)
        return snap_dir

    for name, db_path in dbs.items():
        try:
            # Use SQLite backup API for a consistent snapshot
            tmp_fd, tmp_name = tempfile.mkstemp(suffix=".db")
            os.close(tmp_fd)
            try:
                src = sqlite3.connect(str(db_path))
                dst = sqlite3.connect(tmp_name)
                src.backup(dst)
                src.close()
                dst.close()

                with open(tmp_name, "rb") as fh:
                    plaintext = fh.read()
            finally:
                os.unlink(tmp_name)

            ciphertext = f.encrypt(plaintext)
            out = snap_dir / f"{name}.db.enc"
            out.write_bytes(ciphertext)
            print(f"  [+] {name}: {db_path} → {out} ({len(plaintext):,} bytes)")
        except Exception as exc:
            print(f"  [!] {name}: snapshot failed — {exc}", file=sys.stderr)

    if label:
        (snap_dir / "label.txt").write_text(label)

    _rotate()
    print(f"\nSnapshot complete: {snap_dir}")
    return snap_dir


def _rotate() -> None:
    """Keep only the last _KEEP snapshot directories."""
    if not _SNAPSHOT_DIR.exists():
        return
    dirs = sorted(
        [d for d in _SNAPSHOT_DIR.iterdir() if d.is_dir()],
        key=lambda d: d.name,
    )
    for old in dirs[:-_KEEP]:
        shutil.rmtree(old, ignore_errors=True)
        print(f"  [-] Rotated old snapshot: {old}")


def list_snapshots() -> None:
    if not _SNAPSHOT_DIR.exists():
        print("No snapshots found.")
        return
    dirs = sorted(d for d in _SNAPSHOT_DIR.iterdir() if d.is_dir())
    if not dirs:
        print("No snapshots found.")
        return
    for d in dirs:
        files = list(d.glob("*.enc"))
        label = (d / "label.txt").read_text().strip() if (d / "label.txt").exists() else ""
        print(f"  {d.name}  ({len(files)} DBs){f'  [{label}]' if label else ''}")


def restore(snap_path: str, db_name: str | None = None) -> None:
    """Decrypt and restore a snapshot. If db_name given, restore only that DB."""
    snap_dir = Path(snap_path)
    if not snap_dir.exists():
        print(f"Snapshot not found: {snap_dir}", file=sys.stderr)
        sys.exit(1)

    f = _fernet()
    dbs = _resolve_dbs()
    files = list(snap_dir.glob("*.enc"))

    for enc_file in files:
        name = enc_file.stem.removesuffix(".db")
        if db_name and name != db_name:
            continue
        target = dbs.get(name)
        if not target:
            target = Path(_DB_DEFAULTS.get(name, f"/tmp/warden_{name}_restored.db"))

        try:
            ciphertext = enc_file.read_bytes()
            plaintext  = f.decrypt(ciphertext)
            target.parent.mkdir(parents=True, exist_ok=True)
            # Atomic write: mkstemp then rename
            tmp_fd, tmp_name = tempfile.mkstemp(dir=target.parent, suffix=".db.tmp")
            try:
                os.write(tmp_fd, plaintext)
            finally:
                os.close(tmp_fd)
            os.replace(tmp_name, target)
            print(f"  [+] Restored {name} → {target}")
        except Exception as exc:
            print(f"  [!] Restore {name} failed: {exc}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description="Shadow Warden DB Snapshot Tool")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--list",    action="store_true", help="List existing snapshots")
    group.add_argument("--restore", metavar="SNAP_DIR",  help="Restore from snapshot directory")
    group.add_argument("--purge",   action="store_true", help="Delete old snapshots (keep last 7)")
    parser.add_argument("--db",     metavar="NAME",      help="Restrict restore to single DB name")
    parser.add_argument("--label",  default="",          help="Label for this snapshot")
    args = parser.parse_args()

    if args.list:
        list_snapshots()
    elif args.restore:
        restore(args.restore, db_name=args.db)
    elif args.purge:
        _rotate()
    else:
        snapshot(label=args.label)


if __name__ == "__main__":
    main()
