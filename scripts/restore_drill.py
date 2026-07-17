"""
scripts/restore_drill.py — R6: scripted restore rehearsal.

Exercises the actual disaster-recovery path end-to-end: pulls the latest
encrypted snapshot from the OFFSITE_S3_* target (the copy that has to work
if the VPS itself is lost — same-host MinIO doesn't prove anything about
surviving host loss), decrypts it, and restores every artifact into a
throwaway scratch Postgres + SQLite set (a distinct `restore-drill` Docker
project — separate network/volume/containers from prod, torn down after).
Reports timing at each stage so docs/sla.md can carry a measured RTO instead
of a guess.

Scope: this proves the DATA is genuinely restorable (the highest-risk
unverified assumption — a backup nobody has ever restored is a hypothesis,
not a backup). It does NOT boot a full parallel warden+dependency stack
against the restored data; that's a heavier drill for a future pass once
this one has run clean a few times.

Usage:
    python scripts/restore_drill.py                  # pull latest offsite snapshot
    python scripts/restore_drill.py --local <dir>     # use a local snapshot dir instead
    python scripts/restore_drill.py --keep            # leave the scratch container running (debug)

Requires: VAULT_MASTER_KEY, OFFSITE_S3_*, docker, boto3, cryptography.
pg_restore/psql run INSIDE the scratch postgres container (via docker exec/
docker cp) — no local Postgres client install needed on the host running
this script.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

DRILL_PG_CONTAINER = "warden-drill-postgres"
DRILL_PG_PASSWORD = "drill-only-not-a-real-secret"
DRILL_PG_PORT = "15433"  # avoid colliding with a real local postgres on 5432


def _timed(label: str):
    class _T:
        def __enter__(self):
            self.t0 = time.monotonic()
            print(f"[drill] {label} ...")
            return self

        def __exit__(self, *exc):
            dt = time.monotonic() - self.t0
            print(f"[drill] {label} -> {dt:.1f}s")
            self.elapsed = dt
    return _T()


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    print(f"[drill] $ {' '.join(cmd)}")
    check = kw.pop("check", True)
    return subprocess.run(cmd, check=check, **kw)


def fetch_latest_offsite(tmpdir: Path) -> Path:
    """Download the newest snapshot prefix from OFFSITE_S3_* into tmpdir."""
    import boto3  # noqa: PLC0415

    endpoint = os.environ["OFFSITE_S3_ENDPOINT"]
    bucket = os.environ.get("OFFSITE_S3_BUCKET", "warden-backups")
    client = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=os.environ["OFFSITE_S3_ACCESS_KEY"],
        aws_secret_access_key=os.environ["OFFSITE_S3_SECRET_KEY"],
        region_name=os.environ.get("OFFSITE_S3_REGION", "us-east-1"),
    )
    resp = client.list_objects_v2(Bucket=bucket, Prefix="backups/")
    keys = [o["Key"] for o in resp.get("Contents", [])]
    if not keys:
        raise RuntimeError(f"no backups found in offsite bucket {bucket!r}")
    latest_prefix = sorted({k.split("/")[1] for k in keys})[-1]
    print(f"[drill] latest offsite snapshot: {latest_prefix}")

    dest = tmpdir / latest_prefix
    dest.mkdir(parents=True, exist_ok=True)
    for key in keys:
        if not key.startswith(f"backups/{latest_prefix}/"):
            continue
        name = key.rsplit("/", 1)[-1]
        client.download_file(bucket, key, str(dest / name))
        print(f"[drill]   downloaded {name}")
    return dest


def start_scratch_postgres() -> None:
    _run(["docker", "rm", "-f", DRILL_PG_CONTAINER],
         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    _run([
        "docker", "run", "-d", "--name", DRILL_PG_CONTAINER,
        "-e", f"POSTGRES_PASSWORD={DRILL_PG_PASSWORD}",
        "-e", "POSTGRES_DB=warden",
        "-p", f"{DRILL_PG_PORT}:5432",
        "timescale/timescaledb:latest-pg16",
    ])
    for _ in range(60):
        r = subprocess.run(
            ["docker", "exec", DRILL_PG_CONTAINER, "pg_isready", "-U", "postgres"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if r.returncode == 0:
            break
        time.sleep(1)
    else:
        raise RuntimeError("scratch postgres did not become ready in 60s")
    # pg_isready flips true before TimescaleDB's own post-init (extension load,
    # background workers) has settled — an immediate connect can race a still-
    # restarting server. A short fixed buffer is cheap insurance.
    time.sleep(3)
    # Pre-create the extension — the real prod DB has it enabled via
    # `shared_preload_libraries=timescaledb` + init.sql; a bare pg_restore
    # into a fresh DB without it first fails hypertable FK restoration.
    _run([
        "docker", "exec", DRILL_PG_CONTAINER, "psql", "-U", "postgres", "-d", "warden",
        "-c", "CREATE EXTENSION IF NOT EXISTS timescaledb;",
    ])


def restore_pg(snap_dir: Path) -> int:
    """Decrypt postgres.pgdump.enc (if present) and pg_restore it into the
    scratch container. Returns row count of a sanity-check table, or -1 if
    no pg dump was in this snapshot."""
    enc = snap_dir / "postgres.pgdump.enc"
    if not enc.exists():
        print("[drill] no postgres.pgdump.enc in this snapshot — skipping pg restore")
        return -1

    from cryptography.fernet import Fernet  # noqa: PLC0415
    key = os.environ["VAULT_MASTER_KEY"]
    dump = Fernet(key.encode() if isinstance(key, str) else key).decrypt(enc.read_bytes())

    tmp_dump = snap_dir / "_decrypted.pgdump"
    tmp_dump.write_bytes(dump)
    try:
        # pg_restore must match (or exceed) the pg_dump version that made the
        # archive — the scratch server's OWN bundled client is Postgres 16's
        # (timescale/timescaledb:latest-pg16), but warden/Dockerfile (R1)
        # installs Debian trixie's postgresql-client, which is v17: real
        # backups are v17-format archives a v16 pg_restore can't read
        # ("unsupported version in file header"). Run pg_restore from a
        # matching postgres:17 client container instead of the server's own,
        # over the network — this is exactly the drill catching a real
        # version-skew risk, not a drill-only artifact.
        drill_url = (
            f"postgresql://postgres:{DRILL_PG_PASSWORD}"
            f"@host.docker.internal:{DRILL_PG_PORT}/warden"
        )
        try:
            _run([
                "docker", "run", "--rm",
                "--add-host", "host.docker.internal:host-gateway",
                "-v", f"{tmp_dump}:/tmp/drill.pgdump:ro",
                "postgres:17-alpine",
                "pg_restore", "--no-password", "--dbname", drill_url,
                "--no-owner", "--no-privileges", "/tmp/drill.pgdump",
            ], stderr=subprocess.PIPE, text=True)
        except subprocess.CalledProcessError as exc:
            print(f"[drill] pg_restore stderr:\n{exc.stderr}")
            raise
    finally:
        tmp_dump.unlink(missing_ok=True)

    # Sanity check: count tables actually created.
    r = subprocess.run(
        ["docker", "exec", DRILL_PG_CONTAINER, "psql", "-U", "postgres", "-d", "warden",
         "-t", "-c",
         "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'"],
        capture_output=True, text=True, check=True,
    )
    return int(r.stdout.strip())


def restore_sqlite(snap_dir: Path, dest_dir: Path) -> list[str]:
    """Decrypt and write every *.db.enc into dest_dir. Returns restored names."""
    from warden.backup.service import _fernet  # noqa: PLC0415

    os.environ.setdefault("VAULT_MASTER_KEY", os.environ["VAULT_MASTER_KEY"])
    f = _fernet()
    restored = []
    for enc in sorted(snap_dir.glob("*.db.enc")):
        name = enc.name[: -len(".db.enc")]
        plaintext = f.decrypt(enc.read_bytes())
        target = dest_dir / f"warden_{name}.db"
        target.write_bytes(plaintext)
        # Cheap integrity check: SQLite header magic.
        if not plaintext.startswith(b"SQLite format 3"):
            raise RuntimeError(f"{enc.name} did not decrypt to a valid SQLite file")
        restored.append(name)
    return restored


def teardown(keep: bool) -> None:
    if keep:
        print(f"[drill] --keep set: leaving {DRILL_PG_CONTAINER} running for inspection")
        return
    subprocess.run(["docker", "rm", "-f", DRILL_PG_CONTAINER],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    print("[drill] scratch postgres removed")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--local", metavar="DIR", help="use a local snapshot dir instead of offsite")
    ap.add_argument("--keep", action="store_true", help="leave the scratch container running")
    args = ap.parse_args()

    if "VAULT_MASTER_KEY" not in os.environ:
        print("ERROR: VAULT_MASTER_KEY not set — cannot decrypt any snapshot.", file=sys.stderr)
        return 2

    t_start = time.monotonic()
    stage_times: dict[str, float] = {}

    with tempfile.TemporaryDirectory(prefix="warden-restore-drill-") as td:
        tmpdir = Path(td)

        if args.local:
            snap_dir = Path(args.local)
            print(f"[drill] using local snapshot: {snap_dir}")
        else:
            with _timed("fetch latest offsite snapshot") as t:
                snap_dir = fetch_latest_offsite(tmpdir)
            stage_times["fetch"] = t.elapsed

        try:
            with _timed("start scratch postgres") as t:
                start_scratch_postgres()
            stage_times["postgres_start"] = t.elapsed

            with _timed("restore postgres dump") as t:
                table_count = restore_pg(snap_dir)
            stage_times["postgres_restore"] = t.elapsed

            with _timed("restore SQLite snapshots") as t:
                sqlite_dest = tmpdir / "sqlite_restored"
                sqlite_dest.mkdir()
                restored_dbs = restore_sqlite(snap_dir, sqlite_dest)
            stage_times["sqlite_restore"] = t.elapsed

            total = time.monotonic() - t_start
            print()
            print("=" * 60)
            print("RESTORE DRILL — RESULT: PASS")
            print(f"  snapshot:        {snap_dir.name}")
            print(f"  pg tables found: {table_count if table_count >= 0 else 'N/A (no pg dump)'}")
            print(f"  sqlite restored: {restored_dbs or 'none'}")
            print(f"  stage timings:   {stage_times}")
            print(f"  TOTAL RTO:       {total:.1f}s")
            print("=" * 60)
            return 0

        except Exception as exc:  # noqa: BLE001
            print()
            print("=" * 60)
            print(f"RESTORE DRILL — RESULT: FAIL ({exc})")
            print("=" * 60)
            return 1
        finally:
            teardown(args.keep)


if __name__ == "__main__":
    raise SystemExit(main())
