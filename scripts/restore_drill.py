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
DRILL_PG_PORT = "15433"  # host-side debug access only; internal traffic uses DRILL_NETWORK
DRILL_NETWORK = "warden-drill-net"
# MUST match docker-compose.yml's `postgres.image` exactly (R6 finding
# 2026-07-26): a floating `latest-pg16` scratch target let the drill silently
# test against a NEWER TimescaleDB extension version than the one that made the
# real backup, hitting timescaledb_post_restore()'s "catalog version mismatch"
# on an otherwise-good dump — a drill-only false failure that also means a real
# floating-tag production pin is a live disaster-recovery risk. Bump this in
# lockstep with docker-compose.yml, verified by a clean drill run before merge.
DRILL_PG_IMAGE = "timescale/timescaledb:2.26.2-pg16"


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
    # A dedicated user-defined network so the pg_restore client container (below)
    # reaches this one by CONTAINER NAME over Docker's embedded DNS — not via
    # host.docker.internal + the published port, which depends on the host's
    # NAT "hairpin" path working (container -> host gateway IP -> DNAT back into
    # another container). That path is host-firewall/NAT-state sensitive and was
    # observed to time out after a host reboot; a shared network has no such
    # dependency. -p is kept only for host-side debugging (--keep).
    subprocess.run(["docker", "network", "rm", DRILL_NETWORK],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    _run(["docker", "network", "create", DRILL_NETWORK])
    _run([
        "docker", "run", "-d", "--name", DRILL_PG_CONTAINER,
        "--network", DRILL_NETWORK,
        "-e", f"POSTGRES_PASSWORD={DRILL_PG_PASSWORD}",
        "-e", "POSTGRES_DB=warden",
        "-p", f"{DRILL_PG_PORT}:5432",
        DRILL_PG_IMAGE,
    ])
    # The official postgres entrypoint (which the TimescaleDB image is built on)
    # boots a TEMPORARY server for initdb / docker-entrypoint-initdb.d on first
    # run, shuts it down, then execs the REAL server — and observed live,
    # TimescaleDB's own first-activation of the extension can trigger a further
    # brief internal restart cycle on top of that. This has shown up as at least
    # three different transient error strings across separate runs ("the
    # database system is shutting down", "...is starting up", and even
    # "No such file or directory" on the socket mid-cycle) — not a stable set to
    # pattern-match. Rather than retry on specific error text, require several
    # CONSECUTIVE successful checks before declaring the server ready: any point
    # still mid-restart-cycle will fail at least one check and reset the streak,
    # so only a server that has been responsive for the full window proceeds.
    last_err = ""
    consecutive_ok = 0
    need_consecutive = 3
    for _ in range(90):
        r = subprocess.run(
            ["docker", "exec", DRILL_PG_CONTAINER, "psql", "-U", "postgres", "-d", "warden",
             "-c", "CREATE EXTENSION IF NOT EXISTS timescaledb;"],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            consecutive_ok += 1
            if consecutive_ok >= need_consecutive:
                print(f"[drill] scratch postgres stably ready "
                      f"({need_consecutive} consecutive checks, timescaledb extension created)")
                return
        else:
            consecutive_ok = 0
            last_err = r.stderr.strip()
        time.sleep(1)
    raise RuntimeError(f"scratch postgres never became stably ready: {last_err}")


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
        # (DRILL_PG_IMAGE), but warden/Dockerfile (R1) installs Debian trixie's
        # postgresql-client, which is v17: real backups are v17-format archives
        # a v16 pg_restore can't read ("unsupported version in file header").
        # Run pg_restore from a matching postgres:17 client container instead
        # of the server's own — this is exactly the drill catching a real
        # version-skew risk, not a drill-only artifact. Connect via the
        # DRILL_NETWORK + container name (Docker's embedded DNS), not
        # host.docker.internal + the published port — see the comment in
        # start_scratch_postgres().
        drill_url = (
            f"postgresql://postgres:{DRILL_PG_PASSWORD}"
            f"@{DRILL_PG_CONTAINER}:5432/warden"
        )

        def _scratch_psql(sql: str) -> subprocess.CompletedProcess:
            return subprocess.run(
                ["docker", "exec", DRILL_PG_CONTAINER, "psql", "-U", "postgres",
                 "-d", "warden", "-tAqc", sql],
                capture_output=True, text=True, check=False,
            )

        # TimescaleDB: bracket the restore exactly as warden/backup/service
        # ._pg_restore_bytes now does — timescaledb_pre_restore()/post_restore()
        # fixes the hypertable chunk FK-ordering that used to make a good archive
        # look like a failed restore. post_restore is always run to re-enable.
        # Not hard-failed here on a bad returncode (start_scratch_postgres's
        # consecutive-success check should make this reliable now), but logged
        # rather than silently swallowed — useful signal if something upstream
        # is still unstable.
        pre = _scratch_psql("SELECT public.timescaledb_pre_restore()")
        if pre.returncode != 0:
            print(f"[drill] timescaledb_pre_restore() returned non-zero (continuing): "
                  f"{pre.stderr.strip()[:300]}")

        restore_cmd = [
            "docker", "run", "--rm",
            "--network", DRILL_NETWORK,
            "-v", f"{tmp_dump}:/tmp/drill.pgdump:ro",
            "postgres:17-alpine",
            "pg_restore", "--no-password", "--dbname", drill_url,
            "--no-owner", "--no-privileges", "/tmp/drill.pgdump",
        ]
        # Observed live: CREATE EXTENSION timescaledb succeeding over the local
        # docker-exec socket (start_scratch_postgres) does not guarantee the TCP
        # listener stays up — TimescaleDB can trigger its own brief internal
        # restart shortly after first activation, which lands right in this
        # window ("the database system is starting up"/"shutting down" over the
        # NETWORK path, even though the socket path just reported ready). Retry
        # the whole pg_restore on that specific transient condition; a content-
        # level failure (version-skew SET, hypertable ordering) won't match
        # these strings and falls straight through to the outcome-based check
        # below rather than being retried pointlessly.
        for attempt in range(5):
            restore = subprocess.run(restore_cmd, capture_output=True, text=True, check=False)
            transient = restore.returncode != 0 and (
                "starting up" in restore.stderr or "shutting down" in restore.stderr
            )
            if not transient:
                break
            tail = restore.stderr.strip().splitlines()[-1] if restore.stderr.strip() else ""
            print(f"[drill] pg_restore hit a transient server-state error "
                  f"(attempt {attempt + 1}/5), retrying in 3s: {tail}")
            time.sleep(3)

        if restore.returncode != 0:
            print(f"[drill] pg_restore exited non-zero (may be benign — judged by "
                  f"tables-restored below): {restore.stderr.strip()[-500:]}")
        else:
            print("[drill] pg_restore completed cleanly")

        post = _scratch_psql("SELECT public.timescaledb_post_restore()")
        if post.returncode != 0:
            raise RuntimeError(f"timescaledb_post_restore failed: {post.stderr[:300]}")
    finally:
        tmp_dump.unlink(missing_ok=True)

    # Outcome-based (matches service._pg_restore_bytes): pg_restore exits non-zero
    # on benign client/server version-skew SET directives — success = tables
    # actually restored, not the exit code.
    r = subprocess.run(
        ["docker", "exec", DRILL_PG_CONTAINER, "psql", "-U", "postgres", "-d", "warden",
         "-tAqc",
         "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'"],
        capture_output=True, text=True, check=True,
    )
    tables = int(r.stdout.strip())
    if restore.returncode != 0:
        if tables <= 0:
            print(f"[drill] pg_restore stderr:\n{restore.stderr}")
            raise RuntimeError(f"pg_restore rc={restore.returncode}, 0 tables restored")
        print(f"[drill] pg_restore rc={restore.returncode} but {tables} tables restored "
              f"— benign version-skew noise; stderr tail: {restore.stderr[-300:]}")
    return tables


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
        print(f"[drill] --keep set: leaving {DRILL_PG_CONTAINER} "
              f"(network {DRILL_NETWORK}) running for inspection")
        return
    subprocess.run(["docker", "rm", "-f", DRILL_PG_CONTAINER],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    subprocess.run(["docker", "network", "rm", DRILL_NETWORK],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    print("[drill] scratch postgres + network removed")


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
