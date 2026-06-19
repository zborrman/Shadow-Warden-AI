#!/usr/bin/env python3
"""
Migrate individual SQLite databases to unified domain databases.

Usage
-----
Dry-run (default — no files are written):
    python scripts/migrate_to_unified_sqlite.py

Execute migration:
    python scripts/migrate_to_unified_sqlite.py --execute

The script uses ATTACH DATABASE to copy tables between SQLite files without
loading data into Python memory. Row counts are verified before and after.

Target databases
----------------
  CORE_DB_PATH     (env, default /warden/data/warden_core.db)
      ← BILLING_DB_PATH     : billing_daily, tenant_quotas, agg_watermark

  EXCHANGE_DB_PATH (env, default /warden/data/warden_exchange.db)
      ← MARKETPLACE_DB_PATH : marketplace_agents, marketplace_assets,
                               marketplace_listings, marketplace_purchases,
                               marketplace_escrow, marketplace_negotiations,
                               marketplace_offers, marketplace_proposals,
                               marketplace_votes, marketplace_reputation
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from pathlib import Path

# ── Import shared pragma helper (works when run from repo root) ───────────────
try:
    from warden.db.sqlite_pragmas import init_pragmas
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from warden.db.sqlite_pragmas import init_pragmas


# ── Source / target paths ─────────────────────────────────────────────────────

BILLING_SRC     = os.getenv("BILLING_DB_PATH",     "/warden/data/billing.db")
MARKETPLACE_SRC = os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")

CORE_DST     = os.getenv("CORE_DB_PATH",     "/warden/data/warden_core.db")
EXCHANGE_DST = os.getenv("EXCHANGE_DB_PATH", "/warden/data/warden_exchange.db")

# Tables to migrate: (source_path, table_name, destination_path)
MIGRATIONS: list[tuple[str, str, str]] = [
    # ── Billing → Core ────────────────────────────────────────────────────────
    (BILLING_SRC, "billing_daily",   CORE_DST),
    (BILLING_SRC, "tenant_quotas",   CORE_DST),
    (BILLING_SRC, "agg_watermark",   CORE_DST),

    # ── Marketplace → Exchange ────────────────────────────────────────────────
    (MARKETPLACE_SRC, "marketplace_agents",       EXCHANGE_DST),
    (MARKETPLACE_SRC, "marketplace_assets",       EXCHANGE_DST),
    (MARKETPLACE_SRC, "marketplace_listings",     EXCHANGE_DST),
    (MARKETPLACE_SRC, "marketplace_purchases",    EXCHANGE_DST),
    (MARKETPLACE_SRC, "marketplace_escrow",       EXCHANGE_DST),
    (MARKETPLACE_SRC, "marketplace_negotiations", EXCHANGE_DST),
    (MARKETPLACE_SRC, "marketplace_offers",       EXCHANGE_DST),
    (MARKETPLACE_SRC, "marketplace_proposals",    EXCHANGE_DST),
    (MARKETPLACE_SRC, "marketplace_votes",        EXCHANGE_DST),
    (MARKETPLACE_SRC, "marketplace_reputation",   EXCHANGE_DST),
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _open(path: str) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path, check_same_thread=False)
    init_pragmas(con)
    return con


def _row_count(con: sqlite3.Connection, table: str) -> int | None:
    try:
        return con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: S608
    except sqlite3.OperationalError:
        return None  # table doesn't exist yet


def _table_exists(con: sqlite3.Connection, table: str) -> bool:
    row = con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row is not None


def _copy_table(
    src_path: str,
    table: str,
    dst_path: str,
    dry_run: bool,
) -> tuple[int | None, int | None, str]:
    """Copy one table from src to dst. Returns (src_count, dst_count, status)."""
    if not Path(src_path).exists():
        return None, None, "SKIP (source db missing)"

    src = _open(src_path)
    if not _table_exists(src, table):
        src.close()
        return None, None, "SKIP (table not in source)"

    src_count = _row_count(src, table)
    src.close()

    if dry_run:
        return src_count, None, "DRY-RUN"

    # Use ATTACH to avoid loading rows into Python
    dst = _open(dst_path)
    try:
        dst.execute("ATTACH DATABASE ? AS src", (src_path,))  # noqa: S608

        # Get CREATE TABLE DDL from source
        ddl_row = dst.execute(
            "SELECT sql FROM src.sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone()
        if not ddl_row:
            dst.close()
            return src_count, None, "SKIP (no DDL in source)"

        # Create table in destination (if not exists)
        ddl = ddl_row[0]
        dst.execute(ddl.replace(
            f"CREATE TABLE {table}",
            f"CREATE TABLE IF NOT EXISTS {table}",
        ).replace(
            "CREATE TABLE IF NOT EXISTS IF NOT EXISTS",  # avoid double
            "CREATE TABLE IF NOT EXISTS",
        ))

        # Copy rows (INSERT OR IGNORE avoids PK conflicts on re-run)
        dst.execute(f"INSERT OR IGNORE INTO {table} SELECT * FROM src.{table}")  # noqa: S608
        dst.commit()
        dst.execute("DETACH DATABASE src")

        dst_count = _row_count(dst, table)
        dst.close()
        return src_count, dst_count, "OK"
    except Exception as exc:
        dst.close()
        return src_count, None, f"ERROR: {exc}"


# ── Main ──────────────────────────────────────────────────────────────────────

def run(dry_run: bool) -> bool:
    mode = "DRY-RUN" if dry_run else "EXECUTE"
    print(f"\n{'='*64}")
    print(f" Shadow Warden SQLite Consolidation — {mode}")
    print(f"{'='*64}\n")

    col = "{:<50} {:>8} {:>8} {}"
    print(col.format("Table", "Source", "Dest", "Status"))
    print("-" * 80)

    all_ok = True
    for src_path, table, dst_path in MIGRATIONS:
        src_label = Path(src_path).name
        dst_label = Path(dst_path).name
        src_count, dst_count, status = _copy_table(src_path, table, dst_path, dry_run)

        src_str = str(src_count) if src_count is not None else "-"
        dst_str = str(dst_count) if dst_count is not None else "-"
        label = f"{src_label}/{table} → {dst_label}"
        print(col.format(label, src_str, dst_str, status))

        if "ERROR" in status:
            all_ok = False
        elif not dry_run and src_count is not None and dst_count is not None and dst_count < src_count:
            print(f"  ⚠  Row count mismatch: src={src_count} dst={dst_count}")
            all_ok = False

    print()
    if dry_run:
        print("No files were written. Pass --execute to apply the migration.")
    elif all_ok:
        print("Migration complete. Verify application behaviour before deleting source databases.")
        print(f"  Core DB:     {CORE_DST}")
        print(f"  Exchange DB: {EXCHANGE_DST}")
        print()
        print("Next step: update BILLING_DB_PATH → CORE_DB_PATH")
        print("           update MARKETPLACE_DB_PATH → EXCHANGE_DB_PATH")
        print("           in /opt/shadow-warden/.env and restart services.")
    else:
        print("Migration finished with errors. Review output above.")
    return all_ok


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Consolidate SQLite domain databases.")
    parser.add_argument("--execute", action="store_true", help="Write to destination DBs.")
    args = parser.parse_args()
    ok = run(dry_run=not args.execute)
    sys.exit(0 if ok else 1)
