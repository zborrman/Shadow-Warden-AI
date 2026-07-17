"""
DB Snapshot — Fernet-encrypted SQLite snapshots (thin CLI wrapper).

The implementation now lives in ``warden/backup/service.py`` (single source of
truth, shared with the ``sova_nightly_backup`` ARQ cron). This script preserves
the historical CLI used by the autonomous loop's Step 1b (subprocess call).

Usage:
    python scripts/db_snapshot.py                   # snapshot all DBs under WARDEN_DATA_DIR
                                                    # + pg_dump of DATABASE_URL (R1)
    python scripts/db_snapshot.py --ship            # also push encrypted files to S3/MinIO
                                                    # + OFFSITE_S3_* target (R1)
    python scripts/db_snapshot.py --list            # list existing snapshots
    python scripts/db_snapshot.py --restore <path>  # decrypt + restore snapshot
    python scripts/db_snapshot.py --restore <path> --db postgres   # pg only
    python scripts/db_snapshot.py --purge           # delete snapshots beyond retention

Encryption: Fernet (AES-128-CBC + HMAC-SHA256) via VAULT_MASTER_KEY (fail-closed).
Discovery: every warden_*.db under config.data_dir() (WARDEN_DATA_DIR).
Snapshots stored in: SNAPSHOT_DIR (default data/snapshots), keep last SNAPSHOT_KEEP.
"""
from __future__ import annotations

import os
import sys

# Allow running as a bare script (python scripts/db_snapshot.py) without install.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from warden.backup.service import _cli  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(_cli())
