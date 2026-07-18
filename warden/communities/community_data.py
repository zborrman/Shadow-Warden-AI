"""
Community Data — shared file storage per community.
Files are assigned UECIID provenance and optionally stored in MinIO.
All uploads are tracked in SQLite with SHA-256 integrity hash.
"""
from __future__ import annotations

import hashlib
import os
import threading
import time
import uuid
from collections.abc import Generator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from typing import Any

from warden.config import data_path
from warden.db.connect import open_db
from warden.db.ddl_registry import register

COMM_DB_PATH = data_path("warden_communities.db", "COMM_DB_PATH")
_lock = threading.RLock()

FILE_SIZE_LIMIT = int(os.getenv("COMM_FILE_MAX_BYTES", str(100 * 1024 * 1024)))  # 100 MB


@dataclass
class CommunityFile:
    file_id: str
    community_id: str
    uploader_tenant_id: str
    filename: str
    content_type: str
    size_bytes: int
    ueciid: str
    s3_key: str
    sha256: str
    uploaded_at: str
    download_count: int = 0
    status: str = "active"
    context: str = ""


# Shares warden_communities.db with membership.py / network.py /
# community_evolution.py / community_factory.py — same db_key, distinct module.
# `context` is baked into CREATE for fresh DBs; the ALTER below is a one-time
# additive migration for pre-existing deployments created before that column
# existed. ALTER TABLE ADD COLUMN is not idempotent, so it can't go in the
# registered DDL — it stays as a suppress-wrapped statement run once per
# real connection, exactly as before.
_COMMUNITY_DATA_DDL = """
    CREATE TABLE IF NOT EXISTS community_files (
        file_id             TEXT PRIMARY KEY,
        community_id        TEXT NOT NULL,
        uploader_tenant_id  TEXT NOT NULL,
        filename            TEXT NOT NULL,
        content_type        TEXT NOT NULL DEFAULT 'application/octet-stream',
        size_bytes          INTEGER NOT NULL DEFAULT 0,
        ueciid              TEXT NOT NULL DEFAULT '',
        s3_key              TEXT NOT NULL DEFAULT '',
        sha256              TEXT NOT NULL DEFAULT '',
        uploaded_at         TEXT NOT NULL,
        download_count      INTEGER NOT NULL DEFAULT 0,
        status              TEXT NOT NULL DEFAULT 'active'
    );
    CREATE INDEX IF NOT EXISTS idx_cf_community ON community_files(community_id, status);
    CREATE INDEX IF NOT EXISTS idx_cf_uploader  ON community_files(uploader_tenant_id);
"""
register("communities", "warden.communities.community_data", _COMMUNITY_DATA_DDL)


@contextmanager
def _conn() -> Generator[Any, None, None]:
    with open_db("communities", COMM_DB_PATH, module_default_path=COMM_DB_PATH) as con:
        with suppress(Exception):
            con.execute("ALTER TABLE community_files ADD COLUMN context TEXT NOT NULL DEFAULT ''")
        yield con


def _assign_ueciid() -> str:
    try:
        from warden.communities.sep import new_ueciid
        result = new_ueciid()
        return str(result[0]) if isinstance(result, tuple) else str(result)
    except Exception:
        return f"SEP-{uuid.uuid4().hex[:11]}"


def _upload_to_s3(content: bytes, s3_key: str, content_type: str) -> bool:
    try:
        import io  # noqa: PLC0415

        from warden.storage.s3 import _get_client as get_s3_client
        client = get_s3_client()
        if client:
            client.upload_fileobj(
                io.BytesIO(content),
                "warden-community",
                s3_key,
                ExtraArgs={"ContentType": content_type},
            )
            return True
    except Exception:
        pass
    return False


def register_file(
    community_id: str,
    uploader_tenant_id: str,
    filename: str,
    content_type: str,
    size_bytes: int,
    content: bytes,
    context: str = "",
) -> CommunityFile:
    if size_bytes > FILE_SIZE_LIMIT:
        raise ValueError(f"File exceeds {FILE_SIZE_LIMIT // (1024*1024)} MB limit")

    fid = uuid.uuid4().hex[:32]
    sha256 = hashlib.sha256(content).hexdigest()
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    s3_key = f"warden-community/{community_id}/{fid}/{filename}"
    ueciid = _assign_ueciid()

    _upload_to_s3(content, s3_key, content_type)

    cf = CommunityFile(
        file_id=fid,
        community_id=community_id,
        uploader_tenant_id=uploader_tenant_id,
        filename=filename,
        content_type=content_type,
        size_bytes=size_bytes,
        ueciid=ueciid,
        s3_key=s3_key,
        sha256=sha256,
        uploaded_at=ts,
        context=context,
    )
    with _lock, _conn() as db:
        db.execute(
            "INSERT INTO community_files VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (fid, community_id, uploader_tenant_id, filename, content_type,
             size_bytes, ueciid, s3_key, sha256, ts, 0, "active", context),
        )
    return cf


def list_files(community_id: str, status: str = "active") -> list[CommunityFile]:
    with _conn() as db:
        rows = db.execute(
            "SELECT * FROM community_files WHERE community_id=? AND status=? ORDER BY uploaded_at DESC",
            (community_id, status),
        ).fetchall()
    return [CommunityFile(**dict(r)) for r in rows]


def get_file(file_id: str) -> CommunityFile | None:
    with _conn() as db:
        row = db.execute(
            "SELECT * FROM community_files WHERE file_id=?", (file_id,)
        ).fetchone()
    return CommunityFile(**dict(row)) if row else None


def delete_file(file_id: str, requester_tenant_id: str) -> bool:
    f = get_file(file_id)
    if not f or f.uploader_tenant_id != requester_tenant_id:
        return False
    with _lock, _conn() as db:
        db.execute(
            "UPDATE community_files SET status='deleted' WHERE file_id=?", (file_id,)
        )
    return True


def increment_download(file_id: str) -> None:
    with _lock, _conn() as db:
        db.execute(
            "UPDATE community_files SET download_count=download_count+1 WHERE file_id=?",
            (file_id,),
        )


def get_data_stats(community_id: str) -> dict:
    with _conn() as db:
        row = db.execute(
            """SELECT COUNT(*) AS total_files,
                      COALESCE(SUM(size_bytes), 0) AS total_bytes,
                      COALESCE(SUM(download_count), 0) AS total_downloads
               FROM community_files
               WHERE community_id=? AND status='active'""",
            (community_id,),
        ).fetchone()
    d = dict(row)
    d["total_mb"] = round(d["total_bytes"] / (1024 * 1024), 2)
    return d
