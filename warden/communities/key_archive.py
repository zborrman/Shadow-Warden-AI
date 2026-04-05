"""
warden/communities/key_archive.py
───────────────────────────────────
Community Key Archive — lifecycle management for versioned Root Keys.

Key statuses
────────────
  ACTIVE          Current signing/encryption key. All new traffic uses this kid.
  ROTATION_ONLY   Old key being migrated away. Can decrypt existing CEKs for
                  re-wrapping; cannot be used for new entity encryption.
  SHREDDED        Private key deleted. Tombstone record kept for audit trail.
                  Historical entities with this kid are permanently inaccessible
                  (Forward Secrecy achieved).

The archive is stored in PostgreSQL table `warden_core.community_key_archive`.
In-memory cache (TTL 60s) reduces DB reads on hot paths.

Root Key Rollover flow (see rotation.py for the ARQ worker):
  1. generate_community_keypair(community_id, kid="v2") → store as ACTIVE
  2. Previous kid → set status=ROTATION_ONLY
  3. ARQ worker re-wraps all CEKs from kid=v1 → kid=v2 in background
  4. Multi-Sig confirmation → crypto_shred(community_id, kid="v1")
"""
from __future__ import annotations

import base64
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Optional

log = logging.getLogger("warden.communities.key_archive")

# ── Key status ────────────────────────────────────────────────────────────────

class KeyStatus(StrEnum):
    ACTIVE         = "ACTIVE"
    ROTATION_ONLY  = "ROTATION_ONLY"
    SHREDDED       = "SHREDDED"


@dataclass
class ArchiveEntry:
    community_id:    str
    kid:             str
    status:          KeyStatus
    ed25519_pub_b64: str
    x25519_pub_b64:  str
    ed_priv_enc_b64: Optional[str]   # None when SHREDDED
    x_priv_enc_b64:  Optional[str]   # None when SHREDDED
    created_at:      str
    shredded_at:     Optional[str]


# ── In-memory cache ───────────────────────────────────────────────────────────

_cache_lock   = threading.RLock()
_cache:        dict[str, tuple[ArchiveEntry, float]] = {}   # key=(community_id,kid)
_CACHE_TTL    = 60.0   # seconds


def _cache_key(community_id: str, kid: str) -> str:
    return f"{community_id}:{kid}"


def _set_cache(entry: ArchiveEntry) -> None:
    with _cache_lock:
        _cache[_cache_key(entry.community_id, entry.kid)] = (entry, time.monotonic())


def _get_cache(community_id: str, kid: str) -> Optional[ArchiveEntry]:
    with _cache_lock:
        item = _cache.get(_cache_key(community_id, kid))
        if item and (time.monotonic() - item[1]) < _CACHE_TTL:
            return item[0]
        return None


def invalidate_cache(community_id: str, kid: str) -> None:
    """Force next read to hit the database (call after status changes)."""
    with _cache_lock:
        _cache.pop(_cache_key(community_id, kid), None)


# ── SQLite-backed archive (used in tests / air-gapped) ───────────────────────

_ARCHIVE_DB_PATH = os.getenv("COMMUNITY_KEY_ARCHIVE_PATH", "/tmp/warden_community_key_archive.db")

def _get_sqlite():
    import sqlite3
    conn = sqlite3.connect(_ARCHIVE_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS community_key_archive (
            community_id    TEXT NOT NULL,
            kid             TEXT NOT NULL,
            status          TEXT NOT NULL DEFAULT 'ACTIVE',
            ed25519_pub_b64 TEXT NOT NULL,
            x25519_pub_b64  TEXT NOT NULL,
            ed_priv_enc_b64 TEXT,
            x_priv_enc_b64  TEXT,
            created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            shredded_at     TEXT,
            PRIMARY KEY (community_id, kid)
        )
    """)
    conn.commit()
    return conn


# ── Public API ────────────────────────────────────────────────────────────────

def store_keypair(keypair, status: KeyStatus = KeyStatus.ACTIVE) -> None:
    """
    Persist a new CommunityKeypair to the archive.

    Parameters
    ──────────
    keypair   CommunityKeypair instance (from keypair.py)
    status    Initial status (ACTIVE for new keys, ROTATION_ONLY when superseded)
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()

    d = keypair.to_dict()
    entry = ArchiveEntry(
        community_id    = keypair.community_id,
        kid             = keypair.kid,
        status          = status,
        ed25519_pub_b64 = d["ed25519_pub_b64"],
        x25519_pub_b64  = d["x25519_pub_b64"],
        ed_priv_enc_b64 = d["ed_priv_enc"],
        x_priv_enc_b64  = d["x_priv_enc"],
        created_at      = now,
        shredded_at     = None,
    )
    conn = _get_sqlite()
    conn.execute("""
        INSERT OR REPLACE INTO community_key_archive
          (community_id, kid, status, ed25519_pub_b64, x25519_pub_b64,
           ed_priv_enc_b64, x_priv_enc_b64, created_at, shredded_at)
        VALUES (?,?,?,?,?,?,?,?,?)
    """, (
        entry.community_id, entry.kid, str(entry.status),
        entry.ed25519_pub_b64, entry.x25519_pub_b64,
        entry.ed_priv_enc_b64, entry.x_priv_enc_b64,
        entry.created_at, entry.shredded_at,
    ))
    conn.commit()
    _set_cache(entry)
    log.info("KeyArchive: stored kid=%s community=%s status=%s",
             keypair.kid, keypair.community_id[:8], status)


def get_entry(community_id: str, kid: str) -> Optional[ArchiveEntry]:
    """Return the archive entry for (community_id, kid), or None if not found."""
    cached = _get_cache(community_id, kid)
    if cached:
        return cached

    conn = _get_sqlite()
    row = conn.execute(
        "SELECT * FROM community_key_archive WHERE community_id=? AND kid=?",
        (community_id, kid)
    ).fetchone()
    if not row:
        return None

    entry = _row_to_entry(row)
    _set_cache(entry)
    return entry


def get_active_entry(community_id: str) -> Optional[ArchiveEntry]:
    """Return the currently ACTIVE keypair entry for a community."""
    conn = _get_sqlite()
    row = conn.execute(
        "SELECT * FROM community_key_archive WHERE community_id=? AND status='ACTIVE' LIMIT 1",
        (community_id,)
    ).fetchone()
    if not row:
        return None
    entry = _row_to_entry(row)
    _set_cache(entry)
    return entry


def set_status(community_id: str, kid: str, status: KeyStatus) -> bool:
    """Update the status of a key entry. Returns True if a row was modified."""
    conn = _get_sqlite()
    cur = conn.execute(
        "UPDATE community_key_archive SET status=? WHERE community_id=? AND kid=?",
        (str(status), community_id, kid)
    )
    conn.commit()
    invalidate_cache(community_id, kid)
    log.info("KeyArchive: status→%s kid=%s community=%s", status, kid, community_id[:8])
    return cur.rowcount > 0


def crypto_shred(community_id: str, kid: str) -> bool:
    """
    Permanently delete private key material for (community_id, kid).

    Sets ed_priv_enc_b64 = NULL, x_priv_enc_b64 = NULL, status = SHREDDED.
    The public keys and audit record remain — only private key bytes are gone.

    After shredding:
      - Historical entities encrypted under this kid are permanently inaccessible.
      - Forward Secrecy is achieved: compromise of future keys cannot decrypt past data.
      - The tombstone record satisfies SOC 2 / GDPR Art. 25 audit requirements.

    Returns True if a row was modified, False if entry not found.
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()

    conn = _get_sqlite()
    cur = conn.execute("""
        UPDATE community_key_archive
           SET status          = 'SHREDDED',
               ed_priv_enc_b64 = NULL,
               x_priv_enc_b64  = NULL,
               shredded_at     = ?
         WHERE community_id = ?
           AND kid           = ?
           AND status       != 'SHREDDED'
    """, (now, community_id, kid))
    conn.commit()
    invalidate_cache(community_id, kid)
    if cur.rowcount > 0:
        log.warning(
            "KeyArchive: CRYPTO SHRED complete kid=%s community=%s — "
            "historical data with this kid is permanently inaccessible.",
            kid, community_id[:8],
        )
        return True
    return False


def load_keypair_from_entry(entry: ArchiveEntry):
    """
    Reconstruct a CommunityKeypair from an ArchiveEntry.

    Raises ValueError if the entry is SHREDDED (no private key material).
    """
    from warden.communities.keypair import CommunityKeypair

    if entry.status == KeyStatus.SHREDDED:
        raise ValueError(
            f"Key kid={entry.kid} for community {entry.community_id[:8]}… "
            "has been crypto-shredded and cannot be loaded."
        )
    if not entry.ed_priv_enc_b64 or not entry.x_priv_enc_b64:
        raise ValueError(f"Key kid={entry.kid} has missing private key material.")

    return CommunityKeypair.from_dict({
        "kid":             entry.kid,
        "community_id":    entry.community_id,
        "ed25519_pub_b64": entry.ed25519_pub_b64,
        "x25519_pub_b64":  entry.x25519_pub_b64,
        "ed_priv_enc":     entry.ed_priv_enc_b64,
        "x_priv_enc":      entry.x_priv_enc_b64,
    })


def list_entries(community_id: str) -> list[ArchiveEntry]:
    """Return all key archive entries for a community, newest first."""
    conn = _get_sqlite()
    rows = conn.execute(
        "SELECT * FROM community_key_archive WHERE community_id=? ORDER BY created_at DESC",
        (community_id,)
    ).fetchall()
    return [_row_to_entry(r) for r in rows]


# ── Internal helpers ──────────────────────────────────────────────────────────

def _row_to_entry(row) -> ArchiveEntry:
    return ArchiveEntry(
        community_id    = row["community_id"],
        kid             = row["kid"],
        status          = KeyStatus(row["status"]),
        ed25519_pub_b64 = row["ed25519_pub_b64"],
        x25519_pub_b64  = row["x25519_pub_b64"],
        ed_priv_enc_b64 = row["ed_priv_enc_b64"],
        x_priv_enc_b64  = row["x_priv_enc_b64"],
        created_at      = row["created_at"],
        shredded_at     = row["shredded_at"],
    )
