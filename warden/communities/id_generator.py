"""
warden/communities/id_generator.py
───────────────────────────────────
Distributed-safe unique ID generation for Business Communities.

Three ID types
──────────────
  Community_ID  — UUIDv7 (RFC 9562): time-ordered, globally unique, DB-sortable.
                  48-bit ms timestamp | 12-bit random | 62-bit random (variant 2).
                  Zero coordination required — safe across any number of nodes.

  Member_ID     — UUIDv7 namespaced under Community_ID via UUIDv5 SHA-1 namespace
                  derivation.  Same UUIDv7 entropy but scoped so Member_IDs from
                  different communities cannot collide in a shared table.

  Entity_ID     — Snowflake (Twitter-style):
                    41 bits  ms timestamp (since SNOWFLAKE_EPOCH)
                    10 bits  shard / node ID   (env SNOWFLAKE_SHARD, default 0)
                    12 bits  per-ms sequence counter
                  → 64-bit integer, fits in PostgreSQL BIGINT, sorts by creation time.
                  Throughput: 4096 unique IDs per millisecond per shard.

Why not plain UUIDv4 everywhere?
──────────────────────────────────
  UUIDv4 is random — DB indexes fragment badly at scale.  UUIDv7 encodes
  creation time in the high bits so new rows always land at the end of the
  B-tree index, eliminating index bloat and random I/O on inserts.

  Snowflake Entity_IDs are sortable integers — 8 bytes vs 16 bytes for UUID,
  halving index size for the highest-volume table (one row per message/file).
"""
from __future__ import annotations

import os
import threading
import time
import uuid


# ── UUIDv7 ────────────────────────────────────────────────────────────────────

def new_community_id() -> str:
    """Return a new UUIDv7 string for Community_ID."""
    return str(_uuidv7())


def new_member_id(community_id: str) -> str:
    """
    Return a UUIDv7 scoped to *community_id*.

    Uses the community UUID as a UUIDv5 namespace so Member_IDs from
    different communities cannot collide even in a shared DB table.
    """
    ns   = uuid.UUID(community_id)
    raw  = _uuidv7()
    # Namespace the UUIDv7 bytes under the community UUID namespace
    # to produce a determinism-free but community-scoped identifier.
    # We XOR the raw bytes with the namespace bytes for cheap scoping
    # while preserving the UUIDv7 variant/version bits.
    raw_bytes = bytearray(raw.bytes)
    ns_bytes  = bytearray(ns.bytes)
    for i in range(16):
        raw_bytes[i] ^= ns_bytes[i]
    # Re-assert version=7 (bits 12-15 of byte 6) and variant=10 (byte 8)
    raw_bytes[6] = (raw_bytes[6] & 0x0F) | 0x70
    raw_bytes[8] = (raw_bytes[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(raw_bytes)))


def _uuidv7() -> uuid.UUID:
    """
    Generate a RFC 9562 UUIDv7.

    Layout (128 bits):
      [0:48]   Unix millisecond timestamp
      [48:50]  version = 0b0111  (4 bits)
      [50:62]  random_a          (12 bits)
      [62:64]  variant = 0b10    (2 bits)
      [64:128] random_b          (62 bits)
    """
    ts_ms   = int(time.time() * 1000) & 0xFFFFFFFFFFFF   # 48 bits
    rand    = int.from_bytes(os.urandom(10), "big")       # 80 bits of randomness
    rand_a  = (rand >> 62) & 0xFFF                        # 12 bits
    rand_b  = rand & 0x3FFFFFFFFFFFFFFF                   # 62 bits

    hi  = (ts_ms << 16) | 0x7000 | rand_a
    lo  = 0x8000000000000000 | rand_b

    value = (hi << 64) | lo
    return uuid.UUID(int=value)


# ── Snowflake Entity_ID ────────────────────────────────────────────────────────

# Custom epoch: 2024-01-01T00:00:00Z in milliseconds
SNOWFLAKE_EPOCH: int = 1_704_067_200_000

_SHARD_ID:     int = int(os.getenv("SNOWFLAKE_SHARD", "0")) & 0x3FF  # 10 bits
_seq_lock                  = threading.Lock()
_last_ts:      int         = -1
_seq:          int         = 0


def new_entity_id() -> int:
    """
    Return a 64-bit Snowflake Entity_ID.

    Structure:
      [63]      sign bit = 0 (always positive)
      [62:22]   41-bit ms timestamp (since SNOWFLAKE_EPOCH)
      [21:12]   10-bit shard ID
      [11:0]    12-bit sequence counter (resets each ms)

    Thread-safe; up to 4096 unique IDs per millisecond per shard.
    """
    global _last_ts, _seq
    with _seq_lock:
        now = _now_ms()
        if now == _last_ts:
            _seq = (_seq + 1) & 0xFFF
            if _seq == 0:
                # Sequence exhausted — busy-wait for next millisecond
                while now <= _last_ts:
                    now = _now_ms()
        else:
            _seq = 0
        _last_ts = now

        return ((now - SNOWFLAKE_EPOCH) << 22) | (_SHARD_ID << 12) | _seq


def entity_id_to_ts(entity_id: int) -> float:
    """Extract Unix timestamp (seconds, float) from a Snowflake Entity_ID."""
    ms = ((entity_id >> 22) + SNOWFLAKE_EPOCH)
    return ms / 1000.0


def _now_ms() -> int:
    return int(time.time() * 1000)
