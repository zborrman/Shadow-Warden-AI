"""
warden/corpus_sync.py
━━━━━━━━━━━━━━━━━━━━
Cross-region corpus synchronisation — Step 2 of v1.3 Global Threat Intelligence.

When EvolutionEngine extends the MiniLM corpus on any node, the updated
embeddings (.npz) and text examples (.json) are:
  1. Uploaded to S3 (under a region-namespaced key).
  2. An invalidation signal is published to a Redis Stream so other nodes
     know a fresher corpus is available.
  3. Remote nodes consume the signal, download the snapshot, and hot-reload
     their local corpus — no restart required.

Why S3 + Redis signal (not Redis directly)
───────────────────────────────────────────
  The compressed corpus (.npz) can be several MB.  Stuffing binary blobs
  into Redis is wasteful and hits the 512 MB key-size soft limit quickly.
  S3 is the right store for large objects; Redis carries only the tiny
  invalidation message (< 200 bytes).

Upload layout (S3)
──────────────────
  {CORPUS_S3_PREFIX}/{source_region}/corpus.npz
  {CORPUS_S3_PREFIX}/{source_region}/corpus.json

Each region writes only its own prefix.  Consumers pull from any region
that published a more recent snapshot (determined by published_at in the
invalidation message).

Invalidation message (Redis Stream warden:corpus:invalidations)
────────────────────────────────────────────────────────────────
  source_region   publishing node ("usa" | "eu" | "dubai")
  npz_key         S3 key for the .npz file
  json_key        S3 key for the .json file
  embedding_count number of vectors in this snapshot
  published_at    ISO 8601 timestamp

Failure modes
─────────────
  • S3 unavailable       → upload silently no-ops; local snapshot still saved
  • Redis unavailable    → invalidation not published; other nodes use previous
  • Download fails       → local corpus unchanged (logged at WARNING)
  • numpy/torch absent   → watcher silently disabled (test environments)

Environment variables
─────────────────────
  CORPUS_SYNC_ENABLED        "false" to disable entirely (default: true)
  CORPUS_S3_BUCKET           S3 bucket name  (required to enable uploads)
  CORPUS_S3_PREFIX           Key prefix      (default: warden/corpus)
  CORPUS_S3_REGION           AWS region      (default: us-east-1)
  CORPUS_INVALIDATION_STREAM Redis stream name (default: warden:corpus:invalidations)
  CORPUS_INVALIDATION_MAX    Max stream length (default: 500)
  WARDEN_REGION              This node's region label (shared with threat_sync)
"""
from __future__ import annotations

import contextlib
import logging
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

log = logging.getLogger("warden.corpus_sync")

# ── Config ────────────────────────────────────────────────────────────────────

ENABLED: bool     = os.getenv("CORPUS_SYNC_ENABLED", "true").lower() != "false"
S3_BUCKET: str    = os.getenv("CORPUS_S3_BUCKET", "")
S3_PREFIX: str    = os.getenv("CORPUS_S3_PREFIX", "warden/corpus")
S3_AWS_REGION: str = os.getenv("CORPUS_S3_REGION", "us-east-1")
INV_STREAM: str   = os.getenv("CORPUS_INVALIDATION_STREAM", "warden:corpus:invalidations")
INV_MAX: int      = int(os.getenv("CORPUS_INVALIDATION_MAX", "500"))
REGION: str       = os.getenv("WARDEN_REGION", "default")

_BLOCK_MS   = 5_000   # xreadgroup block timeout
_BATCH      = 10      # messages per poll cycle
_GROUP      = f"warden:corpus:{REGION}"
_CONSUMER   = f"{REGION}-corpus-worker"


# ── S3 helpers ────────────────────────────────────────────────────────────────

def _s3_client():
    import boto3  # noqa: PLC0415
    return boto3.client("s3", region_name=S3_AWS_REGION)


def _npz_key(region: str) -> str:
    return f"{S3_PREFIX}/{region}/corpus.npz"


def _json_key(region: str) -> str:
    return f"{S3_PREFIX}/{region}/corpus.json"


# ── Redis helpers ─────────────────────────────────────────────────────────────

_redis_client = None
_redis_lock   = threading.Lock()


def _get_redis():
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    with _redis_lock:
        if _redis_client is not None:
            return _redis_client
        url = os.getenv("GLOBAL_REDIS_URL") or os.getenv("REDIS_URL", "redis://redis:6379/0")
        try:
            import redis as _redis  # noqa: PLC0415
            c = _redis.from_url(url, decode_responses=True,
                                socket_connect_timeout=3,
                                socket_timeout=_BLOCK_MS / 1000 + 3)  # must exceed xreadgroup block
            c.ping()
            _redis_client = c
        except Exception as exc:
            log.warning("CorpusSync: Redis unavailable: %s", exc)
            _redis_client = None
    return _redis_client


# ── Producer — upload + invalidate ───────────────────────────────────────────

def upload_snapshot(npz_path: Path, json_path: Path, embedding_count: int) -> bool:
    """
    Upload corpus snapshot files to S3 and publish an invalidation signal.

    Called from DataPoisoningGuard after each successful _save_snapshot_sync().
    Fail-silent: returns False instead of raising.

    Args:
        npz_path:        Local path to the .npz embeddings file.
        json_path:       Local path to the .json examples file.
        embedding_count: Number of embedding vectors in this snapshot.

    Returns True if both upload + invalidation succeeded.
    """
    if not ENABLED or not S3_BUCKET:
        return False

    try:
        s3 = _s3_client()
    except ImportError:
        log.debug("CorpusSync: boto3 not installed — S3 upload skipped")
        return False
    except Exception as exc:
        log.warning("CorpusSync: S3 client init failed: %s", exc)
        return False

    npz_key  = _npz_key(REGION)
    json_key = _json_key(REGION)

    try:
        s3.upload_file(str(npz_path),  S3_BUCKET, npz_key)
        s3.upload_file(str(json_path), S3_BUCKET, json_key)
        log.info(
            "CorpusSync: snapshot uploaded — region=%s embeddings=%d npz=%s",
            REGION, embedding_count, npz_key,
        )
        try:
            from warden.metrics import SYNC_CORPUS_UPLOADS_TOTAL  # noqa: PLC0415
            SYNC_CORPUS_UPLOADS_TOTAL.inc()
        except Exception:
            pass
    except Exception as exc:
        log.warning("CorpusSync: S3 upload failed: %s", exc)
        return False

    return _publish_invalidation(npz_key, json_key, embedding_count)


def _publish_invalidation(npz_key: str, json_key: str, embedding_count: int) -> bool:
    """Publish corpus invalidation signal to Redis Stream."""
    r = _get_redis()
    if r is None:
        return False
    try:
        r.xadd(
            INV_STREAM,
            {
                "source_region":   REGION,
                "npz_key":         npz_key,
                "json_key":        json_key,
                "embedding_count": str(embedding_count),
                "published_at":    datetime.now(UTC).isoformat(),
            },
            maxlen=INV_MAX,
            approximate=True,
        )
        log.info("CorpusSync: invalidation published to %s", INV_STREAM)
        return True
    except Exception as exc:
        log.warning("CorpusSync: invalidation publish failed: %s", exc)
        return False


# ── Consumer — watch + download + reload ──────────────────────────────────────

def _ensure_inv_group(r) -> bool:
    try:
        r.xgroup_create(INV_STREAM, _GROUP, id="0", mkstream=True)
    except Exception as exc:
        if "BUSYGROUP" not in str(exc):
            log.warning("CorpusSync: xgroup_create error: %s", exc)
            return False
    return True


def _download_and_reload(entry: dict, poison_guard) -> None:
    """Download corpus snapshot from S3 and reload local corpus."""
    source_region = entry.get("source_region", "")
    if source_region == REGION:
        return  # own snapshot — skip

    npz_key  = entry.get("npz_key", "")
    json_key = entry.get("json_key", "")
    if not npz_key or not json_key or not S3_BUCKET:
        return

    snapshot_base = Path(os.getenv("CORPUS_SNAPSHOT_PATH", "/tmp/warden_corpus_snapshot"))
    npz_local  = snapshot_base.with_suffix(".npz")
    json_local = snapshot_base.with_suffix(".json")
    tmp_npz    = snapshot_base.with_suffix(".sync.npz")
    tmp_json   = snapshot_base.with_suffix(".sync.json")

    try:
        s3 = _s3_client()
        s3.download_file(S3_BUCKET, npz_key,  str(tmp_npz))
        s3.download_file(S3_BUCKET, json_key, str(tmp_json))
        os.replace(str(tmp_npz),  str(npz_local))
        os.replace(str(tmp_json), str(json_local))
        log.info(
            "CorpusSync: downloaded snapshot from region=%s embeddings=%s",
            source_region, entry.get("embedding_count", "?"),
        )
    except ImportError:
        log.debug("CorpusSync: boto3 not installed — download skipped")
        return
    except Exception as exc:
        log.warning("CorpusSync: snapshot download failed: %s", exc)
        _cleanup(tmp_npz, tmp_json)
        return

    # Hot-reload via DataPoisoningGuard.restore_snapshot_async()
    if poison_guard is not None:
        try:
            import asyncio  # noqa: PLC0415
            loop = asyncio.new_event_loop()
            try:
                restored = loop.run_until_complete(poison_guard.restore_snapshot_async())
            finally:
                loop.close()
            if restored:
                log.info(
                    "CorpusSync: corpus hot-reloaded from region=%s", source_region
                )
                try:
                    from warden.metrics import SYNC_CORPUS_DOWNLOADS_TOTAL  # noqa: PLC0415
                    SYNC_CORPUS_DOWNLOADS_TOTAL.labels(source_region=source_region).inc()
                except Exception:
                    pass
            else:
                log.warning("CorpusSync: restore_snapshot_async returned False")
        except Exception as exc:
            log.warning("CorpusSync: corpus reload failed: %s", exc)


def _cleanup(*paths) -> None:
    for p in paths:
        with contextlib.suppress(OSError):
            Path(p).unlink(missing_ok=True)


def _poll_invalidations(r, poison_guard) -> int:
    try:
        results = r.xreadgroup(
            groupname    = _GROUP,
            consumername = _CONSUMER,
            streams      = {INV_STREAM: ">"},
            count        = _BATCH,
            block        = _BLOCK_MS,
        )
    except Exception as exc:
        log.debug("CorpusSync: xreadgroup error: %s", exc)
        return 0

    if not results:
        return 0

    processed = 0
    for _stream, messages in results:
        for msg_id, fields in messages:
            try:
                _download_and_reload(fields, poison_guard)
                r.xack(INV_STREAM, _GROUP, msg_id)
                processed += 1
            except Exception as exc:
                log.warning("CorpusSync: message error msg_id=%s: %s", msg_id, exc)
    return processed


# ── Background watcher ────────────────────────────────────────────────────────

class CorpusSyncWatcher:
    """
    Background thread that watches the invalidation stream and hot-reloads
    the local corpus when a remote region publishes a new snapshot.

    Usage (warden/main.py lifespan)::

        _corpus_watcher = CorpusSyncWatcher(poison_guard=_poison_guard)
        _corpus_watcher.start()
        ...
        _corpus_watcher.stop()
    """

    def __init__(self, poison_guard=None) -> None:
        self._poison_guard = poison_guard
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        if not ENABLED:
            log.info("CorpusSync disabled (CORPUS_SYNC_ENABLED=false)")
            return
        if not S3_BUCKET:
            log.info("CorpusSync: CORPUS_S3_BUCKET not set — watcher not started")
            return
        r = _get_redis()
        if r is None:
            log.warning("CorpusSync: Redis unavailable — watcher not started")
            return
        if not _ensure_inv_group(r):
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name="corpus-sync-watcher",
            daemon=True,
        )
        self._thread.start()
        log.info(
            "CorpusSyncWatcher started: region=%s stream=%s", REGION, INV_STREAM
        )

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)

    def _loop(self) -> None:
        backoff = 1
        while not self._stop.is_set():
            r = _get_redis()
            if r is None:
                self._stop.wait(backoff)
                backoff = min(backoff * 2, 60)
                continue
            backoff = 1
            try:
                _poll_invalidations(r, self._poison_guard)
            except Exception as exc:
                log.warning("CorpusSyncWatcher loop error: %s", exc)
                self._stop.wait(2)
