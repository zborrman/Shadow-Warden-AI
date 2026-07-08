"""
GSAM collector — fail-open, bounded, zero hot-path cost.

Producers call gsam_emit(obs) which is dict-build + Queue.put_nowait only
(microseconds, never blocks, never raises). A single daemon thread batches
the queue and ships to ClickHouse; when ClickHouse is disabled or down the
batch is appended to a size-capped NDJSON spool and replayed on the next
healthy flush. Mirrors analytics/logger.py's background S3 shipping.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import queue
import tempfile
import threading
import time
from collections.abc import Callable

from warden.config import settings

log = logging.getLogger("warden.gsam.collector")

_queue: queue.Queue[dict] = queue.Queue(maxsize=max(1, settings.gsam_queue_max))
_drop_count = 0
_flushed_count = 0
_worker: threading.Thread | None = None
_worker_lock = threading.Lock()
_stop = threading.Event()

# Optional per-batch sinks (e.g. the SQLite rollup) — each called fail-open.
_sinks: list[Callable[[list[dict]], None]] = []


def register_sink(fn: Callable[[list[dict]], None]) -> None:
    """Register a callable invoked with every flushed batch (fail-open)."""
    if fn not in _sinks:
        _sinks.append(fn)


def gsam_emit(obs: dict) -> None:
    """Enqueue one observation. Never raises, never blocks."""
    global _drop_count
    try:
        _ensure_worker()
        _queue.put_nowait(obs)
    except queue.Full:
        _drop_count += 1
    except Exception:  # noqa: BLE001, S110
        pass


def stats() -> dict:
    """Health snapshot for GET /gsam/health."""
    spool_bytes = 0
    try:
        if os.path.exists(settings.gsam_spool_path):
            spool_bytes = os.path.getsize(settings.gsam_spool_path)
    except OSError:
        pass
    ch_reachable = False
    try:
        from warden.gsam.clickhouse import get_clickhouse  # noqa: PLC0415
        ch = get_clickhouse()
        ch_reachable = ch.is_enabled() and ch.ping()
    except Exception:  # noqa: BLE001, S110
        pass
    return {
        "queue_depth": _queue.qsize(),
        "queue_max": settings.gsam_queue_max,
        "dropped": _drop_count,
        "flushed": _flushed_count,
        "spool_bytes": spool_bytes,
        "clickhouse_enabled": bool(settings.gsam_clickhouse_enabled),
        "clickhouse_reachable": ch_reachable,
    }


# ── Worker ────────────────────────────────────────────────────────────────────

def _ensure_worker() -> None:
    global _worker
    if _worker is not None and _worker.is_alive():
        return
    with _worker_lock:
        if _worker is not None and _worker.is_alive():
            return
        _stop.clear()
        _worker = threading.Thread(target=_run, name="gsam-collector", daemon=True)
        _worker.start()


def _run() -> None:
    interval = max(0.1, float(settings.gsam_flush_interval_s))
    while not _stop.wait(interval):
        with contextlib.suppress(Exception):
            flush_once()


def _drain(max_items: int) -> list[dict]:
    batch: list[dict] = []
    while len(batch) < max_items:
        try:
            batch.append(_queue.get_nowait())
        except queue.Empty:
            break
    return batch


def flush_once() -> int:
    """Drain up to one batch and ship it. Returns rows handled (test hook)."""
    global _flushed_count
    batch = _drain(max(1, settings.gsam_batch_size))
    if not batch:
        _replay_spool()
        return 0

    for sink in list(_sinks):
        with contextlib.suppress(Exception):
            sink(batch)

    if _ship(batch):
        _flushed_count += len(batch)
        _replay_spool()
    else:
        _spool(batch)
    return len(batch)


def _ship(batch: list[dict]) -> bool:
    """Insert into ClickHouse. False when disabled or failed."""
    try:
        from warden.gsam.clickhouse import get_clickhouse  # noqa: PLC0415
        ch = get_clickhouse()
        if not ch.is_enabled():
            return False
        return ch.insert_rows(batch)
    except Exception:  # noqa: BLE001
        return False


# ── NDJSON spool (fail-open persistence while ClickHouse is unavailable) ─────

def _spool(batch: list[dict]) -> None:
    try:
        path = settings.gsam_spool_path
        if os.path.exists(path) and os.path.getsize(path) >= settings.gsam_spool_max_bytes:
            return  # spool full — drop silently (bounded disk usage)
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            for row in batch:
                fh.write(json.dumps(row, default=str) + "\n")
    except Exception:  # noqa: BLE001, S110
        pass


def _replay_spool() -> None:
    """Ship spooled rows once ClickHouse is healthy again."""
    global _flushed_count
    try:
        path = settings.gsam_spool_path
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return
        rows: list[dict] = []
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        if not rows:
            _truncate_spool(path)
            return
        if _ship(rows):
            _flushed_count += len(rows)
            _truncate_spool(path)
    except Exception:  # noqa: BLE001, S110
        pass


def _truncate_spool(path: str) -> None:
    """Atomically replace the spool with an empty file (tempfile + os.replace)."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".")
    os.close(fd)
    os.replace(tmp, path)


def shutdown(timeout: float = 2.0) -> None:
    """Stop the worker and flush what's left (used by tests/lifespan)."""
    _stop.set()
    worker = _worker
    if worker is not None and worker.is_alive():
        worker.join(timeout=timeout)
    deadline = time.monotonic() + timeout
    while not _queue.empty() and time.monotonic() < deadline:
        flush_once()
