"""
warden/testing/fakes/s3_fake.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Fake S3/MinIO storage — in-memory dict вместо реального объектного хранилища.

Реализует тот же интерфейс, что warden.storage.s3.S3Storage:
  • save_bundle(session_id, bundle)
  • ship_log_entry(entry)
  • get_bundle(session_id)  — дополнительно для верификации в тестах
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field


@dataclass
class FakeS3Storage:
    """
    Thread-safe in-memory S3 fake.

    Использование:
        fake_s3 = FakeS3Storage()
        with patch("warden.storage.s3._instance", fake_s3):
            # вызовы save_bundle() идут в память
        assert fake_s3.bundle_count == 1
        bundle = fake_s3.get_bundle("session-id")
    """

    _bundles: dict[str, dict]   = field(default_factory=dict)
    _log_entries: list[dict]    = field(default_factory=list)
    _lock: threading.Lock       = field(default_factory=threading.Lock)
    _enabled: bool              = True

    # ── S3Storage interface ───────────────────────────────────────────────────

    def save_bundle(self, session_id: str, bundle: dict) -> None:
        with self._lock:
            self._bundles[session_id] = bundle

    def ship_log_entry(self, entry: dict) -> None:
        with self._lock:
            self._log_entries.append(entry)

    def is_enabled(self) -> bool:
        return self._enabled

    # ── Test helpers ──────────────────────────────────────────────────────────

    def get_bundle(self, session_id: str) -> dict | None:
        with self._lock:
            return self._bundles.get(session_id)

    @property
    def bundle_count(self) -> int:
        with self._lock:
            return len(self._bundles)

    @property
    def log_count(self) -> int:
        with self._lock:
            return len(self._log_entries)

    @property
    def log_entries(self) -> list[dict]:
        with self._lock:
            return list(self._log_entries)

    def clear(self) -> None:
        with self._lock:
            self._bundles.clear()
            self._log_entries.clear()

    def assert_bundle_saved(self, session_id: str) -> dict:
        """Проверяет, что bundle был сохранён, и возвращает его."""
        bundle = self.get_bundle(session_id)
        assert bundle is not None, f"Bundle for session '{session_id}' was not saved to S3"
        return bundle

    def assert_log_shipped(self, min_count: int = 1) -> None:
        """Проверяет минимальное количество отправленных лог-записей."""
        assert self.log_count >= min_count, (
            f"Expected at least {min_count} log entries shipped, got {self.log_count}"
        )
