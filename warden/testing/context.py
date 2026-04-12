"""
warden/testing/context.py
━━━━━━━━━━━━━━━━━━━━━━━━━
FakeContext — единая точка входа для подмены всех зависимостей.

Аналог "тестового хендлера" из системы фейков Avito:
  • Активирует все фейки одновременно через patch
  • Обеспечивает изоляцию (каждый тест получает чистое состояние)
  • Предоставляет удобный API для настройки поведения фейков

Использование (минимальное):
    with FakeContext() as ctx:
        resp = client.post("/filter", json={"content": "test"})
        assert resp.json()["allowed"] is True

Использование (расширенное):
    with FakeContext() as ctx:
        ctx.evolution.queue_rule("ignore.*instructions")
        ctx.s3.clear()
        resp = client.post("/filter", json={"content": "jailbreak"})
        assert ctx.evolution.was_called()
        assert ctx.s3.log_count == 1
"""
from __future__ import annotations

import contextlib
import uuid
from contextlib import contextmanager
from unittest.mock import patch

from warden.testing.fakes.anthropic_fake import FakeAnthropicClient
from warden.testing.fakes.evolution_fake import FakeEvolutionEngine
from warden.testing.fakes.nvidia_fake import FakeNvidiaClient
from warden.testing.fakes.s3_fake import FakeS3Storage


class FakeContext:
    """
    Контекстный менеджер для активации всех фейков Shadow Warden.

    Реализует принцип "request-level isolation" из системы фейков Avito:
    каждый вызов FakeContext создаёт независимую изолированную среду.
    """

    def __init__(
        self,
        simulation_id: str | None = None,
        enable_evolution: bool = True,
        enable_s3: bool = True,
        enable_anthropic: bool = True,
        enable_nvidia: bool = True,
    ) -> None:
        self.simulation_id = simulation_id or str(uuid.uuid4())[:8]
        self._enable_evolution = enable_evolution
        self._enable_s3 = enable_s3
        self._enable_anthropic = enable_anthropic
        self._enable_nvidia = enable_nvidia

        # Экземпляры фейков — доступны после __enter__
        self.anthropic:  FakeAnthropicClient = FakeAnthropicClient()
        self.nvidia:     FakeNvidiaClient    = FakeNvidiaClient()
        self.s3:         FakeS3Storage       = FakeS3Storage()
        self.evolution:  FakeEvolutionEngine = FakeEvolutionEngine()

        self._patches: list = []

    def __enter__(self) -> FakeContext:
        self._activate()
        return self

    def __exit__(self, *args) -> None:
        self._deactivate()

    # ── Patch management ──────────────────────────────────────────────────────

    def _activate(self) -> None:
        """Активировать все фейки через unittest.mock.patch."""
        patches: list[tuple[str, object]] = []

        if self._enable_s3:
            patches.extend([
                ("warden.storage.s3._instance", self.s3),
                ("warden.compliance.bundler._s3_storage", self.s3),
                ("warden.analytics.logger._s3_storage", self.s3),
            ])

        if self._enable_anthropic:
            patches.extend([
                ("warden.brain.evolve.anthropic.Anthropic", lambda **kw: self.anthropic),
                ("warden.brain.evolve.anthropic.AsyncAnthropic", lambda **kw: self.anthropic),
            ])

        if self._enable_nvidia:
            patches.extend([
                ("warden.brain.nemotron_client.openai.OpenAI", lambda **kw: self.nvidia),
            ])

        # Активируем все patches
        for target, new_val in patches:
            try:
                p = patch(target, new_val)
                p.start()
                self._patches.append(p)
            except AttributeError:
                pass  # Модуль может не существовать в конкретной конфигурации

    def _deactivate(self) -> None:
        """Остановить все patches и сбросить состояние."""
        for p in reversed(self._patches):
            with contextlib.suppress(RuntimeError):
                p.stop()
        self._patches.clear()

    # ── Convenience methods ───────────────────────────────────────────────────

    def simulation_header(self) -> dict[str, str]:
        """Заголовок X-Simulation-ID для request-level isolation."""
        return {"X-Simulation-ID": self.simulation_id}

    def assert_evolution_triggered(self) -> None:
        assert self.evolution.was_called(), (
            "Expected Evolution Engine to be triggered, but process_blocked() was never called"
        )

    def assert_s3_bundle_count(self, expected: int) -> None:
        assert self.s3.bundle_count == expected, (
            f"Expected {expected} S3 bundles, got {self.s3.bundle_count}"
        )

    def assert_no_evidence_bundles(self) -> None:
        """Assert no tamper-evident evidence bundles were written (e.g. for benign requests)."""
        assert self.s3.bundle_count == 0, (
            f"Expected no S3 evidence bundles, got bundle_count={self.s3.bundle_count}"
        )

    def assert_no_s3_writes(self) -> None:
        """Assert neither evidence bundles nor analytics logs were written.

        NOTE: analytics logger ships a log entry for every /filter request (by design).
        Use assert_no_evidence_bundles() when testing benign requests that produce log
        entries but should not produce compliance evidence bundles.
        """
        assert self.s3.bundle_count == 0 and self.s3.log_count == 0, (
            f"Expected no S3 writes, got bundles={self.s3.bundle_count} logs={self.s3.log_count}"
        )


@contextmanager
def fake_evolution_context(semantic_guard=None):
    """
    Минимальный контекст: только подмена Evolution Engine.
    Полезен в тестах, которые проверяют, что EvolutionEngine вызывается.
    """
    fake = FakeEvolutionEngine()
    if semantic_guard is not None:
        fake.set_guard(semantic_guard)
    with patch("warden.main._evolve", fake):
        yield fake
