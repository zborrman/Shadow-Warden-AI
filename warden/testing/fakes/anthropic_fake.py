"""
warden/testing/fakes/anthropic_fake.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Fake Anthropic client для Evolution Engine и EvolutionResponse.

Вместо реального API возвращает заранее подготовленные ответы из очереди.
Поддерживает как обычные ответы, так и streaming (async generator).

Паттерн из системы фейков Avito: реальный интерфейс, подменённое поведение.
"""
from __future__ import annotations

import asyncio
import json
from collections import deque
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock, MagicMock


@dataclass
class _FakeContentBlock:
    text: str
    type: str = "text"


@dataclass
class _FakeMessage:
    content: list[_FakeContentBlock]
    stop_reason: str = "end_turn"
    model: str = "claude-opus-4-6-fake"
    usage: Any = None

    def __post_init__(self):
        if self.usage is None:
            self.usage = MagicMock(input_tokens=10, output_tokens=20)


class FakeAnthropicClient:
    """
    Drop-in замена для `anthropic.Anthropic` и `anthropic.AsyncAnthropic`.

    Использование:
        fake = FakeAnthropicClient()
        fake.queue_evolution_response(attack_type="jailbreak", rule="ignore.*instructions")
        fake.queue_raw("any text response")

        with patch("warden.brain.evolve.anthropic.Anthropic", return_value=fake):
            engine = EvolutionEngine(...)
    """

    def __init__(self) -> None:
        self._queue: deque[str] = deque()
        self._calls: list[dict] = []   # audit: все вызовы для проверки в тестах
        self.messages = self        # совместимость: client.messages.create(...)

    # ── Queue management ──────────────────────────────────────────────────────

    def queue_raw(self, text: str) -> None:
        """Положить произвольный текст в очередь ответов."""
        self._queue.append(text)

    def queue_evolution_response(
        self,
        attack_type: str = "jailbreak",
        rule_type: str = "semantic_example",
        rule_value: str = "ignore all previous instructions",
        severity: str = "HIGH",
        description: str = "Auto-generated fake rule",
        confidence: float = 0.92,
    ) -> None:
        """Сформировать валидный EvolutionResponse JSON и поставить в очередь."""
        payload = {
            "attack_type": attack_type,
            "new_rule": {
                "rule_type": rule_type,
                "value": rule_value,
                "description": description,
                "severity": severity,
            },
            "confidence": confidence,
            "reasoning": f"Fake reasoning for {attack_type}",
        }
        self._queue.append(json.dumps(payload))

    def queue_error(self, message: str = "Fake API error") -> None:
        """Поставить в очередь исключение (проверка обработки ошибок)."""
        self._queue.append(Exception(message))

    @property
    def call_count(self) -> int:
        return len(self._calls)

    def last_call(self) -> dict | None:
        return self._calls[-1] if self._calls else None

    # ── Anthropic messages.create interface ──────────────────────────────────

    def create(self, **kwargs: Any) -> _FakeMessage:
        """Синхронный messages.create — используется в EvolutionEngine."""
        self._calls.append({"mode": "sync", **kwargs})
        return self._build_response()

    async def acreate(self, **kwargs: Any) -> _FakeMessage:
        """Асинхронный messages.create."""
        self._calls.append({"mode": "async", **kwargs})
        await asyncio.sleep(0)
        return self._build_response()

    # Поддержка client.messages.stream() как context manager
    def stream(self, **kwargs: Any):
        self._calls.append({"mode": "stream", **kwargs})
        return _FakeStreamContext(self._next_text())

    def _build_response(self) -> _FakeMessage:
        text = self._next_text()
        return _FakeMessage(content=[_FakeContentBlock(text=text)])

    def _next_text(self) -> str:
        if not self._queue:
            return json.dumps({
                "attack_type": "unknown",
                "new_rule": {"rule_type": "semantic_example", "value": "default fake"},
                "confidence": 0.5,
                "reasoning": "Queue empty — default fake response",
            })
        item = self._queue.popleft()
        if isinstance(item, Exception):
            raise item
        return item


class _FakeStreamContext:
    """Имитация streaming context manager для anthropic.messages.stream()."""

    def __init__(self, text: str) -> None:
        self._text = text
        self._message = _FakeMessage(content=[_FakeContentBlock(text=text)])

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    def get_final_message(self) -> _FakeMessage:
        return self._message

    def text_stream(self):
        """Async generator: отдаёт текст по словам (имитация streaming)."""
        async def _gen():
            for word in self._text.split():
                yield word + " "
                await asyncio.sleep(0)
        return _gen()
