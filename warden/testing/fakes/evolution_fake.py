"""
warden/testing/fakes/evolution_fake.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Fake EvolutionEngine — имитирует генерацию правил без LLM-вызовов.

Реализует интерфейс BaseEvolutionEngine: process_blocked(content, flags, risk_level).
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FakeEvolutionEngine:
    """
    Fake для любого EvolutionEngine (Claude или Nemotron).

    Записывает все вызовы process_blocked() для последующей проверки.
    Опционально генерирует фейковые правила в SemanticGuard.

    Использование:
        fake_evolve = FakeEvolutionEngine()
        with patch.object(app_state, "_evolve", fake_evolve):
            client.post("/filter", json={"content": "jailbreak attempt"})
        assert fake_evolve.was_called_with_flags({"JAILBREAK"})
    """

    _calls: list[dict]              = field(default_factory=list)
    _rules_to_inject: list[str]     = field(default_factory=list)
    _guard: object | None           = field(default=None)

    def set_guard(self, guard: object) -> None:
        """Связать с реальным SemanticGuard для инъекции фейковых правил."""
        self._guard = guard

    def queue_rule(self, rule_value: str) -> None:
        """Запланировать добавление правила при следующем process_blocked()."""
        self._rules_to_inject.append(rule_value)

    async def process_blocked(
        self,
        content: str,
        flags: list[str],
        risk_level: str,
        **kwargs,
    ) -> None:
        self._calls.append({
            "content_len": len(content),
            "flags": list(flags),
            "risk_level": risk_level,
        })
        if self._rules_to_inject and self._guard is not None:
            rules = list(self._rules_to_inject)
            self._rules_to_inject.clear()
            if hasattr(self._guard, "add_examples"):
                self._guard.add_examples(rules)

    # ── Синхронная версия для non-async контекстов ────────────────────────────

    def process_blocked_sync(
        self,
        content: str,
        flags: list[str],
        risk_level: str,
        **kwargs,
    ) -> None:
        self._calls.append({
            "content_len": len(content),
            "flags": list(flags),
            "risk_level": risk_level,
        })

    # ── Test assertion helpers ────────────────────────────────────────────────

    @property
    def call_count(self) -> int:
        return len(self._calls)

    def was_called(self) -> bool:
        return bool(self._calls)

    def was_called_with_flags(self, expected_flags: set[str]) -> bool:
        return any(
            expected_flags.issubset(set(c["flags"]))
            for c in self._calls
        )

    def was_called_with_risk(self, risk_level: str) -> bool:
        return any(c["risk_level"] == risk_level for c in self._calls)

    def clear(self) -> None:
        self._calls.clear()
        self._rules_to_inject.clear()
