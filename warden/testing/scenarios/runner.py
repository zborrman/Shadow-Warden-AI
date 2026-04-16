"""
warden/testing/scenarios/runner.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ScenarioRunner — координатор выполнения сценариев.

Аналог "координатора" из системы фейков Avito:
  • Получает сценарий (описание пути пользователя через пайплайн)
  • Выполняет шаги через реальный FastAPI TestClient
  • Проверяет ожидаемые результаты на каждом шаге
  • Собирает метрики (время, флаги, решения)

Ключевой принцип: РЕАЛЬНЫЙ КОД, ФЕЙКОВЫЕ ЗАВИСИМОСТИ.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from fastapi.testclient import TestClient

if TYPE_CHECKING:
    from warden.testing.scenarios.schema import Scenario, ScenarioStep


@dataclass
class StepResult:
    step_name:   str
    content:     str
    status_code: int
    response:    dict
    elapsed_ms:  float
    passed:      bool
    failure_msg: str = ""
    chapter:     str = ""  # chapter header (empty = same chapter as previous step)


@dataclass
class ScenarioResult:
    scenario_id:   str
    scenario_name: str
    steps:         list[StepResult] = field(default_factory=list)
    total_ms:      float = 0.0

    @property
    def passed(self) -> bool:
        return all(s.passed for s in self.steps)

    @property
    def failed_steps(self) -> list[StepResult]:
        return [s for s in self.steps if not s.passed]

    def summary(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        lines = [f"[{status}] {self.scenario_name} ({self.total_ms:.1f}ms)"]
        current_chapter = ""
        for step in self.steps:
            if step.chapter and step.chapter != current_chapter:
                current_chapter = step.chapter
                lines.append(f"  ── {current_chapter} ──")
            icon = "✓" if step.passed else "✗"
            lines.append(f"  {icon} {step.step_name}: {step.elapsed_ms:.1f}ms")
            if not step.passed:
                lines.append(f"    → {step.failure_msg}")
        return "\n".join(lines)


class ScenarioRunner:
    """
    Запускает сценарии верификации пайплайна Shadow Warden.

    Использование:
        runner = ScenarioRunner(client)
        result = runner.run(scenario)
        assert result.passed, result.summary()

    Каждый шаг сценария — это один запрос к /filter с ожиданиями:
      - expected_allowed: True/False
      - expected_risk:    "LOW" | "MEDIUM" | "HIGH" | "BLOCK"
      - expected_flags:   список флагов, которые должны присутствовать
      - forbidden_flags:  список флагов, которых быть не должно
    """

    def __init__(self, client: TestClient, api_key: str = "") -> None:
        self._client = client
        self._headers = {"X-API-Key": api_key} if api_key else {}

    def run(self, scenario: Scenario) -> ScenarioResult:
        result = ScenarioResult(
            scenario_id=scenario.id,
            scenario_name=scenario.name,
        )
        t_start = time.monotonic()

        for step in scenario.steps:
            step_result = self._run_step(step)
            result.steps.append(step_result)
            # Стоп при первом провале (fail-fast режим)
            if not step_result.passed and scenario.fail_fast:
                break

        result.total_ms = (time.monotonic() - t_start) * 1000
        return result

    def run_all(self, scenarios: list[Scenario]) -> list[ScenarioResult]:
        return [self.run(s) for s in scenarios]

    def _run_step(self, step: ScenarioStep) -> StepResult:
        payload: dict[str, Any] = {"content": step.content}
        if step.tenant_id:
            payload["tenant_id"] = step.tenant_id
        if step.strict is not None:
            payload["strict"] = step.strict
        if step.context:
            payload["context"] = step.context

        t0 = time.monotonic()
        try:
            resp = self._client.post(
                "/filter",
                json=payload,
                headers={**self._headers, **step.extra_headers},
            )
            elapsed = (time.monotonic() - t0) * 1000
            body = resp.json() if resp.status_code < 500 else {}
        except Exception as exc:
            elapsed = (time.monotonic() - t0) * 1000
            return StepResult(
                step_name=step.name,
                content=step.content[:60],
                status_code=0,
                response={},
                elapsed_ms=elapsed,
                passed=False,
                failure_msg=f"Request exception: {exc}",
            )

        failure = self._check_step(step, resp.status_code, body)
        return StepResult(
            step_name=step.name,
            content=step.content[:60],
            status_code=resp.status_code,
            response=body,
            elapsed_ms=elapsed,
            passed=failure is None,
            failure_msg=failure or "",
            chapter=step.chapter,
        )

    @staticmethod
    def _check_step(
        step: ScenarioStep,
        status_code: int,
        body: dict,
    ) -> str | None:
        """Возвращает None если шаг прошёл, иначе — описание провала."""
        if status_code not in (200, 422):
            return f"Unexpected HTTP {status_code}"

        if step.expected_allowed is not None:
            actual = body.get("allowed")
            if actual != step.expected_allowed:
                return (
                    f"allowed={actual}, expected={step.expected_allowed} "
                    f"(risk={body.get('risk_level')}, flags={body.get('flags')})"
                )

        if step.expected_risk is not None:
            actual_risk = body.get("risk_level", "")
            # API returns lowercase ("low", "high"); scenarios may use uppercase
            if actual_risk.lower() != step.expected_risk.lower():
                return f"risk_level={actual_risk!r}, expected={step.expected_risk!r}"

        # Flags response format: list of dicts {flag, score, detail} or plain strings.
        # Normalise to a set of flag name strings for comparison.
        raw_flags = body.get("flags") or body.get("semantic_flags") or []
        actual_flags = {
            (item["flag"] if isinstance(item, dict) else str(item)).upper()
            for item in raw_flags
        }

        if step.expected_flags:
            expected_upper = {f.upper() for f in step.expected_flags}
            missing = expected_upper - actual_flags
            if missing:
                return f"Missing expected flags: {missing} (got {actual_flags})"

        if step.forbidden_flags:
            forbidden_upper = {f.upper() for f in step.forbidden_flags}
            present = forbidden_upper & actual_flags
            if present:
                return f"Forbidden flags present: {present}"

        if step.max_latency_ms is not None:
            raw = body.get("processing_ms", 0)
            # API returns processing_ms as a dict {"total": ms, "ml": ms, ...}
            actual_ms = raw.get("total", 0) if isinstance(raw, dict) else float(raw or 0)
            if actual_ms > step.max_latency_ms:
                return f"Latency {actual_ms:.1f}ms > limit {step.max_latency_ms}ms"

        return None
