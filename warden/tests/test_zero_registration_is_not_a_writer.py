"""warden/tests/test_zero_registration_is_not_a_writer.py

`test_alert_metrics_have_writers.py` (OB-F12) catches a metric written by
*nothing*. This is the same defect one layer further in: a metric whose only
writes are `.inc(0)` / `.set(0)`.

prometheus_client needs `.labels(...).inc(0)` to make a labelled child appear in
the scrape before it has ever been incremented — otherwise the series is absent
and a rate() over it has no data. That is a legitimate pattern. It becomes a
defect when it is the *only* write the metric ever receives, because then:

  * the metric IS referenced from application code, so OB-F12's writer check
    passes — it deliberately counts any non-test reference as a write path;
  * the series appears in the scrape, so it does not look absent; and
  * it reads a confident 0.0 forever, which is indistinguishable from "this
    subsystem ran and found nothing".

Measured on production 2026-08-29:

    warden_nemotron_evolution_total   declared as "Evolution Engine rule
                                      generation calls, labelled by backend";
                                      all four references in evolve.py were
                                      `.labels(engine=...).inc(0)`

The Evolution Engine had produced nothing in production for months — auto mode
selected a NIM backend whose model 404s at call time, and the fallback to Claude
only fired on *construction* failure, which never happened. Every signal agreed
things were fine: the engine logged "online" at startup, and its own counter
read 0.0 exactly as it would have on a quiet day.

HARD FAIL, and it is at zero: the one offender was given a real increment in the
same change that added this test. There is no baseline to ratchet down.
"""
from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]

#: Modules that construct Prometheus metric singletons.
_METRIC_MODULES = (
    _ROOT / "warden" / "metrics.py",
    _ROOT / "warden" / "voice" / "metrics.py",
)

_DECLARATION = re.compile(
    r"^\s*([A-Z][A-Z0-9_]*)\s*=\s*"
    r"(?:Gauge|Counter|Histogram|Summary|Info|Enum)\(\s*\n?\s*"
    r"[\"']([a-z][a-z0-9_]*)[\"']",
    re.MULTILINE,
)

#: `.inc(0)`, `.inc(0.0)`, `.set(0)` — registers the series, measures nothing.
_ZERO_WRITE = re.compile(r"\.(?:inc|set)\(\s*0(?:\.0)?\s*\)")


def _declared_metrics() -> dict[str, str]:
    """symbol -> exported metric name."""
    out: dict[str, str] = {}
    for module in _METRIC_MODULES:
        if module.exists():
            for symbol, name in _DECLARATION.findall(module.read_text(encoding="utf-8")):
                out[symbol] = name
    return out


def _application_sources() -> dict[Path, str]:
    """Non-test warden modules, excluding the metric declaration modules."""
    out: dict[Path, str] = {}
    for path in (_ROOT / "warden").rglob("*.py"):
        if "tests" in path.parts or path in _METRIC_MODULES:
            continue
        try:
            out[path] = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
    return out


def _reference_lines(symbol: str, sources: dict[Path, str]) -> list[str]:
    """Every source line mentioning *symbol*, outside imports and __all__."""
    pattern = re.compile(r"\b" + re.escape(symbol) + r"\b")
    lines: list[str] = []
    for text in sources.values():
        for match in pattern.finditer(text):
            start = text.rfind("\n", 0, match.start()) + 1
            end = text.find("\n", match.end())
            line = text[start : end if end != -1 else len(text)].strip()
            if line.startswith(("from ", "import ")):
                continue
            # a bare symbol on its own line is a continued import / __all__ entry
            if re.fullmatch(r"[A-Z0-9_]+,?", line):
                continue
            lines.append(line)
    return lines


def test_no_metric_is_written_only_with_zero() -> None:
    """A metric whose every write is `.inc(0)` measures nothing, confidently."""
    sources = _application_sources()
    offenders: dict[str, list[str]] = {}

    for symbol, metric_name in _declared_metrics().items():
        refs = _reference_lines(symbol, sources)
        if not refs:
            # Written by nothing at all — that is OB-F12's job, not this test's.
            continue
        if all(_ZERO_WRITE.search(ref) for ref in refs):
            offenders[metric_name] = refs[:4]

    assert not offenders, (
        "these metrics are only ever written with a zero, so they export a "
        "confident 0.0 whether or not the subsystem behind them ever ran — and "
        "they still satisfy the OB-F12 writer check, because they ARE referenced "
        "from application code:\n"
        + "\n".join(
            f"  {name}\n" + "\n".join(f"      {r}" for r in lines)
            for name, lines in sorted(offenders.items())
        )
        + "\n\nGive the metric a real increment at the point the work actually "
        "happens, or delete it. A counter that can only ever read zero is worse "
        "than no counter, because it looks like a measurement."
    )


def test_the_detector_recognises_a_zero_only_write() -> None:
    """Guard the guard: the regex must actually match the shapes it targets.

    Without this, a typo in `_ZERO_WRITE` makes the test above pass vacuously —
    which is precisely the failure mode the whole file is about.
    """
    should_match = [
        'NEMOTRON_EVOLUTION_TOTAL.labels(engine="claude").inc(0)',
        "SOME_COUNTER.labels(a=1).inc(0.0)",
        "SOME_GAUGE.set(0)",
        "X.inc( 0 )",
    ]
    should_not_match = [
        'NEMOTRON_EVOLUTION_TOTAL.labels(engine=self.ENGINE_LABEL).inc()',
        "SOME_COUNTER.inc(1)",
        "SOME_GAUGE.set(value)",
        "SOME_GAUGE.set(0.5)",
        "SOME_COUNTER.inc(count)",
    ]
    for line in should_match:
        assert _ZERO_WRITE.search(line), f"should be detected as a zero-write: {line}"
    for line in should_not_match:
        assert not _ZERO_WRITE.search(line), f"should NOT be a zero-write: {line}"


def test_the_evolution_counter_now_has_a_real_increment() -> None:
    """The specific metric this test was written for.

    Pinned by name rather than left to the sweep above, because this one was
    dead in production for months and the regression is silent by construction.
    """
    evolve = (_ROOT / "warden" / "brain" / "evolve.py").read_text(encoding="utf-8")
    refs = [
        line.strip()
        for line in evolve.splitlines()
        if "NEMOTRON_EVOLUTION_TOTAL" in line and not line.strip().startswith(("from", "import"))
    ]
    assert refs, "NEMOTRON_EVOLUTION_TOTAL is no longer referenced in evolve.py"
    real = [r for r in refs if not _ZERO_WRITE.search(r)]
    assert real, (
        "every reference to NEMOTRON_EVOLUTION_TOTAL in evolve.py is a zero "
        f"registration again: {refs}"
    )
