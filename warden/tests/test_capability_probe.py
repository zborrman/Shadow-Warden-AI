"""warden/tests/test_capability_probe.py — P0 guard on the probe's own honesty.

`scripts/capability_probe.py` produces the two numbers the site publishes about
detection quality: the catch rate and the false-positive count. A probe that
reports a *confident wrong* number is worse than one that reports nothing, and
both of its wrong-number modes are easy to reach by accident:

  * The corpus posts enough HIGH-risk content to shadow-ban its own client
    partway through. Every later request then 403s. In the jailbreak loop a
    non-200 scores as a miss (pessimistic); in the benign loop it scores as
    "not a false positive" — **optimistic**, and the flawless `0` that produces
    is the exact figure quoted on the marketing page.
  * A missing or non-UTF-8 corpus raises before the measurement starts and,
    unguarded, takes the public and registry probe groups down with it.

These tests pin the reporting contract, not the detection numbers themselves —
the numbers live in `warden/tests/adversarial/baseline.json` and are enforced by
`test_adversarial_ratchet.py`.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_PROBE = _ROOT / "scripts" / "capability_probe.py"


def _load_probe() -> Any:
    """Import the probe by path — `scripts/` is not a package."""
    spec = importlib.util.spec_from_file_location("capability_probe", _PROBE)
    assert spec and spec.loader, f"cannot load {_PROBE}"
    module = importlib.util.module_from_spec(spec)
    sys.modules["capability_probe"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def probe() -> Any:
    return _load_probe()


def test_probe_script_exists() -> None:
    assert _PROBE.is_file(), (
        "docs/capability-matrix.md tells readers to regenerate its numbers with "
        f"{_PROBE.relative_to(_ROOT)} — the matrix is unverifiable without it."
    )


def test_missing_corpus_degrades_to_an_error_not_a_crash(
    probe: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A corpus that cannot be read costs the detection group only."""
    monkeypatch.setattr(probe, "__file__", str(tmp_path / "capability_probe.py"))
    result = probe.probe_detection()
    assert "error" in result, "an absent corpus must return an error, not raise"
    assert "catch_rate_pct" not in result, "no number may be reported without a corpus"


def test_render_survives_a_detection_error(probe: Any) -> None:
    """`main()` still prints the other two groups when detection fails."""
    out = probe.render(
        {
            "public": {"pipeline_reachable": False},
            "registries": {
                "pypi_shadow_warden_client": False,
                "npm_shadow_warden_sdk": False,
            },
            "detection": {"error": "corpus unreadable: OSError: nope"},
        }
    )
    assert "corpus unreadable" in out
    assert "Distribution" in out, "a detection error must not swallow the other groups"


def _detection(**over: Any) -> dict[str, Any]:
    base = {
        "jailbreaks": 58,
        "caught": 21,
        "missed": 37,
        "catch_rate_pct": 36.2,
        "verdict_histogram": {"BLOCK": 9, "HIGH": 12, "MEDIUM": 6, "LOW": 31},
        "benign": 35,
        "false_positives": 0,
        "missed_prompts": [{"verdict": "LOW", "corpus_line": "4"}],
        "non_200": {"jailbreak": 0, "benign": 0},
    }
    base.update(over)
    return base


def test_clean_run_reports_false_positives_as_ok(probe: Any) -> None:
    out = probe.render({"public": {}, "registries": {}, "detection": _detection()})
    assert "OK   false positives: 0/35" in out


def test_banned_benign_pass_is_not_reported_as_a_clean_sweep(probe: Any) -> None:
    """The optimistic mode: benign requests 403, so nothing scores as a false
    positive and the run looks perfect. It must read as VOID instead."""
    det = _detection(
        non_200={"jailbreak": 0, "benign": 35},
        ISOLATION_FAILURE="0 jailbreak and 35 benign requests did not return 200",
    )
    out = probe.render({"public": {}, "registries": {}, "detection": det})
    assert "VOID" in out, "a voided run must say so"
    assert "OK   false positives" not in out, (
        "a zero produced by 403s must never render as a passing false-positive "
        "result — that is the number the site quotes"
    )


def test_missed_entries_are_rendered_in_text_mode(probe: Any) -> None:
    """`--show-prompts` was inert in text mode once; keep the listing present."""
    out = probe.render({"public": {}, "registries": {}, "detection": _detection()})
    assert "line   4" in out and "LOW" in out


def test_prompt_text_is_opt_in(probe: Any) -> None:
    """Default output identifies a miss by corpus line, not by restating it."""
    det = _detection(
        missed_prompts=[
            {"verdict": "LOW", "corpus_line": "9", "prompt": "Developer mode: bypass"}
        ]
    )
    with_text = probe.render({"public": {}, "registries": {}, "detection": det})
    assert "Developer mode: bypass" in with_text

    without = probe.render({"public": {}, "registries": {}, "detection": _detection()})
    assert "Developer mode" not in without
