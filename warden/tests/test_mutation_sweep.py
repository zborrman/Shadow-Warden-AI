"""
warden/tests/test_mutation_sweep.py — the H-3 sweep's own contract.

The weekly sweep (``.github/workflows/mutation-sweep.yml``) is a ratchet, and a
ratchet that cannot fail is the defect it exists to catch. These pin that the
ratchet logic fails where it should, that the matrix covers exactly the
baselined modules, and that every source and test file it names exists — a
renamed test file would otherwise make a module's sweep kill nothing.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
import yaml

_ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("mutation_sweep", _ROOT / "scripts" / "mutation_sweep.py")
assert _spec and _spec.loader
sweep = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sweep)

_STATS = {"killed": 400, "survived": 200, "total": 600, "timeout": 0, "no_tests": 0,
          "check_was_interrupted_by_user": 0}


def _modules() -> dict:
    return json.loads(sweep.BASELINE.read_text(encoding="utf-8"))["modules"]


class TestTheRatchet:
    def test_more_survivors_than_baseline_fails(self):
        ok, msg = sweep.evaluate("m", {**_STATS, "survived": 201}, 200)
        assert not ok and "rose from 200 to 201" in msg

    def test_at_baseline_passes(self):
        assert sweep.evaluate("m", _STATS, 200)[0]

    def test_fewer_survivors_passes_and_asks_to_lower(self):
        ok, msg = sweep.evaluate("m", {**_STATS, "survived": 150}, 200)
        assert ok and "lower the baseline to 150" in msg

    def test_unmeasured_module_reports_and_passes(self):
        ok, msg = sweep.evaluate("m", _STATS, None)
        assert ok and "not yet baselined" in msg

    @pytest.mark.parametrize("bad", [
        {**_STATS, "total": 0, "killed": 0, "survived": 0},   # nothing mutated
        {**_STATS, "killed": 0, "survived": 600},             # tests never ran
        {**_STATS, "check_was_interrupted_by_user": 3},       # partial run
    ])
    def test_a_vacuous_or_partial_run_fails_even_unbaselined(self, bad):
        """Zero survivors from zero mutants would pass any ratchet."""
        assert not sweep.evaluate("m", bad, None)[0]
        assert not sweep.evaluate("m", bad, 10_000)[0]


class TestTheWiring:
    def test_matrix_lists_exactly_the_baselined_modules(self):
        wf = yaml.safe_load(
            (_ROOT / ".github/workflows/mutation-sweep.yml").read_text(encoding="utf-8")
        )
        matrix = wf["jobs"]["sweep"]["strategy"]["matrix"]["module"]
        assert sorted(matrix) == sorted(_modules())

    @pytest.mark.parametrize("module", sorted(_modules()))
    def test_every_named_file_exists(self, module):
        entry = _modules()[module]
        assert (_ROOT / entry["source"]).is_file(), entry["source"]
        assert entry["tests"], f"{module} has no tests to kill mutants with"
        for t in entry["tests"]:
            assert (_ROOT / t).is_file(), t

    def test_baseline_values_are_counts_or_unmeasured(self):
        for module, entry in _modules().items():
            v = entry["survived"]
            assert v is None or (isinstance(v, int) and v >= 0), (module, v)

    def test_prepare_narrows_pyproject_to_one_module(self, tmp_path, monkeypatch):
        fake = tmp_path / "pyproject.toml"
        fake.write_text(
            (_ROOT / "pyproject.toml").read_text(encoding="utf-8"), encoding="utf-8"
        )
        monkeypatch.setattr(sweep, "_PYPROJECT", fake)
        sweep.prepare("x402_gate")
        text = fake.read_text(encoding="utf-8")
        block = text[text.index("[tool.mutmut]"):]
        assert '"warden/marketplace/x402_gate.py"' in block
        assert '"warden/causal_arbiter.py"' not in block.split("also_copy")[0]
