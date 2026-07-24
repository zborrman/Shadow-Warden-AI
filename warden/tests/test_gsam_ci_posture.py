"""GSAM PR 7 — CI governance posture section (GSAM-07)."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SCAN_PATH = Path(__file__).resolve().parents[2] / "scripts" / "warden_github_scan.py"


@pytest.fixture(scope="module")
def scan_mod():
    spec = importlib.util.spec_from_file_location("warden_github_scan", _SCAN_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules["warden_github_scan"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_posture_clean(scan_mod) -> None:
    section = scan_mod.gsam_posture_section([{"verdict": "ALLOW"}])
    assert "GSAM Governance Posture" in section
    assert "1.00" in section
    assert "🟢" in section


def test_posture_block_penalised(scan_mod) -> None:
    section = scan_mod.gsam_posture_section([{"verdict": "BLOCK"}])
    assert "cost_spike_no_value" in section
    assert "🟡" in section


def test_posture_critical_on_cooccurrence(scan_mod) -> None:
    results = [
        {"verdict": "BLOCK"},
        {"verdict": "HIGH", "secrets_found": ["aws_key"]},
        {"verdict": "HIGH"},
    ]
    section = scan_mod.gsam_posture_section(results)
    assert "CRITICAL" in section
    assert "🔴" in section


def test_posture_empty_results(scan_mod) -> None:
    section = scan_mod.gsam_posture_section([])
    # No findings → clean posture, still renders a section
    assert "GSAM Governance Posture" in section
    assert "1.00" in section
