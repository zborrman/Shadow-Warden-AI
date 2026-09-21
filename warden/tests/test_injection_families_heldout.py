"""
warden/tests/test_injection_families_heldout.py

The rule engine used to match phrasings, not attacks. Measured 2026-09-21 it
caught 15 of the 58 baseline jailbreaks — and 0 of 28 rewordings of the same
attacks, because "bypass all safety" slipped past a rule written for "bypass
safety" and "ignore the above instructions" past one written for "ignore above".
The injection-family rules in `semantic_guard.py` match the shape of each attack
instead.

`adversarial/heldout_attacks.txt` and `heldout_benign.txt` were written before
those rules and were not used to tune them — with one disclosed exception: after
the first measurement two benign prompts were flagged, and the rules were made
stricter to clear them (one false positive was pre-existing: "developer mode on
my Android phone"). Nothing was loosened to catch a held-out attack.

Now that these files guard against regression they are no longer held out for
the next rule author. Write a fresh set before tuning, and keep the old one here.
"""
from __future__ import annotations

from pathlib import Path

import pytest

_ADV = Path(__file__).resolve().parent / "adversarial"


def _load(name: str) -> list[str]:
    return [
        ln.strip() for ln in (_ADV / name).read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.startswith("#")
    ]


@pytest.fixture(scope="module")
def guard():
    from warden.semantic_guard import SemanticGuard
    return SemanticGuard()


def test_every_heldout_attack_is_caught(guard):
    missed = [p for p in _load("heldout_attacks.txt") if guard.analyse(p).safe_for(strict=False)]
    assert not missed, f"{len(missed)} held-out attacks pass as safe: {missed}"


def test_no_heldout_benign_prompt_is_flagged(guard):
    flagged = [p for p in _load("heldout_benign.txt") if not guard.analyse(p).safe_for(strict=False)]
    assert not flagged, f"{len(flagged)} ordinary prompts flagged: {flagged}"
