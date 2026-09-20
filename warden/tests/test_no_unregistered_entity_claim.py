"""
warden/tests/test_no_unregistered_entity_claim.py

No company is registered. Incorporation is planned once the service is fully
live — so until then, every sentence in this repository that names a limited
company, or claims a registration with a supervisory authority, is describing
something that does not exist.

Three did, and they were not throwaway lines:

  * `legal/DPA.md` opened "Between: Shadow Warden AI Ltd. (Data Processor)" —
    a data processing agreement, offered to customers, naming a party with no
    capacity to sign it.
  * `legal/RoPA.md` stated the organisation as a limited company and claimed
    registration with the UK Information Commissioner's Office against a
    placeholder number, `[ICO-REG-NUMBER]`.
  * `legal/SOC2_Roadmap.md` carried the same organisation line.

A regulator registration is the kind of claim a buyer's compliance review checks
first, and the one that is worst to be wrong about.

**Delete this file when the company is registered** — and when you do, put the
real entity name and the real registration number in the documents above rather
than the brackets they used to hold.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]

# Asserting a corporate form for *this* project. Third parties (Hetzner Online
# GmbH, Stripe, Inc.) are other people's real companies; masking regexes and
# test fixtures name companies that are deliberately invented.
_ENTITY = re.compile(r"Shadow[- ]Warden[- ]?AI\s+(?:Ltd\.?|Limited|LLC|Inc\.?|GmbH|OÜ|B\.V\.)", re.I)
_REGULATOR = re.compile(r"registered with .{0,40}(?:ICO|Information Commissioner|supervisory authority)", re.I)

_SKIP_DIRS = ("landing/", "node_modules/", "site/dist/")


def _tracked() -> list[str]:
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "ls-files"], cwd=_REPO, capture_output=True, text=True, timeout=120
    )
    if out.returncode != 0:  # pragma: no cover - not a git checkout
        pytest.skip("not a git checkout")
    return out.stdout.splitlines()


def _scan(pattern: re.Pattern[str]) -> dict[str, str]:
    hits: dict[str, str] = {}
    for rel in _tracked():
        if rel.startswith(_SKIP_DIRS) or rel == "warden/tests/test_no_unregistered_entity_claim.py":
            continue
        try:
            text = (_REPO / rel).read_text(encoding="utf-8", errors="ignore")
        except OSError:  # pragma: no cover - unreadable file
            continue
        m = pattern.search(text)
        if m:
            hits[rel] = m.group(0)
    return hits


def test_nothing_claims_a_company_that_does_not_exist():
    hits = _scan(_ENTITY)
    assert not hits, (
        "no company is registered, but these name one: "
        + "; ".join(f"{k} → {v!r}" for k, v in sorted(hits.items()))
    )


def test_nothing_claims_a_regulator_registration():
    hits = _scan(_REGULATOR)
    assert not hits, (
        "a supervisory-authority registration is claimed and none exists: "
        + "; ".join(f"{k} → {v!r}" for k, v in sorted(hits.items()))
    )


def test_the_dpa_says_it_cannot_be_executed_yet():
    """A DPA that reads as a live agreement is worse than one that says it is a
    template: a customer could sign it and believe they had a processor."""
    dpa = (_REPO / "legal" / "DPA.md").read_text(encoding="utf-8")
    assert "cannot be executed yet" in dpa, (
        "legal/DPA.md no longer says it is unexecutable — if an entity now "
        "exists, delete this test file rather than the sentence"
    )
