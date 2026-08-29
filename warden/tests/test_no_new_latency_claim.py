"""
warden/tests/test_no_new_latency_claim.py — the matrix's latency ruling, in every
notation it is written in.

`docs/capability-matrix.md` has ruled on this since 2026-08-28:

    Sub-1ms / sub-2ms / sub-3ms stage latency (19 occurrences across the site)
    | UNMEASURED | No `/filter` latency histogram exists in production. The only
    duration metric scraped is `warden_arq_job_duration_seconds`. There is no
    instrument behind the number. | Instrument first, then publish

`test_public_claims_reconciled.py` enforces that ruling from the matrix's
``banned-claims`` fence, which lists the phrases someone wrote down:
``sub-1ms``, ``sub-2ms``, ``sub-3ms``. The site does not write them that way.
It writes ``<2ms``, ``<8ms``, ``in under 2ms``, ``P99 < 50ms`` — the same claim
in the notation a designer reaches for — and the guard passed over all of it.
The matrix counted 19 occurrences; counting both notations finds three times
that, on the pages a customer actually reads.

This is the repository's recurring shape, and the reason this file is a
*separate* guard rather than three more lines in the fence: a list of phrases
catches the spelling that was fixed, not the claim that was made. Here the
pattern is the claim — a number of milliseconds offered as a bound — so a new
component cannot introduce one by picking different punctuation.

Why a ratchet and not a ban: the existing sites are copy on live marketing
pages, several of them design elements (a per-stage badge in the pipeline
diagram) whose removal is a visual decision, not a mechanical edit. Freezing the
count stops the claim spreading today and leaves the drain to follow-on work.
Instrument the pipeline and the numbers become publishable — that is the exit,
and it is the matrix's own.

Regenerate after a genuine reduction (an increase fails before it can write):

    UPDATE_LATENCY_CLAIM_BASELINE=1 pytest warden/tests/test_no_new_latency_claim.py
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_BASELINE = Path(__file__).with_suffix(".baseline.json")

#: Everything a visitor can read, matching test_public_claims_reconciled.py.
#: `landing/` is the committed build artefact serving the apex, so a claim that
#: survives there is published even if `site/src` has been cleaned.
_SURFACES = ("site/src", "landing", "portal/src", "dashboard/src", "docs")

_SUFFIXES = {".astro", ".html", ".tsx", ".ts", ".jsx", ".js", ".md", ".mdx", ".json", ".svelte", ".vue"}

_SKIP_PARTS = {"node_modules", ".next", "dist", ".astro", "__pycache__", ".git"}

#: The registers whose job is to *discuss* the claim — the matrix records what it
#: is and what to do about it, the programme records that the work happened.
_CLAIM_REGISTERS = {"capability-matrix.md", "launch-program.md"}

#: A duration offered as a bound on how long something takes. Covers the spelled
#: form the matrix listed (`sub-2ms`), the symbolic form the site actually uses
#: (`<2ms`, `< 2 ms`), the prose form (`in under 2ms`), and the SLA form
#: (`P99 < 50ms`). Deliberately not anchored to a specific number: the defect is
#: publishing a latency at all, not publishing a particular one.
_CLAIM = re.compile(
    r"""(
        sub-\s*\d+\s*ms          # sub-2ms
      | <\s*\d+\s*ms             # <2ms, < 2 ms
      | &lt;\s*\d+\s*ms          # HTML-escaped, as built pages carry it
      | under\s+\d+\s*ms         # in under 2ms
      | p99\s*[<≤]\s*\d+\s*ms    # P99 < 50ms
    )""",
    re.X | re.I,
)


def _files():
    for surface in _SURFACES:
        root = _ROOT / surface
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.suffix.lower() not in _SUFFIXES:
                continue
            if _SKIP_PARTS & set(path.parts):
                continue
            if path.name in _CLAIM_REGISTERS:
                continue
            yield path


def _scan() -> dict[str, int]:
    """Published surface → number of latency claims in it."""
    counts: dict[str, int] = {}
    for path in _files():
        try:
            body = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        hits = len(_CLAIM.findall(body))
        if hits:
            counts[path.relative_to(_ROOT).as_posix()] = hits
    return counts


def _load_baseline() -> dict[str, int]:
    if not _BASELINE.exists():
        return {}
    return json.loads(_BASELINE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def counts() -> dict[str, int]:
    return _scan()


def test_the_pattern_still_matches_the_notations_it_was_written_for():
    """A guard that stops matching is a guard that stops guarding."""
    for sample in ("sub-2ms", "<2ms", "< 8 ms", "&lt;3ms", "in under 2ms", "P99 < 50ms"):
        assert _CLAIM.search(sample), f"{sample!r} no longer reads as a latency claim"
    for benign in ("2ms", "milliseconds", "sub-second", "<2 seconds", "P99"):
        assert not _CLAIM.search(benign), f"{benign!r} should not count as a claim"


def test_no_new_latency_claim(counts):
    baseline = _load_baseline()

    if os.getenv("UPDATE_LATENCY_CLAIM_BASELINE") == "1":
        total_now = sum(counts.values())
        total_was = sum(baseline.values())
        assert total_now <= total_was or not baseline, (
            f"refusing to write a larger baseline ({total_was} → {total_now}). "
            "Remove the claim instead."
        )
        _BASELINE.write_text(
            json.dumps(dict(sorted(counts.items())), indent=2) + "\n", encoding="utf-8"
        )
        pytest.skip(f"baseline rewritten: {total_now} claims")

    assert baseline, (
        "no committed baseline — run "
        "UPDATE_LATENCY_CLAIM_BASELINE=1 pytest warden/tests/test_no_new_latency_claim.py"
    )

    regressions = {
        path: (count, baseline.get(path, 0))
        for path, count in counts.items()
        if count > baseline.get(path, 0)
    }
    assert not regressions, (
        "new latency claims — the matrix rules these UNMEASURED "
        "(no /filter histogram exists in production; instrument first, then publish):\n"
        + "\n".join(f"  {p}: {now} (baseline {was})" for p, (now, was) in sorted(regressions.items()))
    )


def test_the_total_only_falls(counts):
    baseline = _load_baseline()
    if not baseline:
        pytest.skip("no baseline yet")
    total_now, total_was = sum(counts.values()), sum(baseline.values())
    assert total_now <= total_was, (
        f"{total_now} latency claims published, baseline {total_was}. "
        "Regenerate only after a genuine reduction."
    )


def test_the_matrix_still_rules_this_unmeasured():
    """
    If someone instruments the pipeline and the matrix changes its verdict, this
    guard should be retired deliberately — not left enforcing a stale ruling.
    """
    matrix = (_ROOT / "docs" / "capability-matrix.md").read_text(encoding="utf-8")
    row = next((line for line in matrix.splitlines() if "stage latency" in line.lower()), None)
    assert row, "the matrix no longer has a stage-latency row — re-check this guard"
    assert "UNMEASURED" in row, (
        "the matrix no longer rules stage latency UNMEASURED. If it is now "
        "instrumented, retire this ratchet along with the ruling."
    )
