"""warden/tests/test_site_no_fabricated_metrics.py — the site may not invent usage.

CLAUDE.md §Claims Rule: "Never publish a number nobody measures" and "Never
imply customers, revenue or usage. There are zero registered users."

`site/src/pages/agentic.astro` fetched marketplace stats at build time with a
2.5s timeout, and the *failure* path was four hardcoded constants:

    let summaryStats = { total_volume_usd: 94200.00, total_trades: 18400,
                         registered_agents: 2847, active_listings: 612, ... };

So an unreachable API did not degrade the page — it published those numbers as
fact. On 2026-08-22 that happened: CI built during a production outage, the
fetch timed out, and the page was rebuilt claiming 2,847 registered agents and
$94,200 of volume for a marketplace with zero users and zero settled trades.

Nothing reached the public, and only by luck: the committed `landing/` still
held zeros from a build made while the API was up, and the landing-freshness
check in ci.yml compares the two, so the build went red instead of shipping.

Two things follow, and this file pins both.

1.  A measured number renders zero until something measures it. The fallback
    for "I could not reach the API" is not a plausible-looking number.

2.  The page does not fetch at build time at all. `landing/` is a committed
    artefact that CI rebuilds and requires to match — so a build-time fetch of
    live data makes the published output a function of what the API happened to
    say during that build. It was already nondeterministic across an outage;
    it would break permanently on the first real trade. The client refreshes
    the same numbers after load, which is where live data belongs.

Sample data is still allowed — the agent directory, tool catalog, auction cards
and hero ticker are invented examples of the format. They carry a visible
"Sample data" badge, which is the third thing pinned here.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

_SITE = Path(__file__).resolve().parents[2] / "site" / "src" / "pages"
_AGENTIC = _SITE / "agentic.astro"


def test_the_retired_marketplace_page_publishes_nothing() -> None:
    """
    /agentic was retired on 2026-11-27 (#829): the dashboard broke on load and
    presented SIMULATED gateway features. The guards that pinned its numbers —
    totals starting at zero, an empty trade log, SEED_* sections labelled as
    samples, no build-time fetch — have nothing left to pin. The page is a
    redirect; if a dashboard comes back here, those guards come back with it.
    """
    if not _AGENTIC.exists():
        pytest.skip("site/ not present in this checkout")
    src = _AGENTIC.read_text(encoding="utf-8")
    assert "Astro.redirect(" in src, "agentic.astro is a page again: restore the fabricated-metrics guards"
    for marker in ("summaryStats", "recentTrades", "SEED_", "fetch(", "<BaseLayout"):
        assert marker not in src, f"agentic.astro carries {marker!r} again"


# ── status page ───────────────────────────────────────────────────────────────
#
# The 90-day uptime grid on `status.astro` was drawn from a seeded PRNG. It took
# the single `uptime_90d` figure, converted it to a count of bad days, and
# scattered that many incidents across the calendar — inventing *which* days were
# down. Worse, the figure defaulted: `uptime_90d ?? 100`, and production's
# `/health` does not return the field, so the live page painted ninety solid
# green cells, each tooltipped with a date and the word "Operational".
#
# Three months of perfect uptime history for a service that has never measured a
# day of it — on the one page people open specifically because they want history
# rather than current state.

def _status_page() -> str:
    from pathlib import Path
    p = Path(__file__).resolve().parents[2] / "site" / "src" / "pages" / "status.astro"
    if not p.exists():
        import pytest as _pytest
        _pytest.skip("status.astro not present")
    return p.read_text(encoding="utf-8")


def test_the_uptime_history_is_not_synthesised() -> None:
    """No PRNG anywhere near the availability record."""
    body = _status_page()
    for marker in ("1664525", "1013904223", "rng()"):
        assert marker not in body, (
            "status.astro is generating uptime history with a PRNG (" + marker + ")"
        )


def test_missing_uptime_does_not_default_to_perfect() -> None:
    """`uptime ?? 100` is how absence became a claim of 100.000%."""
    body = _status_page()
    assert "uptime ?? 100" not in body
    assert "uptime_90d ?? 100" not in body


def test_a_day_with_no_data_renders_as_no_data() -> None:
    """Unknown is a state, and on a status page it is the honest one."""
    body = _status_page()
    assert "no data" in body, "cells with no record must say so rather than render green"


# ── The same invented set, everywhere else ────────────────────────────────────
# Everything above pins agentic.astro. The same constants (2,847 communities,
# 18,400 assets, 94,200 cleared trades) were also a stat bar under the homepage
# hero, a stat tile, and the "Based on 94,200 trades across 2,847 communities"
# baseline of the /price ROI estimator — and the homepage carried a line chart
# titled "Average reduction across SMB customers — first 6 months" with invented
# before/after series, beside a section saying there are no customers. None of
# that was in this file's reach. Removed 2026-10-19, before external auditors
# were sent to the site; these keep any page from bringing them back.

_SITE = Path(__file__).resolve().parents[2] / "site" / "src"
_LANDING = Path(__file__).resolve().parents[2] / "landing"

_INVENTED = re.compile(
    r"""2,847(?!,)|\b2847\b(?!\d)|94,200|\b94200\b|18,400\s*(?:Assets|assets)|2,847,391
      | across\s+SMB\s+customers | incidentChart""",
    re.X,
)


def _published_text():
    for root in (_SITE, _LANDING):
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if p.suffix.lower() in {".astro", ".html", ".ts", ".js", ".md", ".json", ".xml"}:
                yield p, p.read_text(encoding="utf-8", errors="ignore")


def test_the_invented_marketplace_numbers_appear_nowhere() -> None:
    hits = []
    for path, text in _published_text():
        for line_no, line in enumerate(text.splitlines(), 1):
            # agentic.astro's comment that tells the story is the one allowed mention
            if line.lstrip().startswith(("//", "*", "#", "<!--")):
                continue
            if _INVENTED.search(line):
                hits.append(f"{path.as_posix()}:{line_no}: {line.strip()[:110]}")
    assert not hits, "invented usage numbers on a public page:\n  " + "\n  ".join(hits[:20])


def test_the_pattern_catches_what_was_removed() -> None:
    for sample in ('<div class="idx-stat-n">2,847</div>', "Based on 94,200 trades",
                   "Average reduction across SMB customers", '<canvas id="incidentChart">'):
        assert _INVENTED.search(sample), sample
