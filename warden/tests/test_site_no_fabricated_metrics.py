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


@pytest.fixture(scope="module")
def agentic() -> str:
    if not _AGENTIC.exists():
        pytest.skip("site/ not present in this checkout")
    return _AGENTIC.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def frontmatter(agentic: str) -> str:
    """Everything between the opening and closing `---` — runs at build time."""
    parts = agentic.split("---", 2)
    assert len(parts) >= 3, "agentic.astro has no frontmatter fence"
    return parts[1]


def test_marketplace_totals_start_at_zero(frontmatter: str) -> None:
    """The four numbers that were published as fact during an outage."""
    match = re.search(r"summaryStats\s*=\s*\{([^}]*)\}", frontmatter)
    assert match, "summaryStats is gone or reshaped — re-check this guard"

    invented = [
        (key, value)
        for key, value in re.findall(r"(\w+)\s*:\s*([0-9_.]+)", match.group(1))
        if float(value.replace("_", "")) != 0
    ]
    assert not invented, (
        "The marketplace stat bar starts at a non-zero number, which is what "
        "the page publishes whenever the API cannot be reached: "
        + ", ".join(f"{k}={v}" for k, v in invented)
        + ". There are zero registered users and zero settled trades; a number "
        "nobody measures reads zero."
    )


def test_the_page_does_not_fetch_at_build_time(frontmatter: str) -> None:
    """
    A committed `landing/` plus a freshness check plus a build-time fetch of
    live data cannot all three hold. The client fetch after load can.
    """
    assert "fetch(" not in frontmatter, (
        "agentic.astro fetches at build time again. `landing/` is committed and "
        "ci.yml requires it to equal a fresh build, so this makes the published "
        "artefact depend on what the API returned during that build — red on an "
        "outage today, permanently red once the marketplace has real activity. "
        "Fetch from the client instead (see refreshStats / refreshTrades)."
    )


def test_the_trade_log_starts_empty(frontmatter: str) -> None:
    assert re.search(r"recentTrades[^=]*=\s*\[\s*\]", frontmatter), (
        "The recent-trades table must start empty and render its empty state. "
        "Seeding it with invented trades publishes settled transactions that "
        "never happened."
    )


def test_invented_sections_are_labelled_as_samples(agentic: str) -> None:
    """
    The agent directory, tool catalog, auction cards and analytics charts all
    render invented data. That is allowed — showing the shape of an empty
    product is legitimate — but only while it says so on the page.
    """
    seeded_sections = {
        "SEED_AGENTS": "Agent Directory",
        "SEED_TOOLS": "L402-Priced MCP Tools",
        "SEED_AUCTIONS": "Active Sealed-Bid Auctions",
    }
    missing = [
        f"{const} ({heading!r})"
        for const, heading in seeded_sections.items()
        if const in agentic
        and not re.search(re.escape(heading) + r'[^\n]*sample-badge', agentic)
    ]
    assert not missing, (
        "These sections render invented data without a 'Sample data' badge on "
        "their heading: " + ", ".join(missing)
    )

    assert agentic.count("sample-note") >= 4, (
        "Each section built from SEED_* data needs its note explaining what is "
        "invented — a badge alone is easy to scroll past once the table under "
        "it looks authoritative."
    )
