"""
warden/tests/test_site_marketplace_storefront.py — R3.

`/marketplace` was a 301 to `/agentic`: the M2M marketplace, the product this
platform is built around, had no public surface at all. The storefront that
replaces it publishes listings, agents and the protocol manifest.

These tests pin the property that matters, which is not layout: **the page shows
what the gateway said, or it says it could not read it.** The site has already
published fabricated agent counts from an unreachable API once, and the SOC
dashboard did the same on five pages. A storefront is exactly where that
recurs — an empty market looks better with an illustrative number in it.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_SRC = _ROOT / "site" / "src" / "pages" / "marketplace.astro"
_BUILT = [_ROOT / "site" / "dist" / "marketplace" / "index.html",
          _ROOT / "landing" / "marketplace" / "index.html"]

#: The four figures the page reports. None may be present in the shipped HTML.
_STAT_IDS = ("st-listings", "st-agents", "st-trades", "st-vol")


def _source() -> str:
    if not _SRC.is_file():
        pytest.skip("site/src not present in this checkout")
    return _SRC.read_text(encoding="utf-8")


def _built_pages() -> list[tuple[str, str]]:
    """Every built copy of the page, not just the first one found.

    `landing/` is what the apex serves and `site/dist/` is what Vercel builds;
    returning the first match meant a figure baked into the published `landing/`
    copy passed unnoticed — found by baking one in and watching this file stay
    green.
    """
    out = [(str(p.relative_to(_ROOT)), p.read_text(encoding="utf-8"))
           for p in _BUILT if p.is_file()]
    if not out:
        pytest.skip("no built marketplace page in this checkout")
    return out


def test_marketplace_is_a_page_not_a_redirect():
    src = _source()
    assert "Astro.redirect" not in src, "/marketplace is a redirect again"
    for where, html in _built_pages():
        assert 'http-equiv="refresh"' not in html, where
        assert "id=\"listings-body\"" in html, f"{where} has no listings table"


def test_no_figure_is_baked_into_the_shipped_page():
    """Every number must arrive from the gateway at view time, never from the build.

    A figure baked at build time is a measurement of whatever the API was doing
    in CI, presented to a reader as now.
    """
    for where, html in _built_pages():
        for stat in _STAT_IDS:
            m = re.search(rf'id="{stat}"[^>]*>([^<]*)<', html)
            assert m, f"{stat} is missing from {where}"
            value = m.group(1).strip()
            assert not re.search(r"\d", value), (
                f"{where}: {stat} ships with {value!r} — a number rendered at build time"
            )


def test_every_figure_comes_from_a_named_endpoint():
    src = _source()
    for path in ("/marketplace/analytics/summary", "/marketplace/listings",
                 "/marketplace/agents", "/marketplace/protocol"):
        assert path in src, f"the page never reads {path}"
    assert "/v1" in src, "the page must address the versioned surface"


def test_a_failed_read_says_so_instead_of_showing_zero():
    """The failure path is the one that produced fabricated numbers before."""
    src = _source()
    assert "did not answer" in src, "no message for a gateway that does not answer"
    assert "Could not read the catalogue" in src
    assert "Could not read the directory" in src
    # On failure the figures are cleared to the placeholder, not left or zeroed.
    assert re.search(r"forEach\(id => txt\(id, '—'\)\)", src), (
        "a failed summary read must clear the figures, not leave a stale or zero value"
    )


def test_the_settlement_mode_is_reported_not_asserted():
    """The page may not state a settlement posture the gateway did not give it."""
    for where, html in _built_pages():
      # Searched across the whole document, not a slice of it: the layout emits
    # scripts into <head>, so "everything before the first <script>" is the head
    # alone — a split that made this assertion pass without reading the page.
      for claim in ("Settlement: onchain", "Settlement: simulated",
                    "settles on-chain", "escrow-backed"):
          assert claim not in html, f"{where} asserts {claim!r} rather than reporting it"
      assert "Settlement: checking…" in html, f"{where}: no placeholder before the read"


def test_the_empty_market_is_described_as_empty():
    src = _source()
    assert "No listings yet" in src
    assert "No agents registered yet" in src
