"""
warden/tests/test_site_route_collisions.py

Two Astro sources cannot claim the same URL — one of them wins silently.

`site/src/pages/doc.astro` is 936 lines of real documentation: the fairness
algorithm, the bias-guard section, the radar-chart metric table. It renders
**nowhere**. It collides with `site/src/pages/doc/index.astro` (61 lines, a hub
of six cards) on `/doc/`, the hub is what ships, and no built page in
`landing/` contains `bias-guard` or `avg_candidates_evaluated` at all.

Nothing failed. The build is green, the page exists, the file is tracked, and
an editor changing it sees their edit merge and never appear — which is exactly
what happened to the doc-table edit in #325.

This is the same shape as the ghost-schema work in `test_no_ghost_table.py`:
a thing that looks live, reads plausibly, and is wired to nothing. The
difference is that a route collision is decidable from the filesystem alone, so
it does not need a baseline — it needs to be impossible.

Astro's own rule (and Next.js's, and SvelteKit's): `foo.astro` and
`foo/index.astro` both resolve to `/foo/`. Pick one.
"""
from __future__ import annotations

from pathlib import Path

import pytest

_PAGES = Path(__file__).resolve().parents[2] / "site" / "src" / "pages"
_PAGE_SUFFIXES = {".astro", ".md", ".mdx", ".html"}


def _route_of(path: Path) -> str:
    """The URL an Astro page file resolves to, normalised to a trailing slash."""
    rel = path.relative_to(_PAGES).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "index":
        parts.pop()
    return "/" + "/".join(parts) + ("/" if parts else "")


def _page_files() -> list[Path]:
    return [
        p for p in _PAGES.rglob("*")
        if p.is_file() and p.suffix in _PAGE_SUFFIXES
        # `[slug].astro` and friends are dynamic and can legitimately overlap a
        # static sibling — Astro resolves static-wins, which is intended.
        and "[" not in p.name
    ]


@pytest.mark.skipif(not _PAGES.is_dir(), reason="site/ not present in this checkout")
def test_no_two_pages_claim_the_same_route():
    routes: dict[str, list[str]] = {}
    for page in _page_files():
        routes.setdefault(_route_of(page), []).append(
            str(page.relative_to(_PAGES)).replace("\\", "/")
        )

    collisions = {r: sorted(f) for r, f in routes.items() if len(f) > 1}
    assert not collisions, (
        "two page sources resolve to the same URL — one of them is dead and "
        "edits to it will merge and never appear:\n"
        + "\n".join(
            f"  {route}  <-  {', '.join(files)}" for route, files in sorted(collisions.items())
        )
        + "\n\nKeep one. If the larger file is the one that should ship, give it "
          "its own route and link it from the hub; if it is obsolete, delete it. "
          "Leaving both is how site/src/pages/doc.astro came to hold 936 lines "
          "that no visitor has ever seen."
    )


@pytest.mark.skipif(not _PAGES.is_dir(), reason="site/ not present in this checkout")
def test_the_guard_can_actually_see_a_collision(tmp_path, monkeypatch):
    """A guard that cannot fail is not a guard.

    Point `_PAGES` at a fixture that *does* collide and confirm the detector
    reports it — otherwise a refactor of `_route_of` could silently turn this
    file into a pair of always-green assertions.
    """
    pages = tmp_path / "pages"
    (pages / "doc").mkdir(parents=True)
    (pages / "doc.astro").write_text("---\n---\n<p>a</p>\n", encoding="utf-8")
    (pages / "doc" / "index.astro").write_text("---\n---\n<p>b</p>\n", encoding="utf-8")
    (pages / "about.astro").write_text("---\n---\n<p>c</p>\n", encoding="utf-8")

    monkeypatch.setattr("warden.tests.test_site_route_collisions._PAGES", pages)

    routes: dict[str, list[str]] = {}
    for page in _page_files():
        routes.setdefault(_route_of(page), []).append(page.name)

    assert sorted(routes["/doc/"]) == ["doc.astro", "index.astro"]
    assert routes["/about/"] == ["about.astro"], "a non-colliding page must stay singular"
