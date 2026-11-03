"""
The site sold one product under two names: the Trade menu said "Agentic
Commerce" and linked a generated feature list, while the product page and the
API call it the M2M Commerce Store. The menu now names the product page, and
the old URL 308s to it on both surfaces.
"""
from __future__ import annotations

from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_SITE = _ROOT / "site"
_OLD = "/business-community/agentic-commerce"
_NEW = "/business-community/m2m-store"


def _read(rel: str) -> str:
    return (_ROOT / rel).read_text(encoding="utf-8")


def test_menu_names_the_m2m_store_page():
    if not (_SITE / "src/layouts/BaseLayout.astro").exists():
        pytest.skip("site/ not present in this checkout")
    layout = _read("site/src/layouts/BaseLayout.astro")
    assert f"label: 'M2M Commerce Store',  href: '{_NEW}'" in layout
    assert "'Agentic Commerce'" not in layout


def test_old_url_redirects_on_both_surfaces():
    if not (_SITE / "src/pages/business-community/m2m-store.astro").exists():
        pytest.skip("site/ not present in this checkout")
    assert f'"source": "{_OLD}", "destination": "{_NEW}"' in _read("vercel.json")
    assert f"redir {_OLD} {_NEW} 308" in _read("docker/Caddyfile")


def test_no_page_links_the_old_url():
    if not (_SITE / "src").exists():
        pytest.skip("site/ not present in this checkout")
    stale = [str(f.relative_to(_SITE)) for f in (_SITE / "src").rglob("*.astro")
             if _OLD in f.read_text(encoding="utf-8")]
    assert not stale, f"links to the retired URL: {stale}"
