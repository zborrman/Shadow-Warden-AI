"""The portal wears the marketing site's shell (owner request, 2026-11-26).

portal/src/styles/shell.css is a copy of site/src/styles/shell.css and
portal/src/styles/tokens.css carries the site's theme tokens. Two copies drift
unless something compares them; this does.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _decls(css: str, selector: str) -> dict[str, str]:
    start = css.index(selector + " {")
    body = css[start:css.index("\n}", start)]
    return dict(re.findall(r"(--[\w-]+):\s*([^;]+);", body))


def test_the_shell_stylesheet_is_the_sites():
    site = (ROOT / "site/src/styles/shell.css").read_text(encoding="utf-8")
    portal = (ROOT / "portal/src/styles/shell.css").read_text(encoding="utf-8")
    assert portal.replace("\r\n", "\n") == site.replace("\r\n", "\n"), (
        "portal/src/styles/shell.css drifted from the site's - copy it again"
    )


def test_the_theme_tokens_are_the_sites():
    site = (ROOT / "site/src/styles/global.css").read_text(encoding="utf-8")
    portal = (ROOT / "portal/src/styles/tokens.css").read_text(encoding="utf-8")
    for selector in (":root", "html.dark"):
        want = {k: v for k, v in _decls(site, selector).items() if not k.startswith("--color-")}
        got = _decls(portal, selector)
        assert want, selector
        assert got == want, f"{selector}: portal tokens differ from the site's"


def test_every_signed_in_layout_uses_the_shell():
    app = ROOT / "portal/src/app"
    for name in ("dashboard", "api-keys", "settings", "sdk", "preflight", "store/manage"):
        src = (app / name / "layout.tsx").read_text(encoding="utf-8")
        assert "<AppShell>" in src, name
