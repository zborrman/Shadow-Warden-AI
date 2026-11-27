"""The accessibility widget's dyslexia font is served by the site itself.

Found by the integrity sweep (2026-11-27): the widget loaded OpenDyslexic from
cdn.jsdelivr.net, which the site CSP (font-src 'self' …) blocks — and the URL
itself was a 404, the package ships no .woff. The dyslexia-font mode did
nothing on any page. The font now lives in site/public/fonts/.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WIDGETS = [ROOT / "site/src/components/AccessibilityWidget.astro", ROOT / "site/src/components/A11yWidget.astro"]


def test_every_widget_font_is_self_hosted_and_present():
    for widget in WIDGETS:
        css = widget.read_text(encoding="utf-8")
        urls = re.findall(r"url\(['\"]?([^'\")]+)['\"]?\)", css)
        fonts = [u for u in urls if re.search(r"\.(otf|ttf|woff2?)$", u)]
        assert fonts, widget.name
        for u in fonts:
            assert u.startswith("/fonts/"), f"{widget.name} loads a font from {u}: CSP font-src is 'self'"
            assert (ROOT / "site/public" / u.lstrip("/")).is_file(), f"{u} is missing from site/public"


def test_the_font_ships_with_its_licence():
    assert (ROOT / "site/public/fonts/OpenDyslexic-LICENSE.txt").is_file()
