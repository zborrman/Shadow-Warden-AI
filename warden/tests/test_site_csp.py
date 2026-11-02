"""The site's Content-Security-Policy agrees with itself and with the pages it serves.

Two failures this guards, both found 2026-11-02:

- /fraud-score loaded https://cdn.tailwindcss.com, which script-src has blocked
  since 2026-07-22. Every utility class on the page stopped applying and nothing
  reported it for three months.
- The apex (Caddy) policy had fallen behind the www (Vercel) one: no Lemon
  Squeezy script or checkout iframe, no Google Fonts, no api./billing. calls.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "site" / "src"


def _www_csp() -> str:
    vercel = json.loads((_REPO / "vercel.json").read_text(encoding="utf-8"))
    for block in vercel["headers"]:
        for header in block["headers"]:
            if header["key"].lower() == "content-security-policy":
                return header["value"]
    raise AssertionError("vercel.json publishes no Content-Security-Policy")


def _apex_csp() -> str:
    caddy = (_REPO / "docker" / "Caddyfile").read_text(encoding="utf-8")
    block = caddy[caddy.index("shadow-warden-ai.com, www.shadow-warden-ai.com {"):]
    m = re.search(r'header >Content-Security-Policy "([^"]+)"', block)
    assert m, "the landing vhost no longer replaces the CSP - re-check this guard"
    return m.group(1)


def _directive(csp: str, name: str) -> set[str]:
    for part in csp.split(";"):
        tokens = part.split()
        if tokens and tokens[0] == name:
            return set(tokens[1:])
    return set()


def test_apex_and_www_serve_the_same_policy():
    assert _apex_csp() == _www_csp()


def test_every_external_script_a_page_loads_is_allowed():
    allowed = _directive(_www_csp(), "script-src")
    blocked = set()
    for f in _SRC.rglob("*.astro"):
        for host in re.findall(r'<script[^>]+src="(https://[^/"]+)', f.read_text(encoding="utf-8")):
            if host not in allowed:
                blocked.add(f"{f.relative_to(_SRC)}: {host}")
    assert not blocked, f"scripts the CSP refuses to load: {sorted(blocked)}"
