"""A figure the page fills from a live API ships with no number of its own.

/business-community rendered "1,240 active members", "8,340 SEP transfers / mo"
and "24,500 published UECIIDs" under "Production data" as static HTML, replaced
only if /api/public/community answered. It did not answer, so every visitor
saw invented traction for a product with zero registered users. The same page
plotted a six-month "Community growth" chart from hard-coded arrays.
"""
from __future__ import annotations

import re
from pathlib import Path

_PAGES = Path(__file__).resolve().parents[2] / "site" / "src" / "pages"


def test_live_stat_slots_start_empty():
    offenders = []
    for f in _PAGES.rglob("*.astro"):
        src = f.read_text(encoding="utf-8")
        if "data-stat" not in src:
            continue
        for val in re.findall(r"\bval:\s*'([^']*)'", src):
            if re.search(r"\d", val):
                offenders.append(f"{f.relative_to(_PAGES)}: {val}")
    assert not offenders, f"static figures in live-stat slots: {offenders}"


def test_no_page_claims_production_data_it_does_not_have():
    hits = [str(f.relative_to(_PAGES)) for f in _PAGES.rglob("*.astro")
            if "Production data" in f.read_text(encoding="utf-8")]
    assert not hits, f"'Production data' label on: {hits}"


def test_the_community_demo_does_not_claim_encryption_it_does_not_do():
    """
    /community/* keeps every community and tunnel message as plaintext JSON in
    localStorage; nothing encrypts or exchanges keys (capability matrix §7,
    SIMULATED). The pages said "End-to-end encrypted · AES-256-GCM · keys
    never leave clients" on every message.
    """
    # E2EE is matched case-sensitively: lower-case e2ee is a CSS class name.
    claims = re.compile(r"AES-256-GCM|\bE2EE\b|(?i:end-to-end encrypted)")
    hits = [f"{f.relative_to(_PAGES)}: {m.group(0)}"
            for f in (_PAGES / "community").rglob("*.astro")
            for m in claims.finditer(f.read_text(encoding="utf-8"))]
    assert not hits, f"encryption claims on the community demo: {hits}"
