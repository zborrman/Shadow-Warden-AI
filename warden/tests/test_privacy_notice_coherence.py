"""
warden/tests/test_privacy_notice_coherence.py

The privacy notice tells data subjects how long request metadata is kept. The
gateway decides how long it is *actually* kept, from
`settings.gdpr_log_retention_days`. Those two numbers live in different
languages, in different directories, and nothing imports one from the other —
the shape that produced every other defect found on 2026-09-20.

A retention period that the software does not honour is not a stale document.
It is a false statement made to a data subject about their own data, in the one
document GDPR Article 13 requires to be accurate.

The notice was written because `/signup` is live and takes an email and a
password, while the site had no privacy notice at all and the footer's "Privacy
Policy" link on all 75 pages pointed at `#`.
"""
from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_PAGE = _REPO / "site" / "src" / "pages" / "privacy.astro"
_LAYOUT = _REPO / "site" / "src" / "layouts" / "BaseLayout.astro"


def _published_retention_days() -> int:
    src = _PAGE.read_text(encoding="utf-8")
    m = re.search(r"const metadataRetentionDays = (\d+);", src)
    assert m, "the notice no longer declares metadataRetentionDays"
    return int(m.group(1))


def test_the_published_retention_is_the_one_the_gateway_enforces():
    from warden.config import settings

    published = _published_retention_days()
    enforced = settings.gdpr_log_retention_days
    assert published == enforced, (
        f"the privacy notice tells data subjects {published} days; the gateway "
        f"deletes at {enforced}. One of them is a false statement about "
        "someone's own data."
    )


def test_the_notice_says_the_number_it_declares():
    """The constant could drift from the prose beside it without the assertion
    above noticing — it reads the constant, not the page."""
    days = _published_retention_days()
    body = _PAGE.read_text(encoding="utf-8")
    assert "{metadataRetentionDays} days" in body, (
        "the retention figure is no longer rendered from the pinned constant, "
        f"so nothing keeps the prose at {days} days"
    )


def test_the_footer_links_to_the_notice_rather_than_nowhere():
    """It pointed at `#` on every page in the site."""
    layout = _LAYOUT.read_text(encoding="utf-8")
    assert "href: '/privacy'" in layout, "the footer no longer links the notice"
    assert "href: '#'" not in layout, "a footer link points at nothing again"


def test_the_footer_does_not_claim_a_certification_we_do_not_hold():
    """docs/capability-matrix.md rates SOC 2 Type II here as SELF-ATTESTED: a
    control mapping and an evidence collector, which is preparation, not a
    certification. The bare badge read as the latter."""
    layout = _LAYOUT.read_text(encoding="utf-8")
    for line in layout.splitlines():
        if "label:" not in line or "SOC" not in line:
            continue
        assert "readiness" in line or "self-attested" in line.lower(), (
            f"a SOC 2 label in the footer states no qualification: {line.strip()}"
        )
