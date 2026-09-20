"""
warden/tests/test_no_dead_contact_domain.py

`shadowwarden.ai` is not this project's domain and never was. The zone is
NXDOMAIN — apex and every subdomain — while the real one is
`shadow-warden-ai.com`, with hyphens. Nothing had ever checked, so the wrong
spelling spread into the places that matter most:

  * `.github/SECURITY.md` — the vulnerability-disclosure address. A researcher
    following it got a bounce.
  * `legal/RoPA.md` and `legal/DPA.md` — the GDPR Art. 30 record named it as the
    channel for *every* data-subject right: access, rectification, erasure,
    restriction, portability, objection.
  * `browser-extension/STORE_LISTING.md` — a Chrome Web Store listing pointing
    at a privacy policy that could not load, plus test credentials for a "live
    demo environment" whose host does not resolve.
  * `warden/billing/*` — `PORTAL_BASE_URL` defaulted to `app.shadowwarden.ai`,
    so every quota-exceeded response offered an upgrade link to nothing. The
    test covering it asserted `"shadowwarden.ai" in url or "shadow" in url`,
    which is a test agreeing with the defect it should have caught.
  * `cloudflare/installer-worker/` — deployed on every push to main, answering
    on a host in a zone nobody owns.

The distinction this test enforces is not cosmetic. A wrong host inside
`shadow-warden-ai.com` is one DNS record away from working; a host in a zone the
project does not own can never work, whatever anyone does.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_DEAD = "shadowwarden.ai"

# Fake member rows in the site's localStorage demos (`ops@`, `dev@`, `soc@`,
# `ci-bot@`). They are invented personas, not contact claims — and pointing them
# at the real domain would make fabricated users look like real accounts, which
# is the worse defect. Left as a recorded decision rather than silently swept in.
_DEMO_PERSONAS = {
    "site/src/pages/settings.astro",
    "site/src/pages/community/view.astro",
    "site/src/components/ConsoleSection.astro",
}


def _tracked_files() -> list[str]:
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "ls-files"], cwd=_REPO, capture_output=True, text=True, timeout=120
    )
    if out.returncode != 0:  # pragma: no cover - not a git checkout
        pytest.skip("not a git checkout")
    return out.stdout.splitlines()


def _offenders() -> dict[str, int]:
    hits: dict[str, int] = {}
    for rel in _tracked_files():
        # `landing/` is generated from `site/` and is rebuilt, never edited.
        if rel.startswith("landing/") or rel in _DEMO_PERSONAS:
            continue
        if rel == "warden/tests/test_no_dead_contact_domain.py":
            continue
        path = _REPO / rel
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:  # pragma: no cover - unreadable file
            continue
        n = text.count(_DEAD)
        if n:
            hits[rel] = n
    return hits


def test_no_file_addresses_a_zone_this_project_does_not_own():
    offenders = _offenders()
    assert not offenders, (
        "these files point at " + _DEAD + ", which is NXDOMAIN and not this "
        "project's zone — use shadow-warden-ai.com: "
        + ", ".join(f"{k} ({v})" for k, v in sorted(offenders.items()))
    )


def test_the_demo_persona_allowlist_still_describes_real_files():
    """An allowlist that names files which no longer exist quietly widens: the
    entry stops excusing anything and nobody notices it went stale."""
    missing = [p for p in _DEMO_PERSONAS if not (_REPO / p).exists()]
    assert not missing, f"allowlisted files are gone, drop them from the list: {missing}"


def test_the_allowlist_is_only_ever_demo_personas():
    """If one of those files gains a *real* contact claim on the dead zone, the
    allowlist would hide it. Only the invented mailboxes may appear there."""
    allowed_local_parts = ("ops@", "dev@", "soc@", "ci-bot@")
    for rel in sorted(_DEMO_PERSONAS):
        text = (_REPO / rel).read_text(encoding="utf-8", errors="ignore")
        for line in text.splitlines():
            if _DEAD not in line:
                continue
            assert any(p + _DEAD in line for p in allowed_local_parts), (
                f"{rel}: a reference to {_DEAD} that is not one of the demo "
                f"personas — {line.strip()[:120]}"
            )
