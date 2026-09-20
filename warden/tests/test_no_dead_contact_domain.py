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

# The allowlist is empty, and that is the point. It used to hold three site
# files carrying invented member rows (`ops@`, `dev@`, ...) on the dead zone.
# Repointing those at the real domain would have made fabricated users look like
# real accounts — the worse defect — so they moved to `example.com`, which RFC
# 2606 reserves precisely so that a placeholder cannot be mistaken for a real
# address. Nothing in the tree needs an exemption any more; an entry appearing
# here again should have to argue for itself.
_DEMO_PERSONAS: set[str] = set()


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


def test_the_allowlist_is_still_empty():
    """An exemption list is the quiet way a ratchet stops holding. Every entry
    added here excuses a whole file, so adding one is a decision that should be
    visible in a diff rather than arrived at while chasing a red test."""
    assert not _DEMO_PERSONAS, (
        "something was exempted from this guard: "
        f"{sorted(_DEMO_PERSONAS)} — fix the file or argue for the entry"
    )


# ── security.txt ─────────────────────────────────────────────────────────────


def test_security_txt_is_published_and_not_expiring():
    """RFC 9116 makes `Expires` mandatory, and a lapsed file is worse than none:
    it reads as a live channel while telling a parser it is stale. This fails
    while there is still time to renew it, not after.

    The file did not exist at all until 2026-09-20 — `/.well-known/security.txt`
    returned the 404 page on both surfaces while `.github/SECURITY.md` named a
    mailbox in a domain this project does not own.
    """
    import datetime as _dt

    txt = _REPO / "site" / "public" / ".well-known" / "security.txt"
    assert txt.exists(), "site/public/.well-known/security.txt is gone"
    body = txt.read_text(encoding="utf-8")

    assert "mailto:security@shadow-warden-ai.com" in body, "no working contact"
    assert _DEAD not in body

    m = [ln for ln in body.splitlines() if ln.startswith("Expires:")]
    assert len(m) == 1, f"RFC 9116 requires exactly one Expires field, found {len(m)}"
    expires = _dt.datetime.fromisoformat(m[0].split(":", 1)[1].strip().replace("Z", "+00:00"))
    left = expires - _dt.datetime.now(_dt.UTC)
    assert left > _dt.timedelta(days=30), (
        f"security.txt expires in {left.days} days — renew the Expires field"
    )
