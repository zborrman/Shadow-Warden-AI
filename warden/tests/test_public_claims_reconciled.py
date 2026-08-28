"""
warden/tests/test_public_claims_reconciled.py — P0.

The capability matrix's last open exit criterion is "every public claim
reconciled against it". The matrix has always *named* the claims to remove; what
it never had was anything that made the removal stick.

The proof of that: `"SOC 2 compliant"` was struck from `AuthModal.astro` and
survived, untouched, on `portal/src/app/register/` — a signup CTA asserting a
certification with no audit, no auditor and no report behind it. The fix went to
the file someone remembered rather than to every surface carrying the claim, and
nothing noticed for months. `"Sub-3ms decision time"` survived the same way in
`FeaturesGrid.astro`, for a latency nothing instruments.

So this test does not hold a list of banned phrases. A list here would be a
second copy of the vocabulary in `docs/capability-matrix.md`, and two copies of
a vocabulary in this repo have a habit of disagreeing — the marketplace asset
enum was written out twice and the manifest advertised a type `register_asset`
rejected with a 422. The matrix owns the words; this file only enforces them.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_MATRIX = _ROOT / "docs" / "capability-matrix.md"

#: Everything a visitor can read. `landing/` is the committed build artefact
#: that serves the apex domain, so it is a published surface in its own right
#: and not merely a copy of `site/`.
_SURFACES = ("site/src", "landing", "portal/src", "dashboard/src")

_SUFFIXES = {".astro", ".html", ".tsx", ".ts", ".jsx", ".js", ".md", ".mdx", ".svelte", ".vue"}

#: Generated or vendored trees: not authored copy, and huge.
_SKIP_PARTS = {"node_modules", ".next", "dist", ".astro", "__pycache__", ".git"}


def _banned() -> list[str]:
    """The phrases, read out of the matrix's ```banned-claims``` fence."""
    body = _MATRIX.read_text(encoding="utf-8")
    m = re.search(r"```banned-claims\n(.*?)```", body, re.S)
    assert m, (
        "docs/capability-matrix.md has no ```banned-claims``` block. It is the "
        "single source for this test; without it nothing is enforced."
    )
    out = []
    for line in m.group(1).splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def _files():
    for surface in _SURFACES:
        root = _ROOT / surface
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if p.suffix.lower() not in _SUFFIXES:
                continue
            if _SKIP_PARTS & set(p.parts):
                continue
            yield p


class TestTheMatrixOwnsTheWords:
    def test_the_block_exists_and_is_not_empty(self):
        """An empty list would make every assertion below vacuously true."""
        phrases = _banned()
        assert len(phrases) >= 5, f"only {len(phrases)} banned phrases — is the block truncated?"

    def test_no_duplicate_phrases(self):
        phrases = [p.lower() for p in _banned()]
        assert len(phrases) == len(set(phrases))


class TestNoPublishedSurfaceMakesABannedClaim:
    @pytest.mark.parametrize("phrase", _banned())
    def test_phrase_is_absent_everywhere(self, phrase: str):
        """Every surface, not the one that comes to mind.

        The failure this replaces was not "nobody looked" — someone did look,
        fixed the file they were looking at, and the claim went on being served
        from the other one.
        """
        needle = phrase.lower()
        hits = []
        for p in _files():
            try:
                body = p.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for n, line in enumerate(body.splitlines(), 1):
                if needle in line.lower():
                    hits.append(f"{p.relative_to(_ROOT).as_posix()}:{n}")

        assert not hits, (
            f"{phrase!r} is banned by docs/capability-matrix.md but appears at: "
            + ", ".join(hits[:8])
        )


class TestTheTwoThatWereActuallyFound:
    """Named explicitly, because a parametrised suite going green says nothing
    about whether it ever went red. These are the surfaces that carried the
    claims on 2026-08-28."""

    def test_the_signup_cta_claims_no_certification(self):
        p = _ROOT / "portal" / "src" / "app" / "register" / "page.tsx"
        if not p.exists():
            pytest.skip("portal register page not present")
        body = p.read_text(encoding="utf-8").lower()
        assert "soc 2 compliant" not in body
        assert "iso 27001 ready" not in body

    def test_the_causal_arbiter_quotes_no_latency(self):
        p = _ROOT / "site" / "src" / "components" / "FeaturesGrid.astro"
        if not p.exists():
            pytest.skip("FeaturesGrid not present")
        body = p.read_text(encoding="utf-8").lower()
        assert "sub-3ms" not in body, "a latency claim nothing instruments"
