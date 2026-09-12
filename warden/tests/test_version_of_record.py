"""
warden/tests/test_version_of_record.py
──────────────────────────────────────
P-1 ratchet: the product has exactly one version, and everything agrees on it.

Before this test there were three answers at the same commit:

    pyproject.toml          version = "5.3.0"
    warden/__init__.py      __version__ = "5.6.0"
    README / CLAUDE / ROADMAP / PLAN / Rule / TODO.list    7.7

So the built wheel, the importable package and the shipped product each claimed
something different. Anything keyed on the package version — SBOM entries, SLSA
provenance, support tickets, CVE correlation against a published advisory — was
answering with a number two majors behind reality.

`warden/__init__.py::__version__` is now the source of truth; `pyproject.toml`
reads it dynamically. This test pins the documentation surfaces to it.

Scope note: only *declared product-version headers* are checked — the
"**Version:** X" / "Version X" banner near the top of each document. Historical
release notes ("What's New in v7.6"), per-feature version tags ("SAC (FE-52,
v7.8)") and changelog entries are deliberately NOT matched: they describe
history and individual features, not the current product version.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]


def _source_of_truth() -> str:
    """Read __version__ without importing the package (no heavy deps at test time)."""
    text = (_REPO / "warden" / "__init__.py").read_text(encoding="utf-8")
    m = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', text, re.M)
    assert m, "warden/__init__.py no longer declares __version__"
    return m.group(1)


# Each entry: (path, regex with one capture group holding the declared version).
_DECLARED_IN = [
    ("README.md", r"^\*\*Version:\*\*\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    ("CLAUDE.md", r"^\*\*Version:\*\*\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    ("ROADMAP.md", r"^\*\*Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s"),
    ("PLAN.md", r"^\*\*Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s"),
    ("Rule.md", r"^>\s*\*\*Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s"),
    ("TODO.list", r"Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s*·"),
    ("PROGRAM.md", r"^\*\*Version:\*\*\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"),
    ("STRATEGY.md", r"^\*\*Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s"),
    ("CONTRIBUTING.md", r"^\*\*Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s"),
    ("Skill.md", r"^\*\*Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s"),
]


def _major_minor(v: str) -> str:
    parts = v.split(".")
    return f"{parts[0]}.{parts[1]}"


def test_pyproject_reads_the_source_of_truth():
    """pyproject must not carry its own hardcoded copy of the version."""
    data = tomllib.loads((_REPO / "pyproject.toml").read_text(encoding="utf-8"))
    project = data["project"]

    assert "version" not in project, (
        "pyproject.toml declares a static `version` again. That is the field that "
        "drifted to 5.3.0 while the product shipped 7.7. Use "
        '`dynamic = ["version"]` + `[tool.setuptools.dynamic] version = '
        '{ attr = "warden.__version__" }`.'
    )
    assert "version" in project.get("dynamic", []), (
        'pyproject.toml must list "version" in `dynamic`'
    )
    attr = data["tool"]["setuptools"]["dynamic"]["version"]["attr"]
    assert attr == "warden.__version__", (
        f"pyproject reads the version from `{attr}`, expected `warden.__version__`"
    )


@pytest.mark.parametrize("relpath,pattern", _DECLARED_IN, ids=[p for p, _ in _DECLARED_IN])
def test_documents_declare_the_same_version(relpath: str, pattern: str):
    truth = _source_of_truth()
    path = _REPO / relpath
    if not path.exists():
        pytest.skip(f"{relpath} not present in this checkout")

    m = re.search(pattern, path.read_text(encoding="utf-8"), re.M)
    assert m, (
        f"{relpath} no longer carries a recognisable product-version header. Either "
        f"restore it or update the pattern in {Path(__file__).name}."
    )
    declared = m.group(1)
    assert _major_minor(declared) == _major_minor(truth), (
        f"{relpath} declares version {declared}, but warden/__init__.py says {truth}. "
        "One product, one version — update whichever is stale."
    )


def test_version_is_pep440_and_not_a_placeholder():
    v = _source_of_truth()
    assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", v), (
        f"__version__ = {v!r} — expected a three-part release version"
    )
    assert not v.startswith("0."), "0.x reads as pre-release for a product that is in production"


def test_no_orphan_root_openapi_spec():
    """The repo root must not carry a hand-committed ``openapi.json``.

    The live gateway serves ``/openapi.json`` dynamically and
    ``scripts/export_openapi.py`` writes the published copy to
    ``site/public/openapi.json``. A third copy at the repo root has no generator,
    so it silently rots — it last shipped 562 paths at ``info.version`` 5.6.0
    while the product moved four majors on. If it comes back, delete it or wire a
    generator + a version check.
    """
    orphan = _REPO / "openapi.json"
    assert not orphan.exists(), (
        "openapi.json is back at the repo root. It has no generator and drifts "
        "silently — the published spec lives at site/public/openapi.json."
    )


# ── The published site ───────────────────────────────────────────────────────
#
# `_DECLARED_IN` above covers the root markdown documents, and stopped there.
# The site was never in the guard's surface list, so on 2026-09-12 eleven
# stamps across seven files still read `v6.8` while the product shipped 7.9.0 —
# a full major version behind, on the pages a buyer reads first, with
# `562 endpoints` and `11 services` beside them. The version was retyped in
# roughly two dozen places, so bumping it was a find-and-replace nobody ran.
#
# `site/src/data/product.ts` is now the site's single copy. These two tests
# hold it to the version of record and stop a second copy appearing.

_SITE_PRODUCT_TS = "site/src/data/product.ts"

# Files whose job is to name *past* versions. History is allowed to say `v6.8`.
_SITE_HISTORY = {
    "site/src/data/roadmap.json",          # per-feature "shipped in" version
    "site/src/components/WhatsNew.astro",  # changelog cards
    "site/src/pages/doc/changelog.astro",  # the changelog itself
    "site/src/pages/roadmap.astro",        # roadmap rows carry a ship version
}


def test_site_product_file_matches_the_version_of_record():
    truth = _source_of_truth()
    path = _REPO / _SITE_PRODUCT_TS
    if not path.exists():
        pytest.skip(f"{_SITE_PRODUCT_TS} not present in this checkout")
    text = path.read_text(encoding="utf-8")

    m = re.search(r'version:\s*"([^"]+)"', text)
    assert m, f"{_SITE_PRODUCT_TS} no longer declares `version`"
    assert m.group(1) == truth, (
        f"{_SITE_PRODUCT_TS} says {m.group(1)}, warden/__init__.py says {truth}. "
        "Bumping the product means changing both."
    )

    d = re.search(r'display:\s*"([^"]+)"', text)
    assert d, f"{_SITE_PRODUCT_TS} no longer declares `display`"
    assert d.group(1) == "v" + _major_minor(truth), (
        f"`display` is {d.group(1)}, expected v{_major_minor(truth)}"
    )


def test_no_second_copy_of_the_version_on_the_site():
    """Every site surface reads the version from PRODUCT, never retypes it.

    A hardcoded stamp is how the site fell a major version behind: it was
    correct on the day it was typed and nothing ever revisited it. Import
    `PRODUCT` from `src/data/product` instead — that is the one place a bump
    has to touch.
    """
    truth = _source_of_truth()
    site_src = _REPO / "site" / "src"
    if not site_src.exists():
        pytest.skip("site/src not present in this checkout")

    needles = (f"v{_major_minor(truth)}", truth)
    offenders: list[str] = []
    for path in sorted(site_src.rglob("*")):
        if not path.is_file() or path.suffix not in {".astro", ".ts", ".js", ".json", ".md"}:
            continue
        rel = path.relative_to(_REPO).as_posix()
        if rel == _SITE_PRODUCT_TS or rel in _SITE_HISTORY:
            continue
        text = path.read_text(encoding="utf-8")
        for needle in needles:
            if needle in text:
                offenders.append(f"{rel} (contains {needle!r})")
                break

    assert not offenders, (
        "These site files hardcode the current product version instead of "
        "importing PRODUCT from src/data/product:\n  " + "\n  ".join(offenders)
    )
