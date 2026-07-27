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
