"""
warden/tests/test_env_no_duplicate_keys.py — shadowed env keys guard.

Docker Compose reads an env file top to bottom and the **last** definition of a
key wins. Earlier ones are discarded with no warning, so the file still reads as
though the first value is the configured one.

Production carried four of these on 2026-08-23. Three were untidy. The fourth
was a live defect: `NVIDIA_API_KEY` was defined three times, the winning value
was 24 characters and answered HTTP 403 — indistinguishable from a bogus
credential — while the real 70-character key sat twelve lines above it, shadowed.
Nemotron had been failing for as long as the duplicate existed and nothing
reported it, because from the file's point of view the key was present.

`.env` itself is gitignored and cannot be checked here. These tests cover what
*is* in the repository — the committed templates people copy — and pin the
behaviour of `scripts/check_env_duplicates.py`, which is the piece that can be
pointed at a live host.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "scripts" / "check_env_duplicates.py"
_TEMPLATES = sorted(_ROOT.glob(".env*.example"))


def _run(path: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(_SCRIPT), str(path), *extra],
        capture_output=True, text=True,
    )


def test_the_guard_script_exists() -> None:
    assert _SCRIPT.is_file(), (
        f"{_SCRIPT} is missing — without it nothing can check a live host's .env, "
        "which is where the defect this guards against actually occurred."
    )


def test_templates_were_found() -> None:
    """A glob that matches nothing would make every check below vacuously pass."""
    assert _TEMPLATES, (
        "no .env*.example templates found — this suite would pass without "
        "checking anything, which is the exact failure mode it exists to prevent"
    )


@pytest.mark.parametrize("template", _TEMPLATES, ids=lambda p: p.name)
def test_committed_template_has_no_shadowed_keys(template: Path) -> None:
    result = _run(template)
    assert result.returncode == 0, (
        f"{template.name} defines the same key more than once with differing "
        f"values. Compose keeps only the last, so anyone copying this template "
        f"inherits a setting that looks configured and is not.\n\n{result.stdout}"
    )


def test_script_flags_a_shadowed_key(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("API_KEY=first\nOTHER=x\nAPI_KEY=second\n", encoding="utf-8")

    result = _run(env)

    assert result.returncode == 1
    assert "SHADOWED: API_KEY" in result.stdout
    assert "this one wins" in result.stdout


def test_script_never_prints_values(tmp_path: Path) -> None:
    """It has to be safe to run on a host and paste into a ticket."""
    env = tmp_path / ".env"
    env.write_text(
        "SUPER_ADMIN_KEY=deadbeefsecretvalue\nSUPER_ADMIN_KEY=anothersecretvalue\n",
        encoding="utf-8",
    )

    result = _run(env)
    combined = result.stdout + result.stderr

    assert "deadbeefsecretvalue" not in combined
    assert "anothersecretvalue" not in combined
    assert "SUPER_ADMIN_KEY" in combined, "the key name must still be reported"


def test_identical_duplicates_pass_by_default(tmp_path: Path) -> None:
    """Untidy is not the same as broken; only differing values shadow anything."""
    env = tmp_path / ".env"
    env.write_text("PATH_X=/same\nPATH_X=/same\n", encoding="utf-8")

    assert _run(env).returncode == 0
    assert _run(env, "--warn-identical").returncode == 1


def test_comments_and_blank_lines_are_not_keys(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("# A=1\n\n   \nA=2\n", encoding="utf-8")

    assert _run(env).returncode == 0, "a commented-out assignment was counted as real"


def test_export_prefix_is_recognised(tmp_path: Path) -> None:
    """Hand-edited env files pick up `export` from shell habit; Compose tolerates it."""
    env = tmp_path / ".env"
    env.write_text("export TOKEN=one\nTOKEN=two\n", encoding="utf-8")

    result = _run(env)

    assert result.returncode == 1, "an `export `-prefixed assignment was missed"
    assert "SHADOWED: TOKEN" in result.stdout
