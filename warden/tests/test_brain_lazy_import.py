"""
P-3b ratchet — the ML stack must not load just because someone touched
`warden.brain.*`.

`warden/brain/semantic.py` imports torch + sentence-transformers at module
level. `warden/brain/__init__.py` used to re-export `SemanticGuard` eagerly, so
importing ANY module in the package pulled the whole ML stack in.

That cost was paid by the ARQ worker, which imports `warden.brain.online_learner`
only to register the nightly job. Measured in production 2026-07-27: ~500 MB
resident inside a **1 GB** container limit — ~40% of its budget — for models the
worker never runs (it delegates inference to `warden:8001` over HTTP).

Each test runs in a subprocess because `sys.modules` is process-global: once any
earlier test in the session has imported torch, an in-process assertion proves
nothing.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

import pytest

# Heavy, slow-to-import third-party libraries that must stay out of a plain
# `warden.brain.*` import. `numpy` is deliberately NOT here — it is small,
# ubiquitous in this codebase, and several brain modules use it directly.
HEAVY = ("torch", "sentence_transformers", "transformers", "sklearn", "scipy")


def _import_in_subprocess(snippet: str) -> set[str]:
    """Run *snippet*, then report which HEAVY modules ended up in sys.modules."""
    # The result line is prefixed with a sentinel: the clean case prints an
    # EMPTY list, which is indistinguishable from "produced no output at all"
    # if we just read the last line. Any import-time logging from warden
    # modules also lands on stdout, so we must select the line, not take it.
    code = textwrap.dedent(f"""
        import sys
        {snippet}
        heavy = [m for m in {HEAVY!r} if m in sys.modules]
        print("HEAVY_RESULT:" + ",".join(heavy))
    """)
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=180,
    )
    if proc.returncode != 0:
        pytest.fail(f"subprocess import failed:\n{proc.stdout}\n{proc.stderr}")

    marker = [ln for ln in proc.stdout.splitlines() if ln.startswith("HEAVY_RESULT:")]
    if not marker:
        pytest.fail(f"sentinel line missing from subprocess output:\n{proc.stdout}")
    return {m for m in marker[-1].removeprefix("HEAVY_RESULT:").split(",") if m}


def test_importing_brain_package_does_not_load_ml_stack():
    loaded = _import_in_subprocess("import warden.brain")
    assert not loaded, (
        f"`import warden.brain` pulled in {sorted(loaded)}. The package "
        f"__init__ must re-export SemanticGuard/SemanticResult lazily "
        f"(PEP 562 module __getattr__), not eagerly."
    )


def test_importing_online_learner_does_not_load_ml_stack():
    loaded = _import_in_subprocess("import warden.brain.online_learner")
    assert not loaded, (
        f"`import warden.brain.online_learner` pulled in {sorted(loaded)}. "
        f"This is the exact import the 1 GB ARQ worker makes at boot to "
        f"register the nightly job."
    )


def test_lazy_reexport_still_resolves():
    """Deferring the import must not break the public name."""
    code = textwrap.dedent("""
        from warden.brain import SemanticGuard, SemanticResult
        from warden.brain import RedactionResult, SecretRedactor
        assert SemanticGuard.__module__ == "warden.brain.semantic"
        assert SecretRedactor.__module__ == "warden.brain.redactor"
        print("ok")
    """)
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=300
    )
    assert proc.returncode == 0, f"{proc.stdout}\n{proc.stderr}"
    assert "ok" in proc.stdout


def test_unknown_attribute_raises_attribute_error():
    """__getattr__ must not swallow genuine typos into an ImportError."""
    import warden.brain

    with pytest.raises(AttributeError, match="no attribute"):
        warden.brain.NoSuchSymbol  # noqa: B018


def test_dir_lists_the_public_api():
    import warden.brain

    assert set(warden.brain.__all__) <= set(dir(warden.brain))


def test_semantic_still_imports_torch_directly():
    """
    Guard against 'fixing' this by making semantic.py itself lazy.

    The gateway legitimately needs torch resident — it serves the MiniLM
    inference path on /filter. This ratchet is about the *package __init__*
    not forcing that cost on unrelated importers, not about deferring the
    model from the process that actually uses it.
    """
    loaded = _import_in_subprocess("import warden.brain.semantic")
    assert "torch" in loaded, (
        "warden.brain.semantic no longer imports torch eagerly. That is a "
        "different (and riskier) change than P-3b: it moves a multi-second "
        "import onto the first /filter request instead of startup."
    )
