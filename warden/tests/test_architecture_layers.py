"""
warden/tests/test_architecture_layers.py
────────────────────────────────────────────
Phase-4 capstone: the self-defending layer guard.

The architecture (docs/architecture.md) is a layered modular monolith where
dependencies point downward only:

    api/ → services/ → domains/ → runtime/   (leaf, imports no warden domain)

The historic cycle source was domains reaching *upward* into ``warden.main``
(``from warden.main import _brain_guard``), which forced ~250 lazy-import
work-arounds. Phases 1-3 moved that shared state into ``warden.runtime`` and
extracted routes into ``warden/api/*``. This test makes the rule permanent:

    No module under ``warden/`` (except ``main.py`` itself) may import
    ``warden.main`` — directly, ``as`` alias, or ``from warden import main``.

Any new upward import fails CI here, so the architecture defends itself against
regression. AST-based: prose mentions of "warden.main" in docstrings/comments
are ignored; only real import statements count.
"""
from __future__ import annotations

import ast
from pathlib import Path

_WARDEN = Path(__file__).resolve().parent.parent


def _imports_main(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module == "warden.main":
                return True
            if node.module == "warden" and any(a.name == "main" for a in node.names):
                return True
        if isinstance(node, ast.Import) and any(a.name == "warden.main" for a in node.names):
            return True
    return False


def _source_files() -> list[Path]:
    files: list[Path] = []
    for p in _WARDEN.rglob("*.py"):
        parts = p.parts
        if "__pycache__" in parts or "tests" in parts:
            continue
        if p.name == "main.py":
            continue
        files.append(p)
    return files


def test_no_module_imports_warden_main():
    """Enforce the downward-only layer rule: nothing imports warden.main upward."""
    violations: list[str] = []
    for path in _source_files():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        if _imports_main(tree):
            violations.append(str(path.relative_to(_WARDEN)))

    assert not violations, (
        "These modules import warden.main (upward import — forbidden by the "
        "layer rule). Read the shared state from warden.runtime instead:\n  "
        + "\n  ".join(sorted(violations))
    )


def test_runtime_is_a_leaf():
    """warden.runtime must import no warden.* package — it is the cycle-proof leaf."""
    tree = ast.parse((_WARDEN / "runtime.py").read_text(encoding="utf-8"))
    bad: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("warden"):
            bad.append(node.module or "")
        if isinstance(node, ast.Import):
            bad += [a.name for a in node.names if a.name.startswith("warden")]
    assert not bad, f"warden.runtime must be a leaf but imports: {bad}"
