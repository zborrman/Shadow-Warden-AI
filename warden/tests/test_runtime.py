"""
warden/tests/test_runtime.py
─────────────────────────────
Tests for the Phase-1 runtime container (warden/runtime.py).
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _clean_runtime():
    from warden.runtime import runtime
    saved = dict(runtime._slots)
    yield
    runtime._slots.update(saved)


def test_slots_default_none():
    from warden.runtime import runtime
    runtime.clear()
    assert runtime.brain_guard is None
    assert runtime.evolve is None


def test_publish_and_read():
    from warden.runtime import runtime
    sentinel = object()
    runtime.publish(brain_guard=sentinel)
    assert runtime.brain_guard is sentinel


def test_module_level_publish():
    from warden import runtime as rt
    sentinel = object()
    rt.publish(evolve=sentinel)
    assert rt.runtime.evolve is sentinel


def test_unknown_attribute_raises():
    from warden.runtime import runtime
    with pytest.raises(AttributeError):
        _ = runtime.does_not_exist


def test_is_dependency_free_leaf():
    """runtime must not import any warden domain package (cycle prevention)."""
    import ast
    import inspect

    from warden import runtime as rt
    tree = ast.parse(inspect.getsource(rt))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
    warden_imports = [m for m in imported if m == "warden" or m.startswith("warden.")]
    assert warden_imports == [], f"runtime must be a leaf; found {warden_imports}"
