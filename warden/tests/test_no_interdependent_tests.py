"""warden/tests/test_no_interdependent_tests.py — tests must not hand each other state.

A test that stores its result on its own class, for a later test to read, is not
a test — it is one step of a script that only works when the whole script runs in
file order.

`test_hub_marketplace_flow.py` was written that way: `TestCreateCommunity.community_id`
assigned by one test and read by eight others, then `agent_id`, `asset_id`,
`listing_id` and `escrow_id` in a chain five deep. Twenty-five tests, one
implicit ordering. Measured 2026-08-19, running that file alongside a `-k`
selection produced

    AttributeError: type object 'TestAssetTokenization' has no attribute 'asset_id'

for three of them, because the selection filtered out the test that assigns it.
CI never saw it: CI runs the whole suite, in order, so the chain always held.

Two costs, and neither shows up as a red build:

  * `-k`, `--lf`, `-x`, `-p xdist` and random ordering all break — every workflow
    for debugging one endpoint.
  * When a step genuinely regresses, everything downstream fails with
    AttributeError instead of an assertion, so the real cause arrives buried at
    the bottom of a cascade.

The fix is pytest's own answer: a fixture returns the value, the tests that need
it declare it, and pytest resolves the order from the dependency graph. That
file now does exactly that, and this guard keeps the pattern from coming back.

Detection is AST-based, not textual: it matches assignments to classes *defined
in the same file* whose names start with `Test`. A regex would flag
`TestClient.foo = ...`, which is an imported HTTP client and not a test class at
all.
"""

from __future__ import annotations

import ast
from pathlib import Path

_TESTS_DIR = Path(__file__).resolve().parent


def _offenders(tree: ast.Module) -> list[tuple[str, int]]:
    """Assignments of the form `TestSomething.attr = ...` inside the module.

    Only classes defined in this file count — an imported name that happens to
    start with `Test` is somebody else's type.
    """
    local_test_classes = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and node.name.startswith("Test")
    }
    if not local_test_classes:
        return []

    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id in local_test_classes
            ):
                found.append((f"{target.value.id}.{target.attr}", node.lineno))
    return found


def test_no_test_class_is_used_as_a_state_channel() -> None:
    dirty: dict[str, list[tuple[str, int]]] = {}
    for path in sorted(_TESTS_DIR.glob("test_*.py")):
        if path.name == Path(__file__).name:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError:  # pragma: no cover - a broken test file fails elsewhere
            continue
        hits = _offenders(tree)
        if hits:
            dirty[path.name] = hits

    assert not dirty, (
        "Test classes are being used to pass state between tests:\n"
        + "\n".join(
            f"  {name}\n"
            + "\n".join(f"      line {line}: {attr} = ..." for attr, line in hits)
            for name, hits in dirty.items()
        )
        + "\n\nA test that reads state another test wrote only passes when both "
        "run, in order, in the same session — so it breaks under -k, --lf, -x, "
        "xdist and random ordering, and it turns a single real regression into a "
        "cascade of AttributeErrors that hides the cause.\n"
        "Return the value from a fixture instead and let the tests that need it "
        "declare it as a parameter; pytest will order them by the dependency "
        "graph. See test_hub_marketplace_flow.py for the shape."
    )
