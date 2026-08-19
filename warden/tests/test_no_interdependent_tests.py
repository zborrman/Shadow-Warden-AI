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
import textwrap
from pathlib import Path

import pytest

_TESTS_DIR = Path(__file__).resolve().parent


def _class_base(node: ast.expr, local_test_classes: set[str]) -> str | None:
    """Name of the test class an assignment target writes to, if any.

    Three spellings reach the same place, and the last two are the likelier way
    the pattern comes back, because they are written from inside a test method
    where the class name is not in scope:

        TestFoo.attr = ...          → ast.Name
        self.__class__.attr = ...   → ast.Attribute on `self`
        type(self).attr = ...       → ast.Call to `type`
    """
    if isinstance(node, ast.Name) and node.id in local_test_classes:
        return node.id
    if (
        isinstance(node, ast.Attribute)
        and node.attr == "__class__"
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
    ):
        return "self.__class__"
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "type"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "self"
    ):
        return "type(self)"
    return None


def _offenders(tree: ast.Module) -> list[tuple[str, int]]:
    """Writes of the form `<test class>.attr = ...` inside the module.

    Only classes defined in this file count — an imported name that happens to
    start with `Test` is somebody else's type.

    All three assignment nodes are checked. A guard that only understood plain
    `=` would miss `attr: str = ...` and `attr += ...`, which store state just
    as durably.
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
        if isinstance(node, ast.Assign):
            targets: list[ast.expr] = list(node.targets)
        elif isinstance(node, ast.AnnAssign | ast.AugAssign):
            targets = [node.target]
        else:
            continue

        for target in targets:
            if not isinstance(target, ast.Attribute):
                continue
            base = _class_base(target.value, local_test_classes)
            if base is not None:
                found.append((f"{base}.{target.attr}", node.lineno))
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


# ── the guard's own coverage ───────────────────────────────────────────────────
# A recurrence guard is only worth the forms it recognises, so each spelling is
# pinned. `self.__class__` and `type(self)` matter most: they are what somebody
# writes from inside a test method, where the class name is not in scope.

@pytest.mark.parametrize(
    "body",
    [
        pytest.param("TestFoo.captured = 1", id="plain-assign"),
        pytest.param("TestFoo.captured: int = 1", id="annotated-assign"),
        pytest.param("TestFoo.captured += 1", id="augmented-assign"),
        pytest.param("self.__class__.captured = 1", id="via-self-class"),
        pytest.param("type(self).captured = 1", id="via-type-self"),
    ],
)
def test_guard_catches_every_spelling(body: str) -> None:
    src = textwrap.dedent(f"""
        class TestFoo:
            def test_one(self):
                {body}
    """)
    assert _offenders(ast.parse(src)), f"guard missed: {body}"


@pytest.mark.parametrize(
    "body",
    [
        # Imported types whose names merely start with "Test" are not test classes.
        pytest.param("TestClient.timeout = 5", id="imported-testclient"),
        # Instance state dies with the instance — that is not a state channel.
        pytest.param("self.captured = 1", id="instance-attribute"),
        # A local, and a plain call.
        pytest.param("captured = 1", id="local-variable"),
    ],
)
def test_guard_does_not_flag_legitimate_writes(body: str) -> None:
    src = textwrap.dedent(f"""
        class TestFoo:
            def test_one(self):
                {body}
    """)
    assert not _offenders(ast.parse(src)), f"false positive on: {body}"
