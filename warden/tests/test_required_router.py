"""
warden/tests/test_required_router.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
`/filter` is the product. It must not be able to go missing quietly.

While the seven filter routes were inline `@app.post` handlers in `main.py` they
could not fail separately from the app: if the module imported, they existed.
P-2 moved them into `warden/api/filter.py`, and `register_router_safe`
deliberately swallows every exception so that a broken *optional* subsystem
cannot kill the gateway. Applied to the core router that is the wrong contract —
one bad import boots a gateway that answers 404 on the endpoint it exists to
serve.

Nothing downstream would catch it:

  * the startup canary calls `filter_orchestrator` directly and never touches
    the HTTP route;
  * `/health` reports no route inventory;
  * `test_route_inventory.py` tolerates a whole module being absent, so once its
    fixture attributes these paths to `warden.api.filter` it stops failing on
    their disappearance.

So boot has to fail. These tests prove it does, rather than trusting that the
call site passes the right helper.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI

from warden.app_factory import (
    RequiredRouterError,
    RouterSpec,
    register_required_router,
    register_router_safe,
)


class TestRequiredRouterRaises:
    def test_a_missing_module_refuses_to_boot(self):
        app = FastAPI()
        with pytest.raises(RequiredRouterError) as exc:
            register_required_router(
                app, RouterSpec("warden.api.does_not_exist_at_all", label="probe")
            )
        assert "does_not_exist_at_all" in str(exc.value)
        assert "refusing to boot" in str(exc.value)

    def test_a_module_that_raises_on_import_refuses_to_boot(self, monkeypatch):
        """The realistic failure: the module exists but one of its imports blows up."""
        import importlib

        def _boom(name, *a, **kw):
            raise RuntimeError("warden.shadow_ban exploded")

        monkeypatch.setattr(importlib, "import_module", _boom)
        with pytest.raises(RequiredRouterError):
            register_required_router(app := FastAPI(), RouterSpec("warden.api.filter"))
        assert app is not None

    def test_a_module_without_the_router_attribute_refuses_to_boot(self):
        # `attr` defaults to "router"; warden.schemas has no such attribute.
        with pytest.raises(RequiredRouterError):
            register_required_router(FastAPI(), RouterSpec("warden.schemas", label="probe"))

    def test_a_healthy_router_mounts_silently(self):
        """The guard must not be a tripwire on the happy path.

        The path check recurses: under starlette>=1.0 `include_router` leaves a
        lazy `_IncludedRouter` node whose real routes hang off `.original_router`,
        so a flat scan of `app.routes` reports "/filter" absent on a perfectly
        healthy mount. (This test asserted exactly that at first and failed.)
        """
        app = FastAPI()
        register_required_router(app, RouterSpec("warden.api.filter"))

        def _paths(routes):
            for r in routes:
                orig = getattr(r, "original_router", None)
                if orig is not None:
                    yield from _paths(orig.routes)
                    continue
                sub = getattr(r, "routes", None)
                if getattr(r, "endpoint", None) is None and sub:
                    yield from _paths(sub)
                    continue
                p = getattr(r, "path", None)
                if p:
                    yield p

        mounted = set(_paths(app.routes))
        assert "/filter" in mounted, mounted


class TestTheOptionalHelperStillTolerates:
    def test_register_router_safe_returns_false_rather_than_raising(self):
        """The optional contract is unchanged — that isolation is deliberate."""
        assert register_router_safe(
            FastAPI(), RouterSpec("warden.api.does_not_exist_at_all", label="probe")
        ) is False


class TestTheCallSiteUsesIt:
    def test_main_registers_the_filter_router_as_required(self):
        """A correct helper nobody calls is the same defect in a different place."""
        import ast
        import inspect
        import textwrap

        import warden.main as main_mod

        src = textwrap.dedent(inspect.getsource(main_mod))
        tree = ast.parse(src)

        required: set[str] = set()
        optional: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            if node.func.id not in {"register_required_router", "register_router_safe"}:
                continue
            for arg in node.args:
                # RouterSpec("warden.api.x", ...) — read the literal import path
                if isinstance(arg, ast.Call) and arg.args and isinstance(arg.args[0], ast.Constant):
                    target = required if node.func.id == "register_required_router" else optional
                    target.add(arg.args[0].value)

        assert "warden.api.filter" in required, (
            "the /filter router is registered with the optional helper — a swallowed "
            "import error would boot a gateway that 404s the core product endpoint"
        )
        assert "warden.api.filter" not in optional, (
            "warden.api.filter is registered both ways; the optional call would still "
            "let a boot with no /filter succeed"
        )


class TestWhatIsDeliberatelyStillOptional:
    def test_the_websocket_router_is_not_yet_required(self):
        """Recorded, not endorsed.

        `warden.api.ws_stream` (P-2 inc. 4) carries `/ws/stream`, `/ws/filter`
        and `/ws/monitor` and is still mounted with the optional helper, so a
        broken import there also disappears quietly. It is a smaller surface than
        `/filter` and promoting it is a posture decision rather than part of this
        change, so the current shape is pinned here instead of being left to
        drift unnoticed. Flip this test when it is promoted.
        """
        import ast
        import inspect
        import textwrap

        import warden.main as main_mod

        tree = ast.parse(textwrap.dedent(inspect.getsource(main_mod)))
        calls = {
            arg.args[0].value: node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id in {"register_required_router", "register_router_safe"}
            for arg in node.args
            if isinstance(arg, ast.Call) and arg.args and isinstance(arg.args[0], ast.Constant)
        }
        assert calls.get("warden.api.ws_stream") == "register_router_safe", (
            "warden.api.ws_stream changed registration helper — if it was promoted to "
            "required, that is an improvement: delete this test and say so."
        )
