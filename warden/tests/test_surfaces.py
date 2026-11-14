"""
Lab surfaces are withheld from production, and stay withheld.

docs/surface-decision-2026-11-14.md: a router with no client is not a product.
``warden/surfaces.py`` names the lab routers; the registrar skips them unless
``WARDEN_LAB_SURFACES=true``. The suite itself runs with the flag on (conftest),
so these tests set the flag explicitly instead of trusting the ambient value.
"""
from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest
from fastapi import FastAPI

from warden import app_factory, surfaces
from warden.app_factory import RouterSpec, register_router_safe

_REPO = Path(__file__).resolve().parents[2]
_INVENTORY = Path(__file__).with_name("fixtures") / "route_inventory.json"


def _prefixes(import_path: str) -> set[str]:
    router = importlib.import_module(import_path).router
    return {"/" + r.path.strip("/").split("/")[0] for r in router.routes}


def test_the_lab_list_is_not_empty():
    """An empty list would make every other assertion here pass for free."""
    assert len(surfaces.LAB_ROUTER_MODULES) >= 4


@pytest.mark.parametrize("import_path", sorted(surfaces.LAB_ROUTER_MODULES))
def test_a_lab_router_is_not_mounted_with_the_flag_off(import_path, monkeypatch):
    monkeypatch.setattr(app_factory, "lab_enabled", lambda: False)
    app = FastAPI()
    assert register_router_safe(app, RouterSpec(import_path)) is False
    mounted = {getattr(r, "path", "") for r in app.routes}
    assert not any(p.startswith(tuple(_prefixes(import_path))) for p in mounted)


@pytest.mark.parametrize("import_path", sorted(surfaces.LAB_ROUTER_MODULES))
def test_a_lab_router_still_mounts_with_the_flag_on(import_path, monkeypatch):
    """Lab keeps its code alive. A module that no longer imports is retired, not lab."""
    monkeypatch.setattr(app_factory, "lab_enabled", lambda: True)
    app = FastAPI()
    assert register_router_safe(app, RouterSpec(import_path)) is True


def test_a_product_router_ignores_the_flag(monkeypatch):
    monkeypatch.setattr(app_factory, "lab_enabled", lambda: False)
    assert register_router_safe(FastAPI(), RouterSpec("warden.api.kya")) is True


def test_the_flag_is_off_unless_set(monkeypatch):
    from warden.config import Settings

    monkeypatch.delenv("WARDEN_LAB_SURFACES", raising=False)
    assert Settings().lab_surfaces_enabled is False


def test_an_unreadable_config_does_not_widen_the_surface(monkeypatch):
    import warden.config as config

    monkeypatch.setattr(config, "settings", object())
    assert surfaces.lab_enabled() is False


def test_every_lab_module_carries_a_reason():
    for path, why in surfaces.LAB_ROUTER_MODULES.items():
        assert len(why.strip()) > 20, f"{path} is lab without a stated reason"


def test_the_route_inventory_holds_no_lab_module():
    """The inventory is measured without the flag, so it is the production surface."""
    inventory = json.loads(_INVENTORY.read_text(encoding="utf-8"))
    leaked = sorted(set(inventory) & set(surfaces.LAB_ROUTER_MODULES))
    assert not leaked, f"lab module(s) still in the route inventory: {leaked}"


def test_the_published_spec_advertises_no_lab_route():
    lab_prefixes: set[str] = set()
    for path in surfaces.LAB_ROUTER_MODULES:
        lab_prefixes |= _prefixes(path)
    for spec in ("site/public/openapi.json", "landing/openapi.json"):
        paths = json.loads((_REPO / spec).read_text(encoding="utf-8"))["paths"]
        leaked = sorted(p for p in paths if "/" + p.strip("/").split("/")[0] in lab_prefixes)
        assert not leaked, f"{spec} advertises withdrawn route(s): {leaked[:5]}"


def test_the_isolation_hook_does_not_count_a_lab_module():
    from warden.hooks.tenant_isolation import scan_file

    rel = "warden/api/whitelabel.py"
    assert scan_file(_REPO / rel, rel) == []
