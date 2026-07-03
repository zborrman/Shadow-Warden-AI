"""
warden/tests/test_threats_endpoint.py
────────────────────────────────────────
Phase-3 extraction tests for warden/api/threats.py.

Locks the behaviour of the Threat Intelligence + ThreatVault endpoints after
they moved out of main.py, and enforces the layer rule (the router must not
import warden.main).
"""
from __future__ import annotations

import ast
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from warden.api.threats import router
from warden.runtime import runtime

_MODULE = Path(__file__).parent.parent / "api" / "threats.py"


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


def test_router_does_not_import_main():
    """Layer rule: an api/ router may not import warden.main (upward import)."""
    tree = ast.parse(_MODULE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert node.module != "warden.main", "threats router must not import warden.main"
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name != "warden.main"


def test_intel_stats_503_when_disabled():
    """No published store → 503 (engine disabled), same as the old inline route."""
    runtime.publish(threat_intel_store=None, ti_scheduler=None)
    r = _client().get("/threats/intel/stats")
    assert r.status_code == 503


def test_vault_503_when_uninitialised():
    runtime.publish(threat_vault=None)
    r = _client().get("/threats/vault")
    assert r.status_code == 503


def test_vault_stats_from_runtime():
    """A published vault singleton is resolved and its stats returned."""

    class _FakeVault:
        def stats(self):
            return {"total": 3}

        def list_threats(self):
            return [{"id": "t1"}]

    try:
        runtime.publish(threat_vault=_FakeVault())
        r = _client().get("/threats/vault")
        assert r.status_code == 200
        body = r.json()
        assert body["stats"]["total"] == 3
        assert body["threats"] == [{"id": "t1"}]
    finally:
        runtime.publish(threat_vault=None)


def test_intel_list_from_runtime():
    class _Item:
        def model_dump(self):
            return {"id": "i1", "source": "arxiv"}

    class _FakeStore:
        def list_items(self, **kw):
            return [_Item()]

    try:
        runtime.publish(threat_intel_store=_FakeStore())
        r = _client().get("/threats/intel")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 1
        assert body["items"][0]["id"] == "i1"
    finally:
        runtime.publish(threat_intel_store=None)
