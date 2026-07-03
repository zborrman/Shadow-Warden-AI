"""
warden/tests/test_pipeline_service.py
──────────────────────────────────────
Tests for the Phase-2 FilterPipeline service seam (warden/services/pipeline.py).
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _clean_runtime():
    from warden.runtime import runtime
    saved = dict(runtime._slots)
    yield
    runtime._slots.update(saved)


@pytest.mark.asyncio
async def test_run_delegates_to_published_orchestrator():
    from warden.runtime import runtime
    from warden.services.pipeline import FilterPipeline

    seen = {}

    async def fake_orchestrator(payload, rid, auth, bg, ip):
        seen.update(payload=payload, rid=rid, auth=auth, bg=bg, ip=ip)
        return "RESULT"

    runtime.publish(filter_orchestrator=fake_orchestrator)
    out = await FilterPipeline().run("P", "rid-1", "AUTH", None, "1.2.3.4")
    assert out == "RESULT"
    assert seen == {"payload": "P", "rid": "rid-1", "auth": "AUTH", "bg": None, "ip": "1.2.3.4"}


@pytest.mark.asyncio
async def test_fails_closed_when_unpublished():
    from warden.runtime import runtime
    from warden.services.pipeline import FilterPipeline, PipelineUnavailableError

    runtime.clear()
    with pytest.raises(PipelineUnavailableError):
        await FilterPipeline().run("P", "rid", "AUTH")


def test_is_available_reflects_publication():
    from warden.runtime import runtime
    from warden.services import pipeline

    runtime.clear()
    assert pipeline.is_available() is False
    runtime.publish(filter_orchestrator=lambda *a: None)
    assert pipeline.is_available() is True


def test_service_is_not_importing_main():
    """The service seam must not import warden.main (keeps the layer boundary)."""
    import ast
    import inspect

    from warden.services import pipeline
    tree = ast.parse(inspect.getsource(pipeline))
    mods: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.append(node.module)
    assert "warden.main" not in mods
