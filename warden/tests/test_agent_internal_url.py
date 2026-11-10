"""
SOVA tools and the healer must reach the gateway through WARDEN_INTERNAL_URL.

Both modules hard-coded ``http://localhost:8001``. That is right only inside the
gateway container. SOVA's scheduled jobs (morning brief, threat sync, community
digest) and the healer's corpus watchdog run in ``arq-worker``, where localhost
has no gateway, so every one of their HTTP tools failed with "All connection
attempts failed". Production logged it on each run of the community-feed jobs.
"""
from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest

_AGENT = Path(__file__).resolve().parent.parent / "agent"


@pytest.mark.parametrize("module", ["warden.agent.tools", "warden.agent.healer"])
def test_base_url_follows_warden_internal_url(module, monkeypatch):
    from warden import config

    monkeypatch.setattr(config.settings, "warden_internal_url", "http://warden:8001")
    mod = importlib.reload(importlib.import_module(module))
    try:
        assert mod._BASE == "http://warden:8001"
    finally:
        monkeypatch.undo()
        importlib.reload(mod)


def test_the_compose_worker_sets_the_internal_url():
    compose = (_AGENT.parent.parent / "docker-compose.yml").read_text(encoding="utf-8")
    worker = compose.split("\n  arq-worker:", 1)[1].split("\n  analytics:", 1)[0]
    assert "WARDEN_INTERNAL_URL=" in worker
    assert "http://warden:8001" in worker


def test_no_agent_module_hardcodes_the_gateway_as_localhost():
    """A literal localhost base URL in warden/agent/ is the same defect again."""
    pattern = re.compile(r"""^\s*_?BASE\w*\s*=\s*["']http://localhost:8001""", re.M)
    offenders = [
        p.name for p in sorted(_AGENT.glob("*.py"))
        if pattern.search(p.read_text(encoding="utf-8"))
    ]
    assert not offenders, offenders
