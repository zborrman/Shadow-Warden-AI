"""
warden/testing/__init__.py
━━━━━━━━━━━━━━━━━━━━━━━━━
Shadow Warden Fake Engine (SWFE) — unified testing infrastructure.

Adapts the Avito "fake system" pattern to Python/FastAPI:
  • warden.testing.fakes   — drop-in fakes for every external dependency
  • warden.testing.scenarios — YAML scenario DSL + pipeline orchestrator
  • warden.testing.isolation — X-Simulation-ID request-level isolation

Usage in tests:
    from warden.testing import FakeContext
    with FakeContext() as ctx:
        ctx.anthropic.queue_response("ALLOWED")
        resp = client.post("/filter", json={"content": "test"})
        assert resp.json()["allowed"] is True
"""
from warden.testing.context import FakeContext

__all__ = ["FakeContext"]
