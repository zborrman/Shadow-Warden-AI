"""
warden/tests/test_pipeline_canary.py — Deep-Eng P0.3 live canary self-test.

Boots the real app (lifespan publishes the orchestrator + runs the startup canary
gate) and exercises /health/pipeline?deep=true. Asserts the canary MECHANISM
(runs live, reports a verdict) rather than a specific detection score — detection
quality is the adversarial ratchet's job, not this test's.
"""
from __future__ import annotations

from fastapi.testclient import TestClient


def test_health_pipeline_shallow_has_no_canary():
    from warden.main import app

    with TestClient(app) as client:
        r = client.get("/health/pipeline")
        assert r.status_code == 200
        body = r.json()
        assert "stages" in body
        assert "canary" not in body  # cheap probe stays canary-free


def test_health_pipeline_deep_runs_live_canary():
    from warden.main import app

    with TestClient(app) as client:
        r = client.get("/health/pipeline?deep=true")
        assert r.status_code == 200
        body = r.json()
        assert "canary" in body
        canary = body["canary"]
        # Orchestrator is published by lifespan → the canary must have run live.
        assert canary["available"] is True
        for key in ("caught", "missed", "false_positive", "healthy"):
            assert key in canary
        # The live pipeline must block at least one blatant canary jailbreak —
        # a floor proving the detector is wired, without demanding a perfect score.
        assert canary["caught"] >= 1
