"""
warden/tests/test_pipeline_canary.py — Deep-Eng P0.3 live canary self-test.

Boots the real app (lifespan publishes the orchestrator + runs the startup canary
gate) and exercises /health/pipeline?deep=true. Asserts the canary MECHANISM
(runs live, reports a verdict) rather than a specific detection score — detection
quality is the adversarial ratchet's job, not this test's.

The second half locks the STARTUP GATE behaviour — the most safety-critical part
of P0.3 — by monkeypatching the canary verdict rather than the detector:
  * PIPELINE_FAILCLOSED_ON_CANARY=true + unhealthy verdict → boot must crash-loop.
  * default (flag off) + unhealthy verdict            → boot proceeds, DEGRADED.
  * verdict available=false (self-test couldn't run)  → never crashes boot.
These guard against a future refactor silently inverting or swallowing the gate.
"""
from __future__ import annotations

import pytest
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


# ── Startup gate ────────────────────────────────────────────────────────────
# The startup gate is the safety-critical half of P0.3: on a regressed detector
# it must refuse to serve (fail-closed) when explicitly configured to. We drive
# it by patching the *verdict* (warden.observability.run_pipeline_canary, which
# lifespan re-imports locally) so the tests are deterministic and detector-quality
# independent.

_UNHEALTHY = {"available": True, "caught": 0, "missed": 3,
              "false_positive": 0, "healthy": False}
_UNAVAILABLE = {"available": False, "caught": 0, "missed": 0,
                "false_positive": 0, "healthy": False}


def _patch_canary(monkeypatch, verdict):
    async def _fake_canary():
        return dict(verdict)

    import warden.observability as obs
    monkeypatch.setattr(obs, "run_pipeline_canary", _fake_canary)


def test_startup_gate_failclosed_crashes_boot(monkeypatch):
    """flag=true + unhealthy verdict → lifespan raises SecurityDegradedError so the
    container crash-loops and a broken detector never serves traffic."""
    import warden.main as main_mod
    from warden.observability import SecurityDegradedError

    _patch_canary(monkeypatch, _UNHEALTHY)
    monkeypatch.setattr(main_mod.settings, "pipeline_failclosed_on_canary", True)

    with pytest.raises(SecurityDegradedError), TestClient(main_mod.app):
        pass  # boot alone must fail — we never reach a request


def test_startup_gate_default_boots_degraded(monkeypatch):
    """flag=false (default) + unhealthy verdict → boot proceeds (availability-first);
    the failure surfaces loudly via /health/pipeline?deep=true, not a crash."""
    import warden.main as main_mod

    _patch_canary(monkeypatch, _UNHEALTHY)
    monkeypatch.setattr(main_mod.settings, "pipeline_failclosed_on_canary", False)

    with TestClient(main_mod.app) as client:
        body = client.get("/health/pipeline?deep=true").json()
        assert body["canary"]["healthy"] is False
        assert "canary" in body["degraded_stages"]
        assert body["status"] == "degraded"


def test_startup_gate_unavailable_never_crashes(monkeypatch):
    """A verdict of available=false (self-test couldn't run — orchestrator not up)
    must NOT crash boot even when fail-closed is armed. The gate only acts on a
    verdict that actually ran; an inconclusive self-test is not a detector failure."""
    import warden.main as main_mod

    _patch_canary(monkeypatch, _UNAVAILABLE)
    monkeypatch.setattr(main_mod.settings, "pipeline_failclosed_on_canary", True)

    with TestClient(main_mod.app) as client:
        assert client.get("/health/pipeline").status_code == 200
