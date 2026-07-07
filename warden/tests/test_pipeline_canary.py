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


# The startup gate policy lives in warden.observability.enforce_canary_gate — the
# same function main.py's lifespan calls. We test it directly rather than booting
# the full app: booting is order-fragile because the session-scoped `client`
# fixture keeps the app's lifespan already started, so a nested boot would skip the
# gate entirely. Testing the pure policy function is deterministic and isolated.

def test_startup_gate_failclosed_crashes_boot():
    """failclosed + unhealthy verdict → raises SecurityDegradedError so the container
    crash-loops and a broken detector never serves traffic."""
    from warden.observability import SecurityDegradedError, enforce_canary_gate

    with pytest.raises(SecurityDegradedError):
        enforce_canary_gate(_UNHEALTHY, failclosed=True)


def test_startup_gate_default_boots_degraded():
    """default (failclosed off) + unhealthy verdict → no raise (availability-first),
    but the gate reports DEGRADED so startup logs CRITICAL / health shows degraded."""
    from warden.observability import enforce_canary_gate

    assert enforce_canary_gate(_UNHEALTHY, failclosed=False) is True


def test_startup_gate_unavailable_never_crashes():
    """available=false (self-test couldn't run) → inconclusive: never degraded,
    never raises, even when fail-closed is armed."""
    from warden.observability import enforce_canary_gate

    assert enforce_canary_gate(_UNAVAILABLE, failclosed=True) is False
    assert enforce_canary_gate(_UNAVAILABLE, failclosed=False) is False


def test_startup_gate_healthy_not_degraded():
    """A healthy verdict is never degraded and never raises, regardless of the flag."""
    from warden.observability import enforce_canary_gate

    healthy = {"available": True, "caught": 3, "missed": 0,
               "false_positive": 0, "healthy": True}
    assert enforce_canary_gate(healthy, failclosed=True) is False
