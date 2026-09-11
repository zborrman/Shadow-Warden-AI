"""
warden/tests/test_gateway_state.py
──────────────────────────────────
`warden.gateway_state` — the shared leaf holding the gateway's live-tunable
knobs (`POST /api/config` writes, the filter pipeline reads) and the resilience
sliding windows (`GET /health` reads, the pipeline appends). Moved out of
`warden/main.py` module globals in P-2.
"""
from __future__ import annotations

import pytest

from warden.gateway_state import GatewayState


def test_seeds_from_env(monkeypatch) -> None:
    monkeypatch.setenv("WARDEN_FAIL_STRATEGY", "closed")
    monkeypatch.setenv("PIPELINE_TIMEOUT_MS", "250")
    monkeypatch.setenv("UNCERTAINTY_LOWER_THRESHOLD", "0.6")
    gs = GatewayState()
    assert gs.fail_strategy == "closed"
    assert gs.pipeline_timeout_ms == 250
    assert gs.uncertainty_lower == 0.6
    assert len(gs.bypass_window) == len(gs.filter_window) == 0


def test_defaults_when_env_unset(monkeypatch) -> None:
    for var in ("WARDEN_FAIL_STRATEGY", "PIPELINE_TIMEOUT_MS", "UNCERTAINTY_LOWER_THRESHOLD"):
        monkeypatch.delenv(var, raising=False)
    gs = GatewayState()
    assert gs.fail_strategy == "open"
    assert gs.pipeline_timeout_ms == 0
    assert gs.uncertainty_lower == 0.55


@pytest.mark.parametrize(
    "raw,applied",
    [(0.7, 0.7), (-1.0, 0.0), (5.0, 0.99), (0.0, 0.0)],
)
def test_set_uncertainty_lower_clamps_and_persists(monkeypatch, raw, applied) -> None:
    monkeypatch.delenv("UNCERTAINTY_LOWER_THRESHOLD", raising=False)
    gs = GatewayState()
    out = gs.set_uncertainty_lower(raw)
    assert out == applied
    assert gs.uncertainty_lower == applied
    # persisted so a fresh worker / restart picks it up
    import os
    assert os.environ["UNCERTAINTY_LOWER_THRESHOLD"] == str(applied)


def test_reset_reseeds_and_clears_windows(monkeypatch) -> None:
    gs = GatewayState()
    gs.bypass_window.append(1.0)
    gs.filter_window.extend([1.0, 2.0])
    gs.set_uncertainty_lower(0.9)

    monkeypatch.setenv("UNCERTAINTY_LOWER_THRESHOLD", "0.5")
    monkeypatch.setenv("WARDEN_FAIL_STRATEGY", "closed")
    gs.reset()

    assert gs.uncertainty_lower == 0.5
    assert gs.fail_strategy == "closed"
    assert len(gs.bypass_window) == len(gs.filter_window) == 0


def test_windows_are_independent_instances() -> None:
    a, b = GatewayState(), GatewayState()
    a.bypass_window.append(1.0)
    assert len(b.bypass_window) == 0  # no shared mutable default


def test_tenant_guards_starts_empty_and_independent() -> None:
    a, b = GatewayState(), GatewayState()
    a.tenant_guards["acme"] = object()
    assert b.tenant_guards == {}


def test_reset_does_not_clear_tenant_guards() -> None:
    # tenant_guards are long-lived ML guard instances tied to app lifecycle, not
    # a per-request resilience window — reset() must not evict them.
    gs = GatewayState()
    sentinel = object()
    gs.tenant_guards["acme"] = sentinel
    gs.reset()
    assert gs.tenant_guards == {"acme": sentinel}
