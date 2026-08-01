"""
warden/tests/test_marketplace_sybil_gate.py — MP-4.

Marketplace rule #4: "Sybil gate fires on every POST /listings.
SybilGuard.is_flagged() before accept. Flagged agents → HTTP 403."

Scope note (a correction to the Track M audit): ``sybil_guard.py`` was reported
as 0% covered. That was wrong — ``warden/tests/test_sybil_guard.py`` has covered
the detector *unit* behaviour (circular trades, volume z-score, penalty, flag
lifecycle) at 74% all along. The audit measured only the ``test_marketplace_*``
selection, which does not match that filename.

What genuinely had no test is the thing rule #4 actually asserts: the **gate at
the request boundary**. The unit tests never call ``POST /marketplace/listings``,
so nothing verified that a flagged agent is refused, that a clean agent is not,
or that the documented fail-open posture holds. That is what this file covers;
detector internals are deliberately left to the existing file rather than
duplicated here.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    """Per-test DB + in-memory flag store (REDIS_URL=memory:// forces the fallback)."""
    monkeypatch.setenv("MARKETPLACE_DB_PATH", str(tmp_path / "mkt.db"))
    monkeypatch.setenv("REDIS_URL", "memory://")
    from warden.marketplace import sybil_guard
    sybil_guard._mem_flags.clear()
    yield
    sybil_guard._mem_flags.clear()


def _client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from warden.marketplace import api_listings
    app = FastAPI()
    app.include_router(api_listings.router, prefix="/marketplace")
    return TestClient(app)


def _body(seller: str) -> dict:
    return {
        "asset_id": "SEP-AAAAAAAAAAA", "seller_agent_id": seller,
        "community_id": "C1", "tenant_id": "t1", "asset_type": "compute",
        "price_usd": 10.0,
    }


class TestListingGate:
    """Rule #4 at the request boundary — the part no test reached before."""

    def test_flagged_seller_is_rejected_with_403(self):
        from warden.marketplace.sybil_guard import SybilGuard
        SybilGuard().flag_suspicious("did:shadow:BAD", "circular_trading")
        resp = _client().post("/marketplace/listings", json=_body("did:shadow:BAD"))
        assert resp.status_code == 403
        assert "flagged" in str(resp.json()).lower()

    def test_clean_seller_is_not_blocked_by_the_gate(self):
        """The gate must not be a blanket deny — otherwise 403 proves nothing."""
        resp = _client().post("/marketplace/listings", json=_body("did:shadow:CLEAN"))
        assert resp.status_code != 403

    def test_clearing_a_flag_restores_access(self):
        from warden.marketplace.sybil_guard import SybilGuard
        sg = SybilGuard()
        sg.flag_suspicious("did:shadow:BAD", "circular_trading")
        assert _client().post("/marketplace/listings", json=_body("did:shadow:BAD")).status_code == 403
        sg.clear_flag("did:shadow:BAD")
        assert _client().post("/marketplace/listings", json=_body("did:shadow:BAD")).status_code != 403

    def test_a_flag_does_not_spill_onto_a_bystander(self):
        from warden.marketplace.sybil_guard import SybilGuard
        SybilGuard().flag_suspicious("did:shadow:BAD", "circular_trading")
        resp = _client().post("/marketplace/listings", json=_body("did:shadow:GOOD"))
        assert resp.status_code != 403

    def test_gate_consults_the_claimed_seller_id(self):
        """Documented weakness in rule #4, pinned so it is not mistaken for strength.

        The gate checks the *claimed* seller id from the request body, so naming
        an unflagged agent defeats it. That is precisely why MP-1a put
        require_api_key in front of this route, and why rule #24 says an API key
        authenticates a tenant, not an agent.
        """
        from warden.marketplace.sybil_guard import SybilGuard
        SybilGuard().flag_suspicious("did:shadow:BAD", "circular_trading")
        resp = _client().post("/marketplace/listings", json=_body("did:shadow:NOT_BAD"))
        assert resp.status_code != 403

    def test_gate_fails_open_when_the_guard_errors(self, monkeypatch):
        """Rule #4 is fail-open by design; api_listings counts it via record_failopen.

        Asserted so the deliberate posture is not silently 'fixed' into a
        fail-closed one — or quietly lost the other way.
        """
        import warden.marketplace.sybil_guard as sg_mod

        class _Boom:
            def is_flagged(self, _agent_id):
                raise RuntimeError("flag store unavailable")

        monkeypatch.setattr(sg_mod, "SybilGuard", _Boom)
        resp = _client().post("/marketplace/listings", json=_body("did:shadow:ANY"))
        assert resp.status_code != 403


class TestDetectorDegradation:
    """Not covered by the unit file: behaviour when the backing DB is absent."""

    def test_detectors_survive_a_missing_database(self, tmp_path):
        from warden.marketplace.sybil_guard import SybilGuard
        missing = str(tmp_path / "does_not_exist.db")
        sg = SybilGuard()
        assert sg.detect_circular_trades(db_path=missing) == []
        assert sg.detect_volume_spike("did:shadow:X", db_path=missing) == 0.0

    def test_clear_flag_on_an_unflagged_agent_is_a_noop(self):
        from warden.marketplace.sybil_guard import SybilGuard
        SybilGuard().clear_flag("did:shadow:NEVER")  # must not raise
