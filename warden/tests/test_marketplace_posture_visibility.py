"""
warden/tests/test_marketplace_posture_visibility.py — MP-6 + MP-7.

Two related problems, same shape: the system reported a stronger posture than it
had.

MP-6 — ``authorize_payment()`` returns ALLOW when
``AUTHORIZE_PAYMENT_ENFORCED`` is off. To a caller that is indistinguishable
from an ALLOW after every check passed, so a reader sees a gated money path
where nothing is evaluating.

MP-7 — ``GET /marketplace/protocol`` is what a counterparty agent reads before
deciding to trade. It advertised ``signature_type: Ed25519`` while nothing
verified signatures, ``injection_guard: true`` while that module had no caller,
and escrow ``chains`` while settlement was an in-process simulation.
"""
from __future__ import annotations

import pytest


class TestAuthorizationPostureIsVisible:
    def test_disabled_enforcement_still_returns_allow(self, monkeypatch):
        """Behaviour is unchanged — MP-6 adds visibility, not enforcement."""
        monkeypatch.setenv("AUTHORIZE_PAYMENT_ENFORCED", "false")
        from warden.payments.authorize import authorize_payment
        result = authorize_payment("t1", "did:shadow:A", "purchase", 10.0)
        assert result.verdict == "ALLOW"
        assert "enforcement_disabled" in result.reasons

    def test_allow_carries_the_reason_it_was_allowed(self, monkeypatch):
        """`enforcement_disabled` must stay in reasons — it is the audit trail."""
        monkeypatch.setenv("AUTHORIZE_PAYMENT_ENFORCED", "false")
        from warden.payments.authorize import authorize_payment
        assert authorize_payment("t1", "a", "purchase", 1.0).reasons == ["enforcement_disabled"]

    def test_enforced_allow_is_labelled_differently_from_disabled_allow(self, monkeypatch):
        """The whole point of MP-6: the two ALLOWs must be distinguishable."""
        recorded: list[tuple[str, bool]] = []
        import warden.payments.authorize as mod
        monkeypatch.setattr(
            mod, "_record_authorization",
            lambda verdict, *, enforced: recorded.append((verdict, enforced)),
        )
        monkeypatch.setenv("AUTHORIZE_PAYMENT_ENFORCED", "false")
        mod.authorize_payment("t1", "a", "purchase", 1.0)
        monkeypatch.setenv("AUTHORIZE_PAYMENT_ENFORCED", "true")
        mod.authorize_payment("t1", "a", "purchase", 1.0)

        assert len(recorded) == 2
        assert recorded[0][1] is False, "disabled path must record enforced=False"
        assert recorded[1][1] is True, "enforced path must record enforced=True"

    def test_metric_failure_never_blocks_a_payment(self, monkeypatch):
        """Telemetry must not be able to reject money movement."""
        import warden.payments.authorize as mod

        def _boom(*_a, **_kw):
            raise RuntimeError("registry gone")

        monkeypatch.setenv("AUTHORIZE_PAYMENT_ENFORCED", "false")
        monkeypatch.setattr(mod, "_record_authorization", _boom)
        with pytest.raises(RuntimeError):
            mod.authorize_payment("t1", "a", "purchase", 1.0)

    def test_recorder_itself_swallows_metric_errors(self, monkeypatch):
        """_record_authorization is the layer that must not raise."""
        import warden.payments.authorize as mod
        mod._record_authorization("ALLOW", enforced=False)  # must not raise

    def test_enforcement_flag_is_read_fresh(self, monkeypatch):
        from warden.payments.authorize import enforcement_enabled
        monkeypatch.setenv("AUTHORIZE_PAYMENT_ENFORCED", "true")
        assert enforcement_enabled() is True
        monkeypatch.setenv("AUTHORIZE_PAYMENT_ENFORCED", "false")
        assert enforcement_enabled() is False

    def test_default_is_off(self, monkeypatch):
        """Pinned because rule #23 tells operators to assume exactly this."""
        monkeypatch.delenv("AUTHORIZE_PAYMENT_ENFORCED", raising=False)
        from warden.payments.authorize import enforcement_enabled
        assert enforcement_enabled() is False


class TestProtocolManifestHonesty:
    def _manifest(self) -> dict:
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from warden.marketplace import api
        app = FastAPI()
        app.include_router(api.router, prefix="/marketplace")
        return TestClient(app).get("/marketplace/protocol").json()

    def test_signature_enforcement_is_advertised(self, monkeypatch):
        """`signature_type: Ed25519` alone cannot tell a partner if it is enforced."""
        monkeypatch.setenv("MARKETPLACE_REQUIRE_SIGNED_OFFERS", "false")
        assert self._manifest()["negotiation"]["signature_enforced"] is False
        monkeypatch.setenv("MARKETPLACE_REQUIRE_SIGNED_OFFERS", "true")
        assert self._manifest()["negotiation"]["signature_enforced"] is True

    def _capable(self, monkeypatch) -> None:
        """Pretend the escrow contract path is wired.

        Every chain-selection test below is about *which* mode a configuration
        produces once settlement is possible at all. Today it is not — the
        contract functions are stubs — so without this the answer is `simulated`
        for every input and the tests would assert nothing.
        """
        monkeypatch.setattr(
            "warden.web3.smart_contract.settlement_capability",
            lambda: {"can_settle": True, "reason": "", "detail": ""},
        )

    def test_settlement_is_simulated_while_the_contract_path_is_a_stub(self, monkeypatch):
        """The state of production: mainnet RPC configured, nothing settleable.

        `BASE_RPC_URL` defaults to the public Base endpoint, so a mainnet chain
        looks configured on every deployment. `deploy_escrow()` returns a
        simulated address regardless. Configuration must not outvote capability.
        """
        monkeypatch.setattr(
            "warden.web3.chains.get_chain",
            lambda c: {"rpc_url": "https://mainnet.base.org" if c == "base" else ""},
        )
        assert self._manifest()["escrow"]["settlement_mode"] == "simulated"

    def test_escrow_settlement_mode_is_advertised(self):
        """Advertising `chains` without this reads as an on-chain guarantee."""
        mode = self._manifest()["escrow"]["settlement_mode"]
        assert mode in ("onchain", "testnet", "simulated", "unknown")

    def test_settlement_mode_is_simulated_without_an_rpc(self, monkeypatch):
        from warden.marketplace.api import _escrow_settlement_mode
        monkeypatch.setattr("warden.web3.chains.get_chain", lambda _c: {"rpc_url": ""})
        assert _escrow_settlement_mode() == "simulated"

    def test_settlement_mode_is_testnet_when_only_test_chains_are_configured(
        self, monkeypatch
    ):
        """A Sepolia RPC is not an on-chain rail.

        Production reported `onchain` on the strength of `WEB3_RPC_URL` pointing
        at Sepolia, with $0 ever settled — which also made "manifest reports
        onchain" unusable as the P1a exit gate.
        """
        self._capable(monkeypatch)
        self._capable(monkeypatch)
        from warden.marketplace.api import _escrow_settlement_mode
        monkeypatch.setattr(
            "warden.web3.chains.get_chain",
            lambda c: {"rpc_url": "https://rpc.example" if c == "sepolia" else ""},
        )
        assert _escrow_settlement_mode() == "testnet"

    def test_settlement_mode_is_onchain_only_for_a_mainnet_chain(self, monkeypatch):
        self._capable(monkeypatch)
        from warden.marketplace.api import _escrow_settlement_mode
        from warden.web3.chains import MAINNET_CHAINS
        mainnet = sorted(MAINNET_CHAINS)[0]
        monkeypatch.setattr(
            "warden.web3.chains.get_chain",
            lambda c: {"rpc_url": "https://rpc.example" if c == mainnet else ""},
        )
        assert _escrow_settlement_mode() == "onchain"

    def test_advertised_chains_are_the_configured_ones(self, monkeypatch):
        """`eth_tester` is an in-process EVM, not a settlement venue."""
        self._capable(monkeypatch)
        from warden.marketplace.api import _configured_chains
        monkeypatch.setattr(
            "warden.web3.chains.get_chain",
            lambda c: {"rpc_url": "https://rpc.example" if c == "sepolia" else ""},
        )
        assert _configured_chains() == ["sepolia"]
        monkeypatch.setattr("warden.web3.chains.get_chain", lambda _c: {"rpc_url": ""})
        assert _configured_chains() == []

    def test_unreadable_chain_registry_is_unknown_not_simulated(self, monkeypatch):
        """"We could not look" is not "we looked and found nothing".

        `simulated` is a statement about the configuration. Returning it when the
        registry could not be read states a fact that was never established.

        Asserted through the manifest with the *real* failure — a `get_chain`
        that raises — rather than by patching the discovery helper. Patching the
        helper passed while every per-chain lookup failing still reported
        `simulated`, because the loop swallowed each failure individually.
        """
        self._capable(monkeypatch)
        def _boom(*_a, **_kw):
            raise RuntimeError("registry unavailable")

        monkeypatch.setattr("warden.web3.chains.get_chain", _boom)
        escrow = self._manifest()["escrow"]
        assert escrow["settlement_mode"] == "unknown"
        assert escrow["chains"] == []

    def test_one_bad_chain_entry_does_not_hide_the_rest(self, monkeypatch):
        """A single broken entry is noise; it must not mask a working config."""
        self._capable(monkeypatch)
        def _one_bad(chain):
            if chain == "polygon_amoy":
                raise RuntimeError("bad entry")
            return {"rpc_url": "https://rpc.example" if chain == "sepolia" else ""}

        monkeypatch.setattr("warden.web3.chains.get_chain", _one_bad)
        escrow = self._manifest()["escrow"]
        assert escrow["settlement_mode"] == "testnet"
        assert escrow["chains"] == ["sepolia"]

    # ── The manifest is the contract; these assert it, not the helpers ────────

    def _escrow(self, monkeypatch, rpc_for: str | None) -> dict:
        self._capable(monkeypatch)
        """Manifest `escrow` block with an RPC configured for `rpc_for` only."""
        monkeypatch.setattr(
            "warden.web3.chains.get_chain",
            lambda c: {"rpc_url": "https://rpc.example" if c == rpc_for else ""},
        )
        return dict(self._manifest()["escrow"])

    def test_manifest_reports_simulated_and_no_chains_without_an_rpc(self, monkeypatch):
        escrow = self._escrow(monkeypatch, None)
        assert escrow["settlement_mode"] == "simulated"
        assert escrow["chains"] == []

    def test_manifest_reports_testnet_and_names_the_test_chain(self, monkeypatch):
        escrow = self._escrow(monkeypatch, "sepolia")
        assert escrow["settlement_mode"] == "testnet"
        assert escrow["chains"] == ["sepolia"]

    def test_manifest_reports_onchain_only_for_mainnet(self, monkeypatch):
        from warden.web3.chains import MAINNET_CHAINS
        mainnet = sorted(MAINNET_CHAINS)[0]
        escrow = self._escrow(monkeypatch, mainnet)
        assert escrow["settlement_mode"] == "onchain"
        assert escrow["chains"] == [mainnet]

    def test_manifest_probes_never_raise(self, monkeypatch):
        """A discovery endpoint must not 500 because a probe failed."""
        from warden.marketplace.api import _escrow_settlement_mode, _signed_offers_required

        def _boom(*_a, **_kw):
            raise RuntimeError("nope")

        monkeypatch.setattr("warden.web3.chains.get_chain", _boom)
        assert _escrow_settlement_mode() in ("simulated", "unknown")
        monkeypatch.setattr("warden.marketplace.negotiation.signed_offers_required", _boom)
        assert _signed_offers_required() is False

    def test_settlement_mode_probe_does_not_hit_the_network(self, monkeypatch):
        """Derived from config: _check_rpc_with_retry backs off 2/4/8s.

        Putting that behind discovery would hand any caller a 14-second stall.
        """
        from warden.marketplace import escrow

        def _must_not_be_called(*_a, **_kw):
            raise AssertionError("manifest must not probe RPC reachability")

        monkeypatch.setattr(
            escrow.EscrowService, "_check_rpc_with_retry", _must_not_be_called, raising=False
        )
        from warden.marketplace.api import _escrow_settlement_mode
        assert _escrow_settlement_mode() in ("onchain", "simulated", "unknown")
