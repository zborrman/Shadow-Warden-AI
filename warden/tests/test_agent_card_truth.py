"""
warden/tests/test_agent_card_truth.py — P2.

`/.well-known/agent.json` is this node's machine-readable identity. A foreign
agent reads it to decide how to authenticate, what to send, and whether it has
to pay — with no human in the loop to notice that a field is stale or that a
"false" is a string. Everything else in the document is checked by
`test_agent_discovery.py`, which asks whether the fields are *present*. These
tests ask whether they are *true*, which is a different question and the one
that was failing.

Two things were wrong when this file was written:

  - `version` was pinned at "5.6.0" while the gateway shipped 7.9.0. pyproject
    already names `warden.__version__` the single version of record; the
    discovery document simply did not read it.

  - `payment_schemes[].enabled` carried the string "false". Python, JavaScript,
    Ruby and PHP all consider a non-empty string true, so a disabled payment
    gate advertised itself as enabled to every consumer that wrote the obvious
    `if scheme["enabled"]`. The gate itself was off, so this was an interop
    defect rather than a hole — an agent would send a signature nobody asked
    for — but a flag that cannot express "off" is not a flag.
"""
from __future__ import annotations

import json

import pytest

from warden import __version__
from warden.protocols.a2a.agent_card import build_agent_card


@pytest.fixture()
def card() -> dict:
    return build_agent_card()


class TestTheVersionIsTheRealOne:
    def test_the_card_reports_the_package_version(self, card):
        assert card["version"] == __version__

    def test_the_version_is_not_a_literal_in_the_source(self):
        """A hardcoded version is correct exactly until the next release."""
        from pathlib import Path
        src = Path(__file__).resolve().parents[1] / "protocols" / "a2a" / "agent_card.py"
        body = src.read_text(encoding="utf-8")
        line = next(ln for ln in body.splitlines() if ln.startswith("_AGENT_VER"))
        assert "__version__" in line, f"version pinned by hand: {line!r}"


class TestBooleansAreBooleans:
    def test_payment_enabled_is_a_real_boolean(self, card):
        """`"false"` is true in every language a consumer is likely to use."""
        for scheme in card["payment_schemes"]:
            assert isinstance(scheme["enabled"], bool), (
                f"{scheme['scheme']}.enabled is {type(scheme['enabled']).__name__} "
                f"{scheme['enabled']!r}; a consumer doing `if enabled:` reads it as on"
            )

    def test_the_disabled_gate_advertises_itself_as_disabled(self, card, monkeypatch):
        """The shape that shipped: the gate off, the document saying otherwise."""
        from warden.config import settings
        monkeypatch.setattr(settings, "x402_gate_enabled", False)
        scheme = next(s for s in build_agent_card()["payment_schemes"]
                      if s["scheme"].startswith("x402"))
        assert scheme["enabled"] is False
        assert bool(scheme["enabled"]) is False, "truthiness must agree with the value"

    def test_an_enabled_gate_says_so(self, card, monkeypatch):
        from warden.config import settings
        monkeypatch.setattr(settings, "x402_gate_enabled", True)
        scheme = next(s for s in build_agent_card()["payment_schemes"]
                      if s["scheme"].startswith("x402"))
        assert scheme["enabled"] is True

    @pytest.mark.parametrize("raw,expected", [
        ("true", True), ("TRUE", True), ("  true  ", False),
        ("yes", False), ("1", False), ("false", False), ("", False),
    ])
    def test_the_setting_only_accepts_true(self, monkeypatch, raw, expected):
        """The gate enables on "true" alone; the card must not disagree.

        `_bool()` in config.py treats anything not in false/0/no/off as true,
        which would have made X402_GATE_ENABLED=yes mean "off" at the gate and
        "on" in the document.

        A fresh `Settings()` re-runs every `default_factory`, so it reads the
        patched environment without `importlib.reload`. Reloading the module
        would swap `warden.config.settings` for a new object while every
        importer still holds the old one — which broke three unrelated tests
        further down the run the first time this was written.
        """
        from warden.config import Settings
        monkeypatch.setenv("X402_GATE_ENABLED", raw)
        assert Settings().x402_gate_enabled is expected


class TestTheDocumentSurvivesSerialisation:
    def test_the_card_is_json(self, card):
        """It is served as JSON; anything unserialisable is a 500 at discovery."""
        json.dumps(card)


class TestTheServedDocument:
    """The wire, not the builder.

    `/.well-known/agent.json` returns the A2A card merged with the marketplace
    manifest, so a field can be correct in `build_agent_card()` and wrong by the
    time an agent reads it — the marketplace half wins any collision.
    """

    @pytest.fixture()
    def served(self) -> dict:
        from fastapi.testclient import TestClient

        import warden.main as m
        resp = TestClient(m.app, raise_server_exceptions=False).get("/.well-known/agent.json")
        assert resp.status_code == 200
        return resp.json()

    def test_the_served_version_is_the_package_version(self, served):
        assert served["version"] == __version__

    def test_the_served_payment_flags_are_booleans(self, served):
        for scheme in served.get("payment_schemes", []):
            assert isinstance(scheme["enabled"], bool), (
                f"{scheme['scheme']}.enabled survived the merge as "
                f"{scheme['enabled']!r}"
            )

    def test_settlement_mode_is_one_of_the_four_honest_answers(self, served):
        """P1a's whole point: escrow claims describe capability, not config."""
        mode = served.get("escrow", {}).get("settlement_mode")
        assert mode in {"onchain", "testnet", "simulated", "unknown"}, mode
