"""
warden/tests/test_first_party_supply.py — P3.

Seeding a market is the one job where writing rows is trivially easy and being
right is the whole point. Twenty listings in a table take one loop; twenty
listings that correspond to capabilities the gateway actually serves take a
check, and the difference does not show up until a buyer pays for one.

So the tests here are about refusal, not creation:

  - a catalogue entry whose route the gateway does not serve must not be listed
  - a second run must add nothing
  - the asset vocabulary advertised to agents must be the one that is enforced

That last one was a live defect. `/marketplace/protocol` advertised
`asset_type: "general"` and `register_asset` rejected it with a 422, because the
enum was written out twice. An agent reading the machine-readable schema and
believing it got an error.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "scripts" / "seed_first_party_supply.py"


def _seeder():
    if not _SCRIPT.exists():
        pytest.skip("seed_first_party_supply.py not present")
    spec = importlib.util.spec_from_file_location("seed_fps", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def seeder():
    return _seeder()


class TestTheVocabularyIsNotWrittenTwice:
    def test_the_manifest_advertises_exactly_what_is_enforced(self):
        """The `general` bug: advertised, rejected, nobody noticed."""
        from warden.marketplace.api import _PROTOCOL_SCHEMAS  # noqa: PLC0415
        from warden.marketplace.service import VALID_ASSET_TYPES  # noqa: PLC0415

        advertised = set(
            _PROTOCOL_SCHEMAS["search"]["properties"]["asset_type"]["enum"]
        )
        assert advertised == set(VALID_ASSET_TYPES), (
            f"the manifest offers {sorted(advertised - set(VALID_ASSET_TYPES))} "
            f"that register_asset rejects, and omits "
            f"{sorted(set(VALID_ASSET_TYPES) - advertised)}"
        )

    def test_services_and_reports_can_be_expressed(self):
        """What this platform sells is mostly neither a rule nor a model."""
        from warden.marketplace.service import VALID_ASSET_TYPES  # noqa: PLC0415
        assert {"service", "report"} <= set(VALID_ASSET_TYPES)

    def test_a_metered_service_must_name_its_endpoint(self):
        """Otherwise the buyer has bought a name and finds out after paying."""
        from warden.marketplace.tokenizer import AssetTokenizer  # noqa: PLC0415
        with pytest.raises(ValueError, match="endpoint"):
            AssetTokenizer().tokenize_service({"name": "x"}, None, "a", "c")


class TestTheCatalogueIsHonest:
    def test_every_entry_has_a_verify_path(self, seeder):
        for e in seeder.CATALOGUE:
            assert e["verify"].startswith("/"), e["sku"]
            assert e["price"] > 0, e["sku"]

    def test_skus_are_unique(self, seeder):
        """A duplicate sku would make the idempotency check silently wrong."""
        skus = [e["sku"] for e in seeder.CATALOGUE]
        assert len(skus) == len(set(skus))

    def test_every_asset_type_is_one_the_marketplace_accepts(self, seeder):
        """The catalogue invented `feed` and `service` before either existed.

        `feed` was the mistake — `signals` already meant a threat feed — and
        two listings failed with a 422 that this test would have caught.
        """
        from warden.marketplace.service import VALID_ASSET_TYPES  # noqa: PLC0415
        for e in seeder.CATALOGUE:
            assert e["type"] in VALID_ASSET_TYPES, f"{e['sku']} is a {e['type']!r}"


class TestItRefusesWhatItCannotVerify:
    def test_an_unserved_route_is_skipped_not_listed(self, seeder, monkeypatch, capsys):
        """The whole point. Supply that the gateway cannot deliver is not supply."""
        class _Resp:
            status_code = 200

            @staticmethod
            def json():
                return {"paths": {"/filter": {}}}   # only one of the twenty

        class _Client:
            def get(self, *a, **kw):
                return _Resp()

        monkeypatch.setattr(seeder, "_client", lambda *a: _Client())
        monkeypatch.setattr("sys.argv", ["seed"])
        rc = seeder.main()
        out = capsys.readouterr().out
        assert rc == 0
        assert "19 skipped" in out, out
        assert "is not served here" in out

    def test_no_openapi_means_nothing_is_listed(self, seeder, monkeypatch, capsys):
        """A gateway that will not describe itself cannot be sold on trust."""
        class _Client:
            def get(self, *a, **kw):
                return type("R", (), {"status_code": 503, "json": staticmethod(dict)})()

        monkeypatch.setattr(seeder, "_client", lambda *a: _Client())
        monkeypatch.setattr("sys.argv", ["seed"])
        assert seeder.main() == 1
        assert "cannot verify any capability" in capsys.readouterr().out

    def test_dry_run_is_the_default(self, seeder):
        """--commit writes rows to a real marketplace; it should be deliberate."""
        src = _SCRIPT.read_text(encoding="utf-8")
        assert '"--commit", action="store_true"' in src
        assert "--no-commit" not in src, "commit must be opt-in, not opt-out"
