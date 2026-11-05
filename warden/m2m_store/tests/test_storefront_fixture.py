"""The portal's offline storefront audit replays a recorded API answer (M6).

`portal/e2e/mock-gateway.mjs` serves `portal/e2e/fixtures/storefront.json`,
recorded from this router by `scripts/storefront_fixture.py`. If the router's
answers change shape and nobody re-records, the audit keeps passing against a
storefront API that no longer exists. Keys and JSON types must match.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _ROOT / "scripts" / "storefront_fixture.py"


def _module():
    spec = importlib.util.spec_from_file_location("storefront_fixture", _SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["storefront_fixture"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_recorded_fixture_has_the_routers_shape(monkeypatch, tmp_path):
    mod = _module()
    # record() points the module DBs at a fresh temp dir; keep the env change local.
    for key in ("M2M_STORE_DB_PATH", "WARDEN_DATA_DIR", "VAULT_MASTER_KEY", "PORTAL_JWT_SECRET",
                "REDIS_URL", "ANTHROPIC_API_KEY", "ALLOW_UNAUTHENTICATED", "WARDEN_API_KEY"):
        monkeypatch.setenv(key, os.environ.get(key, ""))
    import warden.storage.s3 as s3
    monkeypatch.setattr(s3, "object_client", s3.object_client)
    live = mod.record()
    committed = json.loads(mod.FIXTURE.read_text(encoding="utf-8"))
    assert mod.shape(committed) == mod.shape(live), (
        "the storefront API changed shape: run python scripts/storefront_fixture.py"
    )


def test_fixture_holds_no_contact_details():
    text = (_ROOT / "portal" / "e2e" / "fixtures" / "storefront.json").read_text(encoding="utf-8")
    for value in ("Fixture Buyer", "buyer@example.org", "1 Example Street", "buyer_token"):
        assert value not in text, value
