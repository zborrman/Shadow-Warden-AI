"""
warden/tests/test_sdks_target_v1.py — P2.

P2 shipped two things in the same fortnight and did not notice they disagreed.

On 2026-08-23 the gateway started serving every unversioned path with::

    deprecation: true
    sunset: Mon, 23 Aug 2027 00:00:00 GMT
    link: </v1/…>; rel="successor-version"

On 2026-08-26 it published `shadow-warden-sdk` 1.0.0 and `@shadow-warden/sdk`
1.0.0 as the platform's front door — both calling `/filter`, `/tax/calculate`
and `/marketplace/*` unversioned. So the SDK a new integrator installs targets
the surface the same release declared deprecated, with a clock already running
on it. Nothing was broken; it was dated on arrival, silently.

Both SDKs now join the version once, at the point the base URL is built, rather
than at the ~15 path literals — the same seam argument as injecting the escrow's
`tradeId` in `_call_contract`. A path literal is easy to add and easy to add
unversioned, and writing a new method does not remind you.

This file pins the seam rather than the literals. Enumerating the paths here
would be a second copy of the vocabulary, which in this repo reliably drifts.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_PY_SDK = _ROOT / "sdk" / "python"
_TS_SDK = _ROOT / "sdk" / "typescript"


@pytest.fixture(scope="module")
def py_sdk():
    if not (_PY_SDK / "shadow_warden" / "__init__.py").exists():
        pytest.skip("python SDK not present")
    sys.path.insert(0, str(_PY_SDK))
    try:
        yield
    finally:
        sys.path.remove(str(_PY_SDK))


class TestThePythonSdkAddressesTheSupportedSurface:
    def test_every_client_builds_under_the_version(self, py_sdk):
        """All of them, not the one that came to mind.

        There are four separate client classes across three modules, each with
        its own base-URL assignment. That is exactly the shape where a fix lands
        on one and the others keep their old behaviour.
        """
        from shadow_warden.client import AsyncWardenClient, WardenClient  # noqa: PLC0415
        from shadow_warden.commerce import ShadowWardenClient  # noqa: PLC0415

        assert WardenClient(gateway_url="http://x:8001")._base.endswith("/v1")
        assert AsyncWardenClient(gateway_url="http://x:8001")._base.endswith("/v1")
        assert ShadowWardenClient(api_key="k", base_url="http://x:8001")._base_url.endswith("/v1")

    def test_the_legacy_surface_stays_reachable_on_purpose(self, py_sdk):
        """For a gateway older than the alias middleware — the one case where
        the deprecated paths are the correct target rather than an oversight."""
        from shadow_warden.client import WardenClient  # noqa: PLC0415
        assert WardenClient(gateway_url="http://x:8001", api_version=None)._base == "http://x:8001"

    def test_joining_is_idempotent(self, py_sdk):
        """A caller who versioned their own base URL must not get /v1/v1."""
        from shadow_warden.client import WardenClient  # noqa: PLC0415
        assert WardenClient(gateway_url="http://x:8001/v1")._base == "http://x:8001/v1"
        assert WardenClient(gateway_url="http://x:8001/")._base == "http://x:8001/v1"

    def test_the_version_is_declared_once(self, py_sdk):
        from shadow_warden._version_path import API_VERSION  # noqa: PLC0415
        assert API_VERSION == "v1"


class TestTheTypeScriptSdkDoesTheSame:
    @pytest.fixture(scope="class")
    def src(self) -> str:
        p = _TS_SDK / "src" / "client.ts"
        if not p.exists():
            pytest.skip("typescript SDK not present")
        return p.read_text(encoding="utf-8")

    def test_the_base_is_built_through_the_helper(self, src):
        """Not `config.gatewayUrl` straight onto `this.base`, which is what
        shipped in 1.0.0."""
        m = re.search(r"this\.base\s*=\s*(.+)", src)
        assert m, "no base assignment found"
        assert "versionedBase(" in m.group(1), (
            f"base is assigned directly: {m.group(1).strip()[:80]}"
        )

    def test_the_version_constant_matches_python(self, src):
        assert 'API_VERSION = "v1"' in src

    def test_the_config_exposes_an_opt_out(self, src):
        types = (_TS_SDK / "src" / "types.ts").read_text(encoding="utf-8")
        assert "apiVersion" in types


class TestBothSdksShipTheSameVersion:
    """They are released from one tag so they cannot drift from each other or
    from the gateway. A mismatch here means the tag would publish two different
    things under one name."""

    def test_python_and_npm_agree(self):
        if not (_PY_SDK / "pyproject.toml").exists() or not (_TS_SDK / "package.json").exists():
            pytest.skip("SDKs not present")
        py = re.search(r'^version\s*=\s*"([^"]+)"',
                       (_PY_SDK / "pyproject.toml").read_text(encoding="utf-8"), re.M)
        ts = json.loads((_TS_SDK / "package.json").read_text(encoding="utf-8"))["version"]
        assert py and py.group(1) == ts, f"python {py and py.group(1)!r} vs npm {ts!r}"

    def test_the_package_dunder_matches_pyproject(self):
        if not (_PY_SDK / "pyproject.toml").exists():
            pytest.skip("SDK not present")
        init = (_PY_SDK / "shadow_warden" / "__init__.py").read_text(encoding="utf-8")
        dunder = re.search(r'__version__\s*=\s*"([^"]+)"', init)
        py = re.search(r'^version\s*=\s*"([^"]+)"',
                       (_PY_SDK / "pyproject.toml").read_text(encoding="utf-8"), re.M)
        assert dunder and py and dunder.group(1) == py.group(1)
