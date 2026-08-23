"""
warden/tests/test_api_versioning.py — P2.

`openapi.json` publishes 562 unversioned paths, every one a contract the moment an
external agent calls it. These tests pin the two halves of the fix: `/v1` reaches
the same handler, and the unversioned form says when it stops.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from warden.api_versioning import (
    API_VERSION,
    APIVersionMiddleware,
    _sunset_http_date,
    is_exempt,
    version_info,
)


@pytest.fixture()
def client() -> TestClient:
    app = FastAPI()

    @app.get("/filter-ish")
    async def _api() -> dict:
        return {"ok": True}

    @app.get("/health")
    async def _health() -> dict:
        return {"status": "ok"}

    @app.post("/v1/chat/completions")
    async def _openai() -> dict:
        # The OpenAI-compatible surface genuinely lives under /v1 — that is where
        # every OpenAI client looks — and must not be rewritten away.
        return {"object": "chat.completion"}

    @app.get("/.well-known/agent.json")
    async def _card() -> dict:
        return {"schema_version": "1.0"}

    app.add_middleware(APIVersionMiddleware)
    return TestClient(app)


class TestVersionedPath:
    def test_v1_reaches_the_same_handler(self, client):
        assert client.get("/v1/filter-ish").json() == {"ok": True}

    def test_v1_response_is_not_deprecated(self, client):
        r = client.get("/v1/filter-ish")
        assert "Deprecation" not in r.headers
        assert "Sunset" not in r.headers

    def test_unknown_path_still_404s_under_v1(self, client):
        """The prefix is an alias, not a catch-all."""
        assert client.get("/v1/no-such-route").status_code == 404


class TestUnversionedPath:
    def test_still_served(self, client):
        assert client.get("/filter-ish").json() == {"ok": True}

    def test_carries_the_deprecation_contract(self, client):
        r = client.get("/filter-ish")
        assert r.headers["Deprecation"] == "true"
        assert r.headers["Sunset"].endswith("GMT"), r.headers["Sunset"]
        assert r.headers["Link"] == '</v1/filter-ish>; rel="successor-version"'

    def test_successor_link_points_at_the_same_resource(self, client):
        """A link to a path that does not exist is worse than no link."""
        link = client.get("/filter-ish").headers["Link"]
        successor = link.split("<", 1)[1].split(">", 1)[0]
        assert client.get(successor).json() == {"ok": True}


class TestPathsThatAlreadyOwnV1:
    def test_openai_compatible_surface_is_not_rewritten(self, client):
        """Stripping /v1 here turns a working endpoint into a 404.

        This is what the CI suite caught: `warden/openai_proxy.py` mounts
        `APIRouter(prefix="/v1")`, so `/v1/chat/completions` is a real route.
        """
        r = client.post("/v1/chat/completions", json={})
        assert r.status_code == 200, r.status_code
        assert r.json() == {"object": "chat.completion"}

    def test_alias_still_works_for_paths_nobody_owns(self, client):
        assert client.get("/v1/filter-ish").json() == {"ok": True}

    def test_wrong_method_on_an_owned_v1_path_is_405_not_404(self, client):
        """Match.PARTIAL means the path is owned; 405 is the honest answer."""
        assert client.get("/v1/chat/completions").status_code == 405


class TestExemptions:
    @pytest.mark.parametrize("path", ["/health", "/.well-known/agent.json"])
    def test_infrastructure_and_discovery_are_not_deprecated(self, client, path):
        """These are not moving, so saying they are would be untrue."""
        r = client.get(path)
        assert r.status_code == 200
        assert "Deprecation" not in r.headers

    def test_exempt_matching_is_prefix_based_not_substring(self):
        assert is_exempt("/health")
        assert is_exempt("/health/pipeline")
        assert is_exempt("/metrics")
        assert not is_exempt("/healthy-agents")
        assert not is_exempt("/filter")


class TestContract:
    def test_sunset_is_an_http_date(self):
        assert _sunset_http_date("2027-08-23") == "Mon, 23 Aug 2027 00:00:00 GMT"

    def test_a_malformed_override_is_passed_through_not_crashed(self):
        assert _sunset_http_date("whenever") == "whenever"

    def test_version_info_publishes_the_window(self):
        info = version_info()
        assert info["current"] == API_VERSION
        assert info["prefix"] == f"/{API_VERSION}"
        assert info["unversioned_supported_until"]
