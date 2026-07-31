"""
warden/tests/test_docs_auth.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Tests for HTTP Basic Auth protection of /docs, /redoc, /openapi.json.

Three modes:
  • Dev (DOCS_PASSWORD="")  — all three routes open, no credentials needed
  • Prod (DOCS_PASSWORD set) — correct credentials → 200, wrong → 401, none → 401

The handlers and the auth dependency live in warden/api/docs_router.py (P-2) —
patch that module's constants, not warden.main's.

/openapi-public.json is deliberately excluded from both classes above: it is
never gated by DOCS_PASSWORD, in any mode, by design (see its docstring in
docs_router.py — docs.shadow-warden-ai.com fetches it cross-origin without
credentials). test_openapi_public_is_always_open pins that on its own, so a
future change to _docs_auth cannot silently start gating it, or silently stop.
"""
from __future__ import annotations

import base64
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from warden.main import app

# ── Helper ────────────────────────────────────────────────────────────────────

def _basic(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {token}"


# ── Dev mode (DOCS_PASSWORD="" — default in CI / conftest) ───────────────────

class TestDocsDevMode:
    """When DOCS_PASSWORD is empty, docs are served without credentials."""

    @pytest.fixture(autouse=True)
    def _client(self):
        # conftest already sets DOCS_PASSWORD="" via os.environ.setdefault —
        # patch the docs_router module variables to be sure.
        with (
            patch("warden.api.docs_router._DOCS_PASSWORD", ""),
            patch("warden.api.docs_router._DOCS_USERNAME", "warden"),
        ):
            self.client = TestClient(app, raise_server_exceptions=True)
            yield  # keep patch active during the test

    def test_docs_open_without_credentials(self) -> None:
        resp = self.client.get("/docs")
        assert resp.status_code == 200
        assert "swagger" in resp.text.lower() or "openapi" in resp.text.lower()

    def test_redoc_open_without_credentials(self) -> None:
        resp = self.client.get("/redoc")
        assert resp.status_code == 200
        assert "redoc" in resp.text.lower()

    def test_openapi_json_open_without_credentials(self) -> None:
        resp = self.client.get("/openapi.json")
        assert resp.status_code == 200
        data = resp.json()
        assert "openapi" in data
        assert "paths" in data

    def test_openapi_json_contains_expected_routes(self) -> None:
        resp = self.client.get("/openapi.json")
        assert resp.status_code == 200
        paths = resp.json()["paths"]
        assert "/health" in paths
        assert "/filter" in paths


# ── Production mode (DOCS_PASSWORD set) ──────────────────────────────────────

class TestDocsProductionMode:
    """When DOCS_PASSWORD is set, Basic Auth is required."""

    @pytest.fixture(autouse=True)
    def _client(self):
        with (
            patch("warden.api.docs_router._DOCS_PASSWORD", "s3cr3tP@ssw0rd"),
            patch("warden.api.docs_router._DOCS_USERNAME", "warden"),
        ):
            self.client = TestClient(app, raise_server_exceptions=True)
            yield  # keep patch active during the test

    # ── /docs ─────────────────────────────────────────────────────────────

    def test_docs_no_credentials_returns_401(self) -> None:
        resp = self.client.get("/docs")
        assert resp.status_code == 401
        assert resp.headers.get("www-authenticate", "").startswith("Basic")

    def test_docs_wrong_password_returns_401(self) -> None:
        resp = self.client.get(
            "/docs", headers={"Authorization": _basic("warden", "wrong")}
        )
        assert resp.status_code == 401

    def test_docs_wrong_username_returns_401(self) -> None:
        resp = self.client.get(
            "/docs", headers={"Authorization": _basic("admin", "s3cr3tP@ssw0rd")}
        )
        assert resp.status_code == 401

    def test_docs_correct_credentials_returns_200(self) -> None:
        resp = self.client.get(
            "/docs", headers={"Authorization": _basic("warden", "s3cr3tP@ssw0rd")}
        )
        assert resp.status_code == 200

    # ── /redoc ────────────────────────────────────────────────────────────

    def test_redoc_no_credentials_returns_401(self) -> None:
        resp = self.client.get("/redoc")
        assert resp.status_code == 401

    def test_redoc_correct_credentials_returns_200(self) -> None:
        resp = self.client.get(
            "/redoc", headers={"Authorization": _basic("warden", "s3cr3tP@ssw0rd")}
        )
        assert resp.status_code == 200

    # ── /openapi.json ──────────────────────────────────────────────────────

    def test_openapi_no_credentials_returns_401(self) -> None:
        resp = self.client.get("/openapi.json")
        assert resp.status_code == 401

    def test_openapi_correct_credentials_returns_200(self) -> None:
        resp = self.client.get(
            "/openapi.json",
            headers={"Authorization": _basic("warden", "s3cr3tP@ssw0rd")},
        )
        assert resp.status_code == 200
        assert "paths" in resp.json()

    # ── Timing-safe comparison (no timing oracle) ──────────────────────────

    def test_empty_credentials_returns_401(self) -> None:
        """Empty username + password must be rejected, not crash."""
        resp = self.client.get(
            "/docs", headers={"Authorization": _basic("", "")}
        )
        assert resp.status_code == 401

    def test_health_still_accessible_without_credentials(self) -> None:
        """Non-doc routes must not be affected by docs auth."""
        resp = self.client.get("/health")
        assert resp.status_code == 200


# ── /openapi-public.json ──────────────────────────────────────────────────────


def test_openapi_public_is_always_open() -> None:
    """
    Unlike the other three, this route ignores DOCS_PASSWORD entirely — pinned
    directly against warden.main.app rather than the patched-password fixtures
    above, since the point is that no patch changes this one's behavior.
    """
    with (
        patch("warden.api.docs_router._DOCS_PASSWORD", "s3cr3tP@ssw0rd"),
        patch("warden.api.docs_router._DOCS_USERNAME", "warden"),
    ):
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/openapi-public.json")
        assert resp.status_code == 200
        assert "paths" in resp.json()


def test_openapi_public_serves_the_same_schema_as_the_gated_one() -> None:
    """
    Both routes call app.openapi() with no filtering — this pins that the two
    stay identical rather than silently diverging, and documents (via the
    module docstring, not this test) that DOCS_PASSWORD therefore does not
    actually stop schema/route enumeration while this endpoint exists.
    """
    with patch("warden.api.docs_router._DOCS_PASSWORD", ""):
        client = TestClient(app, raise_server_exceptions=True)
        gated = client.get("/openapi.json").json()
        public = client.get("/openapi-public.json").json()
        assert gated == public
