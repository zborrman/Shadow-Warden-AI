"""
warden/tests/test_docs_auth.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Tests for HTTP Basic Auth protection of /docs, /redoc, /openapi.json.

Three modes:
  • Dev (DOCS_PASSWORD="")  — all three routes open, no credentials needed
  • Prod (DOCS_PASSWORD set) — correct credentials → 200, wrong → 401, none → 401
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
        # patch main module variables to be sure.
        with (
            patch("warden.main._DOCS_PASSWORD", ""),
            patch("warden.main._DOCS_USERNAME", "warden"),
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
            patch("warden.main._DOCS_PASSWORD", "s3cr3tP@ssw0rd"),
            patch("warden.main._DOCS_USERNAME", "warden"),
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
