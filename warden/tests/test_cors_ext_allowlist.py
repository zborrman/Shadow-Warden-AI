"""
SR-2.4 — CORS hardening.

Two holes:
  1. /ext/* returned `Access-Control-Allow-Origin: *` to EVERY origin, so any web page
     could invoke the extension API from a browser context. The extension ID is unknown
     at build time so a full origin can't be pinned — but the *scheme* can, and no
     ordinary page can forge chrome-extension://.
  2. CORS_ORIGINS=* combined with allow_credentials=True: Starlette does not reject that
     pair — it reflects the Origin *and* sends Allow-Credentials, i.e. full credentialed
     cross-origin access from anywhere.
"""
from __future__ import annotations

import pytest

from warden.main import _cors_origins, _ext_allowed_origin


class TestExtOriginAllowlist:
    @pytest.mark.parametrize("origin", [
        "chrome-extension://abcdefghijklmnop",
        "moz-extension://1234-5678",
        "safari-web-extension://xyz",
    ])
    def test_extension_schemes_allowed(self, origin):
        assert _ext_allowed_origin(origin) == origin

    @pytest.mark.parametrize("origin", [
        "https://evil.example.com",
        "http://localhost:3000",
        "https://gemini.google.com",     # fine for the main API, not for /ext/*
        "null",
        "",
    ])
    def test_web_origins_rejected(self, origin):
        assert _ext_allowed_origin(origin) is None

    def test_explicit_allowlist_env(self, monkeypatch):
        monkeypatch.setenv("EXT_CORS_ORIGINS", "https://partner.example.com")
        assert _ext_allowed_origin("https://partner.example.com") == "https://partner.example.com"
        assert _ext_allowed_origin("https://evil.example.com") is None

    def test_scheme_prefix_cannot_be_spoofed_by_substring(self):
        # Must be a prefix match, not "contains" — a hostile host can embed the text.
        assert _ext_allowed_origin("https://chrome-extension://x.evil.com") is None
        assert _ext_allowed_origin("https://evil.com/chrome-extension://") is None


class TestCorsOriginsWildcardRefused:
    def test_wildcard_is_refused(self, monkeypatch):
        monkeypatch.setenv("CORS_ORIGINS", "*")
        origins = _cors_origins()
        assert "*" not in origins       # never wildcard while credentials are on
        assert origins                  # falls back to the explicit default allowlist

    def test_wildcard_stripped_from_mixed_list(self, monkeypatch):
        monkeypatch.setenv("CORS_ORIGINS", "https://a.example.com,*")
        origins = _cors_origins()
        assert "*" not in origins
        assert "https://a.example.com" in origins

    def test_explicit_list_passes_through(self, monkeypatch):
        monkeypatch.setenv("CORS_ORIGINS", "https://a.example.com,https://b.example.com")
        assert _cors_origins() == ["https://a.example.com", "https://b.example.com"]
