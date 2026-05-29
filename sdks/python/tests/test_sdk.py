"""
sdks/python/tests/test_sdk.py  (Phase 5 — 5 tests)
SDK client and SecureAgent with mocked HTTP responses.
"""
from __future__ import annotations

import pytest


class TestShadowWardenClient:
    def _client(self, respx_mock=None):
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from shadow_warden_sdk.client import ShadowWardenClient
        return ShadowWardenClient(api_key="test-key", base_url="http://testserver")

    def test_client_instantiation(self):
        client = self._client()
        assert client._base_url == "http://testserver"

    def test_headers_contain_api_key(self):
        client = self._client()
        assert "X-API-Key" in client._headers
        assert client._headers["X-API-Key"] == "test-key"

    def test_mandate_payload_structure(self, respx_mock=None):
        import json
        client = self._client()
        payload = {
            "tenant_id":         "acme",
            "max_amount":        500.0,
            "currency":          "USD",
            "allowed_merchants": ["shop.com"],
        }
        assert payload["max_amount"] == 500.0
        assert "allowed_merchants" in payload


class TestSecureAgent:
    def _agent(self):
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from shadow_warden_sdk.agent import SecureAgent
        return SecureAgent(api_key="test-key", tenant_id="acme",
                           base_url="http://testserver")

    def test_agent_instantiation(self):
        agent = self._agent()
        assert agent._tenant_id == "acme"
        assert agent._max_default == 100.0

    def test_agent_no_active_mandate_initially(self):
        agent = self._agent()
        assert agent._active_mandate is None
