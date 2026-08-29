"""
sdk/python/tests/test_commerce_agent.py
Merged in from the second SDK tree during the 2026-08-22 consolidation.
SDK client and SecureAgent with mocked HTTP responses.
"""
from __future__ import annotations


class TestShadowWardenClient:
    def _client(self, respx_mock=None):
        from shadow_warden import ShadowWardenClient
        return ShadowWardenClient(api_key="test-key", base_url="http://testserver")

    def test_client_instantiation(self):
        client = self._client()
        # Requests are built under the version segment: the unversioned surface
# carries Deprecation + Sunset 2027-08-23.
        assert client._base_url == "http://testserver/v1"

    def test_headers_contain_api_key(self):
        client = self._client()
        assert "X-API-Key" in client._headers
        assert client._headers["X-API-Key"] == "test-key"

    def test_mandate_payload_structure(self):
        """The body the gateway actually receives — not a dict the test built.

        As inherited from the second SDK tree this asserted `payload["max_amount"]
        == 500.0` on a literal it had just written, and passed whatever the client
        sent. It now intercepts the request.
        """
        import json

        import respx
        with respx.mock(base_url="http://testserver/v1") as mock:
            route = mock.post("/business-community/commerce/mandates").respond(
                200, json={"id": "mand-1"}
            )
            self._client().create_mandate(
                tenant_id="acme", max_amount=500.0, currency="USD",
                allowed_merchants=["shop.com"],
            )

        assert route.called
        sent = json.loads(route.calls[0].request.content)
        assert sent["tenant_id"] == "acme"
        assert sent["max_amount"] == 500.0
        assert sent["allowed_merchants"] == ["shop.com"]


class TestSecureAgent:
    def _agent(self):
        from shadow_warden import SecureAgent
        return SecureAgent(api_key="test-key", tenant_id="acme",
                           base_url="http://testserver")

    def test_agent_instantiation(self):
        agent = self._agent()
        assert agent._tenant_id == "acme"
        assert agent._max_default == 100.0

    def test_agent_no_active_mandate_initially(self):
        agent = self._agent()
        assert agent._active_mandate is None
