"""
Tests for warden/providers/bedrock.py and openai_proxy Azure routing.

Covers:
  • oai_to_converse   — payload conversion (OpenAI → Bedrock Converse)
  • converse_to_oai   — response conversion (Bedrock → OpenAI)
  • _sigv4_headers    — AWS SigV4 header generation (structure, not crypto correctness)
  • call_bedrock      — end-to-end with mocked httpx
  • _resolve_upstream — Azure URL building + api-key header; Bedrock sentinel
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from warden.providers.bedrock import (
    _sigv4_headers,
    call_bedrock,
    converse_to_oai,
    oai_to_converse,
)

# ── oai_to_converse ────────────────────────────────────────────────────────────

class TestOaiToConverse:
    def test_basic_user_message(self):
        payload = {
            "model": "bedrock/amazon.nova-lite-v1:0",
            "messages": [{"role": "user", "content": "Hello"}],
        }
        result, model_id = oai_to_converse(payload)
        assert model_id == "amazon.nova-lite-v1:0"
        assert result["messages"] == [
            {"role": "user", "content": [{"text": "Hello"}]}
        ]
        assert "system" not in result

    def test_system_message_extracted(self):
        payload = {
            "model": "bedrock/anthropic.claude-3-haiku-20240307-v1:0",
            "messages": [
                {"role": "system", "content": "You are helpful"},
                {"role": "user",   "content": "Hi"},
            ],
        }
        result, _ = oai_to_converse(payload)
        assert result["system"] == [{"text": "You are helpful"}]
        assert len(result["messages"]) == 1
        assert result["messages"][0]["role"] == "user"

    def test_multi_turn_conversation(self):
        payload = {
            "model": "bedrock/meta.llama3-8b-instruct-v1:0",
            "messages": [
                {"role": "user",      "content": "What is 2+2?"},
                {"role": "assistant", "content": "4"},
                {"role": "user",      "content": "And 3+3?"},
            ],
        }
        result, _ = oai_to_converse(payload)
        assert len(result["messages"]) == 3
        assert result["messages"][1]["role"] == "assistant"
        assert result["messages"][1]["content"] == [{"text": "4"}]

    def test_inference_config_mapped(self):
        payload = {
            "model": "bedrock/amazon.nova-lite-v1:0",
            "messages": [{"role": "user", "content": "Hi"}],
            "max_tokens": 512,
            "temperature": 0.7,
            "top_p": 0.9,
            "stop": ["END"],
        }
        result, _ = oai_to_converse(payload)
        cfg = result["inferenceConfig"]
        assert cfg["maxTokens"] == 512
        assert cfg["temperature"] == 0.7
        assert cfg["topP"] == 0.9
        assert cfg["stopSequences"] == ["END"]

    def test_stop_string_wrapped_in_list(self):
        payload = {
            "model": "bedrock/amazon.nova-lite-v1:0",
            "messages": [{"role": "user", "content": "Hi"}],
            "stop": "STOP",
        }
        result, _ = oai_to_converse(payload)
        assert result["inferenceConfig"]["stopSequences"] == ["STOP"]

    def test_no_inference_config_when_empty(self):
        payload = {
            "model": "bedrock/amazon.nova-lite-v1:0",
            "messages": [{"role": "user", "content": "Hi"}],
        }
        result, _ = oai_to_converse(payload)
        assert "inferenceConfig" not in result

    def test_multipart_content_blocks(self):
        payload = {
            "model": "bedrock/amazon.nova-lite-v1:0",
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "text", "text": "Describe this"},
                    {"type": "image_url", "image_url": {"url": "http://example.com/img.png"}},
                ],
            }],
        }
        result, _ = oai_to_converse(payload)
        blocks = result["messages"][0]["content"]
        assert blocks[0] == {"text": "Describe this"}
        assert blocks[1] == {"text": "[image]"}

    def test_model_id_without_prefix_passed_through(self):
        """If model doesn't start with 'bedrock/' the raw string is used."""
        payload = {
            "model": "amazon.nova-lite-v1:0",
            "messages": [{"role": "user", "content": "Hi"}],
        }
        _, model_id = oai_to_converse(payload)
        assert model_id == "amazon.nova-lite-v1:0"

    def test_unknown_role_falls_back_to_user(self):
        payload = {
            "model": "bedrock/amazon.nova-lite-v1:0",
            "messages": [{"role": "function", "content": "result"}],
        }
        result, _ = oai_to_converse(payload)
        assert result["messages"][0]["role"] == "user"


# ── converse_to_oai ────────────────────────────────────────────────────────────

class TestConverseToOai:
    def _bedrock_resp(self, text="Hello!", stop="end_turn", inp=10, out=5):
        return {
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": text}],
                }
            },
            "stopReason": stop,
            "usage": {"inputTokens": inp, "outputTokens": out, "totalTokens": inp + out},
        }

    def test_basic_response_shape(self):
        result = converse_to_oai(self._bedrock_resp(), "bedrock/amazon.nova-lite-v1:0")
        assert result["object"] == "chat.completion"
        assert result["model"] == "bedrock/amazon.nova-lite-v1:0"
        assert len(result["choices"]) == 1
        choice = result["choices"][0]
        assert choice["message"]["role"] == "assistant"
        assert choice["message"]["content"] == "Hello!"
        assert choice["finish_reason"] == "stop"

    def test_finish_reason_end_turn_maps_to_stop(self):
        result = converse_to_oai(self._bedrock_resp(stop="end_turn"), "m")
        assert result["choices"][0]["finish_reason"] == "stop"

    def test_finish_reason_stop_sequence(self):
        result = converse_to_oai(self._bedrock_resp(stop="stop_sequence"), "m")
        assert result["choices"][0]["finish_reason"] == "stop"

    def test_finish_reason_other_passthrough(self):
        result = converse_to_oai(self._bedrock_resp(stop="max_tokens"), "m")
        assert result["choices"][0]["finish_reason"] == "max_tokens"

    def test_usage_tokens(self):
        result = converse_to_oai(self._bedrock_resp(inp=20, out=30), "m")
        assert result["usage"]["prompt_tokens"] == 20
        assert result["usage"]["completion_tokens"] == 30
        assert result["usage"]["total_tokens"] == 50

    def test_total_tokens_fallback_to_sum(self):
        resp = {
            "output": {"message": {"role": "assistant", "content": [{"text": "Hi"}]}},
            "stopReason": "end_turn",
            "usage": {"inputTokens": 5, "outputTokens": 3},  # no totalTokens key
        }
        result = converse_to_oai(resp, "m")
        assert result["usage"]["total_tokens"] == 8

    def test_multiple_content_blocks_joined(self):
        resp = {
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": "Part1"}, {"text": "Part2"}],
                }
            },
            "stopReason": "end_turn",
            "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
        }
        result = converse_to_oai(resp, "m")
        assert result["choices"][0]["message"]["content"] == "Part1Part2"

    def test_id_has_bedrock_prefix(self):
        result = converse_to_oai(self._bedrock_resp(), "m")
        assert result["id"].startswith("chatcmpl-bedrock-")


# ── _sigv4_headers ─────────────────────────────────────────────────────────────

class TestSigV4Headers:
    def _call(self, method="POST", url="https://bedrock-runtime.us-east-1.amazonaws.com/model/x/converse"):
        return _sigv4_headers(
            method=method,
            url=url,
            body=b'{"messages":[]}',
            region="us-east-1",
            service="bedrock",
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )

    def test_returns_required_headers(self):
        hdrs = self._call()
        assert "Authorization" in hdrs
        assert "X-Amz-Date" in hdrs
        assert "X-Amz-Content-SHA256" in hdrs
        assert "Content-Type" in hdrs

    def test_authorization_scheme(self):
        hdrs = self._call()
        assert hdrs["Authorization"].startswith("AWS4-HMAC-SHA256 ")

    def test_authorization_contains_credential(self):
        hdrs = self._call()
        assert "Credential=AKIAIOSFODNN7EXAMPLE/" in hdrs["Authorization"]

    def test_authorization_contains_signed_headers(self):
        hdrs = self._call()
        assert "SignedHeaders=" in hdrs["Authorization"]
        assert "host" in hdrs["Authorization"]

    def test_authorization_contains_signature(self):
        hdrs = self._call()
        assert "Signature=" in hdrs["Authorization"]

    def test_date_format(self):
        hdrs = self._call()
        # e.g. "20260323T120000Z"
        assert len(hdrs["X-Amz-Date"]) == 16
        assert hdrs["X-Amz-Date"].endswith("Z")

    def test_content_sha256_is_hex(self):
        hdrs = self._call()
        sha = hdrs["X-Amz-Content-SHA256"]
        assert len(sha) == 64
        int(sha, 16)  # raises ValueError if not valid hex

    def test_different_body_different_sha(self):
        h1 = _sigv4_headers("POST", "https://bedrock-runtime.us-east-1.amazonaws.com/model/x/converse",
                             b'{"a":1}', "us-east-1", "bedrock", "KEY", "SECRET")
        h2 = _sigv4_headers("POST", "https://bedrock-runtime.us-east-1.amazonaws.com/model/x/converse",
                             b'{"a":2}', "us-east-1", "bedrock", "KEY", "SECRET")
        assert h1["X-Amz-Content-SHA256"] != h2["X-Amz-Content-SHA256"]


# ── call_bedrock (integration with mocked httpx) ──────────────────────────────

class TestCallBedrock:
    def _mock_response(self, text="Test response"):
        bedrock_body = {
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": text}],
                }
            },
            "stopReason": "end_turn",
            "usage": {"inputTokens": 10, "outputTokens": 5, "totalTokens": 15},
        }
        mock_resp = MagicMock()
        mock_resp.json.return_value = bedrock_body
        mock_resp.raise_for_status = MagicMock()
        return mock_resp

    @pytest.mark.asyncio
    async def test_returns_openai_format(self):
        mock_resp = self._mock_response("Hello from Bedrock")
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("warden.providers.bedrock.httpx.AsyncClient", return_value=mock_client):
            result = await call_bedrock(
                {"model": "bedrock/amazon.nova-lite-v1:0",
                 "messages": [{"role": "user", "content": "Hi"}]},
                region="us-east-1",
                access_key="AKID",
                secret_key="SECRET",
            )

        assert result["object"] == "chat.completion"
        assert result["choices"][0]["message"]["content"] == "Hello from Bedrock"
        assert result["usage"]["total_tokens"] == 15

    @pytest.mark.asyncio
    async def test_posts_to_correct_bedrock_url(self):
        mock_resp = self._mock_response()
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("warden.providers.bedrock.httpx.AsyncClient", return_value=mock_client):
            await call_bedrock(
                {"model": "bedrock/meta.llama3-8b-instruct-v1:0",
                 "messages": [{"role": "user", "content": "Hi"}]},
                region="eu-west-1",
                access_key="K",
                secret_key="S",
            )

        call_args = mock_client.post.call_args
        url = call_args[0][0]
        assert "bedrock-runtime.eu-west-1.amazonaws.com" in url
        assert "meta.llama3-8b-instruct-v1:0" in url
        assert url.endswith("/converse")

    @pytest.mark.asyncio
    async def test_request_body_is_valid_json(self):
        mock_resp = self._mock_response()
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("warden.providers.bedrock.httpx.AsyncClient", return_value=mock_client):
            await call_bedrock(
                {"model": "bedrock/amazon.nova-lite-v1:0",
                 "messages": [{"role": "user", "content": "Test"}]},
                region="us-east-1",
                access_key="K",
                secret_key="S",
            )

        call_kwargs = mock_client.post.call_args[1]
        body = json.loads(call_kwargs["content"])
        assert "messages" in body

    @pytest.mark.asyncio
    async def test_sigv4_headers_present(self):
        mock_resp = self._mock_response()
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("warden.providers.bedrock.httpx.AsyncClient", return_value=mock_client):
            await call_bedrock(
                {"model": "bedrock/amazon.nova-lite-v1:0",
                 "messages": [{"role": "user", "content": "Hi"}]},
                region="us-east-1",
                access_key="AK",
                secret_key="SK",
            )

        headers = mock_client.post.call_args[1]["headers"]
        assert "Authorization" in headers
        assert "X-Amz-Date" in headers


# ── Azure routing via _resolve_upstream ───────────────────────────────────────

class TestAzureRouting:
    def test_azure_url_contains_deployment(self):
        from warden.openai_proxy import _resolve_upstream

        with patch("warden.openai_proxy._AZURE_ENDPOINT", "https://myresource.openai.azure.com"):
            url, key, extra = _resolve_upstream("azure/gpt-4o-mini")

        assert "myresource.openai.azure.com" in url
        assert "gpt-4o-mini" in url
        assert "chat/completions" in url

    def test_azure_url_contains_api_version(self):
        from warden.openai_proxy import _resolve_upstream

        with (
            patch("warden.openai_proxy._AZURE_ENDPOINT", "https://r.openai.azure.com"),
            patch("warden.openai_proxy._AZURE_API_VERSION", "2024-02-01"),
        ):
            url, _, _ = _resolve_upstream("azure/my-deployment")

        assert "api-version=2024-02-01" in url

    def test_azure_uses_api_key_header(self):
        from warden.openai_proxy import _resolve_upstream

        with (
            patch("warden.openai_proxy._AZURE_ENDPOINT", "https://r.openai.azure.com"),
            patch("warden.openai_proxy._AZURE_API_KEY", "my-azure-key"),
        ):
            _, bearer_key, extra = _resolve_upstream("azure/gpt-4o")

        assert bearer_key == ""
        assert extra == {"api-key": "my-azure-key"}

    def test_azure_case_insensitive(self):
        from warden.openai_proxy import _resolve_upstream

        with patch("warden.openai_proxy._AZURE_ENDPOINT", "https://r.openai.azure.com"):
            url, _, _ = _resolve_upstream("Azure/gpt-4o")

        assert "gpt-4o" in url

    def test_bedrock_returns_empty_url_sentinel(self):
        from warden.openai_proxy import _resolve_upstream

        url, key, extra = _resolve_upstream("bedrock/amazon.nova-lite-v1:0")
        assert url == ""
        assert key == ""
        assert extra == {}

    def test_openai_model_routes_to_upstream(self):
        from warden.openai_proxy import _resolve_upstream

        with patch("warden.openai_proxy._UPSTREAM", "https://api.openai.com"):
            url, _, extra = _resolve_upstream("gpt-4o-mini")

        assert "api.openai.com" in url
        assert extra == {}

    def test_gemini_routes_to_gemini(self):
        from warden.openai_proxy import _resolve_upstream

        url, key, _ = _resolve_upstream("gemini-1.5-flash")
        assert "generativelanguage.googleapis.com" in url

    def test_perplexity_routes_to_perplexity(self):
        from warden.openai_proxy import _resolve_upstream

        url, _, _ = _resolve_upstream("sonar-small-online")
        assert "perplexity.ai" in url

    def test_r1_routes_to_perplexity(self):
        from warden.openai_proxy import _resolve_upstream

        url, _, _ = _resolve_upstream("r1-1776")
        assert "perplexity.ai" in url
