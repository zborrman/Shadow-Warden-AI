"""Shadow Warden SDK — synchronous and async clients."""
from __future__ import annotations

import uuid
from typing import Any

import httpx

from .exceptions import AuthError, FilterBlockedError, RateLimitError, WardenError
from .models import AgentResponse, FilterResponse, MarketplaceListing

DEFAULT_BASE_URL = "https://api.shadow-warden-ai.com"


# ── Internal helpers ──────────────────────────────────────────────────────────

def _raise(r: httpx.Response) -> None:
    if r.status_code in (401, 403):
        raise AuthError("Invalid or missing API key", status_code=r.status_code, response_body=r.text)
    if r.status_code == 429:
        raise RateLimitError("Rate limit exceeded", status_code=r.status_code, response_body=r.text)
    if r.status_code >= 400:
        raise WardenError(f"API error {r.status_code}", status_code=r.status_code, response_body=r.text)


def _filter_body(content: str, tenant_id: str, session_id: str | None) -> dict[str, Any]:
    return {
        "content": content,
        "tenant_id": tenant_id,
        "session_id": session_id or str(uuid.uuid4()),
    }


# ── Marketplace sub-API (sync) ────────────────────────────────────────────────

class _Marketplace:
    def __init__(self, http: httpx.Client) -> None:
        self._http = http

    def listings(
        self,
        *,
        community_id: str | None = None,
        asset_type: str | None = None,
        status: str = "active",
        limit: int = 20,
    ) -> list[MarketplaceListing]:
        params: dict[str, str] = {"status": status, "limit": str(limit)}
        if community_id:
            params["community_id"] = community_id
        if asset_type:
            params["asset_type"] = asset_type
        r = self._http.get("/marketplace/listings", params=params)
        _raise(r)
        return [MarketplaceListing._from_dict(d) for d in r.json().get("listings", [])]

    def stats(self, *, tenant_id: str | None = None) -> dict[str, Any]:
        params: dict[str, str] = {}
        if tenant_id:
            params["tenant_id"] = tenant_id
        r = self._http.get("/marketplace/stats", params=params)
        _raise(r)
        return r.json()


# ── Chat sub-API (sync) ───────────────────────────────────────────────────────

class _ChatCompletions:
    def __init__(self, http: httpx.Client) -> None:
        self._http = http

    def create(
        self,
        messages: list[dict[str, str]],
        *,
        model: str = "gpt-4o",
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"model": model, "messages": messages, "temperature": temperature}
        if max_tokens is not None:
            body["max_tokens"] = max_tokens
        r = self._http.post("/v1/chat/completions", json=body)
        _raise(r)
        return r.json()


class _Chat:
    def __init__(self, http: httpx.Client) -> None:
        self.completions = _ChatCompletions(http)


# ── Synchronous client ────────────────────────────────────────────────────────

class WardenClient:
    """Synchronous Shadow Warden AI client.

    Typical usage::

        with WardenClient(api_key="sk-...") as client:
            result = client.filter("Tell me how to bypass security")
            if result.blocked:
                print("Blocked:", result.flags)

    Args:
        api_key: Your Shadow Warden API key (``sk-...``).
        base_url: Override the default production endpoint.
        timeout: HTTP timeout in seconds (default 30).
        tenant_id: Default tenant ID applied to all filter calls.
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 30.0,
        tenant_id: str = "default",
    ) -> None:
        self._tenant_id = tenant_id
        self._http = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers={"X-API-Key": api_key},
            timeout=timeout,
        )
        self.chat = _Chat(self._http)
        self.marketplace = _Marketplace(self._http)

    # ── Core methods ──────────────────────────────────────────────────────────

    def filter(
        self,
        content: str,
        *,
        tenant_id: str | None = None,
        session_id: str | None = None,
        raise_on_blocked: bool = False,
    ) -> FilterResponse:
        """Filter content through the 9-layer Shadow Warden pipeline.

        Args:
            content: The text to analyse.
            tenant_id: Override the client-level tenant ID.
            session_id: Session ID for ERS rate tracking (auto-generated if omitted).
            raise_on_blocked: Raise ``FilterBlockedError`` when the verdict is BLOCK.

        Returns:
            ``FilterResponse`` with ``.blocked``, ``.risk_level``, ``.flags``, etc.
        """
        r = self._http.post(
            "/filter",
            json=_filter_body(content, tenant_id or self._tenant_id, session_id),
        )
        _raise(r)
        resp = FilterResponse._from_dict(r.json())
        if raise_on_blocked and resp.blocked:
            raise FilterBlockedError(resp)
        return resp

    def agent(
        self,
        query: str,
        *,
        session_id: str | None = None,
    ) -> AgentResponse:
        """Query the SOVA autonomous security agent.

        Args:
            query: Natural-language request.
            session_id: Conversation session ID for multi-turn memory (6 h TTL).

        Returns:
            ``AgentResponse`` with ``.reply`` and ``.tools_used``.
        """
        body: dict[str, Any] = {"query": query}
        if session_id:
            body["session_id"] = session_id
        r = self._http.post("/agent/sova", json=body)
        _raise(r)
        return AgentResponse._from_dict(r.json())

    def health(self) -> dict[str, Any]:
        """Check the gateway health endpoint."""
        r = self._http.get("/health")
        _raise(r)
        return r.json()

    # ── Context manager ───────────────────────────────────────────────────────

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> WardenClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


# ── Async marketplace sub-API ─────────────────────────────────────────────────

class _AsyncMarketplace:
    def __init__(self, http: httpx.AsyncClient) -> None:
        self._http = http

    async def listings(
        self,
        *,
        community_id: str | None = None,
        asset_type: str | None = None,
        status: str = "active",
        limit: int = 20,
    ) -> list[MarketplaceListing]:
        params: dict[str, str] = {"status": status, "limit": str(limit)}
        if community_id:
            params["community_id"] = community_id
        if asset_type:
            params["asset_type"] = asset_type
        r = await self._http.get("/marketplace/listings", params=params)
        _raise(r)
        return [MarketplaceListing._from_dict(d) for d in r.json().get("listings", [])]


class _AsyncChatCompletions:
    def __init__(self, http: httpx.AsyncClient) -> None:
        self._http = http

    async def create(
        self,
        messages: list[dict[str, str]],
        *,
        model: str = "gpt-4o",
        temperature: float = 0.7,
        max_tokens: int | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"model": model, "messages": messages, "temperature": temperature}
        if max_tokens is not None:
            body["max_tokens"] = max_tokens
        r = await self._http.post("/v1/chat/completions", json=body)
        _raise(r)
        return r.json()


class _AsyncChat:
    def __init__(self, http: httpx.AsyncClient) -> None:
        self.completions = _AsyncChatCompletions(http)


# ── Async client ──────────────────────────────────────────────────────────────

class AsyncWardenClient:
    """Async Shadow Warden AI client for use with ``asyncio``.

    Typical usage::

        async with AsyncWardenClient(api_key="sk-...") as client:
            result = await client.filter("Is this prompt safe?")
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 30.0,
        tenant_id: str = "default",
    ) -> None:
        self._tenant_id = tenant_id
        self._http = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers={"X-API-Key": api_key},
            timeout=timeout,
        )
        self.chat = _AsyncChat(self._http)
        self.marketplace = _AsyncMarketplace(self._http)

    async def filter(
        self,
        content: str,
        *,
        tenant_id: str | None = None,
        session_id: str | None = None,
        raise_on_blocked: bool = False,
    ) -> FilterResponse:
        r = await self._http.post(
            "/filter",
            json=_filter_body(content, tenant_id or self._tenant_id, session_id),
        )
        _raise(r)
        resp = FilterResponse._from_dict(r.json())
        if raise_on_blocked and resp.blocked:
            raise FilterBlockedError(resp)
        return resp

    async def agent(
        self,
        query: str,
        *,
        session_id: str | None = None,
    ) -> AgentResponse:
        body: dict[str, Any] = {"query": query}
        if session_id:
            body["session_id"] = session_id
        r = await self._http.post("/agent/sova", json=body)
        _raise(r)
        return AgentResponse._from_dict(r.json())

    async def health(self) -> dict[str, Any]:
        r = await self._http.get("/health")
        _raise(r)
        return r.json()

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> AsyncWardenClient:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()
