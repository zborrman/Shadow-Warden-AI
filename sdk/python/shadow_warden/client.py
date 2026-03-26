"""
shadow_warden/client.py
━━━━━━━━━━━━━━━━━━━━━━
Synchronous and asynchronous clients for the Shadow Warden AI gateway.

Quick start::

    from shadow_warden import WardenClient

    with WardenClient(gateway_url="http://localhost:8001", api_key="sk_...") as warden:
        result = warden.filter("Summarise the contract for client@example.com")
        if result.allowed:
            # safe to forward to the AI model
            response = openai_client.chat.completions.create(...)

OpenAI passthrough wrapper::

    wrapped = warden.wrap_openai(openai.OpenAI(api_key="..."))
    # Identical API — Warden intercepts transparently
    response = wrapped.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "..."}],
    )
"""
from __future__ import annotations

import asyncio
from typing import Any

import httpx

from shadow_warden.errors import WardenBlockedError, WardenGatewayError, WardenTimeoutError
from shadow_warden.models import FilterResult, ImpactReport

__all__ = ["WardenClient", "AsyncWardenClient"]

# ── Shared request logic ──────────────────────────────────────────────────────


def _build_payload(
    content:   str,
    tenant_id: str,
    strict:    bool,
    context:   dict[str, Any] | None,
) -> dict:
    return {
        "content":   content,
        "tenant_id": tenant_id,
        "strict":    strict,
        **({"context": context} if context else {}),
    }


def _parse_response(resp: httpx.Response) -> FilterResult:
    if resp.status_code == 200:
        return FilterResult.from_dict(resp.json())
    detail = ""
    try:
        detail = resp.json().get("detail", resp.text)
    except Exception:
        detail = resp.text
    raise WardenGatewayError(resp.status_code, detail)


# ── Synchronous client ────────────────────────────────────────────────────────


class WardenClient:
    """
    Thread-safe synchronous Shadow Warden AI client.

    Args:
        gateway_url: Base URL of the Warden gateway
                     (e.g. ``"http://localhost:8001"`` or
                     ``"https://warden.yourcompany.com"``).
        api_key:     ``X-API-Key`` header value.  Leave blank if auth
                     is disabled (default dev configuration).
        tenant_id:   Default tenant identifier sent with every request.
                     Can be overridden per-call.
        timeout:     HTTP request timeout in seconds (default 10).
        fail_open:   If ``True``, a :class:`WardenTimeoutError` or
                     :class:`WardenGatewayError` returns a permissive
                     :class:`FilterResult` instead of raising.
                     Mirrors the gateway's own fail-open behaviour.
                     Default ``False`` (strict mode).
    """

    def __init__(
        self,
        gateway_url: str = "http://localhost:8001",
        api_key:     str = "",
        tenant_id:   str = "default",
        timeout:     float = 10.0,
        fail_open:   bool = False,
    ) -> None:
        self._base    = gateway_url.rstrip("/")
        self._tenant  = tenant_id
        self._fail_open = fail_open

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            headers["X-API-Key"] = api_key

        self._http = httpx.Client(headers=headers, timeout=timeout)

    # ── Core filter ───────────────────────────────────────────────────────

    def filter(
        self,
        content:        str,
        *,
        tenant_id:      str | None = None,
        strict:         bool = False,
        context:        dict[str, Any] | None = None,
        raise_on_block: bool = False,
    ) -> FilterResult:
        """
        Send *content* through the Shadow Warden filter pipeline.

        Args:
            content:        The text to filter (prompt, document, user input…).
            tenant_id:      Override the default tenant for this call.
            strict:         Block on MEDIUM risk (default: only HIGH / BLOCK).
            context:        Arbitrary metadata forwarded to the gateway log.
            raise_on_block: Raise :class:`WardenBlockedError` if the content
                            is blocked instead of returning the result.

        Returns:
            :class:`FilterResult` describing the decision and any findings.
        """
        payload = _build_payload(
            content, tenant_id or self._tenant, strict, context
        )
        try:
            resp = self._http.post(f"{self._base}/filter", json=payload)
        except httpx.TimeoutException as exc:
            if self._fail_open:
                return _permissive_result(content)
            raise WardenTimeoutError("Gateway timed out") from exc
        except httpx.RequestError as exc:
            if self._fail_open:
                return _permissive_result(content)
            raise WardenGatewayError(0, str(exc)) from exc

        try:
            result = _parse_response(resp)
        except WardenGatewayError:
            if self._fail_open:
                return _permissive_result(content)
            raise

        if raise_on_block and result.blocked:
            raise WardenBlockedError(result)
        return result

    # ── Batch filter ──────────────────────────────────────────────────────

    def filter_batch(
        self,
        items: list[str | dict],
        *,
        tenant_id: str | None = None,
    ) -> list[FilterResult]:
        """
        Filter up to 50 items in a single round-trip (``POST /filter/batch``).

        Each element of *items* is either a plain string (the content) or a
        dict with a ``"content"`` key plus optional ``"tenant_id"``/``"strict"``
        overrides.
        """
        tid = tenant_id or self._tenant
        batch = []
        for item in items:
            if isinstance(item, str):
                batch.append({"content": item, "tenant_id": tid})
            else:
                batch.append({"tenant_id": tid, **item})

        try:
            resp = self._http.post(f"{self._base}/filter/batch", json={"items": batch})
        except httpx.TimeoutException as exc:
            raise WardenTimeoutError("Batch request timed out") from exc

        if resp.status_code != 200:
            detail = resp.json().get("detail", resp.text) if resp.content else ""
            raise WardenGatewayError(resp.status_code, detail)

        return [FilterResult.from_dict(r) for r in resp.json()["results"]]

    # ── Billing helpers ───────────────────────────────────────────────────

    def get_billing_status(self, tenant_id: str | None = None) -> dict:
        """Return the current billing plan and quota for a tenant."""
        tid = tenant_id or self._tenant
        resp = self._http.get(f"{self._base}/stripe/status", params={"tenant_id": tid})
        if resp.status_code != 200:
            raise WardenGatewayError(resp.status_code, resp.text)
        return resp.json()

    # ── Dollar Impact (v2.3) ──────────────────────────────────────────────

    def impact(
        self,
        *,
        industry:         str = "technology",
        requests_per_day: int = 10_000,
        annual_cost_usd:  float = 50_000.0,
    ) -> ImpactReport:
        """
        Fetch the Dollar Impact report from ``GET /financial/impact``.

        Requires v2.3+ gateway.  Returns an :class:`ImpactReport` with
        IBM-2024-benchmarked ROI sub-models.

        Args:
            industry:         One of ``technology``, ``financial``, ``healthcare``,
                              ``retail``, ``manufacturing``, ``education``, ``government``.
            requests_per_day: Estimated daily AI requests through the gateway.
            annual_cost_usd:  Annual Shadow Warden licence cost (for ROI calculation).
        """
        params = {
            "industry":         industry,
            "requests_per_day": requests_per_day,
            "annual_cost_usd":  annual_cost_usd,
        }
        resp = self._http.get(f"{self._base}/financial/impact", params=params)
        if resp.status_code != 200:
            raise WardenGatewayError(resp.status_code, resp.text)
        return ImpactReport.from_dict(resp.json())

    # ── OpenAI wrapper ────────────────────────────────────────────────────

    def wrap_openai(self, openai_client: Any) -> _WardenOpenAIWrapper:
        """
        Wrap an ``openai.OpenAI`` instance so every
        ``chat.completions.create()`` call is filtered before forwarding.

        Usage::

            import openai
            from shadow_warden import WardenClient

            warden = WardenClient(api_key="sk_...")
            client = warden.wrap_openai(openai.OpenAI(api_key="sk-openai-..."))

            # Identical to the standard OpenAI API:
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": "..."}],
                raise_on_block=True,   # extra kwarg consumed by Warden
            )
        """
        return _WardenOpenAIWrapper(self, openai_client)

    # ── Context manager ───────────────────────────────────────────────────

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> WardenClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


# ── Asynchronous client ───────────────────────────────────────────────────────


class AsyncWardenClient:
    """
    Async Shadow Warden AI client (``asyncio`` / ``httpx.AsyncClient``).

    Identical interface to :class:`WardenClient` — all methods are coroutines.

    Usage::

        async with AsyncWardenClient(gateway_url="...", api_key="...") as warden:
            result = await warden.filter("user prompt")
    """

    def __init__(
        self,
        gateway_url: str = "http://localhost:8001",
        api_key:     str = "",
        tenant_id:   str = "default",
        timeout:     float = 10.0,
        fail_open:   bool = False,
    ) -> None:
        self._base      = gateway_url.rstrip("/")
        self._tenant    = tenant_id
        self._fail_open = fail_open

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            headers["X-API-Key"] = api_key

        self._http = httpx.AsyncClient(headers=headers, timeout=timeout)

    async def filter(
        self,
        content:        str,
        *,
        tenant_id:      str | None = None,
        strict:         bool = False,
        context:        dict[str, Any] | None = None,
        raise_on_block: bool = False,
    ) -> FilterResult:
        payload = _build_payload(
            content, tenant_id or self._tenant, strict, context
        )
        try:
            resp = await self._http.post(f"{self._base}/filter", json=payload)
        except httpx.TimeoutException as exc:
            if self._fail_open:
                return _permissive_result(content)
            raise WardenTimeoutError("Gateway timed out") from exc
        except httpx.RequestError as exc:
            if self._fail_open:
                return _permissive_result(content)
            raise WardenGatewayError(0, str(exc)) from exc

        try:
            result = _parse_response(resp)
        except WardenGatewayError:
            if self._fail_open:
                return _permissive_result(content)
            raise

        if raise_on_block and result.blocked:
            raise WardenBlockedError(result)
        return result

    async def filter_batch(
        self,
        items: list[str | dict],
        *,
        tenant_id: str | None = None,
    ) -> list[FilterResult]:
        tid = tenant_id or self._tenant
        batch = []
        for item in items:
            if isinstance(item, str):
                batch.append({"content": item, "tenant_id": tid})
            else:
                batch.append({"tenant_id": tid, **item})

        resp = await self._http.post(f"{self._base}/filter/batch", json={"items": batch})
        if resp.status_code != 200:
            detail = resp.json().get("detail", resp.text) if resp.content else ""
            raise WardenGatewayError(resp.status_code, detail)
        return [FilterResult.from_dict(r) for r in resp.json()["results"]]

    async def get_billing_status(self, tenant_id: str | None = None) -> dict:
        tid = tenant_id or self._tenant
        resp = await self._http.get(
            f"{self._base}/stripe/status", params={"tenant_id": tid}
        )
        if resp.status_code != 200:
            raise WardenGatewayError(resp.status_code, resp.text)
        return resp.json()

    async def impact(
        self,
        *,
        industry:         str = "technology",
        requests_per_day: int = 10_000,
        annual_cost_usd:  float = 50_000.0,
    ) -> ImpactReport:
        """Async version of :meth:`WardenClient.impact` (v2.3+)."""
        params = {
            "industry":         industry,
            "requests_per_day": requests_per_day,
            "annual_cost_usd":  annual_cost_usd,
        }
        resp = await self._http.get(f"{self._base}/financial/impact", params=params)
        if resp.status_code != 200:
            raise WardenGatewayError(resp.status_code, resp.text)
        return ImpactReport.from_dict(resp.json())

    def wrap_openai(self, openai_client: Any) -> _AsyncWardenOpenAIWrapper:
        return _AsyncWardenOpenAIWrapper(self, openai_client)

    async def close(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> AsyncWardenClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()


# ── OpenAI wrappers ───────────────────────────────────────────────────────────


class _CompletionsWrapper:
    """Intercepts chat.completions.create() to filter user messages first."""

    def __init__(self, warden: WardenClient, completions: Any) -> None:
        self._warden      = warden
        self._completions = completions

    def create(self, *, messages: list[dict], raise_on_block: bool = False, **kwargs: Any) -> Any:
        # Concatenate all user-role message content for filtering
        user_text = "\n".join(
            m.get("content", "") for m in messages if m.get("role") == "user"
        )
        if user_text.strip():
            result = self._warden.filter(
                user_text, raise_on_block=raise_on_block,
                context={"source": "openai_wrapper"},
            )
            if result.blocked and not raise_on_block:
                raise WardenBlockedError(result)
        return self._completions.create(messages=messages, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._completions, name)


class _ChatWrapper:
    def __init__(self, warden: WardenClient, chat: Any) -> None:
        self.completions = _CompletionsWrapper(warden, chat.completions)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._chat, name)


class _WardenOpenAIWrapper:
    """Wraps ``openai.OpenAI`` — transparent drop-in with Warden filtering."""

    def __init__(self, warden: WardenClient, client: Any) -> None:
        self._warden = warden
        self._client = client
        self.chat    = _ChatWrapper(warden, client.chat)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


class _AsyncCompletionsWrapper:
    def __init__(self, warden: AsyncWardenClient, completions: Any) -> None:
        self._warden      = warden
        self._completions = completions

    async def create(
        self, *, messages: list[dict], raise_on_block: bool = False, **kwargs: Any
    ) -> Any:
        user_text = "\n".join(
            m.get("content", "") for m in messages if m.get("role") == "user"
        )
        if user_text.strip():
            result = await self._warden.filter(
                user_text, raise_on_block=raise_on_block,
                context={"source": "openai_async_wrapper"},
            )
            if result.blocked and not raise_on_block:
                raise WardenBlockedError(result)

        # Support both coroutine and regular completions.create
        coro = self._completions.create(messages=messages, **kwargs)
        if asyncio.iscoroutine(coro):
            return await coro
        return coro

    def __getattr__(self, name: str) -> Any:
        return getattr(self._completions, name)


class _AsyncChatWrapper:
    def __init__(self, warden: AsyncWardenClient, chat: Any) -> None:
        self.completions = _AsyncCompletionsWrapper(warden, chat.completions)


class _AsyncWardenOpenAIWrapper:
    def __init__(self, warden: AsyncWardenClient, client: Any) -> None:
        self._warden = warden
        self._client = client
        self.chat    = _AsyncChatWrapper(warden, client.chat)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _permissive_result(content: str) -> FilterResult:
    """Fail-open result: gateway unreachable → treat as allowed."""
    return FilterResult(
        allowed=True,
        risk_level="low",
        filtered_content=content,
    )
