"""
warden/integrations/langchain_callback.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
LangChain callback handler that filters every LLM input through
Shadow Warden before it reaches the model.

Compatible with: LangChain ≥ 0.1, LangChain-Core ≥ 0.1

Usage::

    from langchain_openai import ChatOpenAI
    from warden.integrations.langchain_callback import WardenCallback

    # Warden running at http://localhost:8001 (default)
    warden = WardenCallback()

    # or point at a remote Warden instance:
    warden = WardenCallback(
        warden_url="https://warden.yourdomain.com",
        api_key="your-warden-api-key",
        strict=True,
    )

    llm = ChatOpenAI(model="gpt-4", callbacks=[warden])
    result = llm.invoke("Hello, world")   # filtered transparently

If Warden blocks the prompt, on_llm_start raises PermissionError.
The LLM call is never made.

Install dependencies::

    pip install langchain-core httpx
"""
from __future__ import annotations

import logging
import os
from typing import Any

import httpx

log = logging.getLogger("warden.integrations.langchain")


class WardenCallback:
    """
    LangChain BaseCallbackHandler that filters every LLM prompt through
    the Shadow Warden /filter endpoint before execution.

    This class is intentionally kept dependency-light: it inherits from
    ``object`` rather than ``BaseCallbackHandler`` so it can be imported
    without LangChain being installed.  It implements the duck-typed
    callback protocol that LangChain requires.
    """

    def __init__(
        self,
        *,
        warden_url: str | None = None,
        api_key:    str | None = None,
        strict:     bool = False,
        timeout:    float = 10.0,
    ) -> None:
        self.url     = (warden_url or os.getenv("WARDEN_URL", "http://localhost:8001")).rstrip("/")
        self.api_key = api_key or os.getenv("WARDEN_API_KEY", "")
        self.strict  = strict
        self.timeout = timeout

    # ── LangChain callback protocol ───────────────────────────────────────

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        **kwargs: Any,
    ) -> None:
        """Called before every LLM invocation. Blocks if Warden rejects."""
        for prompt in prompts:
            result = self._filter(prompt)
            if not result.get("allowed", True):
                raise PermissionError(
                    f"Shadow Warden blocked prompt: {result.get('reason', 'policy violation')}"
                )

    def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[list[Any]],
        **kwargs: Any,
    ) -> None:
        """Called before every ChatModel invocation. Filters the last human message."""
        for message_group in messages:
            for msg in reversed(message_group):
                # HumanMessage / SystemMessage have a .content attribute
                content = getattr(msg, "content", None)
                if content and isinstance(content, str):
                    result = self._filter(content)
                    if not result.get("allowed", True):
                        raise PermissionError(
                            f"Shadow Warden blocked message: {result.get('reason', 'policy violation')}"
                        )
                    break  # only check the last human message

    # ── Internal ──────────────────────────────────────────────────────────

    def _filter(self, content: str) -> dict:
        headers = {}
        if self.api_key:
            headers["X-API-Key"] = self.api_key

        try:
            resp = httpx.post(
                f"{self.url}/filter",
                json={"content": content, "strict": self.strict},
                headers=headers,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as exc:
            log.error("Warden /filter request failed: %s", exc)
            # Fail-open: if Warden is unreachable, allow the request
            # and log the error. Change to raise if you prefer fail-closed.
            return {"allowed": True, "filtered_content": content}
