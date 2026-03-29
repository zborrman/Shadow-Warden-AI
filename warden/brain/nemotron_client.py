"""
warden/brain/nemotron_client.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Async HTTP client for NVIDIA NIM (Nemotron Super).

Uses httpx (already in requirements) — no new dependencies.
NIM exposes an OpenAI-compatible /v1/chat/completions endpoint, so the
wire format is identical to OpenAI; only the base URL and auth header differ.

Thinking mode
─────────────
Nemotron Super supports a native reasoning mode activated via:
    {"thinking": {"type": "enabled", "budget_tokens": N}}

When enabled, the model wraps its chain-of-thought in <think>…</think>
tags before producing the final answer.  NimClient strips those tags and
returns (answer_text, reasoning_summary) as a tuple so callers can:
  • use  answer_text      for parsing / rule extraction
  • store reasoning_summary in the audit trail / Evidence Vault

Retry strategy
──────────────
3 attempts with exponential back-off (1s, 2s, 4s) on transient errors
(network timeouts, 5xx).  4xx errors are not retried (bad request / auth).
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
from typing import Any

import httpx

log = logging.getLogger("warden.brain.nemotron")

# ── Defaults (overridable via env) ────────────────────────────────────────────
NIM_BASE_URL             = os.getenv("NIM_BASE_URL",            "https://integrate.api.nvidia.com/v1")
NEMOTRON_MODEL           = os.getenv("NEMOTRON_MODEL",          "meta/llama-3.3-nemotron-super-49b-instruct")
NEMOTRON_THINKING_BUDGET = int(os.getenv("NEMOTRON_THINKING_BUDGET", "4096"))
_NIM_TIMEOUT             = float(os.getenv("NIM_TIMEOUT_SECONDS", "120"))

# Strips <think>…</think> blocks (including nested whitespace)
_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)

# Extracts a JSON object from freeform text (handles markdown code fences)
_JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*(\{.*?})\s*```", re.DOTALL)
_JSON_BARE_RE  = re.compile(r"\{.*}", re.DOTALL)


def extract_json(text: str) -> str:
    """
    Pull a JSON object out of Nemotron's response text.

    Tries (in order):
      1. Bare JSON — response starts with '{'
      2. Markdown code block — ```json { … } ```
      3. First '{…}' span found anywhere in the text

    Raises ValueError if no JSON object is found.
    """
    text = text.strip()
    if text.startswith("{"):
        return text
    m = _JSON_BLOCK_RE.search(text)
    if m:
        return m.group(1)
    m = _JSON_BARE_RE.search(text)
    if m:
        return m.group(0)
    raise ValueError(f"No JSON object found in NIM response (first 300 chars): {text[:300]!r}")


class NimClient:
    """
    Async wrapper for NVIDIA NIM /v1/chat/completions.

    Parameters
    ----------
    api_key  : NVIDIA API key (falls back to NVIDIA_API_KEY env var)
    base_url : NIM base URL  (falls back to NIM_BASE_URL env var)
    model    : model name    (falls back to NEMOTRON_MODEL env var)
    timeout  : HTTP timeout in seconds (default 120 s)
    """

    def __init__(
        self,
        api_key:  str | None = None,
        base_url: str | None = None,
        model:    str | None = None,
        timeout:  float      = _NIM_TIMEOUT,
    ) -> None:
        self._api_key  = api_key  or os.getenv("NVIDIA_API_KEY", "")
        self._base_url = (base_url or NIM_BASE_URL).rstrip("/")
        self._model    = model    or NEMOTRON_MODEL
        self._timeout  = timeout

    @property
    def is_configured(self) -> bool:
        """True when an API key is present — required before making calls."""
        return bool(self._api_key)

    async def chat(
        self,
        messages:        list[dict[str, Any]],
        *,
        max_tokens:      int   = 8_192,
        thinking_budget: int   = NEMOTRON_THINKING_BUDGET,
        enable_thinking: bool  = True,
        temperature:     float = 0.2,
        response_format: dict[str, Any] | None = None,
    ) -> tuple[str, str]:
        """
        Send a chat completion request to NIM.

        Parameters
        ----------
        messages        : OpenAI-format message list
        max_tokens      : max tokens for the completion
        thinking_budget : token budget for the <think> chain (0 = auto)
        enable_thinking : set False to disable thinking mode entirely
        temperature     : sampling temperature (low = more deterministic)
        response_format : e.g. {"type": "json_object"} — passed as-is

        Returns
        -------
        (answer_text, reasoning_summary)
            answer_text      — model output with <think>…</think> stripped
            reasoning_summary — content of the last <think> block, or ""
        """
        if not self.is_configured:
            raise RuntimeError(
                "NVIDIA_API_KEY is not set — cannot call NIM. "
                "Set NVIDIA_API_KEY or EVOLUTION_ENGINE=claude."
            )

        body: dict[str, Any] = {
            "model":       self._model,
            "messages":    messages,
            "max_tokens":  max_tokens,
            "temperature": temperature,
        }
        if enable_thinking:
            body["thinking"] = {"type": "enabled", "budget_tokens": thinking_budget}
        if response_format:
            body["response_format"] = response_format

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type":  "application/json",
            "Accept":        "application/json",
        }

        last_exc: Exception | None = None
        for attempt in range(3):
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    resp = await client.post(
                        f"{self._base_url}/chat/completions",
                        headers=headers,
                        json=body,
                    )
                resp.raise_for_status()
                data = resp.json()
                raw: str = (data["choices"][0]["message"]["content"] or "").strip()
                return self._split_thinking(raw)

            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code
                if status < 500:
                    # 4xx — bad request / auth — don't retry, surface immediately
                    log.error(
                        "NimClient: HTTP %d from NIM — %s",
                        status, exc.response.text[:400],
                    )
                    raise
                last_exc = exc
                wait = 2 ** attempt
                log.warning(
                    "NimClient: HTTP %d (attempt %d/3) — retrying in %ds",
                    status, attempt + 1, wait,
                )
                await asyncio.sleep(wait)

            except (httpx.TimeoutException, httpx.ConnectError) as exc:
                last_exc = exc
                wait = 2 ** attempt
                log.warning(
                    "NimClient: %s (attempt %d/3) — retrying in %ds",
                    type(exc).__name__, attempt + 1, wait,
                )
                await asyncio.sleep(wait)

        raise RuntimeError(
            f"NIM API unreachable after 3 attempts: {last_exc}"
        ) from last_exc

    @staticmethod
    def _split_thinking(raw: str) -> tuple[str, str]:
        """
        Separate the <think> reasoning trace from the final answer.

        Returns (answer, reasoning) where reasoning may be "" if the model
        did not emit a <think> block (e.g. thinking mode was disabled).
        """
        think_match = _THINK_RE.search(raw)
        if think_match:
            reasoning = think_match.group(0)[7:-8].strip()  # strip <think> tags
        else:
            reasoning = ""
        answer = _THINK_RE.sub("", raw).strip()
        return answer, reasoning
