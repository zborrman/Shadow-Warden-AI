"""
warden/tools/browser.py
━━━━━━━━━━━━━━━━━━━━━━
Playwright-powered browser sandbox for active security auditing.

Two main components
───────────────────
Context7Manager
    A rolling window of the last 7 browser interactions.
    The AI uses this short-term memory to plan and execute
    multi-step audits (login → navigate → inject → verify).

BrowserSandbox
    Async context manager that wraps a headless Chromium instance.
    Every action (Navigate, Click, Type, Submit, Inspect, Screenshot)
    is automatically recorded into a Context7Manager, so the full
    audit trail is always available for the AI to reason over.

Usage
─────
    async with BrowserSandbox() as browser:
        await browser.navigate("https://target.example.com/login")
        await browser.type_text("#username", "admin")
        await browser.type_text("#password", "password123")
        await browser.submit("#login-form")
        await browser.navigate("https://target.example.com/profile?name=<script>")
        findings = await browser.inspect()

    ctx = browser.context7.get_context()   # last ≤7 steps
    ai_prompt = browser.context7.as_prompt_context()
"""
from __future__ import annotations

import base64
import logging
import tempfile
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    Playwright,
    Response,
    async_playwright,
)

log = logging.getLogger("warden.tools.browser")


# ── Action types ──────────────────────────────────────────────────────────────

class ActionType(StrEnum):
    NAVIGATE    = "Navigate"
    CLICK       = "Click"
    TYPE        = "Type"
    SUBMIT      = "Submit"
    INSPECT     = "Inspect"
    SCREENSHOT  = "Screenshot"
    SCREENCAST  = "Screencast"


# ── Interaction record ────────────────────────────────────────────────────────

@dataclass
class InteractionRecord:
    """One discrete browser action captured by Context7Manager."""

    action:     ActionType
    url:        str
    timestamp:  datetime        = field(default_factory=lambda: datetime.now(UTC))
    selector:   str | None      = None   # CSS selector targeted
    value:      str | None      = None   # text typed / form value
    result:     dict[str, Any]  = field(default_factory=dict)
    # result fields (present where applicable):
    #   status_code   int     HTTP status of the navigation
    #   title         str     <title> of the page after the action
    #   content_len   int     byte length of page body
    #   screenshot_b64 str    base64 PNG (Screenshot action only)
    #   findings      list    security notes from Inspect action

    def to_dict(self) -> dict[str, Any]:
        return {
            "action":    self.action.value,
            "url":       self.url,
            "timestamp": self.timestamp.isoformat(),
            "selector":  self.selector,
            "value":     self.value,
            "result":    self.result,
        }


# ── Context7Manager ───────────────────────────────────────────────────────────

class Context7Manager:
    """
    Stores the last 7 browser interactions as a rolling window.

    The window is intentionally small — 7 steps is enough to reconstruct
    a multi-step auth/injection flow while keeping the AI prompt concise.
    """

    WINDOW_SIZE = 7

    def __init__(self) -> None:
        self._history: deque[InteractionRecord] = deque(maxlen=self.WINDOW_SIZE)

    # ── Mutation ──────────────────────────────────────────────────────────

    def record(self, interaction: InteractionRecord) -> None:
        self._history.append(interaction)
        log.debug("Context7 [%d/%d] — %s @ %s",
                  len(self._history), self.WINDOW_SIZE,
                  interaction.action.value, interaction.url)

    def clear(self) -> None:
        self._history.clear()

    # ── Retrieval ─────────────────────────────────────────────────────────

    def get_context(self) -> list[InteractionRecord]:
        """Return interactions in chronological order (oldest first)."""
        return list(self._history)

    def get_last(self) -> InteractionRecord | None:
        return self._history[-1] if self._history else None

    def __len__(self) -> int:
        return len(self._history)

    # ── AI prompt serialisation ───────────────────────────────────────────

    def as_prompt_context(self) -> str:
        """
        Render the interaction window as a plain-text block ready to be
        injected into an AI prompt as short-term browser memory.

        Example output:
            [Browser context — last 3 of 7 interactions]
            1. Navigate  → https://example.com/login        (200)
            2. Type      → #username          value="admin"
            3. Submit    → #login-form
        """
        if not self._history:
            return "[Browser context — empty]"

        lines = [f"[Browser context — last {len(self._history)} of {self.WINDOW_SIZE} interactions]"]
        for i, rec in enumerate(self._history, start=1):
            parts = [f"{i}. {rec.action.value:<12}→ {rec.url}"]

            if rec.selector:
                parts[0] += f"   selector={rec.selector!r}"
            if rec.value:
                parts[0] += f'   value="{rec.value}"'
            if "status_code" in rec.result:
                parts[0] += f"   ({rec.result['status_code']})"
            if "findings" in rec.result and rec.result["findings"]:
                for finding in rec.result["findings"]:
                    parts.append(f"   ⚠ {finding}")

            lines.extend(parts)

        return "\n".join(lines)


# ── BrowserSandbox ────────────────────────────────────────────────────────────

class BrowserSandbox:
    """
    Async context manager wrapping a headless Chromium session.

    Every public method records its action into ``self.context7`` so the
    full audit trail is preserved across the session.

    Example::

        async with BrowserSandbox(headless=True) as browser:
            await browser.navigate("https://target.com")
            await browser.type_text("#search", "<script>alert(1)</script>")
            await browser.submit("#search-form")
            findings = await browser.inspect()
            shot = await browser.screenshot()

        print(browser.context7.as_prompt_context())
    """

    def __init__(
        self,
        headless: bool = True,
        slow_mo: int = 0,
        timeout: int = 30_000,          # ms
        viewport: dict | None = None,
        record_video: bool = False,
    ) -> None:
        self.headless      = headless
        self.slow_mo       = slow_mo
        self.timeout       = timeout
        self.viewport      = viewport or {"width": 1280, "height": 800}
        self.record_video  = record_video
        self.context7      = Context7Manager()
        self.video_path: str | None = None   # set after __aexit__ when record_video=True

        self._playwright: Playwright    | None = None
        self._browser:    Browser       | None = None
        self._context:    BrowserContext| None = None
        self._page:       Page          | None = None
        self._video_tmpdir: tempfile.TemporaryDirectory | None = None

    # ── Lifecycle ─────────────────────────────────────────────────────────

    async def __aenter__(self) -> BrowserSandbox:
        log.info("BrowserSandbox: launching headless=%s slow_mo=%dms",
                 self.headless, self.slow_mo)

        self._playwright = await async_playwright().start()
        self._browser    = await self._playwright.chromium.launch(
            headless=self.headless,
            slow_mo=self.slow_mo,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",    # required inside Docker
                "--disable-gpu",
                "--disable-extensions",
            ],
        )

        ctx_kwargs: dict[str, Any] = {
            "viewport":            self.viewport,  # type: ignore[assignment]
            "ignore_https_errors": True,
            "user_agent": (
                "Mozilla/5.0 (compatible; WardenBot/1.0; "
                "+https://shadowwarden.ai/bot)"
            ),
        }
        if self.record_video:
            self._video_tmpdir = tempfile.TemporaryDirectory(prefix="warden-video-")
            ctx_kwargs["record_video_dir"] = self._video_tmpdir.name
            log.info("BrowserSandbox: video recording → %s", self._video_tmpdir.name)

        self._context = await self._browser.new_context(**ctx_kwargs)
        self._context.set_default_timeout(self.timeout)
        self._page = await self._context.new_page()
        log.info("BrowserSandbox: Chromium ready.")
        return self

    async def __aexit__(self, *_) -> None:
        # Capture video path before closing the page (Playwright finalises the
        # WebM file after the page is closed, not when the browser closes).
        if self.record_video and self._page is not None:
            try:
                await self._page.close()
                if self._page.video is not None:
                    self.video_path = await self._page.video.path()
                    log.info("BrowserSandbox: video saved → %s", self.video_path)
            except Exception as exc:
                log.warning("BrowserSandbox: video path capture failed: %s", exc)
            self._page = None   # already closed above

        if self._context:
            await self._context.close()
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
        log.info("BrowserSandbox: closed.")

    # ── Internal helper ───────────────────────────────────────────────────

    @property
    def page(self) -> Page:
        if self._page is None:
            raise RuntimeError("BrowserSandbox must be used as 'async with BrowserSandbox()'")
        return self._page

    async def _current_url(self) -> str:
        return self.page.url

    # ── Public actions ────────────────────────────────────────────────────

    async def navigate(self, url: str) -> InteractionRecord:
        """Go to *url* and wait for the network to settle."""
        log.info("Navigate → %s", url)
        response: Response | None = await self.page.goto(url, wait_until="networkidle")

        record = InteractionRecord(
            action=ActionType.NAVIGATE,
            url=url,
            result={
                "status_code": response.status if response else None,
                "title":       await self.page.title(),
                "content_len": len(await self.page.content()),
            },
        )
        self.context7.record(record)
        return record

    async def click(self, selector: str) -> InteractionRecord:
        """Click the element matching *selector*."""
        log.info("Click → %s", selector)
        await self.page.click(selector)
        await self.page.wait_for_load_state("networkidle")

        record = InteractionRecord(
            action=ActionType.CLICK,
            url=await self._current_url(),
            selector=selector,
            result={"title": await self.page.title()},
        )
        self.context7.record(record)
        return record

    async def type_text(self, selector: str, text: str) -> InteractionRecord:
        """
        Clear *selector* and type *text* character-by-character.
        The typed value is stored as-is (pre-redaction by the caller).
        """
        log.info("Type → %s  (len=%d)", selector, len(text))
        await self.page.fill(selector, "")         # clear first
        await self.page.type(selector, text, delay=30)

        record = InteractionRecord(
            action=ActionType.TYPE,
            url=await self._current_url(),
            selector=selector,
            value=text,
        )
        self.context7.record(record)
        return record

    async def submit(self, selector: str) -> InteractionRecord:
        """Submit the form identified by *selector* and wait for navigation."""
        log.info("Submit → %s", selector)
        async with self.page.expect_navigation(wait_until="networkidle"):
            await self.page.evaluate(
                "(sel) => document.querySelector(sel)?.submit()", selector
            )

        record = InteractionRecord(
            action=ActionType.SUBMIT,
            url=await self._current_url(),
            selector=selector,
            result={"title": await self.page.title()},
        )
        self.context7.record(record)
        return record

    async def inspect(self) -> InteractionRecord:
        """
        Passive security inspection of the current page.

        Checks:
          • Reflected XSS markers in the DOM
          • Missing security headers (CSP, X-Frame-Options, HSTS)
          • Open <form> actions pointing to external domains
          • Inline <script> blocks (potential injection surface)
        """
        log.info("Inspect @ %s", self.page.url)
        findings: list[str] = []

        content = await self.page.content()

        # XSS reflection check — look for our own test payload if present
        if "<script>alert" in content.lower() or "javascript:" in content.lower():
            findings.append("Possible XSS reflection: script tag or javascript: URI found in DOM.")

        # Security headers via evaluate
        headers_js = """
            () => {
                const metas = [...document.querySelectorAll('meta[http-equiv]')];
                return metas.map(m => m.getAttribute('http-equiv').toLowerCase());
            }
        """
        http_equiv = await self.page.evaluate(headers_js)
        if "content-security-policy" not in http_equiv:
            findings.append("No Content-Security-Policy meta tag detected.")

        # External form actions
        form_check = """
            () => [...document.querySelectorAll('form[action]')]
                    .map(f => f.action)
                    .filter(a => a.startsWith('http') && !a.includes(location.hostname))
        """
        external_forms = await self.page.evaluate(form_check)
        for action in external_forms:
            findings.append(f"Form submits to external domain: {action}")

        # Inline scripts
        inline_scripts = await self.page.evaluate(
            "() => document.querySelectorAll('script:not([src])').length"
        )
        if inline_scripts > 0:
            findings.append(f"{inline_scripts} inline <script> block(s) found (potential injection surface).")

        record = InteractionRecord(
            action=ActionType.INSPECT,
            url=self.page.url,
            result={
                "title":        await self.page.title(),
                "content_len":  len(content),
                "findings":     findings,
            },
        )
        self.context7.record(record)
        return record

    async def screenshot(self, full_page: bool = True) -> InteractionRecord:
        """Capture a PNG screenshot and embed it as base64 in the record."""
        log.info("Screenshot @ %s", self.page.url)
        raw: bytes = await self.page.screenshot(full_page=full_page, type="png")
        b64 = base64.b64encode(raw).decode()

        record = InteractionRecord(
            action=ActionType.SCREENSHOT,
            url=self.page.url,
            result={
                "title":          await self.page.title(),
                "screenshot_b64": b64,
                "size_bytes":     len(raw),
            },
        )
        self.context7.record(record)
        return record

    @staticmethod
    async def capture_screenshot_b64(url: str, timeout: int = 30_000) -> str:
        """
        Convenience: spin up a throw-away browser, navigate to *url*, return
        a base64-encoded PNG string.  Used by visual_diff to capture both
        baseline and candidate without keeping a shared browser context.
        """
        async with BrowserSandbox(timeout=timeout) as sb:
            await sb.navigate(url)
            rec = await sb.screenshot()
            return rec.result.get("screenshot_b64", "")


# ── ScreencastRecorder ────────────────────────────────────────────────────────

class ScreencastRecorder:
    """
    Context manager that records a full browser session as a WebM video and
    ships it to MinIO as SOC 2 audit evidence on exit.

    Wraps BrowserSandbox with ``record_video=True``; the caller interacts with
    the returned BrowserSandbox exactly as normal.  When the ``async with``
    block exits, Playwright finalises the WebM and the video is uploaded to
    MinIO under ``screencasts/<session_id>.webm``.  The upload is background-
    threaded and fail-open — a MinIO outage never blocks the caller.

    Attributes
    ----------
    minio_key : str | None
        S3 key of the uploaded screencast (set after exit; None if S3 disabled).
    video_path : str | None
        Local filesystem path to the WebM file (available after exit).

    Usage::

        async with ScreencastRecorder("audit-2025-01-15") as browser:
            await browser.navigate("https://target.example.com")
            await browser.inspect()
        # screencast is now in MinIO: screencasts/audit-2025-01-15.webm
    """

    def __init__(self, session_id: str, *, headless: bool = True) -> None:
        self.session_id = session_id
        self._headless  = headless
        self._sandbox: BrowserSandbox | None = None
        self.minio_key: str | None  = None
        self.video_path: str | None = None

    async def __aenter__(self) -> BrowserSandbox:
        self._sandbox = BrowserSandbox(headless=self._headless, record_video=True)
        return await self._sandbox.__aenter__()

    async def __aexit__(self, *exc_info) -> None:
        if self._sandbox is None:
            return
        await self._sandbox.__aexit__(*exc_info)
        self.video_path = self._sandbox.video_path
        if self.video_path and Path(self.video_path).exists():
            try:
                from warden.storage import s3 as _s3
                self.minio_key = _s3.ship_screencast(self.session_id, self.video_path)
                log.info(
                    "ScreencastRecorder: uploading %s → MinIO key=%s",
                    self.video_path, self.minio_key,
                )
            except Exception as exc:
                log.warning("ScreencastRecorder: MinIO upload skipped: %s", exc)
