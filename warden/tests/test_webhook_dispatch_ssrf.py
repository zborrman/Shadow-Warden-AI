"""
The singular /webhook delivery path must apply the SSRF guard (vuln-0001 / CWE-918).

Strix registered a webhook pointing at 127.0.0.1 / 169.254.169.254 and the
gateway POSTed to it — the plural /webhooks/* path guards this with
assert_public_url + send_pinned_async, the singular one did neither. Delivery now
validates + IP-pins, and an internal target is dropped (never delivered, never
retried).
"""
from __future__ import annotations

import pytest

from warden import webhook_dispatch as wd


@pytest.mark.asyncio
async def test_deliver_drops_metadata_target(monkeypatch):
    monkeypatch.setenv("NET_GUARD_ALLOW_PRIVATE", "false")
    sent = []
    monkeypatch.setattr(wd.log, "warning", lambda *a, **k: sent.append(("warn", a)))
    # cloud-metadata IP: send_pinned_async must raise SSRFError, _deliver swallows
    # it and returns (drop). No exception escapes, nothing is delivered.
    result = await wd._deliver("http://169.254.169.254/latest/meta-data/", b"{}", "sig")
    assert result is None
    assert any(tag == "warn" for tag, _ in sent), "SSRF drop was not logged"


@pytest.mark.asyncio
async def test_deliver_drops_loopback_target(monkeypatch):
    monkeypatch.setenv("NET_GUARD_ALLOW_PRIVATE", "false")
    # 127.0.0.1 must be blocked at delivery — no raise, dropped.
    assert await wd._deliver("http://127.0.0.1:9/probe", b"{}", "sig") is None
