"""
Security headers are set by each app, not by the proxy.

Public traffic for the API, the portal and the dashboard goes through the
Cloudflare Tunnel straight to the container. Caddy is not on that path, so the
header snippet in docker/Caddyfile never reached a browser: on 2026-11-16 the
public portal answered with no HSTS, no nosniff and no framing rule. These
tests keep the headers where the tunnel cannot skip them.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO = Path(__file__).resolve().parents[2]

REQUIRED = {
    "Strict-Transport-Security": "max-age=63072000",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Content-Security-Policy": "frame-ancestors 'none'",
}

_LOADER = """
const path = process.argv[1];
(async () => {
  let mod = await import('file://' + path);
  const cfg = mod.default && mod.default.default ? mod.default.default : mod.default;
  const rules = await cfg.headers();
  console.log(JSON.stringify({ rules, poweredByHeader: cfg.poweredByHeader }));
})().catch((e) => { console.error(e); process.exit(1); });
"""


def _load_next_config(rel: str) -> dict:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    out = subprocess.run(
        [node, "-e", _LOADER, (REPO / rel).as_posix()],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


@pytest.mark.parametrize("config", ["portal/next.config.js", "dashboard/next.config.mjs"])
def test_next_app_sends_the_headers_on_every_path(config):
    loaded = _load_next_config(config)
    assert loaded["poweredByHeader"] is False
    rules = loaded["rules"]
    catch_all = [r for r in rules if r["source"] == "/:path*"]
    assert len(catch_all) == 1, f"{config}: no single rule covering every path"
    sent = {h["key"]: h["value"] for h in catch_all[0]["headers"]}
    for name, must_contain in REQUIRED.items():
        assert name in sent, f"{config}: {name} missing"
        assert must_contain in sent[name], f"{config}: {name} = {sent[name]!r}"


@pytest.mark.parametrize("config", ["portal/next.config.js", "dashboard/next.config.mjs"])
def test_the_csp_does_not_carry_a_directive_that_breaks_next(config):
    """A script-src or default-src without a nonce blanks a Next page. Adding one
    is deliberate work with a nonce middleware, not a one-line edit here."""
    rules = _load_next_config(config)["rules"]
    csp = next(h["value"] for h in rules[0]["headers"] if h["key"] == "Content-Security-Policy")
    assert "script-src" not in csp
    assert "default-src" not in csp


def test_the_gateway_sends_hsts_itself():
    from warden.main import app

    with TestClient(app) as client:
        resp = client.get("/health")
    assert resp.headers["strict-transport-security"].startswith("max-age=63072000")
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["x-content-type-options"] == "nosniff"


def test_only_the_preflight_simulator_may_be_framed_and_only_by_the_portal():
    rules = _load_next_config("portal/next.config.js")["rules"]
    loosened = [r for r in rules if r["source"] != "/:path*" and any(
        h["key"] in ("X-Frame-Options", "Content-Security-Policy") for h in r["headers"])]
    assert [r["source"] for r in loosened] == ["/preflight/sim.html"]
    sent = {h["key"]: h["value"] for h in loosened[0]["headers"]}
    assert sent["X-Frame-Options"] == "SAMEORIGIN"
    assert "frame-ancestors 'self'" in sent["Content-Security-Policy"]
    assert "connect-src 'none'" in sent["Content-Security-Policy"]
    page = (REPO / "portal/src/app/preflight/page.tsx").read_text(encoding="utf-8")
    import re
    sandbox = re.search(r'sandbox="([^"]*)"', page)
    assert sandbox and "allow-same-origin" not in sandbox.group(1)
