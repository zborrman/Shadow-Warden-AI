"""
SR-2.3 — validated-IP resolver (foundation for DNS-rebind/TOCTOU pinning).

`assert_public_url` resolves + validates a host, but a caller that then hands the URL to
httpx lets httpx **re-resolve** at connect time. Attacker-controlled DNS can answer
"public" during the check and "127.0.0.1 / 169.254.169.254" at connect — the validation
is bypassed. The only robust fix is to dial one of the IPs validated at check time.

`resolve_validated_ips()` returns exactly those validated IPs (raising on any blocked
address), so a pinned transport can connect to them directly instead of re-resolving.
These tests pin the resolver's guarantees; wiring a pinned httpx transport into the live
callers is the remaining SR-2.3 step (needs a real-host TLS-SNI test).
"""
from __future__ import annotations

from unittest import mock

import pytest

from warden.net_guard import SSRFError, assert_public_url, resolve_validated_ips


def _dns(*addrs):
    return mock.patch("warden.net_guard._resolve_all", return_value=list(addrs))


class TestReturnsValidatedIPs:
    def test_public_host_returns_its_addresses(self):
        with _dns("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"):
            ips = resolve_validated_ips("https://example.com/x")
        assert set(ips) == {"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"}

    def test_raw_public_ip_returns_itself_no_dns(self):
        with mock.patch("warden.net_guard._resolve_all", side_effect=AssertionError("no DNS")):
            assert resolve_validated_ips("https://93.184.216.34/") == ["93.184.216.34"]


class TestBlocksRebindTargets:
    @pytest.mark.parametrize("bad", [
        "127.0.0.1",          # loopback
        "169.254.169.254",    # cloud metadata / link-local
        "10.0.0.5",           # RFC1918
        "192.168.1.1",        # RFC1918
        "::1",                # loopback v6
    ])
    def test_host_resolving_to_blocked_ip_is_rejected(self, bad):
        """The rebind payload: DNS answers a private/metadata IP → must raise, not return."""
        with _dns(bad), pytest.raises(SSRFError):
            resolve_validated_ips("https://evil.example.com/")

    def test_mixed_public_and_private_is_rejected(self):
        """One poisoned record among public ones must still fail closed."""
        with _dns("93.184.216.34", "127.0.0.1"), pytest.raises(SSRFError):
            resolve_validated_ips("https://evil.example.com/")

    def test_raw_private_ip_rejected(self):
        with pytest.raises(SSRFError):
            resolve_validated_ips("http://169.254.169.254/latest/meta-data/")


class TestConsistentWithAssertPublicUrl:
    """The two entry points must agree — assert_public_url now delegates here."""

    def test_both_reject_the_same_rebind(self, monkeypatch):
        # conftest sets NET_GUARD_ALLOW_PRIVATE=true globally (offline test URLs);
        # assert_public_url honours that escape hatch, so flip it off to exercise enforcement.
        # resolve_validated_ips is the strict primitive and ignores it by design.
        monkeypatch.setenv("NET_GUARD_ALLOW_PRIVATE", "false")
        with _dns("127.0.0.1"):
            with pytest.raises(SSRFError):
                resolve_validated_ips("https://evil.example.com/")
            with pytest.raises(SSRFError):
                assert_public_url("https://evil.example.com/")

    def test_both_accept_the_same_public_host(self, monkeypatch):
        monkeypatch.setenv("NET_GUARD_ALLOW_PRIVATE", "false")
        with _dns("93.184.216.34"):
            assert resolve_validated_ips("https://example.com/") == ["93.184.216.34"]
            assert_public_url("https://example.com/")   # no raise

    def test_strict_primitive_ignores_allow_private_escape_hatch(self, monkeypatch):
        """resolve_validated_ips must validate even when the dev escape hatch is on —
        a pinned transport can never be allowed to dial a private IP."""
        monkeypatch.setenv("NET_GUARD_ALLOW_PRIVATE", "true")
        with _dns("127.0.0.1"), pytest.raises(SSRFError):
            resolve_validated_ips("https://evil.example.com/")


# ── SR-2.3: connection pinning (build_pinned_url + send_pinned_async) ──────────
#
# The transport wiring step: dial the validated IP while preserving the Host
# header and TLS SNI, so httpx cannot re-resolve to an internal address at
# connect time. These pin the primitive; the real-host SNI proof is the
# integration test at the bottom (network-gated).

import httpx  # noqa: E402

from warden.net_guard import build_pinned_url, send_pinned_async  # noqa: E402


class TestBuildPinnedUrl:
    def test_https_pins_ip_keeps_host_and_sni(self):
        with _dns("93.184.216.34"):
            connect, host_header, sni = build_pinned_url("https://example.com/hook?x=1")
        assert connect == "https://93.184.216.34/hook?x=1"   # dialled by IP
        assert host_header == "example.com"                   # Host header unchanged
        assert sni == "example.com"                           # cert verifies vs real name

    def test_nondefault_port_preserved_in_url_and_host(self):
        with _dns("93.184.216.34"):
            connect, host_header, sni = build_pinned_url("https://example.com:8443/p")
        assert connect == "https://93.184.216.34:8443/p"
        assert host_header == "example.com:8443"
        assert sni == "example.com"

    def test_ipv4_preferred_over_ipv6(self):
        with _dns("2606:2800:220:1:248:1893:25c8:1946", "93.184.216.34"):
            connect, _h, _s = build_pinned_url("https://example.com/")
        assert connect == "https://93.184.216.34/"

    def test_ipv6_only_is_bracketed(self):
        with _dns("2606:2800:220:1:248:1893:25c8:1946"):
            connect, _h, _s = build_pinned_url("https://example.com/")
        assert connect == "https://[2606:2800:220:1:248:1893:25c8:1946]/"

    def test_userinfo_preserved(self):
        with _dns("93.184.216.34"):
            connect, _h, _s = build_pinned_url("https://user:pass@example.com/")
        assert connect == "https://user:pass@93.184.216.34/"

    def test_rebind_target_raises_before_returning(self):
        with _dns("127.0.0.1"), pytest.raises(SSRFError):
            build_pinned_url("https://evil.example.com/")


class TestSendPinnedAsync:
    @pytest.mark.asyncio
    async def test_dials_ip_but_sends_host_and_sni(self):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = request.url
            captured["host"] = request.headers.get("host")
            captured["sni"] = request.extensions.get("sni_hostname")
            return httpx.Response(204)

        with _dns("93.184.216.34"):
            resp = await send_pinned_async(
                "POST", "https://example.com/webhook",
                content=b"{}", headers={"X-Warden-Event": "ping"},
                transport=httpx.MockTransport(handler),
            )
        assert resp.status_code == 204
        assert captured["url"].host == "93.184.216.34"     # connected to the IP
        assert captured["host"] == "example.com"            # Host header = real name
        assert captured["sni"] == "example.com"             # SNI = real name

    @pytest.mark.asyncio
    async def test_caller_host_header_is_overridden(self):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["host"] = request.headers.get("host")
            return httpx.Response(200)

        with _dns("93.184.216.34"):
            await send_pinned_async(
                "GET", "https://example.com/",
                headers={"Host": "spoofed.evil.com"},          # must be ignored
                transport=httpx.MockTransport(handler),
            )
        assert captured["host"] == "example.com"

    @pytest.mark.asyncio
    async def test_blocked_url_raises_before_network(self):
        sent = False

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal sent
            sent = True
            return httpx.Response(200)

        with _dns("169.254.169.254"), pytest.raises(SSRFError):
            await send_pinned_async(
                "GET", "https://metadata-lookalike.example.com/",
                transport=httpx.MockTransport(handler),
            )
        assert sent is False       # never reached the transport

    @pytest.mark.asyncio
    async def test_redirects_disabled_by_default(self):
        """A 302 to an internal URL must NOT be auto-followed (would re-open SSRF)."""
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(302, headers={"Location": "http://169.254.169.254/"})

        with _dns("93.184.216.34"):
            resp = await send_pinned_async(
                "GET", "https://example.com/",
                transport=httpx.MockTransport(handler),
            )
        assert resp.status_code == 302     # returned, not followed


@pytest.mark.integration
@pytest.mark.asyncio
async def test_real_host_tls_sni_roundtrip():
    """End-to-end proof: pin to example.com's real IP, verify the cert still checks
    against the hostname over TLS. Network-gated (skips offline)."""
    try:
        resp = await send_pinned_async("GET", "https://example.com/", timeout=10.0)
    except (httpx.ConnectError, httpx.ConnectTimeout, SSRFError) as exc:
        pytest.skip(f"no network / DNS for real-host SNI test: {exc}")
    assert resp.status_code in (200, 404, 301, 302)


# ── SR-2.3 follow-on: sync send_pinned + params passthrough ────────────────────

from warden.net_guard import send_pinned  # noqa: E402


class TestSendPinnedSync:
    def test_sync_dials_ip_but_sends_host_and_sni(self):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = request.url
            captured["host"] = request.headers.get("host")
            captured["sni"] = request.extensions.get("sni_hostname")
            return httpx.Response(200)

        with _dns("93.184.216.34"):
            resp = send_pinned(
                "POST", "https://example.com/hook", json={"a": 1},
                transport=httpx.MockTransport(handler),
            )
        assert resp.status_code == 200
        assert captured["url"].host == "93.184.216.34"
        assert captured["host"] == "example.com"
        assert captured["sni"] == "example.com"

    def test_sync_blocked_url_raises_before_network(self):
        sent = False

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal sent
            sent = True
            return httpx.Response(200)

        with _dns("10.0.0.5"), pytest.raises(SSRFError):
            send_pinned("GET", "https://evil.example.com/", transport=httpx.MockTransport(handler))
        assert sent is False

    def test_params_are_forwarded(self):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["query"] = dict(request.url.params)
            return httpx.Response(200)

        with _dns("93.184.216.34"):
            send_pinned(
                "GET", "https://example.com/search", params={"q": "abc", "limit": 5},
                transport=httpx.MockTransport(handler),
            )
        assert captured["query"] == {"q": "abc", "limit": "5"}
