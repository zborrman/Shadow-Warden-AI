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
