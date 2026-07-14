"""
SR-7.2 — error/branch coverage for the SSRF guard (warden/net_guard.py).

The DNS-rebind guarantees are pinned in test_net_guard_pinning.py. This file covers
the fail-CLOSED error paths the guard must honour so a malformed or hostile URL can
never slip through as "safe": unparseable URLs, missing hosts, cloud-metadata hosts,
DNS failures, empty resolutions, and unparseable resolved addresses. Every one of
these must raise SSRFError (or return False via is_public_url), never pass silently.
"""
from __future__ import annotations

from unittest import mock

import pytest

from warden import net_guard as ng
from warden.net_guard import (
    SSRFError,
    assert_public_url,
    is_public_url,
    resolve_validated_ips,
)


def _dns(*addrs):
    return mock.patch("warden.net_guard._resolve_all", return_value=list(addrs))


# ── _resolve_all real body ──────────────────────────────────────────────────────

class TestResolveAll:
    def test_localhost_resolves_to_loopback(self):
        """Exercises the real getaddrinfo path (no mock) — localhost is always resolvable."""
        addrs = ng._resolve_all("localhost")
        assert addrs, "localhost must resolve to at least one address"
        # localhost must map only to loopback addresses.
        assert all(a.startswith("127.") or a == "::1" for a in addrs)


# ── Unparseable / malformed input (fail-closed) ─────────────────────────────────

class TestMalformedInput:
    def test_resolve_non_string_raises_ssrf(self):
        # urlparse chokes on a non-str/bytes input → treated as unsafe, not a crash.
        with pytest.raises(SSRFError):
            resolve_validated_ips(123)  # type: ignore[arg-type]

    def test_assert_non_string_raises_ssrf(self):
        with pytest.raises(SSRFError):
            assert_public_url(123)  # type: ignore[arg-type]

    def test_url_without_host_raises(self):
        with pytest.raises(SSRFError, match="no host"):
            resolve_validated_ips("http:///just/a/path")

    def test_assert_url_without_host_raises(self):
        with pytest.raises(SSRFError, match="no host"):
            assert_public_url("http:///just/a/path")

    def test_disallowed_scheme_rejected(self):
        with pytest.raises(SSRFError, match="scheme"):
            assert_public_url("file:///etc/passwd")

    def test_gopher_scheme_rejected(self):
        assert is_public_url("gopher://evil/") is False


# ── Cloud metadata hosts (by name, no DNS) ──────────────────────────────────────

class TestMetadataHosts:
    def test_gcp_metadata_hostname_blocked(self):
        with pytest.raises(SSRFError, match="metadata"):
            resolve_validated_ips("http://metadata.google.internal/computeMetadata/v1/")

    def test_metadata_ip_literal_blocked(self):
        with pytest.raises(SSRFError):
            resolve_validated_ips("http://169.254.169.254/latest/meta-data/")


# ── DNS failure modes (fail-closed) ─────────────────────────────────────────────

class TestDnsFailures:
    def test_dns_resolution_failure_raises(self):
        with mock.patch("warden.net_guard._resolve_all", side_effect=OSError("NXDOMAIN")), \
             pytest.raises(SSRFError, match="DNS resolution failed"):
            resolve_validated_ips("https://nonexistent.example.invalid/")

    def test_empty_resolution_raises(self):
        with _dns(), pytest.raises(SSRFError, match="no addresses"):
            resolve_validated_ips("https://ghost.example.com/")

    def test_unparseable_resolved_address_raises(self):
        with _dns("not-an-ip-at-all"), pytest.raises(SSRFError, match="unparseable"):
            resolve_validated_ips("https://weird.example.com/")

    def test_resolved_metadata_address_blocked(self):
        """A host resolving to the metadata IP is blocked even if its name looks benign."""
        with _dns("169.254.169.254"), pytest.raises(SSRFError):
            resolve_validated_ips("https://benign-name.example.com/")


# ── is_public_url wrapper ───────────────────────────────────────────────────────

class TestIsPublicUrl:
    def test_public_host_true(self, monkeypatch):
        monkeypatch.setenv("NET_GUARD_ALLOW_PRIVATE", "false")
        with _dns("93.184.216.34"):
            assert is_public_url("https://example.com/") is True

    def test_private_host_false(self, monkeypatch):
        monkeypatch.setenv("NET_GUARD_ALLOW_PRIVATE", "false")
        with _dns("10.0.0.1"):
            assert is_public_url("https://internal.example.com/") is False

    def test_allow_private_escape_hatch_permits_loopback_in_assert(self, monkeypatch):
        """assert_public_url honours the dev escape hatch and skips range checks."""
        monkeypatch.setenv("NET_GUARD_ALLOW_PRIVATE", "true")
        # No raise, and no DNS round-trip needed.
        with mock.patch("warden.net_guard._resolve_all", side_effect=AssertionError("no DNS")):
            assert_public_url("http://127.0.0.1:8001/health")
