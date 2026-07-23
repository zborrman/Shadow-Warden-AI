"""
Tests for warden/client_ip.py — client identity resolution behind Cloudflare.

The invariant under test: forwarded headers are honoured *only* from a trusted
proxy peer. Everything downstream (ERS entity key, shadow ban, slowapi bucket,
marketplace quota) keys on this value, so a spoofable resolver would let one
caller shadow-ban another — and a proxy-constant resolver would collapse every
anonymous caller into a single bucket.
"""
from __future__ import annotations

import pytest
from starlette.requests import Request

from warden.client_ip import _trusted_networks, get_client_ip, is_trusted_proxy


def _req(peer: str | None, **headers: str) -> Request:
    """A real Starlette Request built from an ASGI scope.

    Deliberately not a hand-rolled double: header lookup in Starlette is
    case-insensitive and ``request.client`` is an ``Address`` tuple, and a stub
    that got either detail wrong would test something the app never does.
    """
    raw = [
        (k.lower().replace("_", "-").encode(), v.encode())
        for k, v in headers.items()
    ]
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/",
            "raw_path": b"/",
            "query_string": b"",
            "root_path": "",
            "server": ("testserver", 80),
            "client": (peer, 51234) if peer is not None else None,
            "headers": raw,
        }
    )


@pytest.fixture(autouse=True)
def _clear_cidr_cache():
    _trusted_networks.cache_clear()
    yield
    _trusted_networks.cache_clear()


class TestTrustedProxy:
    def test_docker_bridge_is_trusted(self):
        assert is_trusted_proxy("172.18.0.5") is True

    def test_loopback_is_trusted(self):
        assert is_trusted_proxy("127.0.0.1") is True

    def test_public_address_is_not_trusted(self):
        assert is_trusted_proxy("203.0.113.9") is False

    def test_garbage_is_not_trusted(self):
        assert is_trusted_proxy("not-an-ip") is False
        assert is_trusted_proxy("") is False

    def test_cidr_list_is_configurable(self, monkeypatch):
        monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "203.0.113.0/24")
        _trusted_networks.cache_clear()
        assert is_trusted_proxy("203.0.113.9") is True
        assert is_trusted_proxy("127.0.0.1") is False

    def test_malformed_cidr_entries_are_skipped(self, monkeypatch):
        monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "nonsense,,10.0.0.0/8")
        _trusted_networks.cache_clear()
        assert is_trusted_proxy("10.1.2.3") is True


class TestResolution:
    def test_prefers_cf_connecting_ip_from_trusted_peer(self):
        req = _req(
            "172.18.0.5",
            **{
                "cf-connecting-ip": "198.51.100.7",
                "x-real-ip": "10.9.9.9",
                "x-forwarded-for": "10.8.8.8",
            },
        )
        assert get_client_ip(req) == "198.51.100.7"

    def test_falls_back_to_x_real_ip(self):
        req = _req("172.18.0.5", **{"x-real-ip": "198.51.100.7"})
        assert get_client_ip(req) == "198.51.100.7"

    def test_falls_back_to_leftmost_xff_entry(self):
        req = _req("172.18.0.5", **{"x-forwarded-for": "198.51.100.7, 172.18.0.5"})
        assert get_client_ip(req) == "198.51.100.7"

    def test_untrusted_peer_cannot_spoof_identity(self):
        """Direct-to-origin request: headers are ignored, socket address wins."""
        req = _req(
            "203.0.113.9",
            **{"cf-connecting-ip": "1.2.3.4", "x-forwarded-for": "1.2.3.4"},
        )
        assert get_client_ip(req) == "203.0.113.9"

    def test_trusted_peer_without_headers_returns_peer(self):
        assert get_client_ip(_req("172.18.0.5")) == "172.18.0.5"

    def test_empty_header_is_skipped(self):
        req = _req("172.18.0.5", **{"cf-connecting-ip": "  ", "x-real-ip": "198.51.100.7"})
        assert get_client_ip(req) == "198.51.100.7"

    def test_missing_client_returns_empty(self):
        assert get_client_ip(_req(None)) == ""


class TestLimiterKeying:
    """The rate-limit bucket must not collapse to the proxy address."""

    def test_distinct_callers_get_distinct_buckets(self):
        from warden.limiter import tenant_key

        a = tenant_key(_req("172.18.0.5", **{"cf-connecting-ip": "198.51.100.1"}))
        b = tenant_key(_req("172.18.0.5", **{"cf-connecting-ip": "198.51.100.2"}))
        assert a != b

    def test_api_key_still_wins_over_ip(self):
        from warden.limiter import tenant_key

        req = _req("172.18.0.5", **{"x-api-key": "k-123", "cf-connecting-ip": "198.51.100.1"})
        assert tenant_key(req) == "k-123"


class TestMarketplaceBucketKey:
    """The marketplace quota must not be escapable by rotating a header."""

    def test_client_supplied_tenant_header_does_not_change_the_bucket(self):
        from warden.marketplace.rate_limit import _bucket_key

        base = _req("172.18.0.5", **{"cf-connecting-ip": "198.51.100.1"})
        spoofed = _req(
            "172.18.0.5",
            **{"cf-connecting-ip": "198.51.100.1", "x-tenant-id": "made-up-" + "x" * 8},
        )
        assert _bucket_key(base) == _bucket_key(spoofed)

    def test_api_key_identifies_the_bucket(self):
        from warden.marketplace.rate_limit import _bucket_key

        a = _req("172.18.0.5", **{"x-api-key": "key-a"})
        b = _req("172.18.0.5", **{"x-api-key": "key-b"})
        assert _bucket_key(a) != _bucket_key(b)

    def test_distinct_anonymous_callers_get_distinct_buckets(self):
        from warden.marketplace.rate_limit import _bucket_key

        a = _req("172.18.0.5", **{"cf-connecting-ip": "198.51.100.1"})
        b = _req("172.18.0.5", **{"cf-connecting-ip": "198.51.100.2"})
        assert _bucket_key(a) != _bucket_key(b)

    def test_key_material_is_not_echoed_into_the_bucket_name(self):
        """Known vector — the bucket name must be exactly the opaque digest."""
        import hashlib

        from warden.marketplace.rate_limit import _bucket_key

        secret = "super-secret-key"
        expected = "k:" + hashlib.sha256(secret.encode()).hexdigest()[:24]

        key = _bucket_key(_req("172.18.0.5", **{"x-api-key": secret}))
        assert key == expected
        assert secret not in key
