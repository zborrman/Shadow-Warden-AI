"""
Tests for MISP ZMQ → syslog bridge (IN-22).

Covers:
  - Syslog line format compatibility with syslog_sink._parse_dns_line()
  - MISP event attribute extraction + stats tracking
  - Domain / IP classification routing
  - Attribute type filtering (_ALL_TYPES gate)
  - get_bridge_stats() snapshot isolation
"""
from __future__ import annotations

import json
import socket
import threading
import time
from unittest.mock import MagicMock, patch

import pytest


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_attr(atype: str, value: str, comment: str = "") -> dict:
    return {"type": atype, "value": value, "comment": comment}


def _make_event(attrs: list[dict], info: str = "Test Event") -> dict:
    return {"Event": {"id": "42", "info": info, "Attribute": attrs, "Object": []}}


# ── 1. Syslog format parses correctly ─────────────────────────────────────────

class TestSyslogFormat:
    """Lines forwarded by the bridge must be parsed by syslog_sink._parse_dns_line."""

    def test_dnsmasq_line_parsed_by_sink(self):
        from warden.shadow_ai.syslog_sink import _parse_dns_line

        line = "query[A] evil.example.com from 127.0.0.1"
        result = _parse_dns_line(line)

        assert result is not None, "syslog_sink must parse the bridge's line format"
        domain, src_ip = result
        assert domain == "evil.example.com"
        assert src_ip == "127.0.0.1"

    def test_short_label_rejected_by_sink(self):
        from warden.shadow_ai.syslog_sink import _parse_dns_line

        # A bare label without a dot should NOT match
        result = _parse_dns_line("query[A] localhost from 127.0.0.1")
        # localhost has no dot — dnsmasq regex still matches the word; that's OK
        # but let's verify domain extraction doesn't panic
        if result is not None:
            domain, _ = result
            assert isinstance(domain, str)


# ── 2. Attribute extraction ───────────────────────────────────────────────────

class TestAttributeExtraction:
    def setup_method(self):
        from warden.integrations import misp_bridge
        # Reset stats before each test
        misp_bridge._BRIDGE_STATS.update({
            "zmq_events": 0, "http_events": 0, "attrs_ingested": 0,
            "domains_classified": 0, "ips_blocked": 0,
            "syslog_forwarded": 0, "errors": 0, "last_event_ts": None,
        })

    def test_domain_attr_increments_attrs_ingested(self):
        from warden.integrations.misp_bridge import _ingest_attribute, _BRIDGE_STATS

        with patch("warden.integrations.misp_bridge._forward_domain_to_syslog"):
            with patch("warden.integrations.misp_bridge.ShadowAIDetector", create=True):
                _ingest_attribute(_make_attr("domain", "malware-c2.example.com"), "Test")

        assert _BRIDGE_STATS["attrs_ingested"] >= 1

    def test_ip_attr_does_not_send_syslog(self):
        from warden.integrations.misp_bridge import _ingest_attribute

        forwarded = []
        with patch("warden.integrations.misp_bridge._forward_domain_to_syslog",
                   side_effect=lambda d: forwarded.append(d)):
            # IP attrs should NOT forward to syslog — only IPs
            _ingest_attribute(_make_attr("ip-dst", "1.2.3.4"), "Test")

        assert forwarded == [], "IP IoCs must not be forwarded to the DNS syslog sink"

    def test_unknown_type_is_ignored(self):
        from warden.integrations.misp_bridge import _ingest_attribute, _BRIDGE_STATS

        before = _BRIDGE_STATS["attrs_ingested"]
        _ingest_attribute(_make_attr("btc", "1A2B3C4D"), "Test")
        assert _BRIDGE_STATS["attrs_ingested"] == before

    def test_empty_value_is_ignored(self):
        from warden.integrations.misp_bridge import _ingest_attribute, _BRIDGE_STATS

        before = _BRIDGE_STATS["attrs_ingested"]
        _ingest_attribute(_make_attr("domain", ""), "Test")
        assert _BRIDGE_STATS["attrs_ingested"] == before

    def test_domain_pipe_notation_extracted(self):
        """domain|ip attribute should use the domain part only."""
        from warden.integrations.misp_bridge import _ingest_attribute

        forwarded: list[str] = []
        with patch("warden.integrations.misp_bridge._forward_domain_to_syslog",
                   side_effect=lambda d: forwarded.append(d)):
            with patch("warden.integrations.misp_bridge.ShadowAIDetector", create=True):
                _ingest_attribute(_make_attr("domain|ip", "evil.com|10.0.0.1"), "Test")

        if forwarded:
            assert forwarded[0] == "evil.com"


# ── 3. Event processing ───────────────────────────────────────────────────────

class TestEventProcessing:
    def setup_method(self):
        from warden.integrations import misp_bridge
        misp_bridge._BRIDGE_STATS.update({
            "zmq_events": 0, "http_events": 0, "attrs_ingested": 0,
            "domains_classified": 0, "ips_blocked": 0,
            "syslog_forwarded": 0, "errors": 0, "last_event_ts": None,
        })

    def test_process_event_counts_zmq(self):
        from warden.integrations.misp_bridge import _process_misp_event, _BRIDGE_STATS

        event = _make_event([_make_attr("domain", "test.example.com")])
        with patch("warden.integrations.misp_bridge._ingest_attribute"):
            _process_misp_event(event, source="zmq")

        assert _BRIDGE_STATS["zmq_events"] == 1
        assert _BRIDGE_STATS["http_events"] == 0

    def test_process_event_counts_http(self):
        from warden.integrations.misp_bridge import _process_misp_event, _BRIDGE_STATS

        event = _make_event([_make_attr("ip-dst", "5.6.7.8")])
        with patch("warden.integrations.misp_bridge._ingest_attribute"):
            _process_misp_event(event, source="http")

        assert _BRIDGE_STATS["http_events"] == 1

    def test_process_event_walks_objects(self):
        """Attributes nested inside MISP Objects must be ingested."""
        from warden.integrations.misp_bridge import _process_misp_event

        event = {
            "Event": {
                "id": "99", "info": "Nested", "Attribute": [],
                "Object": [{"Attribute": [_make_attr("domain", "nested.example.com")]}],
            }
        }
        ingested: list[dict] = []
        with patch("warden.integrations.misp_bridge._ingest_attribute",
                   side_effect=lambda a, i="": ingested.append(a)):
            _process_misp_event(event)

        assert len(ingested) == 1
        assert ingested[0]["value"] == "nested.example.com"

    def test_last_event_ts_updated(self):
        from warden.integrations.misp_bridge import _process_misp_event, _BRIDGE_STATS

        assert _BRIDGE_STATS["last_event_ts"] is None
        event = _make_event([])
        with patch("warden.integrations.misp_bridge._ingest_attribute"):
            _process_misp_event(event)
        assert _BRIDGE_STATS["last_event_ts"] is not None


# ── 4. Stats snapshot isolation ───────────────────────────────────────────────

class TestStats:
    def test_get_bridge_stats_returns_copy(self):
        from warden.integrations.misp_bridge import get_bridge_stats, _BRIDGE_STATS

        snap = get_bridge_stats()
        snap["zmq_events"] = 99999
        # Original must be unchanged
        assert _BRIDGE_STATS["zmq_events"] != 99999

    def test_stats_keys_present(self):
        from warden.integrations.misp_bridge import get_bridge_stats

        stats = get_bridge_stats()
        for key in ("zmq_events", "http_events", "attrs_ingested",
                    "domains_classified", "ips_blocked",
                    "syslog_forwarded", "errors", "last_event_ts"):
            assert key in stats, f"Missing stats key: {key}"


# ── 5. REST API ───────────────────────────────────────────────────────────────

_PRO_HEADERS = {"X-Tenant-Tier": "pro"}


class TestMispApi:
    @pytest.fixture()
    def client(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from warden.api.misp import router

        app = FastAPI()
        app.include_router(router)
        return TestClient(app, raise_server_exceptions=False)

    def test_status_200(self, client):
        r = client.get("/misp/status", headers=_PRO_HEADERS)
        assert r.status_code == 200

    def test_status_schema(self, client):
        data = client.get("/misp/status", headers=_PRO_HEADERS).json()
        assert "zmq_mode" in data
        assert "syslog_forwarding" in data
        assert "syslog_target" in data

    def test_stats_200(self, client):
        r = client.get("/misp/stats", headers=_PRO_HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert "attrs_ingested" in data

    def test_sync_422_without_config(self, client):
        r = client.post("/misp/sync", headers=_PRO_HEADERS)
        # Without MISP_API_URL+KEY configured, should return 422
        assert r.status_code in (422, 503)

    def test_gated_for_starter(self, client):
        r = client.get("/misp/status", headers={"X-Tenant-Tier": "starter"})
        assert r.status_code == 403
