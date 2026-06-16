"""Tests for Kafka/Flink Event Streaming (MKT-10)."""
from __future__ import annotations

import asyncio

from warden.streams.agent_runner import FlinkAgentRunner, get_runner
from warden.streams.event_bus import KafkaEventBus, get_event_bus

# ── KafkaEventBus ─────────────────────────────────────────────────────────────

class TestKafkaEventBus:

    def test_singleton(self):
        a = get_event_bus()
        b = get_event_bus()
        assert a is b

    def test_produce_fallback_no_error(self):
        """produce() must not raise even when Kafka is unavailable (Redis fallback)."""
        bus = KafkaEventBus(bootstrap_servers="localhost:9999")
        asyncio.run(
            bus.produce("marketplace.test", "key-1", {"event": "test"})
        )

    def test_produce_returns_none(self):
        bus = KafkaEventBus(bootstrap_servers="localhost:9999")
        result = asyncio.run(
            bus.produce("marketplace.test", "key-2", {"x": 1})
        )
        assert result is None

    def test_health_returns_dict(self):
        bus = KafkaEventBus(bootstrap_servers="localhost:9999")
        h = bus.health()
        assert "kafka_connected" in h
        assert "redis_fallback" in h

    def test_start_stop_no_error(self):
        bus = KafkaEventBus(bootstrap_servers="localhost:9999")
        asyncio.run(bus.start())
        asyncio.run(bus.stop())

    def test_produce_json_serializable_payload(self):
        bus = KafkaEventBus(bootstrap_servers="localhost:9999")
        payload = {"amount": 99.5, "agent_id": "agent-42", "ts": "2026-01-01T00:00:00Z"}
        asyncio.run(
            bus.produce("marketplace.escrow", "escrow-1", payload)
        )


# ── FlinkAgentRunner ──────────────────────────────────────────────────────────

class TestFlinkAgentRunner:

    def test_singleton(self):
        r1 = get_runner()
        r2 = get_runner()
        assert r1 is r2

    def test_on_listing_increments_counter(self):
        runner = FlinkAgentRunner()
        asyncio.run(
            runner._on_listing("community-xyz", {"listing_id": "L1", "asset_type": "rule"})
        )
        state = runner.get_state("community-xyz")
        assert state.get("listing_count", 0) >= 1

    def test_on_escrow_records_escrow(self):
        runner = FlinkAgentRunner()
        asyncio.run(
            runner._on_escrow("community-xyz", {
                "escrow_id": "ESC-001",
                "amount_usd": 10.0,
                "status": "FUNDED",
            })
        )

    def test_get_state_returns_dict(self):
        runner = FlinkAgentRunner()
        state = runner.get_state("community-unknown")
        assert isinstance(state, dict)

    def test_auto_dispute_fail_open(self):
        """_auto_dispute must not raise if EscrowService unavailable."""
        runner = FlinkAgentRunner()
        asyncio.run(
            runner._auto_dispute("community-xyz", "ESC-MISSING")
        )
