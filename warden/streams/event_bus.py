"""
warden/streams/event_bus.py
─────────────────────────────
Kafka/Redis dual-rail event bus.

Primary rail: aiokafka (AIOKafkaProducer/Consumer).
Fallback rail: Redis pub/sub when Kafka is unreachable.

Topics:
  marketplace.escrow         — escrow state transitions
  marketplace.listings       — listing lifecycle (created, published, purchased)
  marketplace.negotiations   — offer/counter-offer events
  community.membership       — join/leave/role-change events

Usage:
  bus = KafkaEventBus("localhost:9092")
  await bus.produce("marketplace.escrow", escrow_id, {"status": "funded"})
  await bus.consume("marketplace.escrow", "warden-group", my_handler)
"""
from __future__ import annotations

import json
import logging
import os
from collections.abc import Awaitable, Callable
from typing import Any

log = logging.getLogger("warden.streams.event_bus")

TOPICS = [
    "marketplace.escrow",
    "marketplace.listings",
    "marketplace.negotiations",
    "community.membership",
    "marketplace.agents",
    # Voice-Commerce topics (VC-02)
    "voice.sessions",
    "voice.transactions",
    "voice.latency",
    "voice.errors",
]

_KAFKA_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
_REDIS_URL     = os.getenv("REDIS_URL", "redis://localhost:6379/0")


def _redis_client():
    try:
        import redis as _r  # noqa: PLC0415
        if _REDIS_URL.startswith("memory://"):
            return None
        return _r.from_url(_REDIS_URL, decode_responses=True)
    except Exception:
        return None


class KafkaEventBus:
    """
    Async Kafka event bus with Redis fallback.

    The class is fail-open: if aiokafka is missing or Kafka is unreachable,
    all produce/consume calls fall back to Redis pub/sub silently.
    """

    def __init__(self, bootstrap_servers: str = _KAFKA_SERVERS) -> None:
        self.bootstrap_servers = bootstrap_servers
        self._producer: Any = None
        self._kafka_ok = False

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the Kafka producer. Falls back to no-op if unavailable."""
        try:
            from aiokafka import AIOKafkaProducer  # noqa: PLC0415
            self._producer = AIOKafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode(),
                key_serializer=lambda k: k.encode() if isinstance(k, str) else k,
            )
            await self._producer.start()
            self._kafka_ok = True
            log.info("KafkaEventBus: producer connected to %s", self.bootstrap_servers)
        except Exception as exc:
            log.warning("KafkaEventBus: Kafka unavailable (%s), using Redis fallback.", exc)
            self._kafka_ok = False

    async def stop(self) -> None:
        import contextlib
        if self._producer and self._kafka_ok:
            with contextlib.suppress(Exception):
                await self._producer.stop()

    def health(self) -> dict:
        return {
            "kafka_connected": self._kafka_ok,
            "redis_fallback": _redis_client() is not None,
        }

    # ── Produce ───────────────────────────────────────────────────────────────

    async def produce(self, topic: str, key: str, value: dict) -> None:
        """
        Publish *value* to *topic* with *key*.  Falls back to Redis pub/sub silently.
        """
        if self._kafka_ok and self._producer:
            try:
                await self._producer.send_and_wait(topic, value=value, key=key)
                return
            except Exception as exc:
                log.warning("KafkaEventBus.produce Kafka error: %s — falling back to Redis.", exc)

        # Redis pub/sub fallback (fail-open)
        self._redis_publish(topic, key, value)

    def _redis_publish(self, topic: str, key: str, value: dict) -> bool:
        try:
            r = _redis_client()
            if r:
                payload = json.dumps({"key": key, "value": value})
                r.publish(f"stream:{topic}", payload)
                return True
        except Exception as exc:
            log.debug("KafkaEventBus: Redis fallback also failed: %s", exc)
        return False

    # ── Consume ───────────────────────────────────────────────────────────────

    async def consume(
        self,
        topic:    str,
        group_id: str,
        handler:  Callable[[str, dict], Awaitable[None]],
    ) -> None:
        """
        Consume messages from *topic* and call *handler(key, value)* per message.
        Runs until cancelled.  Falls back to Redis subscribe when Kafka unavailable.
        """
        if self._kafka_ok:
            await self._consume_kafka(topic, group_id, handler)
        else:
            await self._consume_redis(topic, handler)

    async def _consume_kafka(
        self,
        topic:    str,
        group_id: str,
        handler:  Callable[[str, dict], Awaitable[None]],
    ) -> None:
        try:
            from aiokafka import AIOKafkaConsumer  # noqa: PLC0415
            consumer = AIOKafkaConsumer(
                topic,
                bootstrap_servers=self.bootstrap_servers,
                group_id=group_id,
                value_deserializer=lambda v: json.loads(v.decode()),
                auto_offset_reset="latest",
            )
            await consumer.start()
            log.info("KafkaEventBus: consuming from %s (group=%s)", topic, group_id)
            try:
                async for msg in consumer:
                    key = msg.key.decode() if msg.key else ""
                    try:
                        await handler(key, msg.value)
                    except Exception as exc:
                        log.warning("KafkaEventBus handler error topic=%s: %s", topic, exc)
            finally:
                await consumer.stop()
        except Exception as exc:
            log.warning("KafkaEventBus._consume_kafka error: %s", exc)

    async def _consume_redis(
        self,
        topic:   str,
        handler: Callable[[str, dict], Awaitable[None]],
    ) -> None:
        import asyncio  # noqa: PLC0415
        try:
            import redis as _r  # noqa: PLC0415
            if _REDIS_URL.startswith("memory://"):
                log.debug("KafkaEventBus: Redis fallback unavailable (memory mode).")
                return
            r = _r.from_url(_REDIS_URL, decode_responses=True)
            pubsub = r.pubsub()
            pubsub.subscribe(f"stream:{topic}")
            log.info("KafkaEventBus: Redis fallback subscribe stream:%s", topic)
            while True:
                msg = pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if msg and msg["type"] == "message":
                    try:
                        payload = json.loads(msg["data"])
                        await handler(payload.get("key", ""), payload.get("value", {}))
                    except Exception as exc:
                        log.warning("KafkaEventBus Redis handler error: %s", exc)
                await asyncio.sleep(0.1)
        except Exception as exc:
            log.warning("KafkaEventBus._consume_redis error: %s", exc)


# ── Module-level singleton ─────────────────────────────────────────────────────

_bus: KafkaEventBus | None = None


def get_event_bus() -> KafkaEventBus:
    global _bus
    if _bus is None:
        _bus = KafkaEventBus()
    return _bus
