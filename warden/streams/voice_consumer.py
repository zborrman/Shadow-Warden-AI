"""
warden/streams/voice_consumer.py  (VC-02 / B.3)
──────────────────────────────────────────────────
Kafka Consumer → Prometheus Bridge for voice metrics.

Subscribes to voice.* topics and updates Prometheus metrics in real time.

Topics consumed
───────────────
  voice.sessions       — {event: "started"|"ended", session_id, duration_sec?}
  voice.transactions   — {event: "purchase_completed"|"purchase_failed", amount_usd?}
  voice.latency        — {latency_ms: float, stage: str}
  voice.errors         — {stage: "asr"|"nlu"|"tts"|"guardian", error: str}

Usage
─────
  consumer = VoiceMetricsConsumer()
  await consumer.consume()  # runs indefinitely, cancelled by caller
"""
from __future__ import annotations

import logging

from warden.streams.event_bus import _KAFKA_SERVERS, KafkaEventBus

log = logging.getLogger("warden.streams.voice_consumer")

_VOICE_TOPICS = [
    "voice.sessions",
    "voice.transactions",
    "voice.latency",
    "voice.errors",
]


class VoiceMetricsConsumer:
    """
    Consumes voice.* Kafka topics and updates Prometheus metrics.

    Fail-open: if aiokafka is unavailable or Kafka is unreachable, the bus
    automatically falls back to Redis pub/sub.
    """

    def __init__(self, bootstrap_servers: str = _KAFKA_SERVERS) -> None:
        self._bus = KafkaEventBus(bootstrap_servers)

    async def start(self) -> None:
        """Start the underlying Kafka producer (required before consume)."""
        await self._bus.start()

    async def stop(self) -> None:
        await self._bus.stop()

    async def consume(self) -> None:
        """Subscribe to all voice topics and update Prometheus metrics. Runs indefinitely."""
        import asyncio

        await self.start()
        log.info("VoiceMetricsConsumer: starting consumption of voice.* topics")

        tasks = [
            asyncio.create_task(
                self._bus.consume(topic, "warden-voice-metrics", self._handle)
            )
            for topic in _VOICE_TOPICS
        ]
        try:
            await asyncio.gather(*tasks)
        finally:
            await self.stop()

    async def _handle(self, key: str, value: dict) -> None:
        """Route incoming message to the correct metric updater."""
        try:
            from warden.voice.metrics import (
                VOICE_ACTIVE_SESSIONS,
                VOICE_CONVERSIONS,
                VOICE_DEEPFAKE_DETECTED,
                VOICE_ERRORS,
                VOICE_LATENCY,
                VOICE_SESSION_DURATION,
                VOICE_SESSIONS_STARTED,
            )

            event = value.get("event", "")

            # Sessions
            if event == "started":
                VOICE_SESSIONS_STARTED.inc()
                VOICE_ACTIVE_SESSIONS.inc()
            elif event == "ended":
                VOICE_ACTIVE_SESSIONS.dec()
                dur = float(value.get("duration_sec", 0) or 0)
                if dur > 0:
                    VOICE_SESSION_DURATION.observe(dur)

            # Transactions
            elif event == "purchase_completed":
                VOICE_CONVERSIONS.inc()
            elif event == "deepfake_detected":
                VOICE_DEEPFAKE_DETECTED.inc()

            # Latency samples
            latency = value.get("latency_ms")
            if latency is not None:
                VOICE_LATENCY.observe(float(latency))

            # Errors
            stage = value.get("stage")
            if stage and (event in ("error", "failed") or "error" in value):
                VOICE_ERRORS.labels(stage=stage).inc()

        except Exception as exc:
            log.warning("VoiceMetricsConsumer._handle error: %s", exc)
