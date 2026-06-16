# Event Streaming — MKT-10

**Version:** v6.6  
**Tier:** Pro+  
**Add-on:** `event_streaming_pack` — $19/mo

## Overview

Real-time event bus for marketplace agent coordination. Produces and consumes events on `marketplace.escrow` and `marketplace.listings` topics with Kafka as the primary transport and Redis pub/sub as automatic fallback.

## Architecture

```
Producer (marketplace events)
    ↓
KafkaEventBus.produce(topic, key, payload)
    ├── [Kafka available] → aiokafka AIOKafkaProducer → Broker
    └── [Kafka unavailable] → Redis PUBLISH (fail-open)
            ↓
FlinkAgentRunner (stateful stream consumer)
    ├── marketplace.escrow → _on_escrow() → Redis state hash
    │       └── _watchdog_loop() (every 5 min) → _auto_dispute() on TTL expired
    └── marketplace.listings → _on_listing() → community listing_count counter
```

## Files

| File | Role |
|------|------|
| `warden/streams/__init__.py` | Package init |
| `warden/streams/event_bus.py` | `KafkaEventBus` — produce/consume + Redis fallback + `health()` |
| `warden/streams/agent_runner.py` | `FlinkAgentRunner` — stateful processor + watchdog |
| `warden/streams/api.py` | FastAPI router `/streams/*` — health, replay, community state |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/streams/health` | Bus connection health (Kafka + Redis fallback status) |
| `POST` | `/streams/topics/{topic}/replay` | Admin: replay events from offset (requires `X-Admin-Key`) |
| `GET` | `/streams/communities/{community_id}/state` | Per-community runner state from Redis |

## Configuration

| Env Var | Default | Description |
|---------|---------|-------------|
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | Kafka broker address |
| `KAFKA_CONSUMER_GROUP` | `warden-marketplace` | Consumer group ID |
| `STREAMS_WATCHDOG_INTERVAL_S` | `300` | Escrow watchdog polling interval (seconds) |
| `ESCROW_TIMEOUT_S` | `86400` | Seconds before funded escrow is auto-disputed |

## Prometheus Metrics

| Metric | Labels | Description |
|--------|--------|-------------|
| `warden_streams_events_total` | `topic`, `direction` | Events produced/consumed |

## Fail-Open Guarantees

- Missing `aiokafka` → Redis pub/sub used transparently
- Missing Redis → in-memory queue (events lost on restart)
- `_auto_dispute()` is fire-and-forget; `EscrowService` unavailability is logged, not raised
