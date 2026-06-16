"""
warden/streams/api.py
──────────────────────
FastAPI router for Kafka/Redis stream management.

Endpoints:
  GET  /streams/health              — connection status and consumer lag
  POST /streams/topics/{topic}/replay  — admin: replay events from timestamp
"""
from __future__ import annotations

import logging
import os

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from warden.streams.agent_runner import get_runner
from warden.streams.event_bus import TOPICS, get_event_bus

log = logging.getLogger("warden.streams.api")
router = APIRouter(prefix="/streams", tags=["Streams"])

_ADMIN_KEY = os.getenv("ADMIN_KEY", "")


# ── Models ────────────────────────────────────────────────────────────────────

class ReplayRequest(BaseModel):
    from_timestamp: str
    community_id: str = ""


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/health")
def streams_health():
    """Return Kafka connection status and Redis fallback state."""
    bus = get_event_bus()
    runner = get_runner()
    return {
        "kafka_connected":     bus._kafka_ok,
        "bootstrap_servers":   bus.bootstrap_servers,
        "redis_fallback_active": not bus._kafka_ok,
        "topics":              TOPICS,
        "runner_running":      runner._running,
        "runner_tasks":        len(runner._tasks),
    }


@router.post("/topics/{topic}/replay")
def replay_topic(topic: str, body: ReplayRequest, request: Request):
    """Admin — replay events on a topic from a given timestamp."""
    key = request.headers.get("X-Admin-Key", "")
    if _ADMIN_KEY and key != _ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Admin key required.")
    if topic not in TOPICS:
        raise HTTPException(status_code=404, detail=f"Unknown topic: {topic!r}. Valid: {TOPICS}")
    # In production this would seek the Kafka consumer to the given offset.
    # For now, return acknowledgement with metadata.
    return {
        "replaying":      True,
        "topic":          topic,
        "from_timestamp": body.from_timestamp,
        "community_id":   body.community_id,
        "note":           "Consumer offset seek requires a running aiokafka consumer.",
    }


@router.get("/state/{community_id}")
def community_runner_state(community_id: str):
    """Return the FlinkAgentRunner state counters for a community."""
    runner = get_runner()
    return {"community_id": community_id, "state": runner.get_state(community_id)}
