"""
warden/voice/api.py
FastAPI router for voice-commerce endpoints.

Routes
------
  POST   /voice/session              — create session, return session_id
  WS     /voice/stream/{session_id}  — bidirectional audio stream
  POST   /voice/transcribe           — REST fallback: upload audio → transcript + intent
  GET    /voice/sessions/{id}        — session status + history
  POST   /voice/x402/request         — request paid resource, returns 402 if insufficient
  POST   /voice/x402/confirm         — confirm external payment, credit balance
  GET    /voice/x402/balance/{agent} — query agent balance

Feature gate: voice_commerce_enabled (Pro+).
"""
from __future__ import annotations

import base64
import json
import logging
import os
import time
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

log = logging.getLogger("warden.voice.api")

router = APIRouter(prefix="/voice", tags=["voice-commerce"])

_FEATURE_GATE = os.getenv("VOICE_COMMERCE_ENABLED", "true").lower() != "false"
_TTS_ENABLED  = os.getenv("VOICE_TTS_ENABLED", "false").lower() == "true"


def _require_voice():
    if not _FEATURE_GATE:
        raise HTTPException(403, "voice_commerce_enabled requires Pro+ tier")


# ── Pydantic models ────────────────────────────────────────────────────────────

class SessionCreate(BaseModel):
    tenant_id:    str  = "default"
    community_id: str  = "default"
    tts_enabled:  bool = False


class SessionResponse(BaseModel):
    session_id:   str
    ws_url:       str
    created_at:   str


class TranscribeRequest(BaseModel):
    audio_base64: str
    provider:     str  = "whisper"
    tenant_id:    str  = "default"
    community_id: str  = "default"


class TranscribeResponse(BaseModel):
    transcript:   str
    intent_type:  str
    entities:     dict
    confidence:   float
    elapsed_ms:   float


class X402Request(BaseModel):
    agent_id:   str
    service_id: str
    amount_usd: float


class X402Confirm(BaseModel):
    tx_hash:    str
    agent_id:   str
    amount_usd: float
    resource:   str = ""


# ── Session management ─────────────────────────────────────────────────────────

@router.post("/session", response_model=SessionResponse)
async def create_session(body: SessionCreate):
    _require_voice()
    session_id = str(uuid.uuid4())
    return SessionResponse(
        session_id=session_id,
        ws_url=f"/voice/stream/{session_id}",
        created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )


@router.get("/sessions/{session_id}")
async def get_session(session_id: str):
    _require_voice()
    from warden.voice.dialogue import _get_redis  # noqa: PLC0415
    redis = _get_redis()
    state: dict = {}
    if redis:
        try:
            raw = redis.get(f"voice:session:{session_id}")
            state = json.loads(raw) if raw else {}
        except Exception:
            pass
    return {
        "session_id": session_id,
        "turns":      state.get("turns", 0),
        "active":     bool(state),
        "history":    state.get("history", [])[-10:],
    }


# ── WebSocket audio stream ─────────────────────────────────────────────────────

@router.websocket("/stream/{session_id}")
async def voice_stream(websocket: WebSocket, session_id: str):
    await websocket.accept()
    from warden.voice.asr import StreamingASR  # noqa: PLC0415
    from warden.voice.dialogue import DialogueManager  # noqa: PLC0415
    from warden.voice.tts import TTSEngine  # noqa: PLC0415

    asr  = StreamingASR()
    dm   = DialogueManager()
    tts  = TTSEngine() if _TTS_ENABLED else None
    try:
        while True:
            msg = await websocket.receive()
            if "bytes" in msg:
                partial = await asr.stream_audio(msg["bytes"])
                await websocket.send_json({"type": "partial", "transcript": partial.transcript})
            elif "text" in msg:
                data = json.loads(msg["text"])
                if data.get("type") == "finalize":
                    result = await asr.finalize()
                    if result.transcript:
                        resp = await dm.process_turn(session_id, result.transcript)
                        out: dict[str, Any] = {
                            "type":       "response",
                            "transcript": result.transcript,
                            "speech":     resp.text_response,
                            "action":     resp.action,
                            "payload":    resp.action_payload,
                            "turn":       resp.turn,
                        }
                        if tts and resp.text_response:
                            audio = await tts.synthesize(resp.text_response)
                            out["audio_base64"] = base64.b64encode(audio).decode()
                        await websocket.send_json(out)
                elif data.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        log.debug("Voice WS disconnected: session=%s", session_id)
    except Exception as exc:
        log.warning("Voice WS error session=%s: %s", session_id, exc)
        import contextlib  # noqa: PLC0415
        with contextlib.suppress(Exception):
            await websocket.send_json({"type": "error", "message": str(exc)})


# ── REST transcription ─────────────────────────────────────────────────────────

@router.post("/transcribe", response_model=TranscribeResponse)
async def transcribe(body: TranscribeRequest):
    _require_voice()
    t0 = time.monotonic()
    try:
        audio_bytes = base64.b64decode(body.audio_base64)
    except Exception as exc:
        raise HTTPException(400, f"Invalid base64 audio: {exc}") from exc

    from warden.voice.asr import StreamingASR  # noqa: PLC0415
    from warden.voice.nlu import parse_intent  # noqa: PLC0415

    asr    = StreamingASR(provider=body.provider)
    await asr.stream_audio(audio_bytes)
    result = await asr.finalize()

    intent = await parse_intent(result.transcript or "", {"community_id": body.community_id})
    return TranscribeResponse(
        transcript  = result.transcript,
        intent_type = intent.intent_type,
        entities    = intent.entities,
        confidence  = intent.confidence,
        elapsed_ms  = (time.monotonic() - t0) * 1000,
    )


# ── x402 micropayment endpoints ────────────────────────────────────────────────

@router.post("/x402/request")
async def x402_request(body: X402Request):
    _require_voice()
    from warden.voice.x402 import X402Protocol  # noqa: PLC0415
    proto   = X402Protocol()
    balance = proto.get_balance(body.agent_id)
    if balance >= body.amount_usd:
        proto.deduct(body.agent_id, body.amount_usd, body.service_id)
        return {"granted": True, "balance_after": balance - body.amount_usd}
    exc = proto.generate_402_response(body.service_id, body.amount_usd)
    raise exc


@router.post("/x402/confirm")
async def x402_confirm(body: X402Confirm):
    _require_voice()
    from warden.voice.x402 import X402Protocol  # noqa: PLC0415
    proto = X402Protocol()
    ok    = proto.confirm_payment(body.tx_hash, body.agent_id, body.amount_usd, body.resource)
    if not ok:
        raise HTTPException(400, "Payment verification failed")
    return {"confirmed": True, "balance": proto.get_balance(body.agent_id)}


@router.get("/x402/balance/{agent_id}")
async def x402_balance(agent_id: str):
    _require_voice()
    from warden.voice.x402 import X402Protocol  # noqa: PLC0415
    proto = X402Protocol()
    return {"agent_id": agent_id, "balance_usd": proto.get_balance(agent_id)}
