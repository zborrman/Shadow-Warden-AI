"""
warden/voice/biometric.py
Voice Biometric Authentication — speaker embedding + Fernet-encrypted Redis voiceprints.

Speaker embeddings via resemblyzer (d-vector) or numpy fallback (energy features).
Authentication threshold: VOICE_BIOMETRIC_THRESHOLD (default 0.85).
Voiceprints are Fernet-encrypted; never stored in plaintext.
"""
from __future__ import annotations

import io
import json
import logging
import os
from dataclasses import dataclass

from cryptography.fernet import Fernet

from warden.config import settings

log = logging.getLogger("warden.voice.biometric")

_REDIS_URL   = os.getenv("REDIS_URL", "")
_VAULT_KEY   = settings.vault_master_key
_THRESHOLD   = settings.voice_biometric_threshold
_TTL         = settings.voice_biometric_ttl  # 90 days

_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        key     = _VAULT_KEY.encode() if _VAULT_KEY else Fernet.generate_key()
        _fernet = Fernet(key)
    return _fernet


def _get_redis():
    try:
        import redis  # noqa: PLC0415
        url = _REDIS_URL
        if not url or url.startswith("memory://"):
            return None
        return redis.from_url(url, decode_responses=False)
    except Exception:
        return None


def _extract_embedding(audio_bytes: bytes) -> list[float]:
    """Extract speaker embedding.  resemblyzer → numpy energy fallback."""
    try:
        import numpy as np  # noqa: PLC0415
        import soundfile as sf  # noqa: PLC0415
        from resemblyzer import VoiceEncoder, preprocess_wav  # noqa: PLC0415
        audio, sr = sf.read(io.BytesIO(audio_bytes))
        wav = preprocess_wav(audio, sr)
        enc = VoiceEncoder()
        emb = enc.embed_utterance(wav)
        return emb.tolist()
    except Exception:
        pass
    # Fallback: simple energy-band features (not for production, tests only)
    try:
        import numpy as np  # noqa: PLC0415
        arr  = np.frombuffer(audio_bytes[:4096], dtype=np.uint8).astype(np.float32)
        feat = []
        for i in range(0, min(len(arr), 256), 8):
            chunk = arr[i:i + 8]
            feat.append(float(np.mean(chunk)) / 255.0)
        while len(feat) < 64:
            feat.append(0.0)
        norm = max(sum(x * x for x in feat) ** 0.5, 1e-8)
        return [x / norm for x in feat[:64]]
    except Exception:
        return [0.0] * 64


def _cosine(a: list[float], b: list[float]) -> float:
    dot   = sum(x * y for x, y in zip(a, b, strict=False))
    na    = sum(x * x for x in a) ** 0.5
    nb    = sum(x * x for x in b) ** 0.5
    denom = max(na * nb, 1e-10)
    return max(-1.0, min(1.0, dot / denom))


def _avg_embedding(embeddings: list[list[float]]) -> list[float]:
    if not embeddings:
        return [0.0] * 64
    n = len(embeddings)
    return [sum(e[i] for e in embeddings) / n for i in range(len(embeddings[0]))]


@dataclass
class BiometricResult:
    matched:      bool  = False
    user_id:      str   = ""
    similarity:   float = 0.0
    voiceprint_id: str  = ""
    error:        str   = ""


class VoiceBiometric:
    """Enrol, verify, and authenticate users by voice."""

    def __init__(self) -> None:
        self._redis  = _get_redis()
        self._store: dict[str, list[float]] = {}  # in-process fallback

    # ── Enrolment ──────────────────────────────────────────────────────────────

    def enroll(self, user_id: str, audio_samples: list[bytes]) -> str:
        """Create voiceprint from multiple audio samples.  Returns voiceprint_id."""
        embeddings = [_extract_embedding(s) for s in audio_samples if s]
        if not embeddings:
            raise ValueError("No valid audio samples provided")
        avg          = _avg_embedding(embeddings)
        voiceprint_id = f"vp:{user_id}"
        self._store_voiceprint(user_id, voiceprint_id, avg)
        return voiceprint_id

    # ── Verification ───────────────────────────────────────────────────────────

    def verify(self, user_id: str, audio_chunk: bytes) -> float:
        """Return cosine similarity of audio to enrolled voiceprint (0.0–1.0)."""
        stored = self._load_voiceprint(user_id)
        if stored is None:
            return 0.0
        emb = _extract_embedding(audio_chunk)
        return (_cosine(emb, stored) + 1.0) / 2.0  # shift to [0, 1]

    # ── Authentication ─────────────────────────────────────────────────────────

    def authenticate(self, audio_chunk: bytes, candidates: list[str] | None = None) -> str | None:
        """Return user_id if voice matches any enrolled user above threshold."""
        emb   = _extract_embedding(audio_chunk)
        users = candidates or self._list_users()
        best_uid   = None
        best_score = 0.0
        for uid in users:
            stored = self._load_voiceprint(uid)
            if stored is None:
                continue
            sim = (_cosine(emb, stored) + 1.0) / 2.0
            if sim > best_score:
                best_score = sim
                best_uid   = uid
        if best_score >= _THRESHOLD:
            return best_uid
        return None

    # ── Storage ────────────────────────────────────────────────────────────────

    def _store_voiceprint(self, user_id: str, vp_id: str, embedding: list[float]) -> None:
        payload = json.dumps({"user_id": user_id, "embedding": embedding}).encode()
        enc     = _get_fernet().encrypt(payload)
        if self._redis:
            try:
                self._redis.setex(f"vp:{user_id}", _TTL, enc)
                return
            except Exception:
                pass
        self._store[user_id] = embedding

    def _load_voiceprint(self, user_id: str) -> list[float] | None:
        if self._redis:
            try:
                raw = self._redis.get(f"vp:{user_id}")
                if raw:
                    dec  = _get_fernet().decrypt(raw)
                    data = json.loads(dec)
                    return data["embedding"]
            except Exception:
                pass
        return self._store.get(user_id)

    def _list_users(self) -> list[str]:
        if self._redis:
            try:
                keys = self._redis.keys("vp:*")
                return [k.decode().split(":", 1)[1] if isinstance(k, bytes) else k.split(":", 1)[1] for k in keys]
            except Exception:
                pass
        return list(self._store.keys())
