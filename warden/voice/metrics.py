"""
warden/voice/metrics.py  (VC-02 / B.2)
────────────────────────────────────────
Prometheus metrics for the Voice-Commerce Agents layer.

Metrics
───────
  warden_voice_session_duration_sec   — Histogram: session duration (seconds)
  warden_voice_e2e_latency_ms         — Histogram: end-to-end pipeline latency (ms)
  warden_voice_conversions_total      — Counter:   successful voice purchases
  warden_voice_errors_total           — Counter:   voice pipeline errors by stage
  warden_voice_active_sessions        — Gauge:     currently active sessions
  warden_voice_sessions_started_total — Counter:   sessions started
  warden_voice_deepfake_detected_total— Counter:   deepfake audio detections

Integration
───────────
  asr.py       — observe VOICE_LATENCY on each transcription
  dialogue.py  — observe VOICE_SESSION_DURATION on session end
  agent.py     — increment VOICE_CONVERSIONS on purchase completion
  guardian.py  — increment VOICE_ERRORS on blocked transactions
               — increment VOICE_DEEPFAKE_DETECTED on deepfake detection
"""
from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

VOICE_SESSION_DURATION = Histogram(
    "warden_voice_session_duration_sec",
    "Voice session duration in seconds",
    buckets=[10, 30, 60, 120, 300, 600],
)

VOICE_LATENCY = Histogram(
    "warden_voice_e2e_latency_ms",
    "End-to-end voice pipeline latency in milliseconds",
    buckets=[100, 200, 300, 500, 1000, 2000],
)

VOICE_CONVERSIONS = Counter(
    "warden_voice_conversions_total",
    "Total successful voice-initiated purchases",
)

VOICE_ERRORS = Counter(
    "warden_voice_errors_total",
    "Voice pipeline errors by stage",
    ["stage"],
)

VOICE_ACTIVE_SESSIONS = Gauge(
    "warden_voice_active_sessions",
    "Number of currently active voice sessions",
)

VOICE_SESSIONS_STARTED = Counter(
    "warden_voice_sessions_started_total",
    "Total voice sessions started",
)

VOICE_DEEPFAKE_DETECTED = Counter(
    "warden_voice_deepfake_detected_total",
    "Number of deepfake audio detections by VoiceGuardian",
)
