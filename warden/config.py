"""
warden/config.py
━━━━━━━━━━━━━━━
Centralised environment-variable configuration for Shadow Warden AI.

All runtime settings are read from the process environment exactly once
(at import time via the `settings` singleton).  Individual modules import
`from warden.config import settings` instead of calling `os.getenv()` inline.

Groups
──────
  Redis           — REDIS_URL, GLOBAL_REDIS_URL, CACHE_TTL_SECONDS
  Circuit Breaker — CB_WINDOW_SECS, CB_BYPASS_THRESHOLD, CB_MIN_REQUESTS, CB_COOLDOWN_SECS
  Alerting        — SLACK_WEBHOOK_URL, PAGERDUTY_ROUTING_KEY, ALERT_MIN_RISK_LEVEL
                    TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
  Webhooks        — WEBHOOK_DB_PATH, WEBHOOK_TIMEOUT_S, WEBHOOK_MAX_RETRIES
  NIM / NVIDIA    — NVIDIA_API_KEY, NIM_BASE_URL, NEMOTRON_MODEL, NIM_TIMEOUT_SECONDS
                    NEMOTRON_THINKING_BUDGET, NEMOTRON_STORE_THINKING
  Evolution       — ANTHROPIC_API_KEY, EVOLUTION_ENGINE, DYNAMIC_RULES_PATH
                    MAX_CORPUS_RULES, EVOLUTION_RATE_WINDOW, EVOLUTION_RATE_MAX
  ML / Models     — MODEL_CACHE_DIR, SEMANTIC_THRESHOLD, HYPERBOLIC_WEIGHT
  Security        — WARDEN_API_KEY, WARDEN_API_KEYS_PATH, CAUSAL_RISK_THRESHOLD
                    SE_RISK_THRESHOLD, PHISH_URL_THRESHOLD
  Image Guard     — IMAGE_GUARD_ENABLED, IMAGE_GUARD_THRESHOLD, IMAGE_PIPELINE_TIMEOUT_MS
                    IMAGE_GUARD_MODEL, IMAGE_MAX_BYTES
  Audio Guard     — AUDIO_GUARD_ENABLED, AUDIO_GUARD_MODEL, AUDIO_PIPELINE_TIMEOUT_MS
  Data Paths      — AUDIT_TRAIL_PATH, CORPUS_SNAPSHOT_PATH, ANALYTICS_DATA_PATH
  Misc            — LOG_LEVEL, AUDIT_TRAIL_ENABLED, WARDEN_REGION
                    TENANT_RATE_LIMIT, RATE_LIMIT_PER_MINUTE

Adding new settings
───────────────────
  1. Add a typed field in the appropriate group below.
  2. Read via `_env(NAME, default)` (str), `_int(NAME, default)` (int),
     `_float(NAME, default)` (float), or `_bool(NAME, default)` (bool).
  3. Remove the inline `os.getenv()` from the consuming module.

Testing overrides
─────────────────
  pytest can monkeypatch `settings.<field>` directly, or reload the module
  with patched env vars.  The `settings` object is a plain dataclass instance
  — no magic, no validation layer.
"""
from __future__ import annotations

import os
import secrets
from contextlib import suppress
from dataclasses import dataclass, field, fields

__all__ = ["settings", "Settings", "ConfigValidationError", "data_dir", "data_path"]


class ConfigValidationError(RuntimeError):
    """Raised by Settings.validate_or_raise() when configuration is invalid."""


# ── Data-layer path consolidation (Phase 6) ───────────────────────────────────
# Every module SQLite DB + spool file resolves its default location under a
# single base dir (`WARDEN_DATA_DIR`) — a persisted volume in prod instead of
# ephemeral /tmp. Backward-compatible: WARDEN_DATA_DIR defaults to /tmp, so an
# unset environment behaves exactly as before. Per-module env overrides (e.g.
# SEP_DB_PATH) still win when set, preserving the existing override contract.

_DEFAULT_DATA_DIR = "/tmp"


def data_dir() -> str:
    """Base directory for all module data files (persisted volume in prod)."""
    return os.getenv("WARDEN_DATA_DIR", _DEFAULT_DATA_DIR)


def data_path(filename: str, override_env: str | None = None) -> str:
    """
    Resolve a data-file path under ``data_dir()``.

    An explicit per-module env override (``override_env``) wins when set, so
    existing ``X_DB_PATH`` overrides keep working. When the base dir is not the
    legacy /tmp, it is created best-effort (persisted volumes may start empty)
    with mode ``0o700`` (S1) — these DBs hold PII/secret material, so the base
    dir must never be world-readable. The ``chmod`` also tightens a dir that
    pre-existed with looser permissions; both are best-effort and no-ops on
    filesystems (e.g. Windows) that don't honour POSIX modes. ``/tmp`` itself is
    never chmod-ed — its shared sticky-bit permissions are the OS's to own.
    """
    if override_env:
        override = os.getenv(override_env)
        if override:
            return override
    base = data_dir()
    if base != _DEFAULT_DATA_DIR:
        with suppress(OSError):
            os.makedirs(base, mode=0o700, exist_ok=True)
        with suppress(OSError):
            os.chmod(base, 0o700)
    return os.path.join(base, filename)


# ── Env-var helpers ───────────────────────────────────────────────────────────

def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default)


def _db_env(name: str, filename: str) -> str:
    """DB/spool path default routed through WARDEN_DATA_DIR; env override wins."""
    return data_path(filename, override_env=name)

def _int(name: str, default: int) -> int:
    return int(os.getenv(name, str(default)))

def _float(name: str, default: float) -> float:
    return float(os.getenv(name, str(default)))

def _bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.lower() not in ("false", "0", "no", "off")


# ── Settings dataclass ────────────────────────────────────────────────────────

@dataclass
class Settings:
    """Frozen snapshot of all Warden runtime configuration."""

    # ── Redis ──────────────────────────────────────────────────────────────────
    # Primary Redis instance used by cache, circuit breaker, rate limiter, etc.
    redis_url: str = field(
        default_factory=lambda: _env("REDIS_URL", "redis://redis:6379/0")
    )
    # Optional separate Redis for cross-region blocklist / corpus-sync.
    # Falls back to redis_url when not set.
    global_redis_url: str = field(
        default_factory=lambda: _env("GLOBAL_REDIS_URL", "")
    )
    # Content-hash cache TTL in seconds (default 5 min).
    cache_ttl_seconds: int = field(
        default_factory=lambda: _int("CACHE_TTL_SECONDS", 300)
    )

    # ── Circuit Breaker ────────────────────────────────────────────────────────
    # Sliding window for bypass-rate calculation (seconds).
    cb_window_secs: int = field(
        default_factory=lambda: _int("CB_WINDOW_SECS", 60)
    )
    # Bypass fraction threshold to trip the breaker (0–1).
    cb_bypass_threshold: float = field(
        default_factory=lambda: _float("CB_BYPASS_THRESHOLD", 0.10)
    )
    # Minimum requests in the window before the circuit can trip.
    cb_min_requests: int = field(
        default_factory=lambda: _int("CB_MIN_REQUESTS", 10)
    )
    # How long (seconds) the circuit stays OPEN before auto-resetting.
    cb_cooldown_secs: int = field(
        default_factory=lambda: _int("CB_COOLDOWN_SECS", 30)
    )

    # ── Alerting ───────────────────────────────────────────────────────────────
    # Slack Incoming Webhook URL.  Empty = Slack alerts disabled.
    slack_webhook_url: str = field(
        default_factory=lambda: _env("SLACK_WEBHOOK_URL", "")
    )
    # PagerDuty Events API v2 routing key.  Empty = PagerDuty disabled.
    pagerduty_routing_key: str = field(
        default_factory=lambda: _env("PAGERDUTY_ROUTING_KEY", "")
    )
    # Minimum risk level to trigger an alert: medium | high | block.
    alert_min_risk_level: str = field(
        default_factory=lambda: _env("ALERT_MIN_RISK_LEVEL", "high").lower()
    )
    # Telegram Bot token (from @BotFather).  Empty = Telegram disabled.
    telegram_bot_token: str = field(
        default_factory=lambda: _env("TELEGRAM_BOT_TOKEN", "")
    )
    # Telegram chat/channel ID to send alerts to.
    telegram_chat_id: str = field(
        default_factory=lambda: _env("TELEGRAM_CHAT_ID", "")
    )

    # ── Outbound Webhooks ──────────────────────────────────────────────────────
    # SQLite path for per-tenant webhook config.
    webhook_db_path: str = field(
        default_factory=lambda: _env("WEBHOOK_DB_PATH", "data/webhooks.db")
    )
    # HTTP delivery timeout per attempt (seconds).
    webhook_timeout_s: float = field(
        default_factory=lambda: _float("WEBHOOK_TIMEOUT_S", 10.0)
    )
    # Maximum delivery attempts (including first attempt).
    webhook_max_retries: int = field(
        default_factory=lambda: _int("WEBHOOK_MAX_RETRIES", 3)
    )

    # ── NIM / NVIDIA ───────────────────────────────────────────────────────────
    # NVIDIA API key — required to call NIM.
    nvidia_api_key: str = field(
        default_factory=lambda: _env("NVIDIA_API_KEY", "")
    )
    # NIM base URL (OpenAI-compatible endpoint).
    nim_base_url: str = field(
        default_factory=lambda: _env("NIM_BASE_URL", "https://integrate.api.nvidia.com/v1")
    )
    # Nemotron model name.
    nemotron_model: str = field(
        default_factory=lambda: _env("NEMOTRON_MODEL", "meta/llama-3.3-nemotron-super-49b-instruct")
    )
    # NIM HTTP request timeout (seconds).
    nim_timeout_seconds: float = field(
        default_factory=lambda: _float("NIM_TIMEOUT_SECONDS", 120.0)
    )
    # Token budget for Nemotron <think> chain-of-thought.
    nemotron_thinking_budget: int = field(
        default_factory=lambda: _int("NEMOTRON_THINKING_BUDGET", 4096)
    )
    # Whether to persist Nemotron reasoning traces in the audit trail.
    nemotron_store_thinking: bool = field(
        default_factory=lambda: _bool("NEMOTRON_STORE_THINKING", False)
    )

    # ── Evolution Engine ───────────────────────────────────────────────────────
    # Anthropic API key — used when EVOLUTION_ENGINE=claude.
    anthropic_api_key: str = field(
        default_factory=lambda: _env("ANTHROPIC_API_KEY", "")
    )
    # Which LLM backend to use for rule evolution: auto | claude | nemotron.
    evolution_engine: str = field(
        default_factory=lambda: _env("EVOLUTION_ENGINE", "auto").lower().strip()
    )
    # File path for the dynamic rule corpus.
    dynamic_rules_path: str = field(
        default_factory=lambda: _env("DYNAMIC_RULES_PATH", "/warden/data/dynamic_rules.json")
    )
    # Maximum number of rules in the corpus before pruning.
    max_corpus_rules: int = field(
        default_factory=lambda: _int("MAX_CORPUS_RULES", 500)
    )
    # Rate-limit window for evolution calls (seconds).
    evolution_rate_window: int = field(
        default_factory=lambda: _int("EVOLUTION_RATE_WINDOW", 300)
    )
    # Maximum evolution API calls per window.
    evolution_rate_max: int = field(
        default_factory=lambda: _int("EVOLUTION_RATE_MAX", 10)
    )

    # ── ML / Models ────────────────────────────────────────────────────────────
    # Shared directory for Hugging Face model downloads.
    model_cache_dir: str = field(
        default_factory=lambda: _env("MODEL_CACHE_DIR", "/warden/models")
    )
    # MiniLM cosine-similarity threshold for semantic jailbreak detection.
    semantic_threshold: float = field(
        default_factory=lambda: _float("SEMANTIC_THRESHOLD", 0.72)
    )
    # Weight of hyperbolic geometry score in the combined semantic score.
    hyperbolic_weight: float = field(
        default_factory=lambda: _float("HYPERBOLIC_WEIGHT", 0.30)
    )

    # ── Security ───────────────────────────────────────────────────────────────
    # Single API key for gateway auth (legacy single-tenant mode).
    warden_api_key: str = field(
        default_factory=lambda: _env("WARDEN_API_KEY", "")
    )
    # Path to JSON file mapping API keys → tenant config (multi-tenant mode).
    warden_api_keys_path: str = field(
        default_factory=lambda: _env("WARDEN_API_KEYS_PATH", "")
    )
    # Default rate limit per tenant (requests per minute).
    tenant_rate_limit: int = field(
        default_factory=lambda: _int(
            "TENANT_RATE_LIMIT",
            _int("RATE_LIMIT_PER_MINUTE", 60),
        )
    )
    # Causal Arbiter overall risk-score threshold for BLOCK decisions.
    causal_risk_threshold: float = field(
        default_factory=lambda: _float("CAUSAL_RISK_THRESHOLD", 0.65)
    )
    # SE-Arbiter composite risk threshold for social-engineering blocks.
    se_risk_threshold: float = field(
        default_factory=lambda: _float("SE_RISK_THRESHOLD", 0.75)
    )
    # URL phishing score threshold (0–1) for defanging / blocking.
    phish_url_threshold: float = field(
        default_factory=lambda: _float("PHISH_URL_THRESHOLD", 0.60)
    )

    # ── Image Guard ────────────────────────────────────────────────────────────
    image_guard_enabled: bool = field(
        default_factory=lambda: _bool("IMAGE_GUARD_ENABLED", True)
    )
    image_guard_threshold: float = field(
        default_factory=lambda: _float("IMAGE_GUARD_THRESHOLD", 0.28)
    )
    image_pipeline_timeout_ms: int = field(
        default_factory=lambda: _int("IMAGE_PIPELINE_TIMEOUT_MS", 100)
    )
    image_guard_model: str = field(
        default_factory=lambda: _env("IMAGE_GUARD_MODEL", "openai/clip-vit-b-32")
    )
    image_max_bytes: int = field(
        default_factory=lambda: _int("IMAGE_MAX_BYTES", 10 * 1024 * 1024)
    )
    transformers_offline: bool = field(
        default_factory=lambda: _env("TRANSFORMERS_OFFLINE", "0") == "1"
    )

    # ── Audio Guard ────────────────────────────────────────────────────────────
    audio_guard_enabled: bool = field(
        default_factory=lambda: _bool("AUDIO_GUARD_ENABLED", True)
    )
    audio_guard_model: str = field(
        default_factory=lambda: _env("AUDIO_GUARD_MODEL", "tiny.en")
    )
    audio_guard_compute: str = field(
        default_factory=lambda: _env("AUDIO_GUARD_COMPUTE", "int8")
    )
    audio_pipeline_timeout_ms: int = field(
        default_factory=lambda: _int("AUDIO_PIPELINE_TIMEOUT_MS", 3000)
    )
    audio_ultrasound_threshold: float = field(
        default_factory=lambda: _float("AUDIO_ULTRASOUND_THRESHOLD", 0.15)
    )
    audio_max_bytes: int = field(
        default_factory=lambda: _int("AUDIO_MAX_BYTES", 25 * 1024 * 1024)
    )

    # ── Voice ASR (warden/voice/asr.py) ──────────────────────────────────────────
    voice_asr_provider: str = field(
        default_factory=lambda: _env("VOICE_ASR_PROVIDER", "whisper")
    )
    deepgram_api_key: str = field(
        default_factory=lambda: _env("DEEPGRAM_API_KEY", "")
    )
    assemblyai_api_key: str = field(
        default_factory=lambda: _env("ASSEMBLYAI_API_KEY", "")
    )
    voice_asr_model: str = field(
        default_factory=lambda: _env("VOICE_ASR_MODEL", "tiny.en")
    )
    voice_asr_compute: str = field(
        default_factory=lambda: _env("VOICE_ASR_COMPUTE", "int8")
    )

    # ── Voice TTS (warden/voice/tts.py) ───────────────────────────────────────────
    voice_tts_provider: str = field(
        default_factory=lambda: _env("VOICE_TTS_PROVIDER", "edge")
    )
    elevenlabs_api_key: str = field(
        default_factory=lambda: _env("ELEVENLABS_API_KEY", "")
    )
    azure_speech_key: str = field(
        default_factory=lambda: _env("AZURE_SPEECH_KEY", "")
    )
    azure_speech_region: str = field(
        default_factory=lambda: _env("AZURE_SPEECH_REGION", "eastus")
    )
    voice_tts_latency_ms: int = field(
        default_factory=lambda: _int("VOICE_TTS_LATENCY_MS", 200)
    )

    # ── Voice Guardian (warden/voice/guardian.py) ─────────────────────────────────
    voice_guardian_db_path: str = field(
        default_factory=lambda: _db_env("VOICE_GUARDIAN_DB_PATH", "warden_voice_guardian.db")
    )
    voice_coerce_threshold: float = field(
        default_factory=lambda: _float("VOICE_COERCE_THRESHOLD", 0.8)
    )
    voice_deepfake_threshold: float = field(
        default_factory=lambda: _float("VOICE_DEEPFAKE_THRESHOLD", 0.75)
    )
    voice_zscore_threshold: float = field(
        default_factory=lambda: _float("VOICE_ZSCORE_THRESHOLD", 3.0)
    )

    # ── Voice Biometric (warden/voice/biometric.py) ───────────────────────────────
    # NB: REDIS_URL stays a module-level os.getenv("REDIS_URL", "") read in
    # biometric.py — empty string is a deliberate "disabled" sentinel there,
    # different semantics from settings.redis_url's non-empty default (same
    # empty-disabled-sentinel skip class as scheduler.py/wallet_shield.py).
    voice_biometric_threshold: float = field(
        default_factory=lambda: _float("VOICE_BIOMETRIC_THRESHOLD", 0.85)
    )
    voice_biometric_ttl: int = field(
        default_factory=lambda: _int("VOICE_BIOMETRIC_TTL", 90 * 86_400)
    )

    # ── Global Blocklist (warden/global_blocklist.py) ────────────────────────────
    global_blocklist_enabled: bool = field(
        default_factory=lambda: _bool("GLOBAL_BLOCKLIST_ENABLED", True)
    )
    global_blocklist_key: str = field(
        default_factory=lambda: _env("GLOBAL_BLOCKLIST_KEY", "warden:global:blocked")
    )
    blocklist_event_stream: str = field(
        default_factory=lambda: _env("BLOCKLIST_EVENT_STREAM", "warden:blocklist:events")
    )
    blocklist_stream_max: int = field(
        default_factory=lambda: _int("BLOCKLIST_STREAM_MAX", 10000)
    )

    # ── Community notifications (warden/communities/notifications.py) ───────────
    community_notif_db_path: str = field(
        default_factory=lambda: _db_env("COMMUNITY_NOTIF_DB_PATH", "warden_notif.db")
    )
    smtp_from: str = field(
        default_factory=lambda: _env("SMTP_FROM", "noreply@shadow-warden.ai")
    )
    smtp_tls: bool = field(
        default_factory=lambda: _env("SMTP_TLS", "true").lower() != "false"
    )

    # ── AI Worm Defense (warden/worm_guard.py) ───────────────────────────────────
    worm_guard_enabled: bool = field(
        default_factory=lambda: _bool("WORM_GUARD_ENABLED", True)
    )
    worm_overlap_threshold: float = field(
        default_factory=lambda: _float("WORM_OVERLAP_THRESHOLD", 0.65)
    )
    worm_min_tokens: int = field(
        default_factory=lambda: _int("WORM_MIN_TOKENS", 20)
    )
    worm_quarantine_ttl_s: int = field(
        default_factory=lambda: _int("WORM_QUARANTINE_TTL_S", 86400)
    )
    worm_quarantine_stream: str = field(
        default_factory=lambda: _env("WORM_QUARANTINE_STREAM", "warden:worm:quarantine")
    )
    worm_quarantine_set: str = field(
        default_factory=lambda: _env("WORM_QUARANTINE_SET", "warden:worm:hashes")
    )

    # ── Wallet Shield / token budget (warden/wallet_shield.py) ───────────────────
    # NB: REDIS_URL stays a lazy os.getenv() read there (empty-string-means-
    # disabled sentinel — different semantics from settings.redis_url's
    # non-empty docker-service default).
    wallet_default_budget: int = field(
        default_factory=lambda: _int("WALLET_DEFAULT_BUDGET", 100000)
    )
    wallet_window_seconds: int = field(
        default_factory=lambda: _int("WALLET_WINDOW_SECONDS", 3600)
    )
    wallet_hard_limit: int = field(
        default_factory=lambda: _int("WALLET_HARD_LIMIT", 200000)
    )
    token_alert_pct: int = field(
        default_factory=lambda: _int("TOKEN_ALERT_PCT", 80)
    )

    # ── NeMo Guardrails Geometric Bridge (warden/integrations/nemo_bridge.py) ────
    bridge_topology_threshold: float = field(
        default_factory=lambda: _float("BRIDGE_TOPOLOGY_THRESHOLD", 0.75)
    )
    bridge_hyperbolic_high: float = field(
        default_factory=lambda: _float("BRIDGE_HYPERBOLIC_HIGH", 0.80)
    )
    bridge_hyperbolic_gray: float = field(
        default_factory=lambda: _float("BRIDGE_HYPERBOLIC_GRAY", 0.55)
    )
    bridge_causal_high: float = field(
        default_factory=lambda: _float("BRIDGE_CAUSAL_HIGH", 0.65)
    )
    bridge_ers_restrict: float = field(
        default_factory=lambda: _float("BRIDGE_ERS_RESTRICT", 0.70)
    )

    # ── Ledger dual-run (warden/ledger/dual_write.py, FT-2) ──────────────────────
    # When true, live balance writers ALSO mirror into the double-entry ledger
    # (fail-open). Existing counters stay authoritative; a recon job compares the
    # two. Default off — the ledger proves itself before anything reads from it.
    ledger_dual_write: bool = field(
        default_factory=lambda: _bool("LEDGER_DUAL_WRITE", False)
    )

    # ── Entity Risk Scoring (warden/entity_risk.py) ──────────────────────────────
    ers_enabled: bool = field(
        default_factory=lambda: _bool("ERS_ENABLED", True)
    )
    ers_window_secs: int = field(
        default_factory=lambda: _int("ERS_WINDOW_SECS", 3600)
    )
    ers_min_requests: int = field(
        default_factory=lambda: _int("ERS_MIN_REQUESTS", 5)
    )
    ers_medium_threshold: float = field(
        default_factory=lambda: _float("ERS_MEDIUM_THRESHOLD", 0.30)
    )
    ers_high_threshold: float = field(
        default_factory=lambda: _float("ERS_HIGH_THRESHOLD", 0.55)
    )
    ers_shadow_ban_threshold: float = field(
        default_factory=lambda: _float("ERS_SHADOW_BAN_THRESHOLD", 0.75)
    )

    # ── Image PII Redactor (warden/image_redactor.py) ────────────────────────────
    image_redaction_enabled: bool = field(
        default_factory=lambda: _bool("IMAGE_REDACTION_ENABLED", True)
    )
    image_redaction_blur_radius: int = field(
        default_factory=lambda: _int("IMAGE_REDACTION_BLUR_RADIUS", 25)
    )
    image_redaction_doc_blur: bool = field(
        default_factory=lambda: _bool("IMAGE_REDACTION_DOC_BLUR", True)
    )
    image_redaction_fallback_blur: bool = field(
        default_factory=lambda: _bool("IMAGE_REDACTION_FALLBACK_BLUR", True)
    )
    image_redaction_timeout_ms: int = field(
        default_factory=lambda: _int("IMAGE_REDACTION_TIMEOUT_MS", 500)
    )

    # ── Community entity store (warden/communities/entity_store.py) ─────────────
    # NB: S3_ENDPOINT_URL/AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY stay lazy
    # os.getenv() reads there (no default -> None) so boto3's default credential
    # chain (IAM role, ~/.aws/credentials) still applies when unset; a Settings
    # field would coerce to "" instead of None, breaking that fallback.
    entity_db_path: str = field(
        default_factory=lambda: _db_env("ENTITY_DB_PATH", "warden_entity_store.db")
    )
    community_s3_bucket: str = field(
        default_factory=lambda: _env("COMMUNITY_S3_BUCKET", "warden-communities")
    )

    # ── Data Paths ─────────────────────────────────────────────────────────────
    audit_trail_path: str = field(
        default_factory=lambda: _env("AUDIT_TRAIL_PATH", "/warden/data/audit_trail.db")
    )
    corpus_snapshot_path: str = field(
        default_factory=lambda: _db_env("CORPUS_SNAPSHOT_PATH", "warden_corpus_snapshot")
    )
    analytics_data_path: str = field(
        default_factory=lambda: _env("ANALYTICS_DATA_PATH", "/analytics/data")
    )

    # ── Agent Monitor (warden/agent_monitor.py) ──────────────────────────────────
    agent_session_ttl: int = field(
        default_factory=lambda: _int("AGENT_SESSION_TTL", 1800)
    )
    velocity_window_secs: int = field(
        default_factory=lambda: _int("VELOCITY_WINDOW_SECS", 60)
    )
    velocity_threshold: int = field(
        default_factory=lambda: _int("VELOCITY_THRESHOLD", 10)
    )
    rapid_block_threshold: int = field(
        default_factory=lambda: _int("RAPID_BLOCK_THRESHOLD", 3)
    )

    # ── GDPR API (warden/api/gdpr.py) ────────────────────────────────────────────
    gdpr_log_retention_days: int = field(
        default_factory=lambda: _int("GDPR_LOG_RETENTION_DAYS", 30)
    )
    s3_evidence_bucket: str = field(
        default_factory=lambda: _env("S3_EVIDENCE_BUCKET", "warden-evidence")
    )
    logs_path: str = field(
        default_factory=lambda: _env("LOGS_PATH", "/warden/data/logs.json")
    )
    gdpr_auto_purge: bool = field(
        default_factory=lambda: _bool("GDPR_AUTO_PURGE", True)
    )

    # ── SMB Compliance Report (warden/api/compliance_report.py) ──────────────────
    # NB: TENANT_ID is a distinct env var from DEFAULT_TENANT_ID (used elsewhere)
    # despite the same default — kept as its own field, same discipline as
    # T36/T44/T72. RETENTION_DAYS here is display-only text in a report note and
    # is a distinct env var/default from compliance/posture_service.py's own
    # (unmigrated) RETENTION_DAYS read (default "0" there vs "180" here) — do not
    # unify these into one field.
    compliance_report_org_name: str = field(
        default_factory=lambda: _env("ORG_NAME", "Your Organisation")
    )
    compliance_report_tenant_id: str = field(
        default_factory=lambda: _env("TENANT_ID", "default")
    )
    compliance_report_data_residency: str = field(
        default_factory=lambda: _env("DATA_RESIDENCY_JURISDICTION", "EU")
    )
    compliance_report_retention_days: str = field(
        default_factory=lambda: _env("RETENTION_DAYS", "180")
    )

    # ── Data Retention API (warden/api/retention.py) ─────────────────────────────
    retention_pii_days: int = field(
        default_factory=lambda: _int("RETENTION_PII_DAYS", 30)
    )
    retention_phi_days: int = field(
        default_factory=lambda: _int("RETENTION_PHI_DAYS", 30)
    )
    retention_financial_days: int = field(
        default_factory=lambda: _int("RETENTION_FINANCIAL_DAYS", 90)
    )
    retention_secrets_days: int = field(
        default_factory=lambda: _int("RETENTION_SECRETS_DAYS", 7)
    )
    retention_general_days: int = field(
        default_factory=lambda: _int("RETENTION_GENERAL_DAYS", 180)
    )

    # ── Data Poisoning Detection (warden/brain/poison.py) ────────────────────────
    poison_detection_enabled: bool = field(
        default_factory=lambda: _bool("POISON_DETECTION_ENABLED", True)
    )
    poison_boundary_window: int = field(
        default_factory=lambda: _int("POISON_BOUNDARY_WINDOW", 60)
    )
    poison_boundary_max: int = field(
        default_factory=lambda: _int("POISON_BOUNDARY_MAX", 6)
    )
    poison_drift_threshold: float = field(
        default_factory=lambda: _float("POISON_DRIFT_THRESHOLD", 0.08)
    )
    poison_monitor_interval: int = field(
        default_factory=lambda: _int("POISON_MONITOR_INTERVAL", 300)
    )

    # ── Compliance Dashboard ROI model (warden/compliance/dashboard.py) ──────────
    compliance_llm_cost_per_token_usd: float = field(
        default_factory=lambda: _float("COMPLIANCE_LLM_COST_PER_TOKEN_USD", 0.15 / 1_000_000)
    )
    compliance_avg_shadow_ban_tokens: int = field(
        default_factory=lambda: _int("COMPLIANCE_AVG_SHADOW_BAN_TOKENS", 500)
    )
    compliance_breach_cost_usd: float = field(
        default_factory=lambda: _float("COMPLIANCE_BREACH_COST_USD", 4_450_000)
    )
    compliance_breach_incidents_per_year: float = field(
        default_factory=lambda: _float("COMPLIANCE_BREACH_INCIDENTS_PER_YEAR", 2)
    )
    compliance_credential_exposure_cost_usd: float = field(
        default_factory=lambda: _float("COMPLIANCE_CREDENTIAL_EXPOSURE_COST_USD", 50_000)
    )

    # ── Deploy Health (warden/api/deploy_health.py) ──────────────────────────────
    minio_url: str = field(
        default_factory=lambda: _env("MINIO_URL", "http://minio:9000")
    )
    prometheus_url: str = field(
        default_factory=lambda: _env("PROMETHEUS_URL", "http://prometheus:9090")
    )
    grafana_url: str = field(
        default_factory=lambda: _env("GRAFANA_URL", "http://grafana:3000")
    )
    app_url: str = field(
        default_factory=lambda: _env("APP_URL", "http://app:8000")
    )
    analytics_int_url: str = field(
        default_factory=lambda: _env("ANALYTICS_INT_URL", "http://analytics:8002")
    )

    # ── Integrations API (warden/api/integrations.py) ────────────────────────────
    teams_webhook_url: str = field(
        default_factory=lambda: _env("TEAMS_WEBHOOK_URL", "")
    )
    notion_api_token: str = field(
        default_factory=lambda: _env("NOTION_API_TOKEN", "")
    )
    notion_parent_page_id: str = field(
        default_factory=lambda: _env("NOTION_PARENT_PAGE_ID", "")
    )
    zapier_webhook_url: str = field(
        default_factory=lambda: _env("ZAPIER_WEBHOOK_URL", "")
    )
    make_webhook_url: str = field(
        default_factory=lambda: _env("MAKE_WEBHOOK_URL", "")
    )
    # NB: same DASHBOARD_URL env var as agent/scheduler.py's dashboard_url field,
    # but this file's own default is the public dashboard host, not empty — a
    # pre-existing drift, kept separate to preserve exact per-file behaviour.
    integrations_dashboard_url: str = field(
        default_factory=lambda: _env("DASHBOARD_URL", "https://dash.shadow-warden-ai.com")
    )

    # ── SAML SP provider (warden/auth/saml_provider.py) ──────────────────────────
    # NB: SAML_JWT_SECRET, SAML_SP_ENTITY_ID (function-level), SAML_SP_ACS_URL,
    # SAML_IDP_METADATA_XML/URL stay as live env reads in saml_provider.py —
    # dynamically monkeypatch.setenv'd per-test in test_saml.py, and
    # SAML_JWT_SECRET is also re-read via importlib.reload() in
    # test_jwt_no_secret_raises (same class of gotcha as T23's weekly_report.py)
    # — a frozen Settings singleton would not observe either kind of override.
    saml_otp_ttl: int = field(
        default_factory=lambda: _int("SAML_OTP_TTL", 30)
    )
    saml_session_ttl: int = field(
        default_factory=lambda: _int("SAML_SESSION_TTL", 28800)
    )
    saml_allowed_domains: str = field(
        default_factory=lambda: _env("SAML_ALLOWED_DOMAINS", "")
    )

    # ── SAML SSO — Enterprise (warden/auth/saml.py) ──────────────────────────────
    # No test file imports this module directly — all reads are safe frozen
    # module-level constants (unlike the sibling saml_provider.py above).
    saml_sso_sp_entity_id: str = field(
        default_factory=lambda: _env("SAML_SP_ENTITY_ID", "https://api.shadow-warden-ai.com/auth/saml/metadata")
    )
    saml_sso_sp_acs_url: str = field(
        default_factory=lambda: _env("SAML_SP_ACS_URL", "https://api.shadow-warden-ai.com/auth/saml/acs")
    )
    saml_sso_idp_metadata_url: str = field(
        default_factory=lambda: _env("SAML_IDP_METADATA_URL", "")
    )
    saml_default_tier: str = field(
        default_factory=lambda: _env("SAML_DEFAULT_TIER", "enterprise")
    )
    saml_clock_skew_s: int = field(
        default_factory=lambda: _int("SAML_CLOCK_SKEW_S", 60)
    )
    saml_require_sha256: bool = field(
        default_factory=lambda: _bool("SAML_REQUIRE_SHA256", True)
    )
    saml_cert_path: str = field(
        default_factory=lambda: _env("SAML_CERT_PATH", "")
    )

    # ── Billing Streamlit page (warden/analytics/pages/9_Billing.py) ─────────────
    # NB: reuses lemonsqueezy_api_key/store_id/webhook_secret (pre-existing).
    # WARDEN_INTERNAL_URL and PORTAL_BASE_URL are distinct env-var names from
    # warden_base_url/portal_url (different defaults too) — kept as separate
    # fields, not reused, to preserve exact per-file behaviour.
    billing_page_db_path: str = field(
        default_factory=lambda: _env("LEMONSQUEEZY_DB_PATH", "/warden/data/lemon.db")
    )
    dunning_grace_days: int = field(
        default_factory=lambda: _int("DUNNING_GRACE_DAYS", 7)
    )
    warden_internal_url: str = field(
        default_factory=lambda: _env("WARDEN_INTERNAL_URL", "http://localhost:8001")
    )
    billing_page_portal_url: str = field(
        default_factory=lambda: _env("PORTAL_BASE_URL", "https://app.shadowwarden.ai")
    )
    billing_page_warden_url: str = field(
        default_factory=lambda: _env("WARDEN_BASE_URL", "https://api.shadow-warden-ai.com")
    )

    # ── MasterAgent (warden/agent/master.py) ─────────────────────────────────────
    # NB: reuses redis_url, warden_base_url, slack_webhook_url (pre-existing,
    # matching defaults). No test file imports this module.
    master_agent_token_budget: int = field(
        default_factory=lambda: _int("MASTER_AGENT_TOKEN_BUDGET", 8192)
    )

    # ── Settings drift watchdog (warden/workers/settings_watcher.py) ─────────────
    # NB: reuses warden_internal_url, slack_webhook_url, warden_api_key
    # (pre-existing, matching defaults). No test file imports this module.
    config_snapshot_path: str = field(
        default_factory=lambda: _env("CONFIG_SNAPSHOT_PATH", "data/config_snapshot.json")
    )

    # ── Session Guard (warden/session_guard.py) ──────────────────────────────────
    # NB: SESSION_GUARD_ENABLED stays a live env read in session_guard.py —
    # test_session_honey.py's test_disabled_guard_never_escalates
    # monkeypatch.setenv's it THEN importlib.reload()s the module, same gotcha
    # class as T23/T45. Not observed by a frozen Settings singleton.
    session_guard_ttl_sec: int = field(default_factory=lambda: _int("SESSION_GUARD_TTL_SEC", 1800))
    session_guard_window: int = field(default_factory=lambda: _int("SESSION_GUARD_WINDOW", 10))
    session_guard_threshold: float = field(default_factory=lambda: _float("SESSION_GUARD_THRESHOLD", 2.5))
    session_guard_medium_limit: int = field(default_factory=lambda: _int("SESSION_GUARD_MEDIUM_LIMIT", 3))

    # ── L402 Lightning payments (warden/payments/l402.py) ────────────────────────
    # NB: L402_BTC_PRICE_USD stays a live env read inside _usd_to_sat() —
    # test_l402.py's test_create_invoice_usd_to_sat monkeypatch.setenv's it
    # mid-test (no reload) and expects the live function-level read to observe
    # the override; a frozen Settings singleton would not.
    l402_lnd_url: str = field(default_factory=lambda: _env("L402_LND_URL", ""))
    l402_lnd_macaroon_hex: str = field(default_factory=lambda: _env("L402_LND_MACAROON_HEX", ""))
    l402_dev_mode: bool = field(default_factory=lambda: _bool("L402_DEV_MODE", True))
    # TLS to the Lightning node. The macaroon is a bearer credential, so verification
    # is ON by default — it used to be hardcoded verify=False, which let a MITM steal
    # the macaroon. LND ships a self-signed cert, so point L402_LND_TLS_CERT at its
    # tls.cert (preferred), or set L402_LND_VERIFY_SSL=false to knowingly opt out.
    l402_lnd_verify_ssl: bool = field(default_factory=lambda: _bool("L402_LND_VERIFY_SSL", True))
    l402_lnd_tls_cert: str = field(default_factory=lambda: _env("L402_LND_TLS_CERT", ""))
    l402_token_ttl_s: int = field(default_factory=lambda: _int("L402_TOKEN_TTL_S", 600))

    # ── Marketplace DAO governance (warden/marketplace/governance.py) ────────────
    # NB: reuses redis_url (inline default "redis://localhost:6379" vs settings.
    # redis_url's "redis://redis:6379/0" — same drift-fix class as prior tiers).
    # test_governance.py always passes db_path= explicitly as a kwarg, never
    # relying on the env-derived default, so freezing it is safe (unlike
    # marketplace/api.py's rejected wholesale MARKETPLACE_DB_PATH pattern).
    marketplace_db_path: str = field(default_factory=lambda: _db_env("MARKETPLACE_DB_PATH", "warden_marketplace.db"))
    dao_proposal_ttl_hours: int = field(default_factory=lambda: _int("DAO_PROPOSAL_TTL_HOURS", 72))
    dao_quorum_pct: float = field(default_factory=lambda: _float("DAO_QUORUM_PCT", 0.15))
    dao_governance_enabled: bool = field(default_factory=lambda: _bool("DAO_GOVERNANCE_ENABLED", False))

    # ── Jira integration (warden/integrations/jira.py) ───────────────────────────
    jira_base_url: str = field(default_factory=lambda: _env("JIRA_BASE_URL", ""))
    jira_email: str = field(default_factory=lambda: _env("JIRA_EMAIL", ""))
    jira_api_token: str = field(default_factory=lambda: _env("JIRA_API_TOKEN", ""))
    jira_project_key: str = field(default_factory=lambda: _env("JIRA_PROJECT_KEY", "SECURITY"))
    jira_issue_type: str = field(default_factory=lambda: _env("JIRA_ISSUE_TYPE", "Bug"))

    # ── GDPR Art. 30 RoPA generator (warden/compliance/art30.py) ─────────────────
    # NB: reuses agent_session_ttl/ers_window_secs (pre-existing, matching
    # defaults). The controller-identity helper (_ctrl / CONTROLLER_NAME etc.)
    # stays a live env read — test_compliance.py monkeypatches those AND
    # importlib.reload()s the module, same T23/T45/T54 gotcha class.
    art30_audit_db_path: str = field(default_factory=lambda: _env("AUDIT_DB_PATH", "/warden/data/audit.db"))

    # ── Zero-Trust Billing Audit Chain (warden/billing/audit_chain.py) ───────────
    # NB: test_billing_audit.py monkeypatch.setattr()'s the module's _DB_PATH
    # attribute directly (not the env var) — unaffected by migrating the
    # attribute's initial value, same pattern as T38's federated_trust finding.
    billing_audit_db_path: str = field(default_factory=lambda: _db_env("BILLING_AUDIT_DB_PATH", "warden_billing_audit.db"))
    billing_audit_evm_attestation: bool = field(default_factory=lambda: _bool("BILLING_AUDIT_EVM_ATTESTATION", False))
    billing_audit_evm_rpc_url: str = field(default_factory=lambda: _env("BILLING_AUDIT_EVM_RPC_URL", "https://sepolia.base.org"))
    billing_audit_evm_private_key: str = field(default_factory=lambda: _env("BILLING_AUDIT_EVM_PRIVATE_KEY", ""))
    billing_audit_evm_anchor_every: int = field(default_factory=lambda: _int("BILLING_AUDIT_EVM_ANCHOR_EVERY", 100))

    # ── Auth pre-seeded users (warden/auth/router.py) ────────────────────────────
    # NB: AUTH_JWT_SECRET / VAULT_MASTER_KEY-or-SAML_JWT_SECRET fallback in
    # _secret() stay live os.getenv reads — signing-key resolution follows the
    # resolve_key()-style lazy-resolution invariant (see
    # security_hardening_invariants), never baked into a module-import-time
    # constant.
    auth_users_json: str = field(default_factory=lambda: _env("AUTH_USERS_JSON", ""))
    auth_admin_email: str = field(default_factory=lambda: _env("AUTH_ADMIN_EMAIL", ""))
    auth_admin_password_hash: str = field(default_factory=lambda: _env("AUTH_ADMIN_PASSWORD_HASH", ""))

    # ── Security Hub (warden/api/security_hub.py) ────────────────────────────────
    # NB: reuses redis_url (inline default "redis://localhost:6379" — same
    # localhost-vs-docker-service-name drift class as prior tiers). ADMIN_KEY
    # stays an established live-read skip (shared dynamically-monkeypatched
    # credential).
    cve_report_path: str = field(default_factory=lambda: _env("CVE_REPORT_PATH", "data/cve_report.json"))
    pentest_db_path: str = field(default_factory=lambda: _env("PENTEST_DB_PATH", "data/pentest_findings.json"))
    security_posture_path: str = field(default_factory=lambda: _env("SECURITY_POSTURE_PATH", "data/security_posture.json"))

    # ── Contact form (warden/api/contact.py) ─────────────────────────────────────
    # NB: reuses smtp_host/smtp_port/smtp_user/smtp_pass (pre-existing, matching
    # defaults). test_contact_endpoint.py's monkeypatch.delenv is defensive
    # (SMTP_HOST/USER are never set to a non-default value anywhere in the test
    # suite) — unlike weekly_report.py's T23 finding, no reload is involved.
    contact_to_email: str = field(default_factory=lambda: _env("CONTACT_TO_EMAIL", "vz@shadow-warden-ai.com"))

    # ── Bot Entity API (warden/api/bot_entity.py) ────────────────────────────────
    # NB: BOT_JWT_SECRET stays a live env read/write — _get_secret() generates
    # and self-persists an ephemeral secret via os.environ when unset, the same
    # lazy signing-key-resolution invariant as T62's auth/router.py skip.
    bot_token_ttl_s: int = field(default_factory=lambda: _int("BOT_TOKEN_TTL_S", 3600))
    bot_db_path: str = field(default_factory=lambda: _db_env("BOT_DB_PATH", "warden_bot_entities.db"))

    # ── CVE Scanner worker (warden/workers/cve_scanner.py) ───────────────────────
    # NB: reuses cve_report_path/security_posture_path (T63)/slack_webhook_url.
    requirements_path: str = field(default_factory=lambda: _env("REQUIREMENTS_PATH", "warden/requirements.txt"))

    # ── Syndicates invites (warden/syndicates/invites_router.py) ─────────────────
    # NB: reuses portal_jwt_secret/portal_url (pre-existing, matching defaults —
    # this also fixes a latent bug where the module's own random JWT-secret
    # fallback wasn't shared with portal_router.py, contradicting the docstring's
    # "same key as portal auth tokens" invariant). New field: super_admin_key.
    super_admin_key: str = field(default_factory=lambda: _env("SUPER_ADMIN_KEY", ""))

    # ── Misc ───────────────────────────────────────────────────────────────────
    log_level: str = field(
        default_factory=lambda: _env("LOG_LEVEL", "info").lower()
    )
    audit_trail_enabled: bool = field(
        default_factory=lambda: _bool("AUDIT_TRAIL_ENABLED", True)
    )
    # Region tag stamped on global blocklist / corpus-sync events.
    warden_region: str = field(
        default_factory=lambda: _env("WARDEN_REGION", "default")
    )
    # Deployment environment (S1). "dev" (default) keeps every historic
    # behaviour — an unset env is unchanged. Set WARDEN_ENV=production (or
    # "prod") on the real deploy so validate() rejects secret-bearing SQLite
    # DBs sitting under ephemeral, potentially world-readable /tmp.
    warden_env: str = field(
        default_factory=lambda: _env("WARDEN_ENV", "dev").strip().lower()
    )


    # ── Security (cont.) ────────────────────────────────
    # VAULT master key (Fernet) — wraps community keypairs + data-pod secrets.
    vault_master_key: str = field(
        default_factory=lambda: _env("VAULT_MASTER_KEY", "")
    )
    # Allow unauthenticated access when no API key is configured (dev/test only).
    allow_unauthenticated: bool = field(
        default_factory=lambda: _bool("ALLOW_UNAUTHENTICATED", False)
    )
    # Fail the boot if the live pipeline canary misses a jailbreak (Deep-Eng P0.3).
    pipeline_failclosed_on_canary: bool = field(
        default_factory=lambda: _bool("PIPELINE_FAILCLOSED_ON_CANARY", False)
    )

    # Prompt Shield (LLM-injection pre-screen). Enabled by default; the actual
    # gate lives in openai_proxy — this is the single source of truth.
    prompt_shield_enabled: bool = field(
        default_factory=lambda: _bool("PROMPT_SHIELD_ENABLED", True)
    )

    # Default tenant id for background jobs / unattributed events.
    default_tenant_id: str = field(
        default_factory=lambda: _env("DEFAULT_TENANT_ID", "default")
    )

    # ── Observability / OpenTelemetry (Deep-Eng P1 config migration) ────────────
    # Master switch for distributed tracing. Off by default (zero overhead).
    otel_enabled: bool = field(
        default_factory=lambda: _bool("OTEL_ENABLED", False)
    )
    # Jaeger/OTel service label.
    otel_service_name: str = field(
        default_factory=lambda: _env("OTEL_SERVICE_NAME", "shadow-warden")
    )
    # gRPC OTLP exporter endpoint.
    otel_exporter_otlp_endpoint: str = field(
        default_factory=lambda: _env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4317")
    )
    # Sampling rate for ALLOW traffic (0–1).
    otel_sample_rate: float = field(
        default_factory=lambda: _float("OTEL_SAMPLE_RATE", 0.1)
    )
    # Sampling rate for HIGH/BLOCK traffic (0–1) — always trace threats.
    otel_sample_rate_high: float = field(
        default_factory=lambda: _float("OTEL_SAMPLE_RATE_HIGH", 1.0)
    )

    # ── S3 / Object storage (MinIO / AWS S3) ────────────────────────────────────
    # Master switch. Off = local storage only.
    s3_enabled: bool = field(
        default_factory=lambda: _bool("S3_ENABLED", False)
    )
    s3_endpoint: str = field(
        default_factory=lambda: _env("S3_ENDPOINT", "http://minio:9000")
    )
    s3_access_key: str = field(
        default_factory=lambda: _env("S3_ACCESS_KEY", "minioadmin")
    )
    s3_secret_key: str = field(
        default_factory=lambda: _env("S3_SECRET_KEY", "minioadmin")
    )
    s3_bucket_evidence: str = field(
        default_factory=lambda: _env("S3_BUCKET_EVIDENCE", "warden-evidence")
    )
    s3_bucket_logs: str = field(
        default_factory=lambda: _env("S3_BUCKET_LOGS", "warden-logs")
    )
    # Required by the SDK even for MinIO.
    s3_region: str = field(
        default_factory=lambda: _env("S3_REGION", "us-east-1")
    )

    # ── Offsite backup ship (R1) — S3 target on different hardware than the VPS,
    # so the encrypted nightly snapshot survives loss of the host itself. Unset =
    # ship_backup() sends zero offsite copies (degrades quietly, counted).
    offsite_s3_endpoint: str = field(
        default_factory=lambda: _env("OFFSITE_S3_ENDPOINT", "")
    )
    offsite_s3_access_key: str = field(
        default_factory=lambda: _env("OFFSITE_S3_ACCESS_KEY", "")
    )
    offsite_s3_secret_key: str = field(
        default_factory=lambda: _env("OFFSITE_S3_SECRET_KEY", "")
    )
    offsite_s3_bucket: str = field(
        default_factory=lambda: _env("OFFSITE_S3_BUCKET", "warden-backups")
    )
    offsite_s3_region: str = field(
        default_factory=lambda: _env("OFFSITE_S3_REGION", "us-east-1")
    )

    # ── Database (Postgres/SQLAlchemy) ──────────────────────────────────────────
    # SQLAlchemy DSN. Empty = feature disabled / SQLite fallback per caller.
    database_url: str = field(
        default_factory=lambda: _env("DATABASE_URL", "")
    )

    # ── mTLS (internal service-to-service) ──────────────────────────────────────
    # Enforce client-cert CN allowlist on internal routes.
    mtls_enabled: bool = field(
        default_factory=lambda: _bool("MTLS_ENABLED", False)
    )
    # Comma-separated allowlist of client-cert CNs. Parsed by warden/mtls.py.
    mtls_allowed_cns: str = field(
        default_factory=lambda: _env("MTLS_ALLOWED_CNS", "proxy,analytics,app")
    )

    # ── Telegram alerts (warden/telegram_alert.py; tokens above) ────────────────
    # Minimum risk level for a Telegram alert: medium | high | block.
    telegram_min_risk: str = field(
        default_factory=lambda: _env("TELEGRAM_MIN_RISK", "high").lower()
    )

    # ── Output-guard notification hook (warden/notification_hook.py) ────────────
    # Comma-separated BusinessRisk types that trigger a manager notification.
    notify_output_risks: str = field(
        default_factory=lambda: _env(
            "NOTIFY_OUTPUT_RISKS", "price_manipulation,unauthorized_commitment"
        )
    )
    # Telegram token/chat for the notification hook (falls back to telegram_bot_token).
    notify_telegram_token: str = field(
        default_factory=lambda: _env("NOTIFY_TELEGRAM_TOKEN", "")
    )
    notify_telegram_chat_id: str = field(
        default_factory=lambda: _env("NOTIFY_TELEGRAM_CHAT_ID", "")
    )
    # Generic outbound webhook + HMAC secret for the notification hook.
    notify_webhook_url: str = field(
        default_factory=lambda: _env("NOTIFY_WEBHOOK_URL", "")
    )
    notify_webhook_secret: str = field(
        default_factory=lambda: _env("NOTIFY_WEBHOOK_SECRET", "")
    )

    # ── SIEM forwarding (warden/analytics/siem.py) ──────────────────────────────
    splunk_hec_url: str = field(
        default_factory=lambda: _env("SPLUNK_HEC_URL", "")
    )
    splunk_hec_token: str = field(
        default_factory=lambda: _env("SPLUNK_HEC_TOKEN", "")
    )
    elastic_url: str = field(
        default_factory=lambda: _env("ELASTIC_URL", "")
    )
    elastic_api_key: str = field(
        default_factory=lambda: _env("ELASTIC_API_KEY", "")
    )
    elastic_index: str = field(
        default_factory=lambda: _env("ELASTIC_INDEX", "warden-events")
    )
    elastic_bypass_index: str = field(
        default_factory=lambda: _env("ELASTIC_BYPASS_INDEX", "warden-bypass-alerts")
    )

    # ── Streamlit dashboard auth (warden/analytics/auth.py) ─────────────────────
    dashboard_username: str = field(
        default_factory=lambda: _env("DASHBOARD_USERNAME", "admin")
    )
    # bcrypt hash string; empty = dev mode (no login). Encoded at use site.
    dashboard_password_hash: str = field(
        default_factory=lambda: _env("DASHBOARD_PASSWORD_HASH", "")
    )
    dashboard_session_minutes: int = field(
        default_factory=lambda: _int("DASHBOARD_SESSION_MINUTES", 60)
    )
    dashboard_max_attempts: int = field(
        default_factory=lambda: _int("DASHBOARD_MAX_ATTEMPTS", 5)
    )
    dashboard_lockout_minutes: int = field(
        default_factory=lambda: _int("DASHBOARD_LOCKOUT_MINUTES", 15)
    )
    # SAML SP entity id; presence enables SSO. Gateway URL for dashboard→API calls.
    saml_sp_entity_id: str = field(
        default_factory=lambda: _env("SAML_SP_ENTITY_ID", "")
    )
    gateway_url: str = field(
        default_factory=lambda: _env("GATEWAY_URL", "http://localhost:8001")
    )

    # ── Stripe billing (warden/stripe_billing.py) ───────────────────────────────
    stripe_secret_key: str = field(
        default_factory=lambda: _env("STRIPE_SECRET_KEY", "")
    )
    stripe_webhook_secret: str = field(
        default_factory=lambda: _env("STRIPE_WEBHOOK_SECRET", "")
    )
    stripe_price_startup: str = field(
        default_factory=lambda: _env("STRIPE_PRICE_STARTUP", "")
    )
    stripe_price_growth: str = field(
        default_factory=lambda: _env("STRIPE_PRICE_GROWTH", "")
    )
    stripe_price_msp: str = field(
        default_factory=lambda: _env("STRIPE_PRICE_MSP", "")
    )
    stripe_db_path: str = field(
        default_factory=lambda: _env("STRIPE_DB_PATH", "/warden/data/stripe.db")
    )

    # ── Lemon Squeezy billing (warden/lemon_billing.py) ─────────────────────────
    # NB: LEMONSQUEEZY_DB_PATH stays a lazy read in lemon_billing._db_path() so
    # tests can override it after import — intentionally NOT mirrored here.
    lemonsqueezy_api_key: str = field(
        default_factory=lambda: _env("LEMONSQUEEZY_API_KEY", "")
    )
    lemonsqueezy_store_id: str = field(
        default_factory=lambda: _env("LEMONSQUEEZY_STORE_ID", "")
    )
    lemonsqueezy_webhook_secret: str = field(
        default_factory=lambda: _env("LEMONSQUEEZY_WEBHOOK_SECRET", "")
    )
    lemonsqueezy_variant_trial: str = field(
        default_factory=lambda: _env("LEMONSQUEEZY_VARIANT_TRIAL", "")
    )
    lemonsqueezy_variant_individual: str = field(
        default_factory=lambda: _env("LEMONSQUEEZY_VARIANT_INDIVIDUAL", "")
    )
    lemonsqueezy_variant_community: str = field(
        default_factory=lambda: _env("LEMONSQUEEZY_VARIANT_COMMUNITY", "")
    )
    lemonsqueezy_variant_pro: str = field(
        default_factory=lambda: _env("LEMONSQUEEZY_VARIANT_PRO", "")
    )
    lemonsqueezy_variant_enterprise: str = field(
        default_factory=lambda: _env("LEMONSQUEEZY_VARIANT_ENTERPRISE", "")
    )
    ls_meter_flush_events: int = field(
        default_factory=lambda: _int("LS_METER_FLUSH_EVENTS", 100)
    )
    ls_meter_flush_secs: int = field(
        default_factory=lambda: _int("LS_METER_FLUSH_SECS", 300)
    )

    # ── Overage billing (warden/billing/overage.py) ──────────────────────────────
    # NB: PORTAL_BASE_URL stays a lazy os.getenv() function-level read in
    # get_upgrade_url()/get_overage_pack_url() — test_billing_quotas_overage.py's
    # test_uses_portal_base_url_env sets/deletes the env var mid-test and expects
    # a live read, same dynamic-override skip class as elsewhere.
    overage_webhook_url: str = field(
        default_factory=lambda: _env("OVERAGE_WEBHOOK_URL", "")
    )

    # ── Add-on catalog Lemon Squeezy variant IDs (warden/billing/addons.py) ─────
    ls_variant_shadow_ai: str = field(
        default_factory=lambda: _env("LS_VARIANT_SHADOW_AI", "")
    )
    ls_variant_xai_audit: str = field(
        default_factory=lambda: _env("LS_VARIANT_XAI_AUDIT", "")
    )
    ls_variant_secrets_vault: str = field(
        default_factory=lambda: _env("LS_VARIANT_SECRETS_VAULT", "")
    )
    ls_variant_on_prem: str = field(
        default_factory=lambda: _env("LS_VARIANT_ON_PREM", "")
    )
    ls_variant_community_seats: str = field(
        default_factory=lambda: _env("LS_VARIANT_COMMUNITY_SEATS", "")
    )
    ls_variant_obsidian_pack: str = field(
        default_factory=lambda: _env("LS_VARIANT_OBSIDIAN_PACK", "")
    )
    ls_variant_smb_governance: str = field(
        default_factory=lambda: _env("LS_VARIANT_SMB_GOVERNANCE", "")
    )
    ls_variant_agentic_commerce: str = field(
        default_factory=lambda: _env("LS_VARIANT_AGENTIC_COMMERCE", "")
    )
    ls_variant_event_streaming: str = field(
        default_factory=lambda: _env("LS_VARIANT_EVENT_STREAMING", "")
    )
    ls_variant_tokenomics: str = field(
        default_factory=lambda: _env("LS_VARIANT_TOKENOMICS", "")
    )
    ls_variant_usdc_payments: str = field(
        default_factory=lambda: _env("LS_VARIANT_USDC_PAYMENTS", "")
    )
    ls_variant_ans_certs: str = field(
        default_factory=lambda: _env("LS_VARIANT_ANS_CERTS", "")
    )
    ls_variant_edge_packs: str = field(
        default_factory=lambda: _env("LS_VARIANT_EDGE_PACKS", "")
    )
    ls_variant_credits_starter: str = field(
        default_factory=lambda: _env("LS_VARIANT_CREDITS_STARTER", "")
    )
    ls_variant_credits_builder: str = field(
        default_factory=lambda: _env("LS_VARIANT_CREDITS_BUILDER", "")
    )
    ls_variant_credits_pro: str = field(
        default_factory=lambda: _env("LS_VARIANT_CREDITS_PRO", "")
    )
    ls_variant_credits_enterprise: str = field(
        default_factory=lambda: _env("LS_VARIANT_CREDITS_ENTERPRISE", "")
    )
    ls_variant_power_bundle: str = field(
        default_factory=lambda: _env("LS_VARIANT_POWER_BUNDLE", "")
    )

    # ── Compliance posture (warden/compliance/posture_service.py) ───────────────
    compliance_cache_ttl: int = field(
        default_factory=lambda: _int("COMPLIANCE_CACHE_TTL", 300)
    )

    # ── Secrets rotation alerts (warden/api/rotation.py) ─────────────────────────
    # NB: ADMIN_KEY stays a lazy os.getenv() read in rotation.py — it's a shared
    # auth-gate credential dynamically monkeypatched per-test elsewhere
    # (action_whitelist.py, tokenomics.py) — intentionally NOT mirrored here.
    key_rotation_warning_days: int = field(
        default_factory=lambda: _int("KEY_ROTATION_WARNING_DAYS", 75)
    )
    key_rotation_max_days: int = field(
        default_factory=lambda: _int("KEY_ROTATION_MAX_DAYS", 90)
    )
    # NB: SOVEREIGN_ATTEST_KEY falls back to VAULT_MASTER_KEY at the call site in
    # warden/sovereign/attestation.py — this field mirrors the raw env read only.
    sovereign_attest_key: str = field(
        default_factory=lambda: _env("SOVEREIGN_ATTEST_KEY", "")
    )
    community_vault_key: str = field(
        default_factory=lambda: _env("COMMUNITY_VAULT_KEY", "")
    )

    # ── Sovereign Tunnel Preflight (warden/sovereign/preflight.py) ───────────────
    # NB: MINIO_ENDPOINT is a distinct env-var name from MINIO_URL (used by
    # api/deploy_health.py) despite sharing the same default — kept as its own
    # field rather than reusing minio_url (same default-drift discipline as
    # T36/T44). REDIS_URL default here drifts from settings.redis_url's
    # "redis://redis:6379/0" (localhost vs docker-service-name) — reused anyway
    # per the established latent-bug-fix precedent (T17/T26/T35/T37/T38/T41/T49/T53).
    preflight_timeout_s: float = field(
        default_factory=lambda: _float("PREFLIGHT_TIMEOUT_S", 5.0)
    )
    sovereign_minio_endpoint: str = field(
        default_factory=lambda: _env("MINIO_ENDPOINT", "http://minio:9000")
    )

    # ── A2A protocol (warden/protocols/a2a/task_lifecycle.py) ────────────────────
    a2a_base_url: str = field(
        default_factory=lambda: _env("A2A_BASE_URL", "http://localhost:8001")
    )

    # ── A2A Agent Card (warden/protocols/a2a/agent_card.py) ──────────────────────
    # NB: same A2A_BASE_URL env var as above but this file's own default is the
    # public API host, not localhost — a pre-existing drift, kept as a separate
    # field (not a2a_base_url) to preserve exact per-file behaviour when unset.
    a2a_card_base_url: str = field(
        default_factory=lambda: _env("A2A_BASE_URL", "https://api.shadow-warden-ai.com")
    )
    a2a_agent_name: str = field(
        default_factory=lambda: _env("A2A_AGENT_NAME", "Shadow Warden AI")
    )
    a2a_agent_did: str = field(
        default_factory=lambda: _env("A2A_AGENT_DID", "did:shadow:default")
    )
    # NB: kept as raw strings (not bool/float) — agent_card.py serialises these
    # verbatim into the public JSON discovery document, matching prior behaviour.
    marketplace_search_fee_usd: str = field(
        default_factory=lambda: _env("MARKETPLACE_SEARCH_FEE_USD", "0.000001")
    )
    x402_gate_enabled: str = field(
        default_factory=lambda: _env("X402_GATE_ENABLED", "false")
    )
    home_jurisdiction: str = field(
        default_factory=lambda: _env("HOME_JURISDICTION", "EU")
    )

    # ── Brand Agent (warden/marketplace/brand_agent.py) ──────────────────────────
    brand_agent_min_trust: float = field(
        default_factory=lambda: _float("BRAND_AGENT_MIN_TRUST", 0.0)
    )
    brand_agent_max_rpm: int = field(
        default_factory=lambda: _int("BRAND_AGENT_MAX_RPM", 60)
    )

    # ── Community peering (warden/communities/peering.py) ────────────────────────
    sep_db_path: str = field(
        default_factory=lambda: _db_env("SEP_DB_PATH", "warden_sep.db")
    )
    federated_trust_flag_ttl_days: int = field(
        default_factory=lambda: _int("FEDERATED_TRUST_FLAG_TTL_DAYS", 30)
    )

    # ── Knock-and-Verify invitations (warden/communities/knock.py) ───────────────
    # NB: COMMUNITY_VAULT_KEY/VAULT_MASTER_KEY fallback in _sep_key() stays a
    # lazy live read — signing-key resolution invariant, same class as T62/T73.
    # REDIS_URL in _redis() reuses settings.redis_url (always explicitly set in
    # practice, same reuse precedent as T72/T73).
    sep_knock_ttl_hours: int = field(
        default_factory=lambda: _int("SEP_KNOCK_TTL_HOURS", 72)
    )

    # ── Compliance Evidence Bundle (warden/compliance/evidence_bundle.py) ────────
    # NB: VENDOR_GOV_DB_PATH default here ("warden_vendor_gov.db") differs
    # from vendor_gov/registry.py's own default ("warden_vendor.db") for the
    # SAME env var — a pre-existing inconsistency, not something to unify here.
    # Kept as its own field to preserve this file's exact fallback behavior.
    evidence_bundle_vendor_db_path: str = field(
        default_factory=lambda: _db_env("VENDOR_GOV_DB_PATH", "warden_vendor_gov.db")
    )
    training_records_db_path: str = field(
        default_factory=lambda: _db_env("TRAINING_RECORDS_DB_PATH", "warden_training.db")
    )

    # ── Community threat score federation (warden/communities/federation.py) ─────
    # NB: REDIS_URL stays a lazy os.getenv() function-level read in _redis() —
    # inline default "" is a deliberate disabled-sentinel, differs from
    # settings.redis_url's non-empty default (same class as T18/T29/T69).
    federation_enabled: bool = field(
        default_factory=lambda: _bool("FEDERATION_ENABLED", False)
    )
    federation_verdict_ttl: int = field(
        default_factory=lambda: _int("FEDERATION_VERDICT_TTL", 86_400 * 7)
    )
    federation_score_boost: float = field(
        default_factory=lambda: _float("FEDERATION_SCORE_BOOST", 0.15)
    )

    # ── Break Glass emergency key access (warden/communities/break_glass.py) ─────
    break_glass_ttl_s: int = field(
        default_factory=lambda: _int("BREAK_GLASS_TTL_S", 3600)
    )
    break_glass_m_sigs: int = field(
        default_factory=lambda: _int("BREAK_GLASS_M_SIGS", 3)
    )
    break_glass_tier: str = field(
        default_factory=lambda: _env("BREAK_GLASS_TIER", "mcp")
    )
    break_glass_audit_path: str = field(
        default_factory=lambda: _db_env("BREAK_GLASS_AUDIT_PATH", "warden_break_glass_audit.jsonl")
    )

    # ── SOVA scheduler jobs (warden/agent/scheduler.py) ──────────────────────────
    warden_base_url: str = field(
        default_factory=lambda: _env("WARDEN_BASE_URL", "http://localhost:8001")
    )
    dashboard_url: str = field(
        default_factory=lambda: _env("DASHBOARD_URL", "")
    )
    patrol_urls: str = field(
        default_factory=lambda: _env("PATROL_URLS", "")
    )
    obsidian_community_id: str = field(
        default_factory=lambda: _env("OBSIDIAN_COMMUNITY_ID", "default")
    )
    evidence_bundle_tenants: str = field(
        default_factory=lambda: _env("EVIDENCE_BUNDLE_TENANTS", "default")
    )
    agents_md_path: str = field(
        default_factory=lambda: _env("AGENTS_MD_PATH", "data/AGENTS.md")
    )

    # ── STIX/TAXII feed (warden/integrations/taxii.py) ───────────────────────────
    taxii_server_url: str = field(
        default_factory=lambda: _env("TAXII_SERVER_URL", "")
    )
    taxii_username: str = field(
        default_factory=lambda: _env("TAXII_USERNAME", "")
    )
    taxii_password: str = field(
        default_factory=lambda: _env("TAXII_PASSWORD", "")
    )
    taxii_api_key: str = field(
        default_factory=lambda: _env("TAXII_API_KEY", "")
    )
    taxii_collections: str = field(
        default_factory=lambda: _env("TAXII_COLLECTIONS", "")
    )
    taxii_poll_interval: int = field(
        default_factory=lambda: _int("TAXII_POLL_INTERVAL", 3600)
    )
    taxii_max_objects: int = field(
        default_factory=lambda: _int("TAXII_MAX_OBJECTS", 200)
    )
    taxii_tenant_id: str = field(
        default_factory=lambda: _env("TAXII_TENANT_ID", "default")
    )

    # ── MISP ZMQ/HTTP bridge (warden/integrations/misp_bridge.py) ────────────────
    # NB: SHADOW_AI_SYSLOG_PORT is shared with warden/shadow_ai/syslog_sink.py
    # (still a lazy os.getenv() read there — untouched by this field).
    misp_zmq_url: str = field(
        default_factory=lambda: _env("MISP_ZMQ_URL", "")
    )
    misp_api_url: str = field(
        default_factory=lambda: _env("MISP_API_URL", "")
    )
    misp_api_key: str = field(
        default_factory=lambda: _env("MISP_API_KEY", "")
    )
    misp_tenant_id: str = field(
        default_factory=lambda: _env("MISP_TENANT_ID", "default")
    )
    misp_poll_interval: int = field(
        default_factory=lambda: _int("MISP_POLL_INTERVAL", 300)
    )
    misp_syslog_enabled: bool = field(
        default_factory=lambda: _bool("MISP_SYSLOG_ENABLED", True)
    )
    misp_syslog_target_host: str = field(
        default_factory=lambda: _env("MISP_SYSLOG_TARGET_HOST", "127.0.0.1")
    )

    # ── MISP threat feed connector (warden/integrations/misp.py) ─────────────────
    # NB: MISP_URL / MISP_API_KEY kept as live env reads in MISPConnector.__init__ —
    # dynamically monkeypatch.setenv'd per-test in test_coverage_boost3.py, and the
    # missing-credential ValueError must observe those overrides at construction time.
    misp_verify_ssl: bool = field(default_factory=lambda: _bool("MISP_VERIFY_SSL", True))
    misp_lookback_days: int = field(default_factory=lambda: _int("MISP_LOOKBACK_DAYS", 7))
    misp_max_events: int = field(default_factory=lambda: _int("MISP_MAX_EVENTS", 100))
    misp_tag_filter: str = field(default_factory=lambda: _env("MISP_TAG_FILTER", ""))
    shadow_ai_syslog_port: int = field(
        default_factory=lambda: _int("SHADOW_AI_SYSLOG_PORT", 5514)
    )

    # ── Shadow AI Discovery (warden/shadow_ai/discovery.py) ──────────────────────
    # NB: reuses redis_url — inline default was "redis://localhost:6379" (no db
    # index) vs settings.redis_url's "redis://redis:6379/0"; same localhost-vs-
    # docker-service-name drift class as prior tiers, harmless since REDIS_URL
    # is always explicitly set in practice and Redis defaults to db 0 anyway.
    shadow_ai_probe_timeout: float = field(default_factory=lambda: _float("SHADOW_AI_PROBE_TIMEOUT", 3))
    shadow_ai_concurrency: int = field(default_factory=lambda: _int("SHADOW_AI_CONCURRENCY", 50))
    shadow_ai_use_scapy: bool = field(default_factory=lambda: _bool("SHADOW_AI_USE_SCAPY", False))
    shadow_ai_scapy_timeout: float = field(default_factory=lambda: _float("SHADOW_AI_SCAPY_TIMEOUT", 2))

    # ── HSM PKCS#11 bridge (warden/crypto/hsm.py) ────────────────────────────────
    # NB: test_crypto_hsm.py monkeypatch.setenv's HSM_ENABLED/PKCS11_LIB mid-test,
    # but both are read once as frozen module constants at import time — the
    # patch is already inert pre-migration (same class as prior findings).
    hsm_enabled: bool = field(default_factory=lambda: _bool("HSM_ENABLED", False))
    pkcs11_lib: str = field(default_factory=lambda: _env("PKCS11_LIB", ""))
    pkcs11_token_label: str = field(default_factory=lambda: _env("PKCS11_TOKEN_LABEL", "shadow-warden"))
    pkcs11_pin: str = field(default_factory=lambda: _env("PKCS11_PIN", ""))
    pkcs11_key_label: str = field(default_factory=lambda: _env("PKCS11_KEY_LABEL", "warden-sign"))

    # ── Red-team autopilot (warden/agent/red_team.py) ────────────────────────────
    red_team_enabled: bool = field(
        default_factory=lambda: _bool("RED_TEAM_ENABLED", False)
    )
    red_team_probes: int = field(
        default_factory=lambda: _int("RED_TEAM_PROBES", 10)
    )
    red_team_target_url: str = field(
        default_factory=lambda: _env("RED_TEAM_TARGET_URL", "http://localhost:8001/filter")
    )
    red_team_api_key: str = field(
        default_factory=lambda: _env("RED_TEAM_API_KEY", _env("WARDEN_API_KEY", ""))
    )
    red_team_model: str = field(
        default_factory=lambda: _env("RED_TEAM_MODEL", "claude-opus-4-6")
    )
    evolution_dataset_path: str = field(
        default_factory=lambda: _env("EVOLUTION_DATASET_PATH", "data/evolution_dataset.jsonl")
    )

    # ── Online Learning (warden/brain/online_learner.py) ─────────────────────────
    online_learning_enabled: bool = field(
        default_factory=lambda: _bool("ONLINE_LEARNING_ENABLED", False)
    )
    online_learning_batch: int = field(
        default_factory=lambda: _int("ONLINE_LEARNING_BATCH", 100)
    )
    online_learning_threshold: float = field(
        default_factory=lambda: _float("ONLINE_LEARNING_THRESHOLD", 0.60)
    )

    # ── Weekly ROI report (warden/workers/weekly_report.py) ──────────────────────
    # NB: SMTP_HOST/PORT/USER/PASS and WEEKLY_REPORT_FROM stay lazy os.getenv()
    # reads there — test_weekly_report.py reload()s the module after patching
    # os.environ to exercise different SMTP configs, which a frozen Settings
    # singleton read would not pick up.
    weekly_report_reply_to: str = field(
        default_factory=lambda: _env("WEEKLY_REPORT_REPLY_TO", "")
    )
    # NB: default here ("...io") intentionally mirrors the module's own prior
    # default, which differs from settings.portal_url's default ("...-ai.com") —
    # not reused to avoid silently changing weekly-report CTA links.
    weekly_report_portal_url: str = field(
        default_factory=lambda: _env("PORTAL_URL", "https://app.shadow-warden.io")
    )

    # ── Honeypot (warden/honey.py) ──────────────────────────────────────────────
    # NB: HONEY_MODE + HONEY_PROBABILITY stay lazy reads in honey.py (per-request
    # runtime toggles) — intentionally NOT mirrored here.
    honey_session_ttl_sec: int = field(
        default_factory=lambda: _int("HONEY_SESSION_TTL_SEC", 3600)
    )
    honey_log_followup: bool = field(
        default_factory=lambda: _bool("HONEY_LOG_FOLLOWUP", True)
    )
    honey_inject_secrets: bool = field(
        default_factory=lambda: _bool("HONEY_INJECT_SECRETS", False)
    )

    # ── FIDO2 / WebAuthn passkeys (warden/auth/fido.py) ─────────────────────────
    fido_db_path: str = field(
        default_factory=lambda: _db_env("FIDO_DB_PATH", "warden_fido.db")
    )
    fido_rp_id: str = field(
        default_factory=lambda: _env("FIDO_RP_ID", "shadow-warden-ai.com")
    )
    fido_rp_name: str = field(
        default_factory=lambda: _env("FIDO_RP_NAME", "Shadow Warden AI")
    )
    fido_origin: str = field(
        default_factory=lambda: _env("FIDO_ORIGIN", "https://shadow-warden-ai.com")
    )

    # ── Shadow Ban (warden/shadow_ban.py) ───────────────────────────────────────
    # Estimated LLM completion cost saved per shadow-banned request (USD).
    shadow_ban_cost_per_request_usd: float = field(
        default_factory=lambda: _float("SHADOW_BAN_COST_PER_REQUEST_USD", 0.60 / 1_000_000 * 200)
    )
    shadow_ban_enabled: bool = field(
        default_factory=lambda: _bool("SHADOW_BAN_ENABLED", True)
    )
    # Real async delay (ms) applied by the "delay" shadow-ban strategy.
    shadow_ban_delay_ms: float = field(
        default_factory=lambda: _float("SHADOW_BAN_DELAY_MS", 3000.0)
    )

    # ── Topological Gatekeeper thresholds (warden/topology_guard.py) ────────────
    topo_noise_threshold: float = field(
        default_factory=lambda: _float("TOPO_NOISE_THRESHOLD", 0.82)
    )
    topo_min_len: int = field(
        default_factory=lambda: _int("TOPO_MIN_LEN", 20)
    )
    topo_noise_threshold_code: float = field(
        default_factory=lambda: _float("TOPO_NOISE_THRESHOLD_CODE", 0.65)
    )
    topo_noise_threshold_natural: float = field(
        default_factory=lambda: _float("TOPO_NOISE_THRESHOLD_NATURAL", 0.82)
    )
    # Fold H₁ persistence (longest-lived 1-cycle lifetime) into the ripser noise
    # score, not just the β₁ count. Default OFF — ripser-gated, purely additive
    # when off (h1_max_lifetime is still reported on TopoResult either way).
    tda_persistence_enabled: bool = field(
        default_factory=lambda: _bool("TDA_PERSISTENCE", False)
    )

    # ── Corpus cross-region sync (warden/corpus_sync.py) ────────────────────────
    # NB: reuses redis_url/global_redis_url, corpus_snapshot_path, warden_region.
    corpus_sync_enabled: bool = field(
        default_factory=lambda: _bool("CORPUS_SYNC_ENABLED", True)
    )
    corpus_s3_bucket: str = field(
        default_factory=lambda: _env("CORPUS_S3_BUCKET", "")
    )
    corpus_s3_prefix: str = field(
        default_factory=lambda: _env("CORPUS_S3_PREFIX", "warden/corpus")
    )
    corpus_s3_region: str = field(
        default_factory=lambda: _env("CORPUS_S3_REGION", "us-east-1")
    )
    corpus_invalidation_stream: str = field(
        default_factory=lambda: _env("CORPUS_INVALIDATION_STREAM", "warden:corpus:invalidations")
    )
    corpus_invalidation_max: int = field(
        default_factory=lambda: _int("CORPUS_INVALIDATION_MAX", 500)
    )

    # ── RAG Evolver (warden/rag_evolver.py) ─────────────────────────────────────
    # NB: NVIDIA_API_KEY / ANTHROPIC_API_KEY stay lazy function-level reads in
    # rag_evolver so the evolution-disable-on-empty-key contract holds in tests.
    rag_evolver_enabled: bool = field(
        default_factory=lambda: _bool("RAG_EVOLVER_ENABLED", True)
    )
    rag_evolver_dataset_path: str = field(
        default_factory=lambda: _env("RAG_EVOLVER_DATASET_PATH", "/warden/data/rag_injection_dataset.jsonl")
    )
    rag_evolver_patterns_path: str = field(
        default_factory=lambda: _env("RAG_EVOLVER_PATTERNS_PATH", "/warden/data/rag_evolved_patterns.json")
    )
    rag_evolver_max_samples: int = field(
        default_factory=lambda: _int("RAG_EVOLVER_MAX_SAMPLES", 5000)
    )
    rag_evolver_batch_size: int = field(
        default_factory=lambda: _int("RAG_EVOLVER_BATCH_SIZE", 10)
    )
    rag_evolver_rate_window: int = field(
        default_factory=lambda: _int("RAG_EVOLVER_RATE_WINDOW", 3600)
    )
    rag_evolver_rate_max: int = field(
        default_factory=lambda: _int("RAG_EVOLVER_RATE_MAX", 4)
    )
    rag_evolver_engine: str = field(
        default_factory=lambda: _env("RAG_EVOLVER_ENGINE", "auto").lower()
    )
    rag_evolver_redos_timeout_s: float = field(
        default_factory=lambda: _float("RAG_EVOLVER_REDOS_TIMEOUT_S", 0.5)
    )

    # ── Cross-region threat sync (warden/threat_sync.py) ────────────────────────
    # NB: REGION reuses warden_region; redis reuses global_redis_url/redis_url.
    threat_sync_enabled: bool = field(
        default_factory=lambda: _bool("THREAT_SYNC_ENABLED", True)
    )
    threat_sync_stream: str = field(
        default_factory=lambda: _env("THREAT_SYNC_STREAM", "warden:threats:global")
    )
    threat_sync_max_len: int = field(
        default_factory=lambda: _int("THREAT_SYNC_MAX_LEN", 10000)
    )
    threat_sync_batch: int = field(
        default_factory=lambda: _int("THREAT_SYNC_BATCH", 50)
    )
    threat_sync_block_ms: int = field(
        default_factory=lambda: _int("THREAT_SYNC_BLOCK_MS", 5000)
    )
    threat_sync_seen_cap: int = field(
        default_factory=lambda: _int("THREAT_SYNC_SEEN_CAP", 50000)
    )

    # ── External threat feed (warden/threat_feed.py) ────────────────────────────
    threat_feed_enabled: bool = field(
        default_factory=lambda: _bool("THREAT_FEED_ENABLED", False)
    )
    threat_feed_url: str = field(
        default_factory=lambda: _env("THREAT_FEED_URL", "")
    )
    threat_feed_api_key: str = field(
        default_factory=lambda: _env("THREAT_FEED_API_KEY", "")
    )
    threat_feed_sync_hrs: float = field(
        default_factory=lambda: _float("THREAT_FEED_SYNC_HRS", 6.0)
    )
    threat_feed_max_rules: int = field(
        default_factory=lambda: _int("THREAT_FEED_MAX_RULES", 500)
    )
    threat_feed_receive_only: bool = field(
        default_factory=lambda: _bool("THREAT_FEED_RECEIVE_ONLY", False)
    )
    threat_feed_consensus_threshold: float = field(
        default_factory=lambda: _float("THREAT_FEED_CONSENSUS_THRESHOLD", 0.80)
    )
    threat_feed_max_worm_hashes: int = field(
        default_factory=lambda: _int("THREAT_FEED_MAX_WORM_HASHES", 10000)
    )
    threat_feed_cache_path: str = field(
        default_factory=lambda: _env("THREAT_FEED_CACHE_PATH", "/warden/data/threat_feed_cache.json")
    )

    # ── Threat Store (warden/threat_store.py) ────────────────────────────────────
    threat_db_path: str = field(
        default_factory=lambda: _env("THREAT_DB_PATH", "/warden/data/threat_store.db")
    )
    auto_block_threshold: int = field(
        default_factory=lambda: _int("AUTO_BLOCK_THRESHOLD", 20)
    )
    auto_block_window: int = field(
        default_factory=lambda: _int("AUTO_BLOCK_WINDOW", 300)
    )
    auto_block_duration: int = field(
        default_factory=lambda: _int("AUTO_BLOCK_DURATION", 3600)
    )

    # ── Threat Intel Analyzer (warden/threat_intel/analyzer.py) ──────────────────
    # NB: ANTHROPIC_API_KEY stays a lazy os.getenv() function-level read in
    # analyzer.py — established test-contract skip category (empty key disables
    # analysis, tests rely on the live read).
    threat_intel_model: str = field(
        default_factory=lambda: _env("THREAT_INTEL_MODEL", "claude-haiku-4-5-20251001")
    )
    threat_intel_min_relevance: float = field(
        default_factory=lambda: _float("THREAT_INTEL_MIN_RELEVANCE", 0.65)
    )
    threat_intel_min_actionability: float = field(
        default_factory=lambda: _float("THREAT_INTEL_MIN_ACTIONABILITY", 0.5)
    )

    # ── Portal SMTP + auth (warden/portal_router.py) ────────────────────────────
    # NB: WARDEN_API_KEYS_PATH read here reuses warden_api_keys_path.
    smtp_host: str = field(
        default_factory=lambda: _env("SMTP_HOST", "")
    )
    smtp_port: int = field(
        default_factory=lambda: _int("SMTP_PORT", 587)
    )
    smtp_user: str = field(
        default_factory=lambda: _env("SMTP_USER", "")
    )
    smtp_pass: str = field(
        default_factory=lambda: _env("SMTP_PASS", "")
    )
    portal_from_email: str = field(
        default_factory=lambda: _env("PORTAL_FROM_EMAIL", "")
    )
    portal_from: str = field(
        default_factory=lambda: _env("PORTAL_FROM", "")
    )
    portal_url: str = field(
        default_factory=lambda: _env("PORTAL_URL", "https://app.shadow-warden-ai.com")
    )
    # Random per-process default if unset — matches portal_router's prior behaviour.
    portal_jwt_secret: str = field(
        default_factory=lambda: _env("PORTAL_JWT_SECRET", "change-me-" + secrets.token_hex(16))
    )
    portal_access_token_ttl: int = field(
        default_factory=lambda: _int("PORTAL_ACCESS_TOKEN_TTL", 60)
    )
    portal_refresh_token_ttl: int = field(
        default_factory=lambda: _int("PORTAL_REFRESH_TOKEN_TTL", 7)
    )

    # ── OpenAI-compatible proxy providers (warden/openai_proxy.py) ──────────────
    openai_upstream: str = field(
        default_factory=lambda: _env("OPENAI_UPSTREAM", "https://api.openai.com")
    )
    warden_filter_url: str = field(
        default_factory=lambda: _env("WARDEN_FILTER_URL", "http://localhost:8001")
    )
    perplexity_api_key: str = field(
        default_factory=lambda: _env("PERPLEXITY_API_KEY", "")
    )
    gemini_api_key: str = field(
        default_factory=lambda: _env("GEMINI_API_KEY", "")
    )
    azure_openai_endpoint: str = field(
        default_factory=lambda: _env("AZURE_OPENAI_ENDPOINT", "")
    )
    azure_openai_api_key: str = field(
        default_factory=lambda: _env("AZURE_OPENAI_API_KEY", "")
    )
    azure_openai_api_version: str = field(
        default_factory=lambda: _env("AZURE_OPENAI_API_VERSION", "2024-05-01-preview")
    )
    aws_region: str = field(
        default_factory=lambda: _env("AWS_REGION", "us-east-1")
    )
    aws_access_key_id: str = field(
        default_factory=lambda: _env("AWS_ACCESS_KEY_ID", "")
    )
    aws_secret_access_key: str = field(
        default_factory=lambda: _env("AWS_SECRET_ACCESS_KEY", "")
    )
    vertex_project_id: str = field(
        default_factory=lambda: _env("VERTEX_PROJECT_ID", "")
    )
    vertex_location: str = field(
        default_factory=lambda: _env("VERTEX_LOCATION", "us-central1")
    )
    streaming_fast_scan_buffer: int = field(
        default_factory=lambda: _int("STREAMING_FAST_SCAN_BUFFER", 400)
    )
    masking_mode: str = field(
        default_factory=lambda: _env("MASKING_MODE", "off").lower()
    )
    wallet_enabled: bool = field(
        default_factory=lambda: _bool("WALLET_ENABLED", True)
    )
    output_guardrails_enabled: bool = field(
        default_factory=lambda: _bool("OUTPUT_GUARDRAILS_ENABLED", True)
    )
    output_max_discount_pct: int = field(
        default_factory=lambda: _int("OUTPUT_MAX_DISCOUNT_PCT", 50)
    )
    output_commitment_block: bool = field(
        default_factory=lambda: _bool("OUTPUT_COMMITMENT_BLOCK", True)
    )
    output_competitor_names: str = field(
        default_factory=lambda: _env("OUTPUT_COMPETITOR_NAMES", "")
    )

    # ── Portal/site auth cookies (warden/auth/router.py) ────────────────────────
    # NB: admin-bootstrap + JWT/vault secret reads stay lazy in auth/router.py.
    auth_session_ttl: int = field(
        default_factory=lambda: _int("AUTH_SESSION_TTL", 3600)
    )
    auth_cookie_domain: str = field(
        default_factory=lambda: _env("AUTH_COOKIE_DOMAIN", ".shadow-warden-ai.com")
    )
    auth_db_path: str = field(
        default_factory=lambda: _db_env("AUTH_DB_PATH", "warden_auth.db")
    )
    auth_signup_rate_limit: int = field(
        default_factory=lambda: _int("AUTH_SIGNUP_RATE_LIMIT", 5)
    )

    # ── Warden Agent Token / WAT ERC-20 (warden/tokenomics/agent_token.py) ───────
    wat_token_address: str = field(
        default_factory=lambda: _env("WAT_TOKEN_ADDRESS", "")
    )
    polygon_amoy_rpc_url: str = field(
        default_factory=lambda: _env("POLYGON_AMOY_RPC_URL", "")
    )
    wat_admin_wallet: str = field(
        default_factory=lambda: _env("WAT_ADMIN_WALLET", "")
    )
    wat_admin_private_key: str = field(
        default_factory=lambda: _env("WAT_ADMIN_PRIVATE_KEY", "")
    )
    wat_simulate: bool = field(
        default_factory=lambda: _bool("WAT_SIMULATE", True)
    )

    # ── USDC stablecoin rail (warden/payments/usdc.py) ──────────────────────────
    usdc_simulate: bool = field(
        default_factory=lambda: _bool("USDC_SIMULATE", True)
    )
    coinbase_commerce_api_key: str = field(
        default_factory=lambda: _env("COINBASE_COMMERCE_API_KEY", "")
    )
    usdc_intent_ttl_s: int = field(
        default_factory=lambda: _int("USDC_INTENT_TTL_S", 3600 * 24)
    )

    # ── Cross-chain escrow RPC endpoints (warden/web3/chains.py) ────────────────
    sepolia_rpc_url: str = field(
        default_factory=lambda: _env("SEPOLIA_RPC_URL", "")
    )
    web3_rpc_url: str = field(
        default_factory=lambda: _env("WEB3_RPC_URL", "")
    )
    arbitrum_sepolia_rpc_url: str = field(
        default_factory=lambda: _env("ARBITRUM_SEPOLIA_RPC_URL", "")
    )

    # ── Document Intelligence converter (warden/document_intel/converter.py) ────
    doc_intel_max_bytes: int = field(
        default_factory=lambda: _int("DOC_INTEL_MAX_BYTES", 50 * 1024 * 1024)
    )
    doc_intel_timeout_s: float = field(
        default_factory=lambda: _float("DOC_INTEL_TIMEOUT_S", 30.0)
    )
    doc_intel_cache_ttl: int = field(
        default_factory=lambda: _int("DOC_INTEL_CACHE_TTL", 3600)
    )

    # ── Decentralized key rotation (warden/web3/key_rotation.py) ─────────────────
    key_rotation_db_path: str = field(
        default_factory=lambda: _db_env("KEY_ROTATION_DB_PATH", "warden_key_rotation.db")
    )
    agent_key_rotation_max_days: int = field(
        default_factory=lambda: _int("AGENT_KEY_ROTATION_MAX_DAYS", 90)
    )
    key_rotation_contract_address: str = field(
        default_factory=lambda: _env("KEY_ROTATION_CONTRACT_ADDRESS", "")
    )

    # ── GSAM — Global Statistic Agentic Marketplace (warden/gsam/) ──────────────
    # Master switch for the GSAM analytics/governance layer.
    gsam_enabled: bool = field(
        default_factory=lambda: _bool("GSAM_ENABLED", True)
    )
    # ClickHouse observations stream (optional — warden runs fine without it).
    gsam_clickhouse_enabled: bool = field(
        default_factory=lambda: _bool("GSAM_CLICKHOUSE_ENABLED", False)
    )
    gsam_clickhouse_url: str = field(
        default_factory=lambda: _env("GSAM_CLICKHOUSE_URL", "http://clickhouse:8123")
    )
    gsam_clickhouse_user: str = field(
        default_factory=lambda: _env("GSAM_CLICKHOUSE_USER", "warden")
    )
    gsam_clickhouse_password: str = field(
        default_factory=lambda: _env("GSAM_CLICKHOUSE_PASSWORD", "")
    )
    gsam_clickhouse_database: str = field(
        default_factory=lambda: _env("GSAM_CLICKHOUSE_DATABASE", "gsam")
    )
    # NDJSON spool used while ClickHouse is disabled/unreachable (size-capped).
    gsam_spool_path: str = field(
        default_factory=lambda: _db_env("GSAM_SPOOL_PATH", "warden_gsam_spool.ndjson")
    )
    gsam_spool_max_bytes: int = field(
        default_factory=lambda: _int("GSAM_SPOOL_MAX_BYTES", 50_000_000)
    )
    # Collector queue/batching (producer side is put_nowait only — never blocks).
    gsam_queue_max: int = field(
        default_factory=lambda: _int("GSAM_QUEUE_MAX", 10_000)
    )
    gsam_flush_interval_s: float = field(
        default_factory=lambda: _float("GSAM_FLUSH_INTERVAL_S", 2.0)
    )
    gsam_batch_size: int = field(
        default_factory=lambda: _int("GSAM_BATCH_SIZE", 500)
    )
    # Drift index: EWMA smoothing factor λ and quarantine threshold.
    gsam_drift_lambda: float = field(
        default_factory=lambda: _float("GSAM_DRIFT_LAMBDA", 0.2)
    )
    gsam_drift_quarantine_threshold: float = field(
        default_factory=lambda: _float("GSAM_DRIFT_QUARANTINE_THRESHOLD", 0.85)
    )
    # Quarantine flag TTL (Redis gsam:quarantine:{agent_id}); default 24h.
    gsam_quarantine_ttl_s: int = field(
        default_factory=lambda: _int("GSAM_QUARANTINE_TTL_S", 86_400)
    )
    # JIT credential lease TTL + HMAC signing key (empty = leasing disabled,
    # fail-CLOSED by design — leases are a credential path, not analytics).
    gsam_lease_ttl_s: int = field(
        default_factory=lambda: _int("GSAM_LEASE_TTL_S", 900)
    )
    gsam_lease_secret: str = field(
        default_factory=lambda: _env("GSAM_LEASE_SECRET", "")
    )
    # SQLite fallback for drift baselines / leases / quarantine log / rollups
    # (Turso db name "gsam" when TURSO_URL_GSAM is set).
    gsam_db_path: str = field(
        default_factory=lambda: _db_env("GSAM_DB_PATH", "warden_gsam.db")
    )

    # ── SAC two-phase preflight billing (reserve → commit) ──────────────────────
    # Default OFF — enabling it makes an unfunded wallet block agent runs.
    sac_preflight_enabled: bool = field(
        default_factory=lambda: _bool("SAC_PREFLIGHT_ENABLED", False)
    )
    # Per-run reservation estimate (USD) held before an agent run; the real token
    # cost is committed afterward and the remainder released.
    sac_preflight_estimate_usd: float = field(
        default_factory=lambda: _float("SAC_PREFLIGHT_ESTIMATE_USD", 0.05)
    )
    sac_wallet_db_path: str = field(
        default_factory=lambda: _db_env("SAC_WALLET_DB_PATH", "warden_sac_wallet.db")
    )

    # ── Validation & audit (Deep-Eng P1) ────────────────────
    _SECRET_HINT = ("key", "token", "secret", "password", "webhook_url", "routing_key")

    @property
    def is_prod(self) -> bool:
        """True on a production deploy (WARDEN_ENV in {prod, production})."""
        return self.warden_env in ("prod", "production")

    def validate(self) -> list[str]:
        """Return human-readable config problems (empty list = healthy).

        Non-raising — callers decide to warn or fail-closed. Covers drift
        classes that have bitten prod: out-of-range thresholds, non-positive
        timeouts, an invalid Fernet master key, and unauthenticated access
        left enabled with no key configured.
        """
        problems: list[str] = []

        def _unit(name: str) -> None:
            v = getattr(self, name)
            if not 0.0 <= v <= 1.0:
                problems.append(f"{name}={v} out of range [0,1]")

        for _n in ("semantic_threshold", "hyperbolic_weight", "causal_risk_threshold",
                   "se_risk_threshold", "phish_url_threshold", "cb_bypass_threshold",
                   "image_guard_threshold"):
            _unit(_n)

        for _n in ("cache_ttl_seconds", "cb_window_secs", "cb_min_requests",
                   "cb_cooldown_secs", "webhook_timeout_s", "webhook_max_retries",
                   "nim_timeout_seconds", "max_corpus_rules", "evolution_rate_window",
                   "evolution_rate_max", "tenant_rate_limit", "image_pipeline_timeout_ms",
                   "audio_pipeline_timeout_ms"):
            if getattr(self, _n) <= 0:
                problems.append(f"{_n}={getattr(self, _n)} must be > 0")

        # Fail-closed auth (invariant #11): no key configured is only OK in dev.
        if not self.warden_api_key and not self.warden_api_keys_path and not self.allow_unauthenticated:
            problems.append(
                "no WARDEN_API_KEY / WARDEN_API_KEYS_PATH set and ALLOW_UNAUTHENTICATED "
                "is false — gateway would fail closed at auth"
            )

        # VAULT master key (invariant #1): if set, must be a valid Fernet key.
        if self.vault_master_key:
            try:
                from cryptography.fernet import Fernet
                Fernet(self.vault_master_key.encode())
            except Exception as exc:  # noqa: BLE001
                problems.append(f"VAULT_MASTER_KEY is not a valid Fernet key: {exc!r}")

        # Secret-bearing SQLite DBs must not live under /tmp in prod (S1).
        # Every module DB resolves under data_dir(); the masking vault, secrets
        # inventory, staff economics, ACP token vault etc. hold PII/secret
        # material. /tmp is ephemeral and often world-readable — one prod
        # misconfig there leaks credentials. Flag it so CONFIG_FAILCLOSED can
        # crash-loop the deploy instead of serving from /tmp. Dev is unaffected.
        if self.is_prod:
            # Normalise with POSIX semantics (prod is Linux); avoid os.path.abspath,
            # which rewrites "/tmp" to a drive path on a Windows dev/test host.
            base = data_dir().replace("\\", "/").rstrip("/") or "/"
            if base == "/tmp" or base.startswith("/tmp/"):
                problems.append(
                    f"WARDEN_DATA_DIR resolves under /tmp ({base!r}) in prod — "
                    "secret-bearing SQLite DBs would be ephemeral/world-readable. "
                    "Set WARDEN_DATA_DIR to a persisted, mode-0700 volume."
                )

        return problems

    def validate_or_raise(self) -> None:
        """Raise ConfigValidationError if any problem is found."""
        problems = self.validate()
        if problems:
            raise ConfigValidationError("invalid configuration: " + "; ".join(problems))

    def redacted_dump(self) -> dict[str, object]:
        """All settings as a dict with secret-like values masked — safe to log at
        startup for an auditable record of the effective configuration."""
        out: dict[str, object] = {}
        for f in fields(self):
            val = getattr(self, f.name)
            if val and any(h in f.name for h in self._SECRET_HINT):
                out[f.name] = "***set***"
            else:
                out[f.name] = val
        return out


# ── Singleton ─────────────────────────────────────────────────────────────────

settings: Settings = Settings()
