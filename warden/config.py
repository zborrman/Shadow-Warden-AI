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
from dataclasses import dataclass, field

__all__ = ["settings", "Settings"]


# ── Env-var helpers ───────────────────────────────────────────────────────────

def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default)

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

    # ── Audio Guard ────────────────────────────────────────────────────────────
    audio_guard_enabled: bool = field(
        default_factory=lambda: _bool("AUDIO_GUARD_ENABLED", True)
    )
    audio_guard_model: str = field(
        default_factory=lambda: _env("AUDIO_GUARD_MODEL", "tiny.en")
    )
    audio_pipeline_timeout_ms: int = field(
        default_factory=lambda: _int("AUDIO_PIPELINE_TIMEOUT_MS", 3000)
    )
    audio_max_bytes: int = field(
        default_factory=lambda: _int("AUDIO_MAX_BYTES", 25 * 1024 * 1024)
    )

    # ── Data Paths ─────────────────────────────────────────────────────────────
    audit_trail_path: str = field(
        default_factory=lambda: _env("AUDIT_TRAIL_PATH", "/warden/data/audit_trail.db")
    )
    corpus_snapshot_path: str = field(
        default_factory=lambda: _env("CORPUS_SNAPSHOT_PATH", "/tmp/warden_corpus_snapshot")
    )
    analytics_data_path: str = field(
        default_factory=lambda: _env("ANALYTICS_DATA_PATH", "/analytics/data")
    )

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


# ── Singleton ─────────────────────────────────────────────────────────────────

settings: Settings = Settings()
