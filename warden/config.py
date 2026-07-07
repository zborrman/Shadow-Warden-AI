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
from dataclasses import dataclass, field, fields

__all__ = ["settings", "Settings", "ConfigValidationError"]


class ConfigValidationError(RuntimeError):
    """Raised by Settings.validate_or_raise() when configuration is invalid."""


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

    # ── A2A protocol (warden/protocols/a2a/task_lifecycle.py) ────────────────────
    a2a_base_url: str = field(
        default_factory=lambda: _env("A2A_BASE_URL", "http://localhost:8001")
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
    shadow_ai_syslog_port: int = field(
        default_factory=lambda: _int("SHADOW_AI_SYSLOG_PORT", 5514)
    )

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
        default_factory=lambda: _env("FIDO_DB_PATH", "/tmp/warden_fido.db")
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

    # ── Portal/site auth cookies (warden/auth/router.py) ────────────────────────
    # NB: admin-bootstrap + JWT/vault secret reads stay lazy in auth/router.py.
    auth_session_ttl: int = field(
        default_factory=lambda: _int("AUTH_SESSION_TTL", 3600)
    )
    auth_cookie_domain: str = field(
        default_factory=lambda: _env("AUTH_COOKIE_DOMAIN", ".shadow-warden-ai.com")
    )
    auth_db_path: str = field(
        default_factory=lambda: _env("AUTH_DB_PATH", "/tmp/warden_auth.db")
    )
    auth_signup_rate_limit: int = field(
        default_factory=lambda: _int("AUTH_SIGNUP_RATE_LIMIT", 5)
    )

    # ── Validation & audit (Deep-Eng P1) ────────────────────
    _SECRET_HINT = ("key", "token", "secret", "password", "webhook_url", "routing_key")

    def validate(self) -> list[str]:
        """Return human-readable config problems (empty list = healthy).

        Non-raising — callers decide to warn or fail-closed. Covers drift
        classes that have bitten prod: out-of-range thresholds, non-positive
        timeouts, an invalid Fernet master key, and fail-open auth with no key.
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
