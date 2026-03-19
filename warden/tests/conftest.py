"""
warden/tests/conftest.py
━━━━━━━━━━━━━━━━━━━━━━━
Shared pytest fixtures for all Warden test modules.

Session-scoped fixtures are expensive (ML model load, app startup) —
they are created once per test session and reused.
"""
from __future__ import annotations

import os

import pytest

# ── Environment setup (must happen before any warden imports) ─────────────────
os.environ.setdefault("ANTHROPIC_API_KEY", "")           # disable Evolution Engine
os.environ.setdefault("SEMANTIC_THRESHOLD", "0.72")
os.environ.setdefault("WARDEN_API_KEY", "")              # auth disabled in tests
os.environ.setdefault("LOGS_PATH",            "/tmp/warden_test_logs.json")
os.environ.setdefault("DYNAMIC_RULES_PATH",   "/tmp/warden_test_dynamic_rules.json")
os.environ.setdefault("STRICT_MODE", "false")
os.environ.setdefault("REDIS_URL", "memory://")          # in-memory limiter; no Redis needed
os.environ.setdefault("MODEL_CACHE_DIR",      "/tmp/warden_test_models")  # default is /warden/models (Docker-only)
# Additional Docker-only paths — redirect to /tmp so tests work outside container
os.environ.setdefault("BILLING_DB_PATH",      "/tmp/warden_test_billing.db")
os.environ.setdefault("POLICY_DB_PATH",       "/tmp/warden_test_data_policy.db")
os.environ.setdefault("RULE_LEDGER_PATH",     "/tmp/warden_test_rule_ledger.db")
os.environ.setdefault("THREAT_DB_PATH",       "/tmp/warden_test_threat_store.db")
os.environ.setdefault("THREAT_FEED_CACHE_PATH", "/tmp/warden_test_threat_feed_cache.json")
os.environ.setdefault("TENANT_POLICIES_PATH", "/tmp/warden_test_tenant_policies.json")
os.environ.setdefault("WARDEN_API_KEYS_PATH", "")        # multi-tenant keys disabled in tests
os.environ.setdefault("FEED_DB_PATH",         "/tmp/warden_test_feed_server.db")
os.environ.setdefault("STRIPE_DB_PATH",       "/tmp/warden_test_stripe.db")
os.environ.setdefault("STRIPE_SECRET_KEY",    "")   # Stripe disabled in tests
os.environ.setdefault("PADDLE_DB_PATH",       "/tmp/warden_test_paddle.db")
os.environ.setdefault("PADDLE_API_KEY",       "")   # Paddle disabled in tests
os.environ.setdefault("AGENT_REGISTRY_DB_PATH", "/tmp/warden_test_agent_registry.db")
os.environ.setdefault("MANDATE_SECRET",       "test-mandate-secret-ci")
os.environ.setdefault("THREAT_INTEL_DB_PATH", "/tmp/warden_test_threat_intel.db")
os.environ.setdefault("THREAT_INTEL_ENABLED", "false")


@pytest.fixture(scope="session")
def redactor():
    from warden.secret_redactor import SecretRedactor
    return SecretRedactor(strict=False)


@pytest.fixture(scope="session")
def strict_redactor():
    from warden.secret_redactor import SecretRedactor
    return SecretRedactor(strict=True)


@pytest.fixture(scope="session")
def guard():
    from warden.semantic_guard import SemanticGuard
    return SemanticGuard(strict=False)


@pytest.fixture(scope="session")
def strict_guard():
    from warden.semantic_guard import SemanticGuard
    return SemanticGuard(strict=True)


@pytest.fixture(scope="session")
def client():
    """
    FastAPI TestClient for end-to-end /filter tests.

    The ML model (~80 MB) is loaded once here and reused for the
    entire test session. Mark individual tests with @pytest.mark.slow
    if they depend on this fixture and you want to skip them normally.
    """
    from fastapi.testclient import TestClient

    from warden.main import app
    with TestClient(app) as c:
        yield c
