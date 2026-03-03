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
os.environ.setdefault("LOGS_PATH", "/tmp/warden_test_logs.json")
os.environ.setdefault("DYNAMIC_RULES_PATH", "/tmp/warden_test_dynamic_rules.json")
os.environ.setdefault("STRICT_MODE", "false")


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
