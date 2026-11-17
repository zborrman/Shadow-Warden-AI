"""
A payment webhook with no secret configured is refused, not trusted.

Found in the 2026-11-16 re-audit. `LEMONSQUEEZY_WEBHOOK_SECRET` was not set on
the production server, and `handle_webhook()` treated "no secret" as "skip the
signature check": the event was applied as sent. Both receivers are anonymous
by nature, so a forged `subscription_created` would have put any tenant on a
paid plan without paying.

The same re-audit found `GET /marketplace/compliance/soc2-report` reading its
plan gate from `X-Tenant-Tier` with no authentication - one header returned the
report to anyone. Both are the same mistake: trusting what the caller wrote.
"""
from __future__ import annotations

import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

import warden.auth_guard as auth_guard
import warden.lemon_billing as lb

FORGED = json.dumps(
    {
        "meta": {
            "event_name": "subscription_created",
            "event_id": "forged-1",
            "custom_data": {"tenant_id": "victim", "plan": "community_business"},
        },
        "data": {"id": "1", "attributes": {"status": "active", "customer_id": 1}},
    }
).encode()

WEBHOOK_ROUTES = ["/billing/webhook", "/subscription/webhook"]


@pytest.fixture
def production_auth(monkeypatch):
    """A real key configured and ALLOW_UNAUTHENTICATED off - what the server runs."""
    monkeypatch.setattr(auth_guard, "tier_header_trusted", lambda: False)


@pytest.fixture
def client():
    from warden.main import app

    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture
def billing(tmp_path):
    return lb.LemonBilling(db_path=tmp_path / "lemon.db")


def test_the_library_refuses_when_there_is_no_secret(monkeypatch, production_auth, billing):
    monkeypatch.setattr(lb, "_LS_WEBHOOK_SECRET", "")
    with pytest.raises(lb.WebhookNotConfiguredError):
        billing.handle_webhook(FORGED, "")
    assert billing.get_plan("victim") == "starter"


def test_a_forged_event_changes_no_plan(monkeypatch, production_auth, billing):
    monkeypatch.setattr(lb, "_LS_WEBHOOK_SECRET", "")
    for signature in ("", "0" * 64, "anything"):
        with pytest.raises(lb.WebhookNotConfiguredError):
            billing.handle_webhook(FORGED, signature)
    assert billing.get_plan("victim") == "starter"


@pytest.mark.parametrize("path", WEBHOOK_ROUTES)
def test_both_receivers_answer_503_without_a_secret(monkeypatch, production_auth, client, path):
    monkeypatch.setattr(lb, "_LS_WEBHOOK_SECRET", "")
    resp = client.post(path, content=FORGED, headers={"Content-Type": "application/json"})
    # Not 200: a 200 tells the sender the event was accepted.
    assert resp.status_code == 503, resp.text


@pytest.mark.parametrize("path", WEBHOOK_ROUTES)
def test_both_receivers_reject_a_bad_signature(monkeypatch, production_auth, client, path):
    monkeypatch.setattr(lb, "_LS_WEBHOOK_SECRET", "real-secret")
    resp = client.post(
        path,
        content=FORGED,
        headers={"Content-Type": "application/json", "X-Signature": "0" * 64},
    )
    assert resp.status_code == 400


def test_a_correctly_signed_event_is_still_processed(monkeypatch, production_auth, billing):
    monkeypatch.setattr(lb, "_LS_WEBHOOK_SECRET", "real-secret")
    signature = hmac.new(b"real-secret", FORGED, hashlib.sha256).hexdigest()
    assert billing.handle_webhook(FORGED, signature) == "subscription_created"


def test_dev_mode_keeps_working_without_a_secret(monkeypatch, billing):
    """Auth switched off (tests, air-gapped dev) is the one place an unsigned
    event is accepted - the same rule the tier header follows."""
    monkeypatch.setattr(auth_guard, "tier_header_trusted", lambda: True)
    monkeypatch.setattr(lb, "_LS_WEBHOOK_SECRET", "")
    assert billing.handle_webhook(FORGED, "") == "subscription_created"


# ── the SOC 2 report gate ────────────────────────────────────────────────────

SOC2 = "/marketplace/compliance/soc2-report"


def test_the_soc2_report_needs_a_key(monkeypatch, client):
    monkeypatch.setattr(auth_guard, "_VALID_KEY", "a-real-key")
    monkeypatch.setattr(auth_guard.settings, "allow_unauthenticated", False, raising=False)
    resp = client.get(SOC2, headers={"X-Tenant-Tier": "lab"})
    assert resp.status_code in (401, 403)
    assert resp.status_code != 200


def test_a_tier_header_does_not_unlock_the_soc2_report(monkeypatch, client):
    """With a valid key, the plan comes from the tenant, not from the header."""
    monkeypatch.setattr(auth_guard, "_VALID_KEY", "a-real-key")
    monkeypatch.setattr(auth_guard.settings, "allow_unauthenticated", False, raising=False)
    resp = client.get(SOC2, headers={"X-API-Key": "a-real-key", "X-Tenant-Tier": "lab"})
    assert resp.status_code == 403, resp.text


def test_no_route_reads_the_tier_header_itself():
    """`X-Tenant-Tier` may be read in two places: the gate that decides whether
    to trust it, and the communities resolver that asks the same question.
    A third reader is a gate the caller can open themselves."""
    import pathlib
    import re

    root = pathlib.Path(lb.__file__).resolve().parent
    allowed = {"billing/feature_gate.py", "communities/router.py"}
    readers = set()
    for path in root.rglob("*.py"):
        rel = path.relative_to(root).as_posix()
        if rel.startswith(("tests/", "analytics/pages/")):
            continue
        if re.search(r"headers\.get\(\s*[\"']X-Tenant-Tier[\"']", path.read_text(encoding="utf-8")):
            readers.add(rel)
    assert readers == allowed, f"unexpected readers of X-Tenant-Tier: {readers - allowed}"
