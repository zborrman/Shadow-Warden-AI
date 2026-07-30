"""
The MCP commerce approval gate was decorative (2026-07-30).

`POST /business-community/commerce/approve/{workflow_id}` accepted any string as
a workflow id, stored nothing, and answered `resolved: true`. Nothing was ever
recorded when the approval was raised either — `_request_approval()` generated a
random id, posted it to Slack, and dropped it — so there was no way to tell an
approval of a real pending purchase from an approval of a typo.

Nothing downstream consumed a resolved workflow, so this could not move money.
It mattered because it *reported* that it had: the endpoint is the human-in-the
loop for purchases above COMMERCE_APPROVAL_THRESHOLD_USD, and it confirmed
decisions about workflows that had never existed. Wiring execution onto that
would have turned "any string approves" into a payment authorization bypass.
"""

from __future__ import annotations

import pytest

from warden.business_community.agentic_commerce import mcp_bridge as mb


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    """No Redis in tests — exercise the in-process fallback."""
    monkeypatch.setattr(mb, "_pending_local", {}, raising=False)
    monkeypatch.setattr(
        mb, "_redis_client", lambda: (_ for _ in ()).throw(RuntimeError("no redis"))
    )


def test_unknown_workflow_is_not_approvable():
    assert mb.resolve_workflow("mcp-approval-doesnotexist", "t1", True) is None


def test_pending_workflow_can_be_approved_once():
    mb.store_pending_workflow("wf-1", {"tenant_id": "t1", "status": "PENDING"})

    record = mb.resolve_workflow("wf-1", "t1", True)
    assert record is not None
    assert record["status"] == "APPROVED"

    # Consumed: a second decision on the same workflow is refused.
    assert mb.resolve_workflow("wf-1", "t1", False) is None


def test_rejection_is_recorded():
    mb.store_pending_workflow("wf-2", {"tenant_id": "t1", "status": "PENDING"})
    record = mb.resolve_workflow("wf-2", "t1", False)
    assert record is not None and record["status"] == "REJECTED"


def test_another_tenant_cannot_approve_your_purchase():
    """The workflow is bound to the tenant that raised it."""
    mb.store_pending_workflow("wf-3", {"tenant_id": "victim", "status": "PENDING"})
    assert mb.resolve_workflow("wf-3", "attacker", True) is None
    # Still pending for its real owner.
    assert mb.get_pending_workflow("wf-3")["status"] == "PENDING"


def test_lookup_fails_closed_when_storage_is_gone(monkeypatch):
    """
    Losing the store must deny, not wave things through. With Redis unavailable
    and the local map cleared, an id that was genuinely issued is no longer
    approvable.
    """
    mb.store_pending_workflow("wf-4", {"tenant_id": "t1", "status": "PENDING"})
    monkeypatch.setattr(mb, "_pending_local", {}, raising=False)
    assert mb.resolve_workflow("wf-4", "t1", True) is None


def test_approval_endpoint_rejects_an_invented_workflow():
    import warden.auth_guard as ag
    from fastapi.testclient import TestClient

    import warden.main as m

    prev = ag._VALID_KEY
    ag._VALID_KEY = ""
    try:
        client = TestClient(m.app, raise_server_exceptions=False)
        resp = client.post(
            "/business-community/commerce/approve/mcp-approval-invented",
            params={"tenant_id": "t1", "action": "approve"},
        )
        assert resp.status_code != 200, (
            "an invented workflow id was reported as resolved"
        )
    finally:
        ag._VALID_KEY = prev
