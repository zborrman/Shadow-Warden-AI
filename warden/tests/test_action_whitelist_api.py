"""
warden/tests/test_action_whitelist_api.py
─────────────────────────────────────────
Tests for Agent Action Whitelist REST API.
"""
from __future__ import annotations

from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from warden.main import app


@pytest.fixture
def api_client():
    # Patch ADMIN_KEY for predictable test environments
    with patch("warden.api.action_whitelist._ADMIN_KEY", "test-admin-key"):
        yield TestClient(app, raise_server_exceptions=True)


def test_action_whitelist_crud_unauthorized(api_client) -> None:
    agent_id = "agent-test-1"
    
    # 1. List rules with invalid/missing key should fail
    resp = api_client.get(f"/admin/agents/{agent_id}/whitelist")
    assert resp.status_code == 403
    
    # 2. Add rule with invalid/missing key should fail
    resp = api_client.post(
        f"/admin/agents/{agent_id}/whitelist",
        json={"http_method": "GET", "endpoint_glob": "/data/*"},
    )
    assert resp.status_code == 403

    # 3. Delete rule with invalid/missing key should fail
    resp = api_client.delete(f"/admin/agents/{agent_id}/whitelist/some-rule-id")
    assert resp.status_code == 403


def test_action_whitelist_crud_success(api_client) -> None:
    agent_id = "agent-test-2"
    headers = {"X-Admin-Key": "test-admin-key"}

    # 1. List rules initially empty
    resp = api_client.get(f"/admin/agents/{agent_id}/whitelist", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == []

    # 2. Add a whitelist rule
    resp = api_client.post(
        f"/admin/agents/{agent_id}/whitelist",
        json={"http_method": "GET", "endpoint_glob": "/users/*", "max_rps": 5.0},
        headers=headers,
    )
    assert resp.status_code == 201
    rule = resp.json()
    assert rule["agent_id"] == agent_id
    assert rule["http_method"] == "GET"
    assert rule["endpoint_glob"] == "/users/*"
    assert rule["max_rps"] == 5.0
    rule_id = rule["rule_id"]

    # 3. List rules contains the rule
    resp = api_client.get(f"/admin/agents/{agent_id}/whitelist", headers=headers)
    assert resp.status_code == 200
    rules = resp.json()
    assert len(rules) == 1
    assert rules[0]["rule_id"] == rule_id

    # 4. Check action - matching
    resp = api_client.post(
        f"/admin/agents/{agent_id}/whitelist/check",
        json={"http_method": "GET", "endpoint": "/users/123"},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["allowed"] is True

    # 5. Check action - non-matching
    resp = api_client.post(
        f"/admin/agents/{agent_id}/whitelist/check",
        json={"http_method": "POST", "endpoint": "/users/123"},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["allowed"] is False

    # 6. Delete the rule
    resp = api_client.delete(f"/admin/agents/{agent_id}/whitelist/{rule_id}", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["deleted"] is True

    # 7. List rules is empty again
    resp = api_client.get(f"/admin/agents/{agent_id}/whitelist", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == []

    # 8. Delete nonexistent rule returns 404
    resp = api_client.delete(f"/admin/agents/{agent_id}/whitelist/{rule_id}", headers=headers)
    assert resp.status_code == 404


def test_action_whitelist_bad_request(api_client) -> None:
    agent_id = "agent-test-3"
    headers = {"X-Admin-Key": "test-admin-key"}

    # Invalid HTTP Method should raise 400
    resp = api_client.post(
        f"/admin/agents/{agent_id}/whitelist",
        json={"http_method": "INVALID", "endpoint_glob": "*"},
        headers=headers,
    )
    assert resp.status_code == 400
