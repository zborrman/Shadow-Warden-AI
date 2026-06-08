"""
Tests for Community Event Notification Service + API.
"""
from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("LOGS_PATH", "/tmp/test_notif_logs.json")
os.environ.setdefault("DYNAMIC_RULES_PATH", "/tmp/test_notif_rules.json")
os.environ.setdefault("COMMUNITY_NOTIF_DB_PATH", "/tmp/test_community_notif.db")


def _cid() -> str:
    return f"comm-{uuid.uuid4().hex[:12]}"


def _tid() -> str:
    return f"tenant-{uuid.uuid4().hex[:8]}"


# ── Unit: notifications module ────────────────────────────────────────────────

class TestSubscribeCRUD:
    def test_subscribe_slack(self):
        from warden.communities.notifications import subscribe, list_subscriptions, unsubscribe
        cid, tid = _cid(), _tid()
        sub = subscribe(cid, tid, "slack", "https://hooks.slack.com/test", "My Slack")
        assert sub.sub_id
        assert sub.community_id == cid
        assert sub.channel == "slack"
        assert sub.active is True
        assert "member_joined" in sub.events

        subs = list_subscriptions(cid, tid)
        assert any(s.sub_id == sub.sub_id for s in subs)

        removed = unsubscribe(sub.sub_id, tid)
        assert removed is True

    def test_subscribe_teams(self):
        from warden.communities.notifications import subscribe
        cid, tid = _cid(), _tid()
        sub = subscribe(cid, tid, "teams", "https://outlook.office.com/webhook/test", "Teams Channel")
        assert sub.channel == "teams"

    def test_subscribe_email(self):
        from warden.communities.notifications import subscribe
        cid, tid = _cid(), _tid()
        sub = subscribe(cid, tid, "email", "admin@example.com", label="Admin Alerts")
        assert sub.channel == "email"
        assert sub.target == "admin@example.com"

    def test_subscribe_invalid_channel(self):
        from warden.communities.notifications import subscribe
        with pytest.raises(ValueError, match="Invalid channel"):
            subscribe(_cid(), _tid(), "discord", "https://discord.com/webhook/test")

    def test_subscribe_custom_events(self):
        from warden.communities.notifications import subscribe
        cid, tid = _cid(), _tid()
        sub = subscribe(cid, tid, "slack", "https://hooks.slack.com/x",
                        events=["member_joined", "compliance_changed"])
        assert sub.events == ["member_joined", "compliance_changed"]
        assert "transfer_completed" not in sub.events

    def test_subscribe_invalid_events_filtered(self):
        from warden.communities.notifications import subscribe
        cid, tid = _cid(), _tid()
        sub = subscribe(cid, tid, "slack", "https://hooks.slack.com/x",
                        events=["member_joined", "nonexistent_event"])
        assert "nonexistent_event" not in sub.events
        assert "member_joined" in sub.events

    def test_subscribe_all_invalid_events_raises(self):
        from warden.communities.notifications import subscribe
        with pytest.raises(ValueError, match="At least one valid event"):
            subscribe(_cid(), _tid(), "slack", "https://hooks.slack.com/x",
                      events=["bad_event"])

    def test_unsubscribe_wrong_tenant(self):
        from warden.communities.notifications import subscribe, unsubscribe
        cid, tid = _cid(), _tid()
        sub = subscribe(cid, tid, "slack", "https://hooks.slack.com/test2")
        removed = unsubscribe(sub.sub_id, "other-tenant")
        assert removed is False

    def test_list_by_tenant(self):
        from warden.communities.notifications import subscribe, list_subscriptions
        cid = _cid()
        tid1, tid2 = _tid(), _tid()
        subscribe(cid, tid1, "slack", "https://hooks.slack.com/t1")
        subscribe(cid, tid2, "slack", "https://hooks.slack.com/t2")
        t1_subs = list_subscriptions(cid, tid1)
        assert all(s.tenant_id == tid1 for s in t1_subs)

    def test_set_active_toggle(self):
        from warden.communities.notifications import subscribe, set_active, list_subscriptions
        cid, tid = _cid(), _tid()
        sub = subscribe(cid, tid, "slack", "https://hooks.slack.com/tog")
        assert sub.active is True
        set_active(sub.sub_id, tid, False)
        subs = list_subscriptions(cid, tid)
        found = next(s for s in subs if s.sub_id == sub.sub_id)
        assert found.active is False

    def test_to_dict_shape(self):
        from warden.communities.notifications import subscribe
        sub = subscribe(_cid(), _tid(), "email", "test@example.com")
        d = sub.to_dict()
        assert all(k in d for k in ("sub_id", "community_id", "tenant_id", "channel", "target", "events", "active"))


class TestFireEvent:
    @pytest.mark.asyncio
    async def test_fire_no_subs(self):
        from warden.communities.notifications import fire_event
        sent = await fire_event(_cid(), "member_joined", {"display_name": "Alice"})
        assert sent == 0

    @pytest.mark.asyncio
    async def test_fire_inactive_sub_skipped(self):
        from warden.communities.notifications import subscribe, set_active, fire_event
        cid, tid = _cid(), _tid()
        sub = subscribe(cid, tid, "slack", "https://hooks.slack.com/inactive")
        set_active(sub.sub_id, tid, False)
        sent = await fire_event(cid, "member_joined", {"display_name": "Bob"})
        assert sent == 0

    @pytest.mark.asyncio
    async def test_fire_event_not_in_sub_events(self):
        from warden.communities.notifications import subscribe, fire_event
        cid, tid = _cid(), _tid()
        subscribe(cid, tid, "slack", "https://hooks.slack.com/limited",
                  events=["compliance_changed"])
        sent = await fire_event(cid, "member_joined", {"display_name": "Carol"})
        assert sent == 0

    @pytest.mark.asyncio
    async def test_fire_invalid_event_type(self):
        from warden.communities.notifications import fire_event
        sent = await fire_event(_cid(), "nonexistent_event", {})
        assert sent == 0

    @pytest.mark.asyncio
    async def test_fire_counts_active_subs(self, monkeypatch):
        from warden.communities import notifications as notif
        cid, tid = _cid(), _tid()

        async def _fake_dispatch(sub, event_type, payload, community_name):
            pass

        monkeypatch.setattr(notif, "_dispatch", _fake_dispatch)
        notif.subscribe(cid, tid, "slack", "https://hooks.slack.com/a1")
        notif.subscribe(cid, tid, "teams", "https://outlook.office.com/w1")
        sent = await notif.fire_event(cid, "member_joined", {"display_name": "Dave"})
        assert sent == 2


class TestBuildSummary:
    def test_member_joined(self):
        from warden.communities.notifications import _build_summary
        s = _build_summary("member_joined", {"display_name": "Alice", "role": "admin"})
        assert "Alice" in s and "admin" in s

    def test_transfer_completed(self):
        from warden.communities.notifications import _build_summary
        s = _build_summary("transfer_completed", {
            "ueciid": "SEP-abc123", "target_community_id": "comm-xyz",
            "status": "completed", "risk_score": 0.15,
        })
        assert "SEP-abc123" in s and "0.15" in s

    def test_compliance_changed(self):
        from warden.communities.notifications import _build_summary
        s = _build_summary("compliance_changed", {"old_score": 65, "new_score": 82, "status": "COMPLIANT"})
        assert "65" in s and "82" in s

    def test_evolution_published(self):
        from warden.communities.notifications import _build_summary
        s = _build_summary("evolution_published", {"title": "inject-v2", "threat_score": 0.88})
        assert "inject-v2" in s and "0.88" in s


# ── API endpoints ─────────────────────────────────────────────────────────────

@pytest.fixture
def client():
    from warden.main import app
    return TestClient(app)


class TestNotificationAPI:
    def test_subscribe_slack_201(self, client):
        cid, tid = _cid(), _tid()
        r = client.post(f"/communities/{cid}/notifications/subscribe", json={
            "tenant_id": tid,
            "channel":   "slack",
            "target":    "https://hooks.slack.com/api-test",
            "label":     "API Test",
        })
        assert r.status_code == 201
        data = r.json()
        assert data["channel"] == "slack"
        assert data["community_id"] == cid

    def test_subscribe_invalid_channel_400(self, client):
        r = client.post(f"/communities/{_cid()}/notifications/subscribe", json={
            "tenant_id": _tid(), "channel": "discord",
            "target": "https://discord.com/webhook",
        })
        assert r.status_code in (400, 422)

    def test_list_subscriptions(self, client):
        cid, tid = _cid(), _tid()
        client.post(f"/communities/{cid}/notifications/subscribe", json={
            "tenant_id": tid, "channel": "email",
            "target": "ops@example.com", "label": "Ops",
        })
        r = client.get(f"/communities/{cid}/notifications/subscriptions?tenant_id={tid}")
        assert r.status_code == 200
        assert any(s["target"] == "ops@example.com" for s in r.json())

    def test_delete_subscription(self, client):
        cid, tid = _cid(), _tid()
        r = client.post(f"/communities/{cid}/notifications/subscribe", json={
            "tenant_id": tid, "channel": "teams",
            "target": "https://outlook.office.com/webhook/del-test",
        })
        sub_id = r.json()["sub_id"]
        r2 = client.delete(f"/communities/{cid}/notifications/{sub_id}?tenant_id={tid}")
        assert r2.status_code == 204

    def test_delete_wrong_tenant_404(self, client):
        cid, tid = _cid(), _tid()
        r = client.post(f"/communities/{cid}/notifications/subscribe", json={
            "tenant_id": tid, "channel": "slack",
            "target": "https://hooks.slack.com/perm-test",
        })
        sub_id = r.json()["sub_id"]
        r2 = client.delete(f"/communities/{cid}/notifications/{sub_id}?tenant_id=wrong-tenant")
        assert r2.status_code == 404

    def test_test_endpoint(self, client):
        cid, tid = _cid(), _tid()
        r = client.post(f"/communities/{cid}/notifications/test", json={
            "tenant_id": tid, "event_type": "member_joined",
        })
        assert r.status_code == 200
        assert r.json()["event_type"] == "member_joined"

    def test_test_invalid_event_400(self, client):
        r = client.post(f"/communities/{_cid()}/notifications/test", json={
            "tenant_id": _tid(), "event_type": "fake_event",
        })
        assert r.status_code == 400

    def test_patch_active(self, client):
        cid, tid = _cid(), _tid()
        r = client.post(f"/communities/{cid}/notifications/subscribe", json={
            "tenant_id": tid, "channel": "slack",
            "target": "https://hooks.slack.com/patch-test",
        })
        sub_id = r.json()["sub_id"]
        r2 = client.patch(
            f"/communities/{cid}/notifications/{sub_id}?tenant_id={tid}",
            json={"active": False},
        )
        assert r2.status_code == 200
        assert r2.json()["active"] is False
