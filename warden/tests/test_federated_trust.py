"""Tests for FederatedTrustRegistry — cross-community threat intel (SEC-06)."""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _reset_sep_db(tmp_path, monkeypatch):
    """Isolate SEP DB for each test."""
    db_path = str(tmp_path / "sep.db")
    monkeypatch.setenv("SEP_DB_PATH", db_path)
    import warden.communities.peering as _peering
    monkeypatch.setattr(_peering, "_SEP_DB_PATH", db_path)
    yield


class TestShareFlag:
    def test_flag_shared_creates_record(self):
        from warden.communities.peering import FederatedTrustRegistry
        result = FederatedTrustRegistry.share_flag(
            agent_did="did:shadow:agent-bad",
            flag_type="COLLUSION",
            source_community="comm-A",
        )
        assert "flag_id" in result
        assert isinstance(result["shared_to"], int)

    def test_flagged_agent_appears_in_deny_list(self):
        from warden.communities.peering import FederatedTrustRegistry
        FederatedTrustRegistry.share_flag("did:shadow:villain", "FRAUD", "comm-B")
        assert FederatedTrustRegistry.check_global_deny("did:shadow:villain")

    def test_unflagged_agent_not_in_deny_list(self):
        from warden.communities.peering import FederatedTrustRegistry
        assert not FederatedTrustRegistry.check_global_deny("did:shadow:innocent")


class TestExpiration:
    def test_flag_expires_after_ttl(self, monkeypatch):
        from warden.communities.peering import FederatedTrustRegistry
        FederatedTrustRegistry.share_flag("did:shadow:temp-bad", "SPAM", "comm-C")

        # Manually expire by backdating
        import sqlite3
        import warden.communities.peering as _peering
        con = sqlite3.connect(_peering._SEP_DB_PATH)
        con.execute(
            "UPDATE fed_trust_flags SET expires_at='2000-01-01T00:00:00+00:00' WHERE agent_did='did:shadow:temp-bad'"
        )
        con.commit()
        con.close()

        removed = FederatedTrustRegistry.expire_flags()
        assert removed >= 1
        # Should no longer be in the deny list
        assert not FederatedTrustRegistry.check_global_deny("did:shadow:temp-bad")
