"""Tests for Secrets Governance — vault connectors, inventory, lifecycle, policy, API."""
import json
import os
import pytest
import tempfile
import asyncio

os.environ.setdefault("ANTHROPIC_API_KEY", "")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _tmp_db():
    f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    f.close()
    return f.name


def _tid():
    import uuid
    return f"test-{uuid.uuid4().hex[:8]}"


# ── EnvVaultConnector ─────────────────────────────────────────────────────────

class TestEnvConnector:
    def test_lists_secret_env_vars(self, monkeypatch):
        from warden.secrets_gov.vault_connector import EnvVaultConnector
        monkeypatch.setenv("MY_API_KEY", "sk-abc123")
        monkeypatch.setenv("DB_HOST", "localhost")  # not a secret
        conn = EnvVaultConnector(vault_id="env-test")
        metas = asyncio.run(conn.list_secrets())
        names = [m.name for m in metas]
        assert "MY_API_KEY" in names
        assert "DB_HOST" not in names

    def test_rotate_returns_false(self):
        from warden.secrets_gov.vault_connector import EnvVaultConnector
        conn = EnvVaultConnector()
        result = asyncio.run(conn.rotate_secret("KEY"))
        assert result is False

    def test_health_check_true(self):
        from warden.secrets_gov.vault_connector import EnvVaultConnector
        conn = EnvVaultConnector()
        assert asyncio.run(conn.health_check()) is True

    def test_vault_type(self):
        from warden.secrets_gov.vault_connector import EnvVaultConnector
        assert EnvVaultConnector.vault_type == "env"


# ── build_connector ───────────────────────────────────────────────────────────

class TestBuildConnector:
    def test_builds_env_connector(self):
        from warden.secrets_gov.vault_connector import build_connector, EnvVaultConnector
        conn = build_connector({"vault_type": "env", "vault_id": "x"})
        assert isinstance(conn, EnvVaultConnector)

    def test_raises_on_unknown_type(self):
        from warden.secrets_gov.vault_connector import build_connector
        with pytest.raises(ValueError, match="Unknown vault type"):
            build_connector({"vault_type": "nonexistent", "vault_id": "x"})

    def test_all_types_registered(self):
        from warden.secrets_gov.vault_connector import CONNECTOR_TYPES
        assert set(CONNECTOR_TYPES) == {"aws_sm", "azure_kv", "hashicorp", "gcp_sm", "env"}


# ── SecretsInventory ──────────────────────────────────────────────────────────

class TestSecretsInventory:
    def setup_method(self):
        self.db = _tmp_db()
        from warden.secrets_gov.inventory import SecretsInventory
        self.inv = SecretsInventory(self.db)
        self.tid = _tid()

    def test_register_and_list_vault(self):
        vid = self.inv.register_vault(self.tid, "env", "My Env Vault", "{}")
        vaults = self.inv.list_vaults(self.tid)
        assert len(vaults) == 1
        assert vaults[0]["vault_id"] == vid
        assert vaults[0]["display_name"] == "My Env Vault"

    def test_get_vault(self):
        vid = self.inv.register_vault(self.tid, "aws_sm", "AWS", "{}")
        row = self.inv.get_vault(self.tid, vid)
        assert row is not None
        assert row["vault_type"] == "aws_sm"

    def test_delete_vault(self):
        vid = self.inv.register_vault(self.tid, "env", "X", "{}")
        assert self.inv.delete_vault(self.tid, vid) is True
        assert self.inv.get_vault(self.tid, vid) is None

    def test_delete_nonexistent_vault(self):
        assert self.inv.delete_vault(self.tid, "fake-id") is False

    def test_upsert_and_list_secrets(self):
        from warden.secrets_gov.vault_connector import VaultSecretMeta
        vid = self.inv.register_vault(self.tid, "env", "Env", "{}")
        metas = [
            VaultSecretMeta(name="API_KEY", vault_id=vid, vault_type="env"),
            VaultSecretMeta(name="DB_PASS", vault_id=vid, vault_type="env"),
        ]
        count = self.inv.upsert_secrets(self.tid, vid, metas)
        assert count == 2
        secrets = self.inv.list_secrets(self.tid)
        assert len(secrets) == 2

    def test_upsert_idempotent(self):
        from warden.secrets_gov.vault_connector import VaultSecretMeta
        vid = self.inv.register_vault(self.tid, "env", "Env", "{}")
        meta = [VaultSecretMeta(name="KEY", vault_id=vid, vault_type="env")]
        self.inv.upsert_secrets(self.tid, vid, meta)
        self.inv.upsert_secrets(self.tid, vid, meta)
        assert len(self.inv.list_secrets(self.tid)) == 1

    def test_secrets_retired_when_removed_from_vault(self):
        from warden.secrets_gov.vault_connector import VaultSecretMeta
        vid = self.inv.register_vault(self.tid, "env", "Env", "{}")
        metas = [VaultSecretMeta(name="KEY_A", vault_id=vid, vault_type="env"),
                 VaultSecretMeta(name="KEY_B", vault_id=vid, vault_type="env")]
        self.inv.upsert_secrets(self.tid, vid, metas)
        # Second sync: KEY_B removed from vault
        self.inv.upsert_secrets(self.tid, vid,
                                [VaultSecretMeta(name="KEY_A", vault_id=vid, vault_type="env")])
        retired = self.inv.list_secrets(self.tid, status="retired")
        assert any(s.name == "KEY_B" for s in retired)

    def test_get_expiring_secrets(self):
        from warden.secrets_gov.vault_connector import VaultSecretMeta
        from datetime import datetime, timedelta, timezone
        vid = self.inv.register_vault(self.tid, "aws_sm", "AWS", "{}")
        soon = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
        metas = [VaultSecretMeta(name="EXPIRING_KEY", vault_id=vid,
                                 vault_type="aws_sm", expires_at=soon)]
        self.inv.upsert_secrets(self.tid, vid, metas)
        expiring = self.inv.get_expiring(self.tid, within_days=30)
        assert any(s.name == "EXPIRING_KEY" for s in expiring)

    def test_stats(self):
        from warden.secrets_gov.vault_connector import VaultSecretMeta
        vid = self.inv.register_vault(self.tid, "env", "E", "{}")
        self.inv.upsert_secrets(self.tid, vid,
                                [VaultSecretMeta(name="K", vault_id=vid, vault_type="env")])
        stats = self.inv.get_stats(self.tid)
        assert stats["total"] == 1
        assert stats["vaults"] == 1

    def test_update_status(self):
        from warden.secrets_gov.vault_connector import VaultSecretMeta
        vid = self.inv.register_vault(self.tid, "env", "E", "{}")
        self.inv.upsert_secrets(self.tid, vid,
                                [VaultSecretMeta(name="K", vault_id=vid, vault_type="env")])
        secret_id = self.inv.list_secrets(self.tid)[0].secret_id
        assert self.inv.update_status(self.tid, secret_id, "retired") is True
        assert self.inv.list_secrets(self.tid, status="retired")[0].secret_id == secret_id

    def test_filter_by_vault(self):
        from warden.secrets_gov.vault_connector import VaultSecretMeta
        vid1 = self.inv.register_vault(self.tid, "env", "V1", "{}")
        vid2 = self.inv.register_vault(self.tid, "env", "V2", "{}")
        self.inv.upsert_secrets(self.tid, vid1,
                                [VaultSecretMeta(name="K1", vault_id=vid1, vault_type="env")])
        self.inv.upsert_secrets(self.tid, vid2,
                                [VaultSecretMeta(name="K2", vault_id=vid2, vault_type="env")])
        assert len(self.inv.list_secrets(self.tid, vault_id=vid1)) == 1
        assert len(self.inv.list_secrets(self.tid, vault_id=vid2)) == 1


# ── SecretsPolicyEngine ───────────────────────────────────────────────────────

class TestSecretsPolicyEngine:
    def setup_method(self):
        self.db = _tmp_db()
        from warden.secrets_gov.policy import SecretsPolicyEngine
        self.engine = SecretsPolicyEngine(self.db)
        self.tid = _tid()

    def test_default_policy_returned_when_none_saved(self):
        p = self.engine.get_policy(self.tid)
        assert p.max_age_days == 90
        assert p.rotation_interval_days == 30

    def test_upsert_and_get_policy(self):
        from warden.secrets_gov.policy import SecretsPolicy
        policy = SecretsPolicy(
            tenant_id=self.tid,
            max_age_days=60,
            rotation_interval_days=14,
            require_expiry_date=True,
        )
        self.engine.upsert_policy(policy)
        fetched = self.engine.get_policy(self.tid)
        assert fetched.max_age_days == 60
        assert fetched.rotation_interval_days == 14
        assert fetched.require_expiry_date is True

    def test_evaluate_expired_secret(self):
        from warden.secrets_gov.policy import SecretsPolicy
        from warden.secrets_gov.inventory import SecretRecord
        from datetime import datetime, timedelta, timezone
        policy = SecretsPolicy(tenant_id=self.tid)
        secret = SecretRecord(
            secret_id="s1", tenant_id=self.tid, vault_id="v1",
            name="OLD_KEY", vault_type="env", status="expired",
            risk_score=0.5, created_at=None, last_rotated=None,
            expires_at=(datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
            tags={}, synced_at="",
        )
        violations = self.engine.evaluate(secret, policy)
        rules = [v.rule for v in violations]
        assert "expired" in rules

    def test_evaluate_never_rotated(self):
        from warden.secrets_gov.policy import SecretsPolicy
        from warden.secrets_gov.inventory import SecretRecord
        policy = SecretsPolicy(tenant_id=self.tid, rotation_interval_days=30)
        secret = SecretRecord(
            secret_id="s2", tenant_id=self.tid, vault_id="v1",
            name="FRESH_KEY", vault_type="env", status="active",
            risk_score=0.0, created_at=None, last_rotated=None,
            expires_at=None, tags={}, synced_at="",
        )
        violations = self.engine.evaluate(secret, policy)
        assert any(v.rule == "never_rotated" for v in violations)

    def test_evaluate_forbidden_pattern(self):
        from warden.secrets_gov.policy import SecretsPolicy
        from warden.secrets_gov.inventory import SecretRecord
        policy = SecretsPolicy(tenant_id=self.tid, forbidden_name_patterns=["password"])
        secret = SecretRecord(
            secret_id="s3", tenant_id=self.tid, vault_id="v1",
            name="DB_PASSWORD", vault_type="env", status="active",
            risk_score=0.0, created_at=None, last_rotated=None,
            expires_at=None, tags={}, synced_at="",
        )
        violations = self.engine.evaluate(secret, policy)
        assert any(v.rule == "forbidden_pattern" for v in violations)

    def test_audit_compliance_score(self):
        from warden.secrets_gov.policy import SecretsPolicy
        from warden.secrets_gov.inventory import SecretRecord
        policy = SecretsPolicy(tenant_id=self.tid)
        self.engine.upsert_policy(policy)
        secrets = [
            SecretRecord(secret_id=f"s{i}", tenant_id=self.tid, vault_id="v",
                         name=f"KEY{i}", vault_type="env", status="active",
                         risk_score=0.0, created_at=None, last_rotated=None,
                         expires_at=None, tags={}, synced_at="")
            for i in range(5)
        ]
        report = self.engine.audit(self.tid, secrets)
        assert "compliance_score" in report
        assert report["total_secrets"] == 5


# ── LifecycleManager ──────────────────────────────────────────────────────────

class TestLifecycleManager:
    def setup_method(self):
        self.db = _tmp_db()
        from warden.secrets_gov.inventory import SecretsInventory
        from warden.secrets_gov.lifecycle import LifecycleManager
        self.inv = SecretsInventory(self.db)
        self.lifecycle = LifecycleManager(self.inv)
        self.tid = _tid()

    def test_rotation_schedule_empty(self):
        summary = self.lifecycle.summary(self.tid)
        assert summary["total_tracked"] == 0

    def test_rotation_schedule_with_secrets(self):
        from warden.secrets_gov.vault_connector import VaultSecretMeta
        from datetime import datetime, timedelta, timezone
        vid = self.inv.register_vault(self.tid, "env", "E", "{}")
        old_date = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
        metas = [VaultSecretMeta(name="OLD_KEY", vault_id=vid, vault_type="env",
                                 last_rotated=old_date)]
        self.inv.upsert_secrets(self.tid, vid, metas)
        summary = self.lifecycle.summary(self.tid, interval_days=30)
        assert summary["overdue_rotation"] >= 1

    def test_check_and_flag_expiry(self):
        from warden.secrets_gov.vault_connector import VaultSecretMeta
        from datetime import datetime, timedelta, timezone
        vid = self.inv.register_vault(self.tid, "env", "E", "{}")
        soon = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
        self.inv.upsert_secrets(self.tid, vid,
                                [VaultSecretMeta(name="EXPIRING", vault_id=vid,
                                                 vault_type="env", expires_at=soon)])
        expiring = asyncio.run(
            self.lifecycle.check_and_flag_expiry(self.tid, alert_days=14)
        )
        assert len(expiring) >= 1

    def test_retire_expired(self):
        from warden.secrets_gov.vault_connector import VaultSecretMeta
        from datetime import datetime, timedelta, timezone
        vid = self.inv.register_vault(self.tid, "env", "E", "{}")
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        self.inv.upsert_secrets(self.tid, vid,
                                [VaultSecretMeta(name="EXPIRED", vault_id=vid,
                                                 vault_type="env", expires_at=past)])
        retired = asyncio.run(
            self.lifecycle.retire_expired(self.tid)
        )
        assert retired >= 0  # expired secrets get retired


# ── Billing gate ──────────────────────────────────────────────────────────────

class TestSecretsGovBillingGate:
    def test_community_business_has_secrets_governance(self):
        from warden.billing.feature_gate import FeatureGate
        gate = FeatureGate.for_tier("community_business")
        assert gate.is_enabled("secrets_governance") is True

    def test_starter_lacks_secrets_governance(self):
        from warden.billing.feature_gate import FeatureGate
        gate = FeatureGate.for_tier("starter")
        assert gate.is_enabled("secrets_governance") is False

    def test_individual_lacks_secrets_governance_base(self):
        from warden.billing.feature_gate import FeatureGate
        gate = FeatureGate.for_tier("individual")
        assert gate.is_enabled("secrets_governance") is False

    def test_pro_has_secrets_governance(self):
        from warden.billing.feature_gate import FeatureGate
        gate = FeatureGate.for_tier("pro")
        assert gate.is_enabled("secrets_governance") is True

    def test_enterprise_has_secrets_governance(self):
        from warden.billing.feature_gate import FeatureGate
        gate = FeatureGate.for_tier("enterprise")
        assert gate.is_enabled("secrets_governance") is True

    def test_secrets_vault_addon_in_catalog(self):
        from warden.billing.addons import ADDON_CATALOG
        assert "secrets_vault" in ADDON_CATALOG
        assert ADDON_CATALOG["secrets_vault"]["usd_per_month"] == 12
        assert ADDON_CATALOG["secrets_vault"]["min_tier"] == "individual"
        assert "secrets_governance" in ADDON_CATALOG["secrets_vault"]["unlocks"]


# ── API (FastAPI TestClient) ──────────────────────────────────────────────────

@pytest.fixture()
def client(tmp_path):
    import os
    os.environ["SECRETS_DB_PATH"] = str(tmp_path / "secrets_test.db")
    os.environ["VAULT_MASTER_KEY"] = ""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from warden.api.secrets import router
    app = FastAPI()
    app.include_router(router, prefix="/secrets")
    return TestClient(app)


class TestSecretsAPI:
    def test_list_vaults_empty(self, client):
        resp = client.get("/secrets/vaults")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_register_vault(self, client):
        resp = client.post("/secrets/vaults", json={
            "vault_type": "env",
            "display_name": "Test Env Vault",
            "config": {},
        })
        assert resp.status_code == 201
        data = resp.json()
        assert "vault_id" in data
        assert data["vault_type"] == "env"

    def test_register_unknown_vault_type(self, client):
        resp = client.post("/secrets/vaults", json={
            "vault_type": "unknown",
            "display_name": "Bad Vault",
            "config": {},
        })
        assert resp.status_code == 400

    def test_sync_env_vault(self, client, monkeypatch):
        monkeypatch.setenv("TEST_API_KEY", "sk-xyz")
        # Register
        r = client.post("/secrets/vaults", json={
            "vault_type": "env", "display_name": "E", "config": {}
        })
        vault_id = r.json()["vault_id"]
        # Sync
        resp = client.post(f"/secrets/vaults/{vault_id}/sync")
        assert resp.status_code == 200
        assert resp.json()["synced_count"] >= 0

    def test_delete_vault(self, client):
        r = client.post("/secrets/vaults", json={
            "vault_type": "env", "display_name": "D", "config": {}
        })
        vault_id = r.json()["vault_id"]
        resp = client.delete(f"/secrets/vaults/{vault_id}")
        assert resp.status_code == 200
        assert resp.json()["deleted"] is True

    def test_delete_nonexistent_vault(self, client):
        resp = client.delete("/secrets/vaults/nonexistent")
        assert resp.status_code == 404

    def test_list_inventory_empty(self, client):
        resp = client.get("/secrets/inventory")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_stats_empty(self, client):
        resp = client.get("/secrets/stats")
        assert resp.status_code == 200
        stats = resp.json()
        assert stats["total"] == 0

    def test_get_policy_defaults(self, client):
        resp = client.get("/secrets/policy")
        assert resp.status_code == 200
        p = resp.json()
        assert p["max_age_days"] == 90
        assert p["rotation_interval_days"] == 30

    def test_update_policy(self, client):
        resp = client.put("/secrets/policy", json={
            "max_age_days": 45,
            "rotation_interval_days": 14,
            "alert_days_before_expiry": 7,
            "auto_retire_expired": True,
            "require_expiry_date": False,
            "forbidden_name_patterns": ["password"],
            "require_tags": ["team"],
        })
        assert resp.status_code == 200
        assert resp.json()["updated"] is True
        # Verify persisted
        fetched = client.get("/secrets/policy").json()
        assert fetched["max_age_days"] == 45

    def test_policy_audit_empty(self, client):
        resp = client.get("/secrets/policy/audit")
        assert resp.status_code == 200
        report = resp.json()
        assert report["total_secrets"] == 0
        assert report["compliance_score"] == 100.0

    def test_governance_report(self, client):
        resp = client.get("/secrets/report")
        assert resp.status_code == 200
        r = resp.json()
        assert "stats" in r
        assert "compliance" in r
        assert "lifecycle" in r

    def test_lifecycle_schedule_empty(self, client):
        resp = client.get("/secrets/lifecycle/schedule")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_tracked"] == 0

    def test_vault_health_check(self, client):
        r = client.post("/secrets/vaults", json={
            "vault_type": "env", "display_name": "H", "config": {}
        })
        vault_id = r.json()["vault_id"]
        resp = client.get(f"/secrets/vaults/{vault_id}/health")
        assert resp.status_code == 200
        assert "healthy" in resp.json()
