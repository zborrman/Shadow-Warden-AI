"""
warden/tests/test_onboarding.py
────────────────────────────────
Unit tests for OnboardingEngine — SMB tenant provisioning.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from warden.onboarding import PLANS, OnboardingEngine, TenantSetupKit


@pytest.fixture
def engine(tmp_path: Path) -> OnboardingEngine:
    return OnboardingEngine(
        gateway_url="https://ai.example.com",
        keys_path=tmp_path / "api_keys.json",
    )


# ── create_tenant ─────────────────────────────────────────────────────────────

class TestCreateTenant:
    def test_returns_setup_kit(self, engine: OnboardingEngine) -> None:
        kit = engine.create_tenant("Acme Dental", "admin@acme.com", plan="pro")
        assert isinstance(kit, TenantSetupKit)
        assert kit.tenant_id == "acme-dental"
        assert kit.plan == "pro"
        assert len(kit.api_key) == 64   # 32 bytes hex

    def test_slug_normalises_company_name(self, engine: OnboardingEngine) -> None:
        kit = engine.create_tenant("  Blue Sky Labs GmbH  ", "x@x.com")
        assert kit.tenant_id == "blue-sky-labs-gmbh"

    def test_slug_max_length(self, engine: OnboardingEngine) -> None:
        long_name = "A" * 100
        kit = engine.create_tenant(long_name, "x@x.com")
        assert len(kit.tenant_id) <= 40

    def test_plan_quota_assigned(self, engine: OnboardingEngine) -> None:
        kit = engine.create_tenant("Co A", "a@a.com", plan="free")
        assert kit.quota_usd == PLANS["free"]["quota_usd"]

    def test_custom_quota_overrides_plan(self, engine: OnboardingEngine) -> None:
        kit = engine.create_tenant("Co B", "b@b.com", plan="free", custom_quota_usd=99.99)
        assert kit.quota_usd == 99.99

    def test_openai_base_url_set(self, engine: OnboardingEngine) -> None:
        kit = engine.create_tenant("Co C", "c@c.com")
        assert kit.openai_base_url == "https://ai.example.com/v1"

    def test_env_template_contains_key(self, engine: OnboardingEngine) -> None:
        kit = engine.create_tenant("Co D", "d@d.com")
        assert kit.api_key in kit.env_template
        assert "OPENAI_BASE_URL" in kit.env_template

    def test_curl_test_contains_key(self, engine: OnboardingEngine) -> None:
        kit = engine.create_tenant("Co E", "e@e.com")
        assert kit.api_key in kit.curl_test

    def test_duplicate_company_raises(self, engine: OnboardingEngine) -> None:
        engine.create_tenant("Dupe Corp", "x@x.com")
        with pytest.raises(ValueError, match="already exists"):
            engine.create_tenant("Dupe Corp", "y@y.com")

    def test_short_name_raises(self, engine: OnboardingEngine) -> None:
        with pytest.raises(ValueError, match="at least 2"):
            engine.create_tenant("X", "x@x.com")

    def test_unknown_plan_raises(self, engine: OnboardingEngine) -> None:
        with pytest.raises(ValueError, match="Unknown plan"):
            engine.create_tenant("Co F", "f@f.com", plan="enterprise")

    def test_key_written_to_file(self, engine: OnboardingEngine, tmp_path: Path) -> None:
        engine.create_tenant("Co G", "g@g.com")
        keys_path = tmp_path / "api_keys.json"
        assert keys_path.exists()
        import json
        data = json.loads(keys_path.read_text())
        assert len(data["keys"]) == 1
        assert data["keys"][0]["tenant_id"] == "co-g"

    def test_key_hash_not_equal_to_raw_key(self, engine: OnboardingEngine) -> None:
        import hashlib
        import json
        kit = engine.create_tenant("Co H", "h@h.com")
        keys_path = engine._keys_path
        data = json.loads(keys_path.read_text())
        stored_hash = data["keys"][0]["key_hash"]
        expected = hashlib.sha256(kit.api_key.encode()).hexdigest()
        assert stored_hash == expected
        assert stored_hash != kit.api_key

    def test_telegram_chat_id_stored(self, engine: OnboardingEngine) -> None:
        engine.create_tenant("Co I", "i@i.com", telegram_chat_id="-123456")
        assert engine.get_telegram_chat_id("co-i") == "-123456"


# ── get_tenant / list_tenants ─────────────────────────────────────────────────

class TestGetListTenants:
    def test_get_existing_tenant(self, engine: OnboardingEngine) -> None:
        engine.create_tenant("Foo Inc", "foo@foo.com")
        t = engine.get_tenant("foo-inc")
        assert t is not None
        assert t["tenant_id"] == "foo-inc"
        assert "key_hash" not in t

    def test_get_nonexistent_returns_none(self, engine: OnboardingEngine) -> None:
        assert engine.get_tenant("nobody") is None

    def test_list_tenants_returns_all(self, engine: OnboardingEngine) -> None:
        engine.create_tenant("A Corp", "a@a.com")
        engine.create_tenant("B Corp", "b@b.com")
        tenants = engine.list_tenants()
        assert len(tenants) == 2
        ids = {t["tenant_id"] for t in tenants}
        assert ids == {"a-corp", "b-corp"}

    def test_list_excludes_key_hashes(self, engine: OnboardingEngine) -> None:
        engine.create_tenant("Z Corp", "z@z.com")
        for t in engine.list_tenants():
            assert "key_hash" not in t


# ── deactivate / reactivate ────────────────────────────────────────────────────

class TestActivation:
    def test_deactivate_returns_true(self, engine: OnboardingEngine) -> None:
        engine.create_tenant("Alpha", "a@a.com")
        assert engine.deactivate_tenant("alpha") is True

    def test_deactivate_sets_active_false(self, engine: OnboardingEngine) -> None:
        engine.create_tenant("Beta", "b@b.com")
        engine.deactivate_tenant("beta")
        t = engine.get_tenant("beta")
        assert t["active"] is False

    def test_reactivate(self, engine: OnboardingEngine) -> None:
        engine.create_tenant("Gamma", "g@g.com")
        engine.deactivate_tenant("gamma")
        engine.reactivate_tenant("gamma")
        t = engine.get_tenant("gamma")
        assert t["active"] is True

    def test_deactivate_unknown_returns_false(self, engine: OnboardingEngine) -> None:
        assert engine.deactivate_tenant("nobody") is False


# ── rotate_key ────────────────────────────────────────────────────────────────

class TestRotateKey:
    def test_rotate_returns_new_key(self, engine: OnboardingEngine) -> None:
        kit = engine.create_tenant("Pivot Inc", "p@p.com")
        new_key = engine.rotate_key("pivot-inc")
        assert new_key is not None
        assert len(new_key) == 64
        assert new_key != kit.api_key

    def test_rotate_updates_hash(self, engine: OnboardingEngine) -> None:
        import hashlib
        import json
        engine.create_tenant("Hash Co", "h@h.com")
        new_key = engine.rotate_key("hash-co")
        data = json.loads(engine._keys_path.read_text())
        stored = data["keys"][0]["key_hash"]
        assert stored == hashlib.sha256(new_key.encode()).hexdigest()

    def test_rotate_unknown_returns_none(self, engine: OnboardingEngine) -> None:
        assert engine.rotate_key("nobody") is None

    def test_rotated_at_updated(self, engine: OnboardingEngine) -> None:
        import json
        engine.create_tenant("Time Co", "t@t.com")
        engine.rotate_key("time-co")
        data = json.loads(engine._keys_path.read_text())
        assert data["keys"][0]["rotated_at"] is not None


# ── update_telegram ────────────────────────────────────────────────────────────

class TestTelegram:
    def test_set_and_get_chat_id(self, engine: OnboardingEngine) -> None:
        engine.create_tenant("TG Corp", "tg@tg.com")
        engine.update_telegram("tg-corp", "-999888")
        assert engine.get_telegram_chat_id("tg-corp") == "-999888"

    def test_clear_chat_id(self, engine: OnboardingEngine) -> None:
        engine.create_tenant("TG2 Corp", "tg2@tg.com", telegram_chat_id="-111")
        engine.update_telegram("tg2-corp", None)
        assert engine.get_telegram_chat_id("tg2-corp") is None

    def test_unknown_tenant_returns_none(self, engine: OnboardingEngine) -> None:
        assert engine.get_telegram_chat_id("nobody") is None

    def test_update_unknown_returns_false(self, engine: OnboardingEngine) -> None:
        assert engine.update_telegram("nobody", "-123") is False
