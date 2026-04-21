"""
Tests for:
  warden/communities/data_pod.py       — Sovereign Data Pods
  warden/communities/stix_audit.py     — STIX 2.1 audit chain
  warden/communities/transfer_guard.py — Causal Transfer Guard
"""
import os
import uuid
import pytest


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Each test gets a fresh SQLite DB and isolated Redis-less env."""
    db = str(tmp_path / "test_sep.db")
    monkeypatch.setenv("SEP_DB_PATH", db)
    monkeypatch.setenv("REDIS_URL", "memory://")
    monkeypatch.setenv("COMMUNITY_VAULT_KEY", "test-vault-key-for-pytest")
    monkeypatch.setenv("TRANSFER_RISK_THRESHOLD", "0.70")
    # Patch module-level path attributes so they pick up the new env var
    import warden.communities.data_pod as dp
    import warden.communities.stix_audit as sa
    monkeypatch.setattr(dp, "_SEP_DB_PATH", db)
    monkeypatch.setattr(sa, "_SEP_DB_PATH", db)
    return db


def _cid():
    return str(uuid.uuid4())


# ══════════════════════════════════════════════════════════════════════════════
# data_pod.py tests
# ══════════════════════════════════════════════════════════════════════════════

class TestDataPod:
    def test_register_and_list(self):
        from warden.communities.data_pod import register_pod, list_pods
        cid = _cid()
        pod = register_pod(cid, jurisdiction="EU",
                           minio_endpoint="https://fsn1.example.com",
                           access_key="AK", secret_key="SK",
                           data_classes=["PII", "PHI"],
                           is_primary=True)
        assert pod.pod_id
        assert pod.jurisdiction == "EU"
        assert pod.status == "ACTIVE"
        assert pod.is_primary is True
        assert "PII" in pod.data_classes

        pods = list_pods(cid)
        assert len(pods) == 1
        assert pods[0].pod_id == pod.pod_id

    def test_register_default_values(self):
        from warden.communities.data_pod import register_pod
        cid = _cid()
        pod = register_pod(cid, jurisdiction="US",
                           minio_endpoint="https://us.example.com")
        assert pod.minio_region == "eu-central-1"
        assert pod.bucket == "warden-evidence"
        assert pod.data_classes == ["GENERAL"]
        assert pod.is_primary is False

    def test_list_empty(self):
        from warden.communities.data_pod import list_pods
        assert list_pods(_cid()) == []

    def test_get_pod(self):
        from warden.communities.data_pod import register_pod, get_pod
        cid = _cid()
        pod = register_pod(cid, jurisdiction="UK",
                           minio_endpoint="https://uk.example.com")
        fetched = get_pod(pod.pod_id)
        assert fetched is not None
        assert fetched.jurisdiction == "UK"

    def test_get_pod_missing(self):
        from warden.communities.data_pod import get_pod
        assert get_pod("nonexistent-pod-id") is None

    def test_decommission_pod(self):
        from warden.communities.data_pod import register_pod, decommission_pod, get_pod
        cid = _cid()
        pod = register_pod(cid, jurisdiction="CA",
                           minio_endpoint="https://ca.example.com")
        result = decommission_pod(pod.pod_id)
        assert result is True
        fetched = get_pod(pod.pod_id)
        assert fetched is None or fetched.status == "SUSPENDED"

    def test_decommission_nonexistent(self):
        from warden.communities.data_pod import decommission_pod
        result = decommission_pod("does-not-exist")
        assert result is False

    def test_get_pod_for_entity_primary(self):
        from warden.communities.data_pod import register_pod, get_pod_for_entity
        cid = _cid()
        register_pod(cid, jurisdiction="EU",
                     minio_endpoint="https://eu.example.com",
                     is_primary=True)
        pod = get_pod_for_entity(cid, entity_id=str(uuid.uuid4()), jurisdiction="EU")
        assert pod is not None
        assert pod.jurisdiction == "EU"

    def test_get_pod_for_entity_no_match(self):
        from warden.communities.data_pod import get_pod_for_entity
        result = get_pod_for_entity(_cid(), entity_id=str(uuid.uuid4()), jurisdiction="SG")
        assert result is None

    def test_get_pod_for_entity_fallback_to_primary(self):
        from warden.communities.data_pod import register_pod, get_pod_for_entity
        cid = _cid()
        # Only an EU primary pod, but asking for US
        register_pod(cid, jurisdiction="EU",
                     minio_endpoint="https://eu.example.com",
                     is_primary=True)
        pod = get_pod_for_entity(cid, entity_id=str(uuid.uuid4()), jurisdiction="US")
        # Should fall back to EU primary
        assert pod is not None

    def test_secret_key_encrypted(self):
        from warden.communities.data_pod import register_pod, get_pod
        cid = _cid()
        pod = register_pod(cid, jurisdiction="JP",
                           minio_endpoint="https://jp.example.com",
                           secret_key="my-secret-key-123")
        fetched = get_pod(pod.pod_id)
        # The stored secret_key_enc should not equal the plaintext
        assert fetched.secret_key_enc != "my-secret-key-123"
        assert fetched.secret_key_enc != ""

    def test_probe_pod_unreachable(self):
        from warden.communities.data_pod import register_pod, probe_pod
        cid = _cid()
        pod = register_pod(cid, jurisdiction="AU",
                           minio_endpoint="https://nonexistent.invalid")
        result = probe_pod(pod.pod_id)
        assert isinstance(result, dict)
        assert "status" in result
        # Should fail gracefully (not raise)

    def test_multiple_pods_same_community(self):
        from warden.communities.data_pod import register_pod, list_pods
        cid = _cid()
        register_pod(cid, jurisdiction="EU",
                     minio_endpoint="https://eu1.example.com")
        register_pod(cid, jurisdiction="EU",
                     minio_endpoint="https://eu2.example.com")
        pods = list_pods(cid)
        assert len(pods) == 2

    def test_get_pod_for_entity_data_class_match(self):
        from warden.communities.data_pod import register_pod, get_pod_for_entity
        cid = _cid()
        register_pod(cid, jurisdiction="EU",
                     minio_endpoint="https://eu.example.com",
                     data_classes=["PHI"], is_primary=False)
        pod = get_pod_for_entity(cid, entity_id=str(uuid.uuid4()),
                                 jurisdiction="EU", data_class="PHI")
        assert pod is not None


# ══════════════════════════════════════════════════════════════════════════════
# stix_audit.py tests
# ══════════════════════════════════════════════════════════════════════════════

class TestStixAudit:
    def _transfer_kwargs(self, src=None, tgt=None, tid=None):
        return dict(
            transfer_id         = tid or str(uuid.uuid4()),
            source_community_id = src or _cid(),
            target_community_id = tgt or _cid(),
            entity_ueciid       = "SEP-abc123def45",
            initiator_mid       = "member-001",
            purpose             = "forensic audit",
            ctp_hmac_signature  = "deadbeef" * 8,
        )

    def test_append_genesis(self):
        from warden.communities.stix_audit import append_transfer, get_chain
        kwargs = self._transfer_kwargs()
        entry = append_transfer(**kwargs)
        assert entry.seq == 0
        assert entry.prev_hash == "0" * 64
        assert entry.bundle_hash

    def test_chain_links(self):
        from warden.communities.stix_audit import append_transfer
        src = _cid()
        tgt = _cid()
        e0 = append_transfer(**self._transfer_kwargs(src=src, tgt=tgt))
        e1 = append_transfer(**self._transfer_kwargs(src=src, tgt=tgt))
        assert e1.seq == 1
        assert e1.prev_hash == e0.bundle_hash

    def test_get_chain_ordered(self):
        from warden.communities.stix_audit import append_transfer, get_chain
        src = _cid()
        tgt = _cid()
        for _ in range(3):
            append_transfer(**self._transfer_kwargs(src=src, tgt=tgt))
        chain = get_chain(src)
        assert len(chain) == 3
        seqs = [e.seq for e in chain]
        assert seqs == sorted(seqs)

    def test_get_chain_empty(self):
        from warden.communities.stix_audit import get_chain
        assert get_chain(_cid()) == []

    def test_verify_chain_valid(self):
        from warden.communities.stix_audit import append_transfer, verify_chain
        src = _cid()
        tgt = _cid()
        for _ in range(3):
            append_transfer(**self._transfer_kwargs(src=src, tgt=tgt))
        result = verify_chain(src)
        assert result["valid"] is True
        assert result["entries"] == 3

    def test_verify_chain_empty(self):
        from warden.communities.stix_audit import verify_chain
        result = verify_chain(_cid())
        assert result["valid"] is True
        assert result["entries"] == 0

    def test_export_chain_jsonl(self):
        from warden.communities.stix_audit import append_transfer, export_chain_jsonl
        import json
        src = _cid()
        tgt = _cid()
        for _ in range(2):
            append_transfer(**self._transfer_kwargs(src=src, tgt=tgt))
        jsonl = export_chain_jsonl(src)
        lines = jsonl.strip().split("\n")
        assert len(lines) == 2
        bundle = json.loads(lines[0])
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"

    def test_export_chain_empty(self):
        from warden.communities.stix_audit import export_chain_jsonl
        assert export_chain_jsonl(_cid()) == ""

    def test_separate_communities_independent_chains(self):
        from warden.communities.stix_audit import append_transfer, get_chain
        src1, src2, tgt = _cid(), _cid(), _cid()
        append_transfer(**self._transfer_kwargs(src=src1, tgt=tgt))
        append_transfer(**self._transfer_kwargs(src=src1, tgt=tgt))
        append_transfer(**self._transfer_kwargs(src=src2, tgt=tgt))
        assert len(get_chain(src1)) == 2
        assert len(get_chain(src2)) == 1
        # src2's first entry should also be genesis
        e = get_chain(src2)[0]
        assert e.seq == 0
        assert e.prev_hash == "0" * 64

    def test_with_pqc_and_risk_score(self):
        from warden.communities.stix_audit import append_transfer, verify_chain
        src = _cid()
        entry = append_transfer(
            **self._transfer_kwargs(src=src),
            pqc_signature="pqc-sig-base64==",
            risk_score=0.45,
            data_class="PHI",
        )
        assert entry.bundle["objects"][2]["extensions"]["x-sep-proof"]["pqc_signature"] == "pqc-sig-base64=="
        assert entry.bundle["objects"][2]["extensions"]["x-sep-proof"]["risk_score"] == 0.45
        result = verify_chain(src)
        assert result["valid"] is True

    def test_bundle_contains_four_stix_objects(self):
        from warden.communities.stix_audit import append_transfer
        entry = append_transfer(**self._transfer_kwargs())
        objects = entry.bundle["objects"]
        types = [o["type"] for o in objects]
        assert "identity" in types
        assert "relationship" in types
        assert "note" in types
        assert len(objects) == 4

    def test_chain_extension_present(self):
        from warden.communities.stix_audit import append_transfer
        src = _cid()
        entry = append_transfer(**self._transfer_kwargs(src=src))
        x_chain = entry.bundle["extensions"]["x-chain"]
        assert x_chain["community_id"] == src
        assert x_chain["seq"] == 0
        assert x_chain["prev_hash"] == "0" * 64


# ══════════════════════════════════════════════════════════════════════════════
# transfer_guard.py tests
# ══════════════════════════════════════════════════════════════════════════════

class TestTransferGuard:
    def test_allow_low_risk(self):
        from warden.communities.transfer_guard import evaluate_transfer_risk
        decision = evaluate_transfer_risk(
            source_community_id = _cid(),
            target_community_id = _cid(),
            peering_id          = str(uuid.uuid4()),
            entity_id           = str(uuid.uuid4()),
            data_class          = "GENERAL",
            peering_policy      = "MIRROR_ONLY",
            peering_age_days    = 180.0,
        )
        assert decision.allowed is True
        assert decision.score < 0.70
        assert isinstance(decision.latency_ms, float)
        assert isinstance(decision.detail, dict)

    def test_block_classified_data(self, monkeypatch):
        import warden.communities.transfer_guard as tg
        from warden.communities.transfer_guard import evaluate_transfer_risk
        monkeypatch.setattr(tg, "_RISK_THRESHOLD", 0.50)

        decision = evaluate_transfer_risk(
            source_community_id = _cid(),
            target_community_id = _cid(),
            peering_id          = str(uuid.uuid4()),
            entity_id           = str(uuid.uuid4()),
            data_class          = "CLASSIFIED",
            peering_policy      = "FULL_SYNC",
            peering_age_days    = 1.0,  # very new peering
        )
        # CLASSIFIED with FULL_SYNC on a 1-day peering produces elevated risk
        assert decision.score > 0.30

    def test_detail_keys_present(self):
        from warden.communities.transfer_guard import evaluate_transfer_risk
        decision = evaluate_transfer_risk(
            source_community_id = _cid(),
            target_community_id = _cid(),
            peering_id          = str(uuid.uuid4()),
            entity_id           = str(uuid.uuid4()),
        )
        required_keys = {
            "ml_score", "ers_score", "obfuscation_detected",
            "block_history", "tool_tier", "content_entropy", "se_risk",
        }
        assert required_keys.issubset(decision.detail.keys())

    def test_data_class_risk_ordering(self):
        from warden.communities.transfer_guard import evaluate_transfer_risk
        scores = {}
        for dc in ["GENERAL", "PII", "FINANCIAL", "PHI", "CLASSIFIED"]:
            d = evaluate_transfer_risk(
                source_community_id = _cid(),
                target_community_id = _cid(),
                peering_id          = str(uuid.uuid4()),
                entity_id           = str(uuid.uuid4()),
                data_class          = dc,
                peering_policy      = "MIRROR_ONLY",
                peering_age_days    = 365.0,
            )
            scores[dc] = d.score
        assert scores["CLASSIFIED"] > scores["GENERAL"]
        assert scores["PHI"] > scores["PII"]

    def test_policy_tier_affects_score(self):
        from warden.communities.transfer_guard import evaluate_transfer_risk
        src, tgt = _cid(), _cid()
        d_mirror = evaluate_transfer_risk(
            source_community_id=src, target_community_id=tgt,
            peering_id=str(uuid.uuid4()), entity_id=str(uuid.uuid4()),
            data_class="PII", peering_policy="MIRROR_ONLY", peering_age_days=30,
        )
        d_full = evaluate_transfer_risk(
            source_community_id=src, target_community_id=tgt,
            peering_id=str(uuid.uuid4()), entity_id=str(uuid.uuid4()),
            data_class="PII", peering_policy="FULL_SYNC", peering_age_days=1,
        )
        # FULL_SYNC on a new peering should be higher risk
        assert d_full.score >= d_mirror.score

    def test_no_redis_still_works(self, monkeypatch):
        monkeypatch.setenv("REDIS_URL", "memory://")
        from warden.communities.transfer_guard import evaluate_transfer_risk
        decision = evaluate_transfer_risk(
            source_community_id=_cid(), target_community_id=_cid(),
            peering_id=str(uuid.uuid4()), entity_id=str(uuid.uuid4()),
        )
        assert isinstance(decision.allowed, bool)

    def test_decision_has_reason(self):
        from warden.communities.transfer_guard import evaluate_transfer_risk
        decision = evaluate_transfer_risk(
            source_community_id=_cid(), target_community_id=_cid(),
            peering_id=str(uuid.uuid4()), entity_id=str(uuid.uuid4()),
            data_class="GENERAL",
        )
        assert isinstance(decision.reason, str)
        assert len(decision.reason) > 0

    @pytest.mark.parametrize("data_class", ["GENERAL", "PII", "PHI", "FINANCIAL", "CLASSIFIED"])
    def test_all_data_classes_run(self, data_class):
        from warden.communities.transfer_guard import evaluate_transfer_risk
        d = evaluate_transfer_risk(
            source_community_id=_cid(), target_community_id=_cid(),
            peering_id=str(uuid.uuid4()), entity_id=str(uuid.uuid4()),
            data_class=data_class,
        )
        assert 0.0 <= d.score <= 1.0

    @pytest.mark.parametrize("policy", ["MIRROR_ONLY", "REWRAP_ALLOWED", "FULL_SYNC"])
    def test_all_policies_run(self, policy):
        from warden.communities.transfer_guard import evaluate_transfer_risk
        d = evaluate_transfer_risk(
            source_community_id=_cid(), target_community_id=_cid(),
            peering_id=str(uuid.uuid4()), entity_id=str(uuid.uuid4()),
            peering_policy=policy,
        )
        assert isinstance(d.allowed, bool)
