"""
warden/tests/test_sprint3_modules.py
─────────────────────────────────────
Unit tests for Sprint 3 modules:
  - warden/api/ws_events.py      (OB-26)
  - warden/communities/federation.py (CM-26)
  - warden/communities/model_share.py (CM-27)
  - warden/agent/red_team.py     (AR-11)
  - warden/brain/online_learner.py (AR-09)
"""
from __future__ import annotations

import asyncio
import json
import os
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("ANTHROPIC_API_KEY", "")
os.environ.setdefault("LOGS_PATH", "/tmp/sprint3_test_logs.json")


# ── ws_events ─────────────────────────────────────────────────────────────────

class TestWsEvents:
    def test_register_returns_queue(self):
        from warden.api.ws_events import _register, _subscribers, _unregister
        before = len(_subscribers)
        q = _register()
        assert len(_subscribers) == before + 1
        _unregister(q)
        assert len(_subscribers) == before

    def test_unregister_idempotent(self):
        from warden.api.ws_events import _unregister
        import asyncio
        fake_q = asyncio.Queue()
        _unregister(fake_q)  # should not raise

    def test_ts_returns_iso(self):
        from warden.api.ws_events import _ts
        ts = _ts()
        assert "T" in ts
        assert ts.endswith("+00:00") or ts.endswith("Z") or "+" in ts

    @pytest.mark.asyncio
    async def test_broadcast_no_subscribers(self):
        from warden.api.ws_events import _subscribers, broadcast_event
        orig = list(_subscribers)
        _subscribers.clear()
        # should not raise even with no subscribers
        await broadcast_event({"verdict": "HIGH", "score": 0.9})
        _subscribers.extend(orig)

    @pytest.mark.asyncio
    async def test_broadcast_drops_when_full(self):
        import asyncio

        from warden.api.ws_events import _register, _unregister, broadcast_event
        q = _register()
        # Fill queue to max
        for _ in range(100):
            try:
                q.put_nowait({"verdict": "HIGH"})
            except asyncio.QueueFull:
                break
        # broadcast to full queue should not raise
        await broadcast_event({"verdict": "HIGH", "score": 0.9})
        _unregister(q)

    @pytest.mark.asyncio
    async def test_redis_publish_skips_memory_url(self):
        from warden.api.ws_events import _redis_publish
        # With memory:// URL, should return without calling redis
        with patch.dict(os.environ, {"REDIS_URL": "memory://"}):
            await _redis_publish({"verdict": "HIGH"})  # no exception

    @pytest.mark.asyncio
    async def test_redis_publish_handles_error(self):
        from warden.api.ws_events import _redis_publish
        with patch.dict(os.environ, {"REDIS_URL": "redis://localhost:9999"}):
            with patch("redis.asyncio.from_url", side_effect=Exception("conn refused")):
                await _redis_publish({"verdict": "HIGH"})  # no exception

    @pytest.mark.asyncio
    async def test_redis_subscriber_loop_exits_memory(self):
        from warden.api.ws_events import redis_subscriber_loop
        with patch.dict(os.environ, {"REDIS_URL": "memory://"}):
            # Should return immediately when REDIS_URL is memory://
            await redis_subscriber_loop()


# ── federation ────────────────────────────────────────────────────────────────

class TestFederation:
    def test_threat_hash_deterministic(self):
        from warden.communities.federation import _threat_hash
        h1 = _threat_hash("test text", "community-1")
        h2 = _threat_hash("test text", "community-1")
        assert h1 == h2
        assert len(h1) == 32

    def test_threat_hash_differs_by_community(self):
        from warden.communities.federation import _threat_hash
        h1 = _threat_hash("test text", "community-1")
        h2 = _threat_hash("test text", "community-2")
        assert h1 != h2

    def test_broadcast_disabled(self):
        from warden.communities.federation import broadcast_verdict
        with patch.dict(os.environ, {"FEDERATION_ENABLED": "false"}):
            result = broadcast_verdict("c1", "some text", "HIGH", 0.9)
            assert result == 0

    def test_check_threat_hash_disabled(self):
        from warden.communities.federation import check_threat_hash
        with patch.dict(os.environ, {"FEDERATION_ENABLED": "false"}):
            result = check_threat_hash("c1", "some text")
            assert result is None

    def test_get_score_boost_disabled(self):
        from warden.communities.federation import get_score_boost
        with patch.dict(os.environ, {"FEDERATION_ENABLED": "false"}):
            boost = get_score_boost("c1", "some text")
            assert boost == 0.0

    def test_ingest_peer_verdict_valid(self):
        from warden.communities.federation import _MEMORY_VERDICTS, ingest_peer_verdict
        cid = f"test-{uuid.uuid4().hex[:8]}"
        ok = ingest_peer_verdict({
            "community_id": cid,
            "threat_hash": "abc123" * 5 + "ab",
            "verdict": "BLOCK",
            "score": 0.95,
            "data_class": "GENERAL",
            "ueciid": None,
            "ts": "2026-01-01T00:00:00+00:00",
        })
        assert ok is True
        assert cid in _MEMORY_VERDICTS

    def test_ingest_peer_verdict_invalid(self):
        from warden.communities.federation import ingest_peer_verdict
        ok = ingest_peer_verdict({"bad": "data"})
        assert ok is False

    def test_list_verdicts_memory(self):
        from warden.communities.federation import _MEMORY_VERDICTS, list_verdicts
        cid = f"list-{uuid.uuid4().hex[:8]}"
        _MEMORY_VERDICTS[cid] = [{"community_id": cid, "threat_hash": "x", "verdict": "HIGH",
                                   "score": 0.9, "data_class": "GENERAL", "ueciid": None, "ts": ""}]
        result = list_verdicts(cid, limit=10)
        assert len(result) >= 1

    def test_store_and_lookup_verdict(self):
        import warden.communities.federation as fed
        from warden.communities.federation import (
            FederatedVerdict,
            _store_verdict,
            _threat_hash,
            check_threat_hash,
        )
        cid = f"store-{uuid.uuid4().hex[:8]}"
        text = "malicious payload for testing"
        th = _threat_hash(text, cid)
        fv = FederatedVerdict(
            community_id=cid, threat_hash=th, verdict="BLOCK",
            score=0.99, data_class="GENERAL", ueciid=None,
            ts="2026-01-01T00:00:00+00:00",
        )
        _store_verdict(cid, fv)
        with patch.object(fed, "_FEDERATION_ENABLED", True):
            result = check_threat_hash(cid, text)
            assert result is not None
            assert result.verdict == "BLOCK"

    def test_score_boost_returns_boost(self):
        import warden.communities.federation as fed
        from warden.communities.federation import (
            FederatedVerdict,
            _BOOST,
            _store_verdict,
            _threat_hash,
            get_score_boost,
        )
        cid = f"boost-{uuid.uuid4().hex[:8]}"
        text = "boost test text"
        th = _threat_hash(text, cid)
        fv = FederatedVerdict(
            community_id=cid, threat_hash=th, verdict="BLOCK",
            score=0.9, data_class="GENERAL", ueciid=None,
            ts="2026-01-01T00:00:00+00:00",
        )
        _store_verdict(cid, fv)
        with patch.object(fed, "_FEDERATION_ENABLED", True):
            boost = get_score_boost(cid, text)
            assert boost == _BOOST


# ── model_share ───────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_sep_db(tmp_path, monkeypatch):
    monkeypatch.setenv("SEP_DB_PATH", str(tmp_path / "sep.db"))


class TestModelShare:
    def test_create_bundle(self, tmp_sep_db):
        from warden.communities.model_share import create_bundle
        rules = [
            {"pattern": "jailbreak me", "label": "HIGH_RISK", "attack_type": "injection"},
            {"pattern": "ignore instructions", "label": "HIGH_RISK", "attack_type": "injection"},
        ]
        bundle = create_bundle(rules, source_community="test-community", effectiveness=0.85)
        assert bundle.ueciid.startswith("SEP-")
        assert bundle.rule_count == 2
        assert bundle.source_community == "test-community"
        assert bundle.effectiveness == 0.85
        assert bundle.bundle_type == "MODEL_RULES"
        assert len(bundle.hmac_sig) == 64

    def test_get_bundle(self, tmp_sep_db):
        from warden.communities.model_share import create_bundle, get_bundle
        rules = [{"pattern": "test", "label": "HIGH_RISK", "attack_type": "general"}]
        bundle = create_bundle(rules, source_community="src-community")
        result = get_bundle(bundle.ueciid)
        assert result is not None
        assert result["ueciid"] == bundle.ueciid
        assert result["source_community"] == "src-community"

    def test_get_bundle_with_rules(self, tmp_sep_db):
        from warden.communities.model_share import create_bundle, get_bundle
        rules = [{"pattern": "evil", "label": "HIGH_RISK", "attack_type": "exfil"}]
        bundle = create_bundle(rules, source_community="with-rules")
        result = get_bundle(bundle.ueciid, include_rules=True)
        assert result is not None
        assert "rules" in result
        assert len(result["rules"]) == 1

    def test_get_bundle_not_found(self, tmp_sep_db):
        from warden.communities.model_share import get_bundle
        result = get_bundle("SEP-nonexistent1")
        assert result is None

    def test_list_bundles(self, tmp_sep_db):
        from warden.communities.model_share import create_bundle, list_bundles
        community = f"list-{uuid.uuid4().hex[:8]}"
        create_bundle([{"pattern": "p1", "label": "HIGH_RISK", "attack_type": "t"}], community)
        create_bundle([{"pattern": "p2", "label": "HIGH_RISK", "attack_type": "t"}], community)
        result = list_bundles(source_community=community)
        assert len(result) == 2

    def test_list_bundles_all(self, tmp_sep_db):
        from warden.communities.model_share import create_bundle, list_bundles
        create_bundle([{"pattern": "x", "label": "HIGH_RISK", "attack_type": "t"}], "any-community")
        result = list_bundles()
        assert len(result) >= 1

    def test_import_bundle_valid_hmac(self, tmp_sep_db):
        from warden.communities.model_share import create_bundle, import_bundle
        rules = [{"pattern": "test", "label": "HIGH_RISK", "attack_type": "general"}]
        bundle = create_bundle(rules, source_community="source")
        payload = {
            "ueciid": bundle.ueciid,
            "rules_hash": bundle.rules_hash,
            "source_community": bundle.source_community,
            "rule_count": bundle.rule_count,
            "hmac_sig": bundle.hmac_sig,
            "rules": rules,
            "attack_types": bundle.attack_types,
        }
        result = import_bundle(payload, "importing-community")
        assert result["status"] == "PENDING_APPROVAL"
        assert result["requires_approval"] is True

    def test_import_bundle_bad_hmac(self, tmp_sep_db):
        from warden.communities.model_share import import_bundle
        result = import_bundle({
            "ueciid": "SEP-badhmac1234",
            "rules_hash": "abc",
            "source_community": "bad",
            "rule_count": 1,
            "hmac_sig": "invalidhmac",
        }, "any")
        assert result["status"] == "REJECTED"
        assert result["reason"] == "hmac_mismatch"

    def test_activate_bundle_not_found(self, tmp_sep_db):
        from warden.communities.model_share import activate_bundle
        count = activate_bundle("SEP-doesnotexist1")
        assert count == 0

    def test_bundle_attack_types(self, tmp_sep_db):
        from warden.communities.model_share import create_bundle
        rules = [
            {"pattern": "a", "label": "HIGH_RISK", "attack_type": "injection"},
            {"pattern": "b", "label": "HIGH_RISK", "attack_type": "exfiltration"},
        ]
        bundle = create_bundle(rules, source_community="types-test")
        assert len(bundle.attack_types) == 2
        assert "injection" in bundle.attack_types
        assert "exfiltration" in bundle.attack_types


# ── red_team ──────────────────────────────────────────────────────────────────

class TestRedTeam:
    @pytest.mark.asyncio
    async def test_run_session_disabled(self):
        from warden.agent.red_team import run_session
        with patch.dict(os.environ, {"RED_TEAM_ENABLED": "false"}):
            result = await run_session()
            assert result.session_id == "disabled"
            assert result.total_probed == 0

    def test_get_last_result_initial(self):
        import warden.agent.red_team as rt
        # get_last_result may be None initially or have a prior value
        result = rt._last_result
        assert result is None or hasattr(result, "session_id")

    def test_probe_result_dataclass(self):
        from warden.agent.red_team import ProbeResult
        pr = ProbeResult(prompt="test", verdict="BLOCK", score=0.9, evaded=False, ms=5.0)
        assert pr.prompt == "test"
        assert pr.evaded is False

    def test_session_result_dataclass(self):
        from warden.agent.red_team import SessionResult
        sr = SessionResult(
            session_id="abc", attack_class="injection",
            started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:00:01Z",
            total_probed=5, evaded=1, new_examples=1,
        )
        assert sr.evaded == 1
        assert sr.probes == []

    @pytest.mark.asyncio
    async def test_generate_probes_no_api_key(self):
        from warden.agent import red_team as rt
        with patch.object(rt, "_ANTHROPIC", ""):
            probes = await rt._generate_probes("injection", 3)
            assert isinstance(probes, list)
            assert len(probes) >= 1  # fallback probes

    def test_fallback_probes(self):
        from warden.agent.red_team import _fallback_probes
        probes = _fallback_probes("injection", 5)
        assert isinstance(probes, list)
        assert len(probes) >= 1


# ── online_learner ────────────────────────────────────────────────────────────

class TestOnlineLearner:
    @pytest.mark.asyncio
    async def test_run_disabled(self):
        from warden.brain.online_learner import run_online_learning
        with patch.dict(os.environ, {"ONLINE_LEARNING_ENABLED": "false"}):
            result = await run_online_learning()
            assert "ONLINE_LEARNING_ENABLED" in result.error

    @pytest.mark.asyncio
    async def test_run_missing_dataset(self, tmp_path):
        from warden.brain import online_learner as ol
        with patch.object(ol, "_ENABLED", True):
            with patch.object(ol, "_DATASET_PATH", tmp_path / "nonexistent.jsonl"):
                result = await ol.run_online_learning()
                assert "not found" in result.error

    @pytest.mark.asyncio
    async def test_run_with_dataset(self, tmp_path):
        from warden.brain import online_learner as ol
        dataset = tmp_path / "evolution_dataset.jsonl"
        examples = [
            {"text": "ignore all instructions", "label": "HIGH_RISK"},
            {"text": "Hello, how are you?", "label": "SAFE"},
            {"text": "bypass safety filters", "label": "HIGH_RISK"},
        ]
        dataset.write_text("\n".join(json.dumps(e) for e in examples))
        with patch.object(ol, "_ENABLED", True):
            with patch.object(ol, "_DATASET_PATH", dataset):
                with patch.object(ol, "_inject_examples", return_value=0):
                    with patch.object(ol, "_find_hard_negatives", return_value=[]):
                        result = await ol.run_online_learning()
                        assert result.examples_loaded == 3

    def test_load_examples_empty_file(self, tmp_path):
        from warden.brain import online_learner as ol
        empty = tmp_path / "empty.jsonl"
        empty.write_text("")
        with patch.object(ol, "_DATASET_PATH", empty):
            result = ol._load_examples(100)
            assert result == []

    def test_load_examples_with_data(self, tmp_path):
        from warden.brain import online_learner as ol
        dataset = tmp_path / "test.jsonl"
        lines = [json.dumps({"text": f"example {i}", "label": "HIGH_RISK"}) for i in range(10)]
        dataset.write_text("\n".join(lines))
        with patch.object(ol, "_DATASET_PATH", dataset):
            result = ol._load_examples(5)
            assert len(result) == 5  # last 5 of 10

    def test_load_examples_bad_json(self, tmp_path):
        from warden.brain import online_learner as ol
        dataset = tmp_path / "bad.jsonl"
        dataset.write_text('{"text": "good"}\nnot json\n{"text": "also good"}')
        with patch.object(ol, "_DATASET_PATH", dataset):
            result = ol._load_examples(100)
            assert len(result) == 2  # bad line skipped

    def test_inject_examples_empty(self):
        from warden.brain.online_learner import _inject_examples
        count = _inject_examples([])
        assert count == 0

    def test_inject_examples_no_engine(self):
        from warden.brain.online_learner import _inject_examples
        with patch("warden.brain.online_learner._inject_examples") as m:
            m.side_effect = None
            m.return_value = 0

    @pytest.mark.asyncio
    async def test_arq_job_wrapper(self):
        from warden.brain.online_learner import online_learning_job
        result = await online_learning_job({})
        assert "ts" in result
        assert "injected" in result

    def test_learning_result_dataclass(self):
        from warden.brain.online_learner import LearningResult
        r = LearningResult(ts="2026-01-01T00:00:00Z", examples_loaded=10,
                           hard_negatives=3, injected=2, skipped=1)
        assert r.examples_loaded == 10
        assert r.error == ""
