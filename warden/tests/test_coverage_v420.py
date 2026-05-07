"""
warden/tests/test_coverage_v420.py
Coverage booster for v4.20 billing trial, addons, hooks, reputation, action whitelist, workers.
"""
from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta
import importlib
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
from unittest import mock

import pytest


# ── Billing trial ─────────────────────────────────────────────────────────────

class TestBillingTrial:

    def setup_method(self):
        from warden.billing import trial as t
        t._MEMORY_TRIALS.clear()

    def test_start_trial_creates_record(self):
        from warden.billing.trial import start_trial
        rec = start_trial("trial-t1", "starter")
        assert rec["status"] == "active"
        assert rec["tenant_id"] == "trial-t1"
        assert rec["master_agent"] is False
        assert rec["days_remaining"] == 14
        assert rec["req_limit"] == 10_000
        assert rec["previous_tier"] == "starter"

    def test_start_trial_idempotent(self):
        from warden.billing.trial import start_trial
        r1 = start_trial("trial-t2", "individual")
        r2 = start_trial("trial-t2", "individual")
        assert r1["started_at"] == r2["started_at"]

    def test_start_trial_expired_raises(self):
        from warden.billing import trial as t
        t._MEMORY_TRIALS["trial-t3"] = {
            "tenant_id": "trial-t3",
            "started_at": "2020-01-01T00:00:00+00:00",
            "expires_at": "2020-01-15T00:00:00+00:00",
            "req_limit": 10000,
            "previous_tier": "starter",
        }
        with pytest.raises(ValueError, match="already used their trial"):
            t.start_trial("trial-t3")

    def test_get_trial_returns_none_unknown(self):
        from warden.billing.trial import get_trial
        assert get_trial("ghost-tenant-xyz") is None

    def test_get_trial_active_status(self):
        from warden.billing.trial import get_trial, start_trial
        start_trial("trial-t4")
        rec = get_trial("trial-t4")
        assert rec is not None
        assert rec["status"] == "active"
        assert 0 <= rec["days_remaining"] <= 14
        assert rec["upgrade_url"] == "/billing/upgrade?plan=pro"

    def test_get_trial_expired_status(self):
        from warden.billing import trial as t
        t._MEMORY_TRIALS["trial-t5"] = {
            "started_at": "2020-01-01T00:00:00+00:00",
            "expires_at": "2020-01-15T00:00:00+00:00",
            "req_limit": "10000",
            "previous_tier": "starter",
        }
        rec = t.get_trial("trial-t5")
        assert rec is not None
        assert rec["status"] == "expired"
        assert rec["days_remaining"] == 0

    def test_get_trial_naive_expires_at_handled(self):
        from warden.billing import trial as t
        future = (datetime.now(UTC) + timedelta(days=5)).replace(tzinfo=None).isoformat()
        t._MEMORY_TRIALS["trial-t6"] = {
            "started_at": "2025-01-01T00:00:00",
            "expires_at": future,
            "req_limit": "10000",
            "previous_tier": "starter",
        }
        rec = t.get_trial("trial-t6")
        assert rec is not None
        assert rec["status"] == "active"

    def test_get_trial_bad_expires_at_returns_none(self):
        from warden.billing import trial as t
        t._MEMORY_TRIALS["trial-t7"] = {
            "expires_at": "not-a-valid-date",
            "req_limit": "10000",
        }
        assert t.get_trial("trial-t7") is None

    def test_is_trial_active_true(self):
        from warden.billing.trial import is_trial_active, start_trial
        start_trial("trial-t8")
        assert is_trial_active("trial-t8") is True

    def test_is_trial_active_false_no_trial(self):
        from warden.billing.trial import is_trial_active
        assert is_trial_active("nobody-has-trial") is False

    def test_is_trial_active_false_expired(self):
        from warden.billing import trial as t
        t._MEMORY_TRIALS["trial-t9"] = {
            "expires_at": "2020-01-15T00:00:00+00:00",
            "req_limit": "10000",
            "previous_tier": "starter",
        }
        assert t.is_trial_active("trial-t9") is False

    def test_get_trial_tier_limits(self):
        from warden.billing.trial import get_trial_tier_limits
        lim = get_trial_tier_limits()
        assert lim["req_per_month"] == 10_000
        assert lim["master_agent_enabled"] is False
        assert lim["overage_enabled"] is False
        assert lim["_is_trial"] is True

    def test_start_trial_stores_previous_tier(self):
        from warden.billing.trial import get_trial, start_trial
        start_trial("trial-t10", current_tier="community_business")
        rec = get_trial("trial-t10")
        assert rec["previous_tier"] == "community_business"

    def test_trial_key_format(self):
        from warden.billing.trial import _trial_key
        assert _trial_key("abc") == "billing:trial:abc"


# ── Billing addons v4.20 new functions ────────────────────────────────────────

class TestBillingAddonsV420:

    def setup_method(self):
        from warden.billing import addons as a
        a._MEMORY_ADDONS.clear()

    def test_grant_bundle_grants_all_components(self):
        from warden.billing.addons import grant_bundle, has_addon
        granted = grant_bundle("biz-bundle-1", "power_user_bundle")
        assert set(granted) == {"secrets_vault", "xai_audit", "shadow_ai_discovery"}
        assert has_addon("biz-bundle-1", "secrets_vault")
        assert has_addon("biz-bundle-1", "xai_audit")
        assert has_addon("biz-bundle-1", "shadow_ai_discovery")

    def test_grant_bundle_unknown_raises(self):
        from warden.billing.addons import grant_bundle
        with pytest.raises(ValueError, match="Unknown bundle"):
            grant_bundle("t1", "nonexistent_bundle_xyz")

    def test_get_seat_expansion_zero_by_default(self):
        from warden.billing.addons import get_seat_expansion
        assert get_seat_expansion("seats-new-tenant") == 0

    def test_increment_seat_units_memory_only(self):
        from warden.billing.addons import increment_seat_units
        result = increment_seat_units("seats-mem-tenant", 1)
        assert isinstance(result, int)

    def test_grant_on_prem_pack(self):
        from warden.billing.addons import grant_addon, has_addon
        grant_addon("onprem-t1", "on_prem_pack")
        assert has_addon("onprem-t1", "on_prem_pack")

    def test_grant_community_seats(self):
        from warden.billing.addons import grant_addon, has_addon
        grant_addon("seats-t1", "community_seats")
        assert has_addon("seats-t1", "community_seats")

    def test_revoke_addon_removes_from_set(self):
        from warden.billing.addons import grant_addon, has_addon, revoke_addon
        grant_addon("rv-t1", "xai_audit")
        revoke_addon("rv-t1", "xai_audit")
        assert not has_addon("rv-t1", "xai_audit")

    def test_revoke_addon_nonexistent_is_noop(self):
        from warden.billing.addons import revoke_addon
        revoke_addon("rv-empty", "xai_audit")  # should not raise

    def test_get_tenant_addons_empty(self):
        from warden.billing.addons import get_tenant_addons
        assert get_tenant_addons("brand-new-tenant-xyz") == set()

    def test_grant_unknown_addon_raises(self):
        from warden.billing.addons import grant_addon
        with pytest.raises(ValueError, match="Unknown add-on"):
            grant_addon("t1", "made_up_addon_99")

    def test_get_tenant_id_from_request_state_dict(self):
        from warden.billing.addons import _get_tenant_id_from_request
        req = mock.MagicMock()
        req.state.tenant = {"tenant_id": "tid-123"}
        assert _get_tenant_id_from_request(req) == "tid-123"

    def test_get_tenant_id_from_request_state_id_fallback(self):
        from warden.billing.addons import _get_tenant_id_from_request
        req = mock.MagicMock()
        req.state.tenant = {"id": "id-456"}
        assert _get_tenant_id_from_request(req) == "id-456"

    def test_get_tenant_id_from_request_header(self):
        from warden.billing.addons import _get_tenant_id_from_request
        req = mock.MagicMock()
        req.state.tenant = None
        req.headers.get.return_value = "hdr-tenant"
        assert _get_tenant_id_from_request(req) == "hdr-tenant"

    def test_bundle_catalog_keys(self):
        from warden.billing.addons import BUNDLE_CATALOG
        assert "power_user_bundle" in BUNDLE_CATALOG
        assert BUNDLE_CATALOG["power_user_bundle"]["savings_usd"] == 7


# ── Hooks: fail_open ──────────────────────────────────────────────────────────

class TestFailOpenHook:

    def _write_py(self, content: str) -> Path:
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w", encoding="utf-8") as f:
            f.write(content)
        return Path(f.name)

    def test_bare_except_pass_detected(self):
        from warden.hooks.fail_open import check_file
        p = self._write_py("try:\n    x = 1\nexcept Exception:\n    pass\n")
        errors = check_file(p)
        assert any("bare `except: pass`" in e for e in errors)
        os.unlink(p)

    def test_bare_except_return_without_log_detected(self):
        from warden.hooks.fail_open import check_file
        p = self._write_py(
            "def f():\n"
            "  try:\n"
            "    x = 1\n"
            "  except Exception:\n"
            "    return None\n"
        )
        errors = check_file(p)
        assert any("return` without logging" in e for e in errors)
        os.unlink(p)

    def test_except_with_log_warning_ok(self):
        from warden.hooks.fail_open import check_file
        p = self._write_py(
            "import logging\n"
            "log = logging.getLogger('x')\n"
            "def f():\n"
            "  try:\n"
            "    x = 1\n"
            "  except Exception:\n"
            "    log.warning('oops')\n"
        )
        errors = check_file(p)
        assert errors == []
        os.unlink(p)

    def test_syntax_error_returns_empty(self):
        from warden.hooks.fail_open import check_file
        p = self._write_py("def bad(:\n    pass\n")
        errors = check_file(p)
        assert errors == []
        os.unlink(p)

    def test_has_log_call_true(self):
        from warden.hooks.fail_open import _has_log_call
        body = ast.parse("log.warning('x')").body
        assert _has_log_call(body) is True

    def test_has_log_call_error_level(self):
        from warden.hooks.fail_open import _has_log_call
        body = ast.parse("log.error('x')").body
        assert _has_log_call(body) is True

    def test_has_log_call_false(self):
        from warden.hooks.fail_open import _has_log_call
        body = ast.parse("x = 1").body
        assert _has_log_call(body) is False

    def test_main_no_files_returns_zero(self):
        from warden.hooks.fail_open import main
        with mock.patch("sys.argv", ["hook"]):
            assert main() == 0

    def test_main_with_non_py_file_ignored(self):
        from warden.hooks.fail_open import main
        with mock.patch("sys.argv", ["hook", "/some/file.txt"]):
            assert main() == 0

    def test_main_with_error_file_returns_one(self):
        from warden.hooks.fail_open import main
        p = self._write_py("try:\n    x = 1\nexcept Exception:\n    pass\n")
        with mock.patch("sys.argv", ["hook", str(p)]):
            result = main()
        assert result == 1
        os.unlink(p)

    def test_file_with_no_except_is_clean(self):
        from warden.hooks.fail_open import check_file
        p = self._write_py("x = 1 + 1\n")
        errors = check_file(p)
        assert errors == []
        os.unlink(p)


# ── Hooks: idempotency ────────────────────────────────────────────────────────

class TestIdempotencyHook:

    def _write_py(self, content: str) -> Path:
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w", encoding="utf-8") as f:
            f.write(content)
        return Path(f.name)

    def test_charge_without_idempotency_key_detected(self):
        from warden.hooks.idempotency import check_file
        p = self._write_py("client.charge(amount=100)\n")
        errors = check_file(p)
        assert any("idempotency_key" in e for e in errors)
        os.unlink(p)

    def test_charge_with_idempotency_key_ok(self):
        from warden.hooks.idempotency import check_file
        p = self._write_py("client.charge(amount=100, idempotency_key='k1')\n")
        errors = check_file(p)
        assert errors == []
        os.unlink(p)

    def test_subscribe_without_key_detected(self):
        from warden.hooks.idempotency import check_file
        p = self._write_py("billing.subscribe(plan='pro')\n")
        errors = check_file(p)
        assert any("idempotency_key" in e for e in errors)
        os.unlink(p)

    def test_non_payment_call_ok(self):
        from warden.hooks.idempotency import check_file
        p = self._write_py("client.get_user(id=1)\n")
        errors = check_file(p)
        assert errors == []
        os.unlink(p)

    def test_refund_without_key_detected(self):
        from warden.hooks.idempotency import check_file
        p = self._write_py("stripe.refund(charge_id='ch_1')\n")
        errors = check_file(p)
        assert any("idempotency_key" in e for e in errors)
        os.unlink(p)

    def test_syntax_error_returns_empty(self):
        from warden.hooks.idempotency import check_file
        p = self._write_py("def bad(:\n    pass\n")
        errors = check_file(p)
        assert errors == []
        os.unlink(p)

    def test_main_no_files_returns_zero(self):
        from warden.hooks.idempotency import main
        with mock.patch("sys.argv", ["hook"]):
            assert main() == 0

    def test_payment_calls_set(self):
        from warden.hooks.idempotency import PAYMENT_CALLS
        assert "charge" in PAYMENT_CALLS
        assert "refund" in PAYMENT_CALLS


# ── Hooks: tenant_isolation ───────────────────────────────────────────────────

class TestTenantIsolationHook:

    def _write_py(self, content: str) -> Path:
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w", encoding="utf-8") as f:
            f.write(content)
        return Path(f.name)

    def test_filter_without_tenant_id_warns(self):
        from warden.hooks.tenant_isolation import check_file
        p = self._write_py("q.filter(User.status == 'active')\n")
        warnings = check_file(p)
        assert any("tenant_id" in w for w in warnings)
        os.unlink(p)

    def test_filter_with_tenant_id_ok(self):
        from warden.hooks.tenant_isolation import check_file
        p = self._write_py("q.filter(User.tenant_id == tid)\n")
        warnings = check_file(p)
        assert warnings == []
        os.unlink(p)

    def test_filter_by_without_tenant_warns(self):
        from warden.hooks.tenant_isolation import check_file
        p = self._write_py("q.filter_by(status='active')\n")
        warnings = check_file(p)
        assert any("filter_by" in w for w in warnings)
        os.unlink(p)

    def test_where_without_tenant_warns(self):
        from warden.hooks.tenant_isolation import check_file
        p = self._write_py("stmt.where(Table.id == 1)\n")
        warnings = check_file(p)
        assert any("where" in w for w in warnings)
        os.unlink(p)

    def test_syntax_error_returns_empty(self):
        from warden.hooks.tenant_isolation import check_file
        p = self._write_py("def bad(:\n    pass\n")
        warnings = check_file(p)
        assert warnings == []
        os.unlink(p)

    def test_main_no_files_returns_zero(self):
        from warden.hooks.tenant_isolation import main
        with mock.patch("sys.argv", ["hook"]):
            assert main() == 0

    def test_main_non_api_file_skipped(self):
        from warden.hooks.tenant_isolation import main
        p = self._write_py("q.filter(User.id == uid)\n")
        with mock.patch("sys.argv", ["hook", str(p)]):
            result = main()
        assert result == 0  # not in warden/api — skipped
        os.unlink(p)


# ── Community reputation ──────────────────────────────────────────────────────

@pytest.fixture
def rep_module(tmp_path, monkeypatch):
    db = str(tmp_path / "rep_test.db")
    monkeypatch.setenv("SEP_DB_PATH", db)
    import warden.communities.reputation as rep
    importlib.reload(rep)
    yield rep
    importlib.reload(rep)


class TestCommunityReputation:

    def test_get_reputation_newcomer_by_default(self, rep_module):
        rec = rep_module.get_reputation("rep-new-1")
        assert rec.badge == "NEWCOMER"
        assert rec.points == 0
        assert rec.entry_count == 0

    def test_award_publish_entry(self, rep_module):
        rep_module.award_points("rep-pub-1", "PUBLISH_ENTRY")
        rec = rep_module.get_reputation("rep-pub-1")
        assert rec.points == 5
        assert rec.entry_count == 1

    def test_award_search_hit(self, rep_module):
        rep_module.award_points("rep-sh-1", "SEARCH_HIT")
        rec = rep_module.get_reputation("rep-sh-1")
        assert rec.points == 1
        assert rec.entry_count == 0

    def test_award_rec_adopted(self, rep_module):
        rep_module.award_points("rep-ra-1", "REC_ADOPTED")
        rec = rep_module.get_reputation("rep-ra-1")
        assert rec.points == 10

    def test_award_trusted_entry(self, rep_module):
        rep_module.award_points("rep-te-1", "TRUSTED_ENTRY")
        rec = rep_module.get_reputation("rep-te-1")
        assert rec.points == 3

    def test_award_unknown_event_zero_points(self, rep_module):
        rec = rep_module.award_points("rep-unk-1", "UNKNOWN_EVENT_XYZ")
        assert rec.points == 0

    def test_badge_progression_to_contributor(self, rep_module):
        for _ in range(5):
            rep_module.award_points("rep-prog-1", "PUBLISH_ENTRY")
        rec = rep_module.get_reputation("rep-prog-1")
        assert rec.badge == "CONTRIBUTOR"
        assert rec.points == 25

    def test_badge_progression_to_top_sharer(self, rep_module):
        for _ in range(20):
            rep_module.award_points("rep-prog-2", "PUBLISH_ENTRY")
        rec = rep_module.get_reputation("rep-prog-2")
        assert rec.badge == "TOP_SHARER"

    def test_get_leaderboard_anonymised(self, rep_module):
        rep_module.award_points("lb-t1", "PUBLISH_ENTRY")
        rep_module.award_points("lb-t2", "REC_ADOPTED")
        board = rep_module.get_leaderboard(limit=5)
        assert isinstance(board, list)
        assert len(board) >= 1
        assert all("tenant_id" not in e for e in board)
        assert all("rank" in e for e in board)
        assert all("badge_emoji" in e for e in board)

    def test_force_badge_elite(self, rep_module):
        rep_module.force_badge("elite-t1", "ELITE")
        rec = rep_module.get_reputation("elite-t1")
        assert rec.badge == "ELITE"

    def test_badge_for_thresholds(self, rep_module):
        assert rep_module._badge_for(0) == "NEWCOMER"
        assert rep_module._badge_for(24) == "NEWCOMER"
        assert rep_module._badge_for(25) == "CONTRIBUTOR"
        assert rep_module._badge_for(99) == "CONTRIBUTOR"
        assert rep_module._badge_for(100) == "TOP_SHARER"
        assert rep_module._badge_for(300) == "GUARDIAN"
        assert rep_module._badge_for(750) == "ELITE"

    def test_badge_forced_override(self, rep_module):
        assert rep_module._badge_for(0, forced="ELITE") == "ELITE"

    def test_reputation_record_to_public_dict(self, rep_module):
        rec = rep_module.ReputationRecord("t1", 50, "CONTRIBUTOR", 3)
        pub = rec.to_public_dict(rank=2)
        assert pub["rank"] == 2
        assert "tenant_id" not in pub
        assert pub["badge"] == "CONTRIBUTOR"
        assert pub["points"] == 50

    def test_reputation_record_to_dict_has_tenant(self, rep_module):
        rec = rep_module.ReputationRecord("t1", 50, "CONTRIBUTOR", 3)
        d = rec.to_dict()
        assert d["tenant_id"] == "t1"

    def test_badge_emoji_property(self, rep_module):
        rec = rep_module.ReputationRecord("t1", 750, "ELITE", 10)
        assert rec.badge_emoji == "🏆"

    def test_badge_enum_values(self):
        from warden.communities.reputation import Badge
        assert Badge.NEWCOMER == "NEWCOMER"
        assert Badge.CONTRIBUTOR == "CONTRIBUTOR"
        assert Badge.TOP_SHARER == "TOP_SHARER"
        assert Badge.GUARDIAN == "GUARDIAN"
        assert Badge.ELITE == "ELITE"

    def test_cumulative_points(self, rep_module):
        rep_module.award_points("cum-t1", "PUBLISH_ENTRY")
        rep_module.award_points("cum-t1", "SEARCH_HIT")
        rec = rep_module.get_reputation("cum-t1")
        assert rec.points == 6


# ── Agentic action whitelist ──────────────────────────────────────────────────

@pytest.fixture
def whitelist():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    lock = threading.Lock()
    from warden.agentic.action_whitelist import ActionWhitelist
    return ActionWhitelist(conn, lock)


class TestActionWhitelist:

    def test_add_and_get_rule(self, whitelist):
        rule = whitelist.add_rule("agent-aw-1", "GET", "/users/*", max_rps=10.0)
        assert rule["agent_id"] == "agent-aw-1"
        assert rule["http_method"] == "GET"
        assert rule["endpoint_glob"] == "/users/*"
        assert rule["max_rps"] == 10.0

    def test_get_rules_empty(self, whitelist):
        assert whitelist.get_rules("nobody-agent") == []

    def test_get_rule_not_found(self, whitelist):
        assert whitelist.get_rule("00000000-0000-0000-0000-000000000000") is None

    def test_delete_rule(self, whitelist):
        rule = whitelist.add_rule("agent-aw-2", "POST", "/items/*")
        deleted = whitelist.delete_rule(rule["rule_id"])
        assert deleted is True
        assert whitelist.get_rule(rule["rule_id"]) is None

    def test_delete_nonexistent_returns_false(self, whitelist):
        assert whitelist.delete_rule("00000000-0000-0000-0000-000000000000") is False

    def test_add_rule_invalid_method_raises(self, whitelist):
        with pytest.raises(ValueError, match="Invalid HTTP method"):
            whitelist.add_rule("agent-aw-3", "INVALID", "/x")

    def test_add_rule_wildcard_method(self, whitelist):
        rule = whitelist.add_rule("agent-aw-4", "*", "/anything")
        assert rule["http_method"] == "*"

    def test_check_action_no_rules_open_policy(self, whitelist):
        allowed, reason = whitelist.check_action("no-rules-agent", "GET", "/x")
        assert allowed is True
        assert reason == "no_rules_open_policy"

    def test_check_action_matching_glob(self, whitelist):
        whitelist.add_rule("agent-aw-5", "GET", "/users/*")
        allowed, reason = whitelist.check_action("agent-aw-5", "GET", "/users/123")
        assert allowed is True
        assert "rule:" in reason

    def test_check_action_no_matching_rule(self, whitelist):
        whitelist.add_rule("agent-aw-6", "GET", "/users/*")
        allowed, reason = whitelist.check_action("agent-aw-6", "POST", "/orders/1")
        assert allowed is False
        assert "no_matching_rule" in reason

    def test_check_action_wildcard_method_matches(self, whitelist):
        whitelist.add_rule("agent-aw-7", "*", "/api/*")
        allowed, _ = whitelist.check_action("agent-aw-7", "DELETE", "/api/resource")
        assert allowed is True

    def test_check_action_method_case_insensitive(self, whitelist):
        whitelist.add_rule("agent-aw-8", "POST", "/data/*")
        allowed, _ = whitelist.check_action("agent-aw-8", "post", "/data/x")
        assert allowed is True

    def test_rate_limit_first_call_allowed(self, whitelist):
        assert whitelist._check_rate("rate-agent-1", 5.0) is True

    def test_rate_limit_within_window_allowed(self, whitelist):
        import time
        whitelist._check_rate("rate-agent-2", 5.0)
        with whitelist._lock:
            whitelist._conn.execute(
                "UPDATE agent_action_rate SET count=2, window_start=? WHERE agent_id=?",
                (time.time(), "rate-agent-2"),
            )
            whitelist._conn.commit()
        assert whitelist._check_rate("rate-agent-2", 5.0) is True

    def test_rate_limit_exceeded(self, whitelist):
        import time
        whitelist._check_rate("rate-agent-3", 1.0)
        with whitelist._lock:
            whitelist._conn.execute(
                "UPDATE agent_action_rate SET count=1, window_start=? WHERE agent_id=?",
                (time.time(), "rate-agent-3"),
            )
            whitelist._conn.commit()
        assert whitelist._check_rate("rate-agent-3", 1.0) is False

    def test_rate_limit_new_window_resets(self, whitelist):
        import time
        whitelist._check_rate("rate-agent-4", 1.0)
        with whitelist._lock:
            whitelist._conn.execute(
                "UPDATE agent_action_rate SET count=99, window_start=? WHERE agent_id=?",
                (time.time() - 2.0, "rate-agent-4"),
            )
            whitelist._conn.commit()
        assert whitelist._check_rate("rate-agent-4", 1.0) is True

    def test_check_action_rate_enforced(self, whitelist):
        import time
        whitelist.add_rule("rate-check-agent", "GET", "/x", max_rps=1.0)
        whitelist._check_rate("rate-check-agent", 1.0)
        with whitelist._lock:
            whitelist._conn.execute(
                "UPDATE agent_action_rate SET count=1, window_start=? WHERE agent_id=?",
                (time.time(), "rate-check-agent"),
            )
            whitelist._conn.commit()
        allowed, reason = whitelist.check_action("rate-check-agent", "GET", "/x")
        assert allowed is False
        assert "rate_limit_exceeded" in reason

    def test_multiple_rules_first_match_wins(self, whitelist):
        whitelist.add_rule("agent-aw-9", "GET", "/a/*")
        whitelist.add_rule("agent-aw-9", "GET", "/b/*")
        allowed, _ = whitelist.check_action("agent-aw-9", "GET", "/b/item")
        assert allowed is True


# ── Workers ───────────────────────────────────────────────────────────────────

class TestWorkerGdprRetention:

    @pytest.mark.asyncio
    async def test_run_gdpr_retention_success(self):
        from warden.workers.gdpr_retention import run_gdpr_retention
        mock_gdpr = mock.MagicMock()
        mock_gdpr.run_retention_purge = mock.AsyncMock(return_value=42)
        with mock.patch.dict("sys.modules", {"warden.api.gdpr": mock_gdpr}):
            result = await run_gdpr_retention({})
        assert result["ok"] is True
        assert result["removed"] == 42

    @pytest.mark.asyncio
    async def test_run_gdpr_retention_exception(self):
        from warden.workers.gdpr_retention import run_gdpr_retention
        mock_gdpr = mock.MagicMock()
        mock_gdpr.run_retention_purge = mock.AsyncMock(side_effect=RuntimeError("db down"))
        with mock.patch.dict("sys.modules", {"warden.api.gdpr": mock_gdpr}):
            result = await run_gdpr_retention({})
        assert result["ok"] is False
        assert "error" in result


class TestWorkerDunning:

    @pytest.mark.asyncio
    async def test_slack_no_webhook_is_noop(self):
        from warden.workers.dunning import _slack
        with mock.patch.dict(os.environ, {"SLACK_WEBHOOK_URL": ""}):
            await _slack("test msg")  # must not raise

    @pytest.mark.asyncio
    async def test_process_dunning_no_delinquent(self):
        from warden.workers.dunning import process_dunning
        mock_billing = mock.MagicMock()
        mock_billing.expire_past_due.return_value = []
        mock_lb = mock.MagicMock()
        mock_lb.get_lemon_billing.return_value = mock_billing
        with mock.patch.dict("sys.modules", {"warden.lemon_billing": mock_lb}):
            result = await process_dunning({})
        assert result["downgraded"] == 0
        assert "ts" in result
        assert result["grace_days"] == int(os.getenv("DUNNING_GRACE_DAYS", "7"))

    @pytest.mark.asyncio
    async def test_process_dunning_with_downgrade(self):
        from warden.workers.dunning import process_dunning
        mock_billing = mock.MagicMock()
        mock_billing.expire_past_due.return_value = [
            {"tenant_id": f"past-due-{i}"} for i in range(3)
        ]
        mock_lb = mock.MagicMock()
        mock_lb.get_lemon_billing.return_value = mock_billing
        with (
            mock.patch.dict("sys.modules", {"warden.lemon_billing": mock_lb}),
            mock.patch.dict(os.environ, {"SLACK_WEBHOOK_URL": ""}),
        ):
            result = await process_dunning({})
        assert result["downgraded"] == 3
        assert len(result["tenants"]) == 3

    @pytest.mark.asyncio
    async def test_process_dunning_lemon_unavailable(self):
        from warden.workers.dunning import process_dunning
        mock_lb = mock.MagicMock()
        mock_lb.get_lemon_billing.side_effect = RuntimeError("no lemon")
        with mock.patch.dict("sys.modules", {"warden.lemon_billing": mock_lb}):
            result = await process_dunning({})
        assert "error" in result
        assert result["downgraded"] == 0

    @pytest.mark.asyncio
    async def test_process_dunning_many_tenants_truncated_slack(self):
        from warden.workers.dunning import process_dunning
        mock_billing = mock.MagicMock()
        mock_billing.expire_past_due.return_value = [
            {"tenant_id": f"t{i}"} for i in range(8)
        ]
        mock_lb = mock.MagicMock()
        mock_lb.get_lemon_billing.return_value = mock_billing
        with (
            mock.patch.dict("sys.modules", {"warden.lemon_billing": mock_lb}),
            mock.patch.dict(os.environ, {"SLACK_WEBHOOK_URL": ""}),
        ):
            result = await process_dunning({})
        assert result["downgraded"] == 8
