"""
Direct unit tests for CausalArbiter — Layer 6 Bayesian DAG.

Tests cover:
  - Clean profile → is_high_risk=False
  - Multi-signal high-risk → is_high_risk=True
  - Obfuscation alone raises risk
  - ERS sigmoid monotonicity
  - Block history escalation
  - Tool tier impact
  - SE-Arbiter node dormant by default
  - SE-Arbiter active with se_risk input
  - P(HIGH_RISK) in [0,1] always
  - Per-node breakdown present in result
  - do-calculus: CPT drift gate rejects > 25% shift
  - Fail-open: any exception → is_high_risk=False
  - calibrate_from_logs: valid JSON updates CPT
  - calibrate_from_logs: drift gate blocks large shift
"""
from __future__ import annotations

import json

import pytest

from warden.causal_arbiter import CausalResult, _cpt, _sigmoid, arbitrate, calibrate_from_logs

# ── Helpers ────────────────────────────────────────────────────────────────────

def _clean_args(**overrides):
    defaults = {
        "ml_score": 0.1,
        "ers_score": 0.05,
        "obfuscation_detected": False,
        "block_history": 0,
        "tool_tier": 0,
        "content_entropy": 3.5,
        "se_risk": 0.0,
    }
    defaults.update(overrides)
    return defaults


# ── Sigmoid helper ─────────────────────────────────────────────────────────────

class TestSigmoid:
    def test_sigmoid_0_is_half(self):
        assert abs(_sigmoid(0.0) - 0.5) < 1e-9

    def test_sigmoid_large_positive_near_1(self):
        assert _sigmoid(100.0) > 0.999

    def test_sigmoid_large_negative_near_0(self):
        assert _sigmoid(-100.0) < 0.001

    def test_sigmoid_monotone(self):
        vals = [_sigmoid(x) for x in [-5, -2, 0, 2, 5]]
        assert all(vals[i] < vals[i + 1] for i in range(len(vals) - 1))

    def test_sigmoid_range(self):
        for x in [-10, -1, 0, 1, 10]:
            s = _sigmoid(x)
            assert 0.0 < s < 1.0


# ── Clean profile ──────────────────────────────────────────────────────────────

class TestCleanProfile:
    def test_all_zero_signals_not_high_risk(self):
        result = arbitrate(**_clean_args())
        assert isinstance(result, CausalResult)
        assert result.is_high_risk is False

    def test_low_ers_low_probability(self):
        result = arbitrate(**_clean_args(ers_score=0.0))
        assert result.risk_probability < 0.5

    def test_normal_entropy_not_flagged(self):
        result = arbitrate(**_clean_args(content_entropy=4.2))
        assert result.is_high_risk is False

    def test_clean_result_fields_present(self):
        result = arbitrate(**_clean_args())
        assert hasattr(result, "p_reputation")
        assert hasattr(result, "p_content_risk")
        assert hasattr(result, "p_persistence")
        assert hasattr(result, "p_tool_risk")
        assert hasattr(result, "p_entropy_risk")
        assert hasattr(result, "p_se_risk")
        assert hasattr(result, "detail")


# ── High-risk profiles ─────────────────────────────────────────────────────────

class TestHighRiskProfiles:
    def test_high_ers_raises_risk(self):
        clean = arbitrate(**_clean_args(ers_score=0.05))
        risky = arbitrate(**_clean_args(ers_score=0.9))
        assert risky.risk_probability > clean.risk_probability

    def test_obfuscation_raises_risk(self):
        no_obf = arbitrate(**_clean_args(obfuscation_detected=False))
        obf    = arbitrate(**_clean_args(obfuscation_detected=True))
        assert obf.risk_probability > no_obf.risk_probability

    def test_block_history_monotone(self):
        prev = 0.0
        for blocks in [0, 1, 3, 10]:
            result = arbitrate(**_clean_args(block_history=blocks))
            assert result.risk_probability >= prev
            prev = result.risk_probability

    def test_destructive_tool_tier_higher_risk(self):
        read   = arbitrate(**_clean_args(tool_tier=0))
        write  = arbitrate(**_clean_args(tool_tier=1))
        destr  = arbitrate(**_clean_args(tool_tier=2))
        assert destr.risk_probability >= write.risk_probability >= read.risk_probability

    def test_full_attack_profile_high_risk(self):
        result = arbitrate(
            ml_score=0.92,
            ers_score=0.85,
            obfuscation_detected=True,
            block_history=5,
            tool_tier=2,
            content_entropy=5.8,
            se_risk=0.9,
        )
        assert result.is_high_risk is True
        assert result.risk_probability > 0.65

    def test_high_entropy_raises_risk(self):
        normal  = arbitrate(**_clean_args(content_entropy=4.0))
        extreme = arbitrate(**_clean_args(content_entropy=6.5))
        assert extreme.risk_probability > normal.risk_probability


# ── SE-Arbiter node ────────────────────────────────────────────────────────────

class TestSEArbiterNode:
    def test_se_risk_zero_dormant(self):
        without_se = arbitrate(**_clean_args(se_risk=0.0))
        assert without_se.p_se_risk == 0.0

    def test_se_risk_nonzero_active(self):
        result = arbitrate(**_clean_args(se_risk=0.8))
        assert result.p_se_risk > 0.0

    def test_se_risk_1_0_maximizes_se_node(self):
        result = arbitrate(**_clean_args(se_risk=1.0))
        assert result.p_se_risk > 0.5

    def test_se_risk_monotone_effect_on_total(self):
        low  = arbitrate(**_clean_args(se_risk=0.1))
        high = arbitrate(**_clean_args(se_risk=0.9))
        assert high.risk_probability >= low.risk_probability


# ── Probability bounds ─────────────────────────────────────────────────────────

class TestProbabilityBounds:
    @pytest.mark.parametrize("ers,obf,blocks,tier,entropy,se", [
        (0.0, False, 0, 0, 3.5, 0.0),
        (1.0, True,  10, 2, 6.0, 1.0),
        (0.5, True,  2, 1, 4.5, 0.5),
        (0.1, False, 0, 0, 4.0, 0.0),
    ])
    def test_risk_probability_in_unit_interval(self, ers, obf, blocks, tier, entropy, se):
        result = arbitrate(
            ml_score=0.5, ers_score=ers, obfuscation_detected=obf,
            block_history=blocks, tool_tier=tier, content_entropy=entropy,
            se_risk=se,
        )
        assert 0.0 <= result.risk_probability <= 1.0

    def test_per_node_probabilities_in_unit_interval(self):
        result = arbitrate(**_clean_args(ers_score=0.5, obfuscation_detected=True))
        for field in ("p_reputation", "p_content_risk", "p_persistence",
                      "p_tool_risk", "p_entropy_risk", "p_se_risk"):
            val = getattr(result, field)
            assert 0.0 <= val <= 1.0, f"{field}={val} out of [0,1]"


# ── CPT drift gate ─────────────────────────────────────────────────────────────

class TestCPTDriftGate:
    def _log_file(self, entries: list[dict], tmp_path) -> str:
        p = tmp_path / "logs.json"
        with open(p, "w") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")
        return str(p)

    def test_calibrate_with_no_data_is_noop(self, tmp_path):
        before = _cpt.ers_center
        path = self._log_file([], tmp_path)
        calibrate_from_logs(path)
        assert _cpt.ers_center == before

    def test_calibrate_with_invalid_path_noop(self):
        before = _cpt.ers_center
        calibrate_from_logs("/nonexistent/path.json")
        assert _cpt.ers_center == before

    def test_calibrate_valid_logs_does_not_crash(self, tmp_path):
        entries = [
            {"risk_level": "HIGH", "causal_arbiter": {"ers_score": 0.8, "obfuscation": True}},
            {"risk_level": "LOW",  "causal_arbiter": {"ers_score": 0.1, "obfuscation": False}},
        ]
        path = self._log_file(entries, tmp_path)
        # Should not raise
        calibrate_from_logs(path)

    def test_calibrate_success_pins_mle_arithmetic(self, tmp_path, monkeypatch):
        """The success path (Laplace smoothing, block-rate/entropy proxies,
        round-to-4dp) had zero coverage -- only the no-op/no-crash paths were
        tested. Baseline chosen so every shift lands comfortably inside the
        25% drift gate; entries use the real top-level flags/risk_level/
        payload_len schema (the pre-existing fixture above nests them under
        a "causal_arbiter" key the parser never reads)."""
        monkeypatch.setattr(_cpt, "obfusc_pos", 0.45)
        monkeypatch.setattr(_cpt, "obfusc_neg", 0.25)
        monkeypatch.setattr(_cpt, "ers_center", 0.50)
        monkeypatch.setattr(_cpt, "entropy_center", 4.5)

        entries = [
            {"flags": ["OBFUSCATION"], "risk_level": "HIGH", "payload_len": 200},
            {"flags": ["OBFUSCATION"], "risk_level": "LOW",  "payload_len": 50},
            {"flags": [],              "risk_level": "LOW",  "payload_len": 50},
            {"flags": [],              "risk_level": "LOW",  "payload_len": 50},
        ]
        path = self._log_file(entries, tmp_path)

        assert calibrate_from_logs(path, min_samples=4) is True
        # obfusc: 1 high / 2 total -> (1+1)/(2+2) = 0.5
        assert _cpt.obfusc_pos == 0.5
        # clean: 0 high / 2 total -> (0+1)/(2+2) = 0.25
        assert _cpt.obfusc_neg == 0.25
        # block_rate = 1/4 = 0.25; shift = (0.25-0.05)*0.5 = 0.10; 0.50-0.10 = 0.40
        assert _cpt.ers_center == 0.40
        # median blocked payload_len (200) == the log1p(200) anchor -> zero shift
        assert _cpt.entropy_center == 4.5
        assert _cpt.calibration_n == 4
        assert _cpt.calibrated_from == path

    def test_calibrate_rejects_when_obfusc_pos_not_greater_than_neg(self, tmp_path, monkeypatch):
        """Data-quality gate: if the obfuscated bucket isn't riskier than the
        clean bucket, the update must be rejected and the CPT left untouched."""
        before_pos, before_neg = _cpt.obfusc_pos, _cpt.obfusc_neg
        entries = [
            {"flags": ["OBFUSCATION"], "risk_level": "LOW", "payload_len": 50},
            {"flags": [],              "risk_level": "HIGH", "payload_len": 50},
        ]
        path = self._log_file(entries, tmp_path)
        assert calibrate_from_logs(path, min_samples=2) is False
        assert _cpt.obfusc_pos == before_pos
        assert _cpt.obfusc_neg == before_neg

    def test_calibrate_exact_min_samples_boundary(self, tmp_path, caplog):
        """len(entries) < min_samples must reject via the sample-count guard
        specifically; len(entries) == min_samples must pass that guard (it may
        still be rejected further down by the drift gate -- this test only
        pins the < vs <= boundary via the guard's own debug message)."""
        entries = [
            {"flags": ["OBFUSCATION"], "risk_level": "HIGH", "payload_len": 50},
            {"flags": [],              "risk_level": "LOW",  "payload_len": 50},
        ]
        path = self._log_file(entries, tmp_path)
        with caplog.at_level("DEBUG", logger="warden.causal_arbiter"):
            calibrate_from_logs(path, min_samples=3)   # 2 < 3 -> guard rejects
        assert any("only 2 samples (need 3)" in r.message for r in caplog.records)

        caplog.clear()
        with caplog.at_level("DEBUG", logger="warden.causal_arbiter"):
            calibrate_from_logs(path, min_samples=2)   # 2 == 2 -> guard passes
        assert not any("only 2 samples" in r.message for r in caplog.records)

    def test_drift_gate_reaches_ers_center_check(self, tmp_path, monkeypatch, caplog):
        """The documented gap (docs/pre-production-plan.md, SR-7.3): the four
        `_drift_ok(...)` calls are chained with `and`, which short-circuits on
        the first False. Every prior test's drift lived entirely in
        obfusc_pos/obfusc_neg, so nothing ever proved evaluation reaches
        ers_center's own check -- a mutant that no-ops, reorders, or None's
        that specific call would have survived undetected.

        obfusc_pos/obfusc_neg are tuned to drift <25% (so the chain doesn't
        short-circuit before reaching ers_center); block_rate is tuned so
        ers_center alone drifts >25%.
        """
        monkeypatch.setattr(_cpt, "obfusc_pos", 0.6)
        monkeypatch.setattr(_cpt, "obfusc_neg", 0.2)
        monkeypatch.setattr(_cpt, "ers_center", 0.50)
        monkeypatch.setattr(_cpt, "entropy_center", 4.5)

        entries = (
            [{"flags": ["OBFUSCATION"], "risk_level": "HIGH", "payload_len": 50}] * 3
            + [{"flags": ["OBFUSCATION"], "risk_level": "LOW",  "payload_len": 50}] * 2
            + [{"flags": [],             "risk_level": "HIGH", "payload_len": 50}] * 1
            + [{"flags": [],             "risk_level": "LOW",  "payload_len": 50}] * 5
        )
        path = self._log_file(entries, tmp_path)

        # new_obfusc_pos = (3+1)/(5+2) = 0.5714 -> 4.8% drift (passes)
        # new_obfusc_neg = (1+1)/(6+2) = 0.25   -> 25.0% drift, not >25% (passes)
        # block_rate = 4/11 = 0.3636 -> shift 0.1568 -> new_ers_center = 0.3432
        #   -> 31.4% drift (fails)
        with caplog.at_level("WARNING", logger="warden.causal_arbiter"):
            assert calibrate_from_logs(path, min_samples=11) is False
        assert any("CPT[ers_center] drift" in r.message for r in caplog.records)
        assert _cpt.ers_center == 0.50   # rejected -- must be untouched

    def test_drift_gate_reaches_entropy_center_check(self, tmp_path, monkeypatch, caplog):
        """Companion to the ers_center test above: proves evaluation reaches
        the LAST `_drift_ok` call in the chain too. obfusc_pos, obfusc_neg,
        AND ers_center are all tuned to drift <25%; only entropy_center (via
        one deliberately huge blocked payload_len) exceeds it. Without this,
        a mutant breaking entropy_center's specific check -- the one every
        earlier check's short-circuit would hide -- had zero coverage."""
        monkeypatch.setattr(_cpt, "obfusc_pos", 0.6)
        monkeypatch.setattr(_cpt, "obfusc_neg", 0.2)
        monkeypatch.setattr(_cpt, "ers_center", 0.50)
        monkeypatch.setattr(_cpt, "entropy_center", 3.6)

        entries = (
            [{"flags": ["OBFUSCATION"], "risk_level": "HIGH", "payload_len": 50}]
            + [{"flags": [], "risk_level": "HIGH", "payload_len": 10**15}]   # dominates median
            + [{"flags": [], "risk_level": "LOW",  "payload_len": 50}] * 7
        )
        path = self._log_file(entries, tmp_path)

        # new_obfusc_pos = (1+1)/(1+2) = 0.667  -> 11.1% drift (passes)
        # new_obfusc_neg = (1+1)/(8+2) = 0.2    -> 0% drift (passes)
        # block_rate = 2/9 = 0.222 -> shift 0.086 -> new_ers_center = 0.414
        #   -> 17.2% drift (passes)
        # median blocked_len = 10**15 -> entropy_shift ~= +1.65 (uncapped by the
        #   per-call *0.3 factor; clamped to [3.5,5.5] only at the CPT level) ->
        #   new_entropy_center = 5.254 -> 45.9% drift (fails)
        with caplog.at_level("WARNING", logger="warden.causal_arbiter"):
            assert calibrate_from_logs(path, min_samples=9) is False
        assert any("CPT[entropy_center] drift" in r.message for r in caplog.records)
        assert _cpt.entropy_center == 3.6   # rejected -- must be untouched


# ── Drift-gate chain (SR-7.3 mutation-testing gap) ─────────────────────────────
#
# The three tests above never exercise the actual MLE-calibration-and-apply
# path: they stay under min_samples (default 100), or use a log-entry shape
# (`causal_arbiter.obfuscation`) calibrate_from_logs never reads — it reads
# top-level `flags`/`risk_level`/`payload_len` (see analytics/logger.py).
# Nothing here has ever driven >= min_samples of real data through the four
# `_drift_ok(...)` calls that gate the update.
#
# That gap matters because `_drift_ok` is a closure inside a function whose
# entire body sits inside `except Exception: return False` (fail-open, by
# design — a corrupt log file must never crash startup). If a `_drift_ok`
# call's argument is corrupted (e.g. `old` swapped for `None`), the internal
# `abs(new - old)` raises `TypeError`, and the outer handler silently turns
# that into the *same* `False` return a genuine drift-rejection produces.
# Nothing here distinguished "correctly rejected" from "silently crashed" —
# which is exactly why mutation testing found the whole four-call chain
# (`obfusc_pos`/`obfusc_neg`/`ers_center`/`entropy_center`) could have any
# argument replaced with `None`, reordered, or relabeled without any test
# noticing. The tests below close that: one drives a real calibration to a
# successful, value-checked update (which fails the instant any one argument
# in the chain is wrong), and one proves the gate rejects an update on a
# single genuinely-drifted parameter while leaving the other three — and the
# applied CPT — untouched. That second property is the actual security
# guarantee this gate exists for: a coordinated attacker who keeps most
# parameters borderline-safe while pushing one past the 25% threshold must
# still be caught.

class TestCalibrateFromLogsAppliesRealValues:
    """Drives calibrate_from_logs() through a full, min_samples-sized MLE
    update and pins the exact resulting CPT — not just "did it run"."""

    @pytest.fixture(autouse=True)
    def _reset_cpt(self):
        # _cpt is a module-level singleton mutated in place by calibration;
        # snapshot and restore so this class can't leak state into other tests.
        before = {
            "ers_center": _cpt.ers_center, "obfusc_pos": _cpt.obfusc_pos,
            "obfusc_neg": _cpt.obfusc_neg, "entropy_center": _cpt.entropy_center,
        }
        yield
        _cpt.ers_center, _cpt.obfusc_pos = before["ers_center"], before["obfusc_pos"]
        _cpt.obfusc_neg, _cpt.entropy_center = before["obfusc_neg"], before["entropy_center"]

    def _log_file(self, entries: list[dict], tmp_path) -> str:
        p = tmp_path / "logs.json"
        with open(p, "w") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")
        return str(p)

    def test_happy_path_updates_all_four_parameters_to_exact_values(self, tmp_path):
        """All four _drift_ok checks pass; verifies the exact MLE output.

        This is the test that actually exercises every argument of every
        _drift_ok(...) call with real, distinguishing data — if any argument
        in the chain (old/new/label, any of the four calls) were corrupted,
        the internal TypeError would be swallowed and this would assert
        False, not the exact values below.
        """
        _cpt.ers_center, _cpt.obfusc_pos = 0.35, 0.82
        _cpt.obfusc_neg, _cpt.entropy_center = 0.12, 4.5

        entries = (
            [{"flags": ["OBFUSCATION"], "risk_level": "HIGH", "payload_len": 220}] * 11
            + [{"flags": ["OBFUSCATION"], "risk_level": "LOW", "payload_len": 60}] * 4
            + [{"flags": [], "risk_level": "HIGH", "payload_len": 200}] * 9
            + [{"flags": [], "risk_level": "LOW", "payload_len": 55}] * 76
        )
        assert len(entries) == 100
        path = self._log_file(entries, tmp_path)

        assert calibrate_from_logs(path, min_samples=100) is True
        assert _cpt.ers_center == pytest.approx(0.275)
        assert _cpt.obfusc_pos == pytest.approx(0.7059)
        assert _cpt.obfusc_neg == pytest.approx(0.1149)
        assert _cpt.entropy_center == pytest.approx(4.5054)
        assert _cpt.calibration_n == 100

    def test_single_parameter_drift_rejects_whole_update_atomically(self, tmp_path):
        """One parameter (ers_center) drifts >25% while obfusc_pos/neg and
        entropy_center all stay within bounds — the coordinated slow-burn
        poisoning scenario the drift gate exists to stop. The whole update
        must be rejected, and NONE of the four CPT fields may change: a
        mutant that reordered the `_drift_ok` calls relative to the `_cpt.x =
        ...` assignments, or dropped one call from the `and`-chain, would let
        a partial update through here.
        """
        _cpt.ers_center, _cpt.obfusc_pos = 0.35, 0.82
        _cpt.obfusc_neg, _cpt.entropy_center = 0.12, 4.5

        entries = (
            [{"flags": ["OBFUSCATION"], "risk_level": "HIGH", "payload_len": 220}] * 22
            + [{"flags": ["OBFUSCATION"], "risk_level": "LOW", "payload_len": 60}] * 3
            + [{"flags": [], "risk_level": "HIGH", "payload_len": 200}] * 8
            + [{"flags": [], "risk_level": "LOW", "payload_len": 55}] * 67
        )
        assert len(entries) == 100
        path = self._log_file(entries, tmp_path)

        assert calibrate_from_logs(path, min_samples=100) is False
        assert _cpt.ers_center == 0.35
        assert _cpt.obfusc_pos == 0.82
        assert _cpt.obfusc_neg == 0.12
        assert _cpt.entropy_center == 4.5

    def test_inverted_correlation_rejected_before_drift_gate(self, tmp_path):
        """When obfuscated entries correlate with LOW risk and clean entries
        correlate with HIGH risk — inverted from the real-world assumption
        this module is built on — new_obfusc_pos <= new_obfusc_neg and the
        update is rejected as a data-quality issue, never reaching the drift
        gate at all. Distinct rejection path from the two tests above.
        """
        _cpt.ers_center, _cpt.obfusc_pos = 0.35, 0.82
        _cpt.obfusc_neg, _cpt.entropy_center = 0.12, 4.5

        entries = (
            [{"flags": ["OBFUSCATION"], "risk_level": "HIGH", "payload_len": 100}] * 2
            + [{"flags": ["OBFUSCATION"], "risk_level": "LOW", "payload_len": 50}] * 18
            + [{"flags": [], "risk_level": "HIGH", "payload_len": 100}] * 60
            + [{"flags": [], "risk_level": "LOW", "payload_len": 50}] * 20
        )
        assert len(entries) == 100
        path = self._log_file(entries, tmp_path)

        assert calibrate_from_logs(path, min_samples=100) is False
        assert _cpt.ers_center == 0.35
        assert _cpt.obfusc_pos == 0.82
        assert _cpt.obfusc_neg == 0.12
        assert _cpt.entropy_center == 4.5


# ── Fail-open ──────────────────────────────────────────────────────────────────

class TestFailOpen:
    def test_nan_input_does_not_raise(self):
        """NaN propagates through sigmoid — result may be is_high_risk True; must not raise."""
        result = arbitrate(
            ml_score=float("nan"), ers_score=float("nan"),
            obfuscation_detected=False, block_history=0,
            tool_tier=0, content_entropy=float("nan"),
        )
        assert isinstance(result, CausalResult)
        assert isinstance(result.is_high_risk, bool)  # NaN may trigger high risk

    def test_inf_input_does_not_raise(self):
        result = arbitrate(
            ml_score=float("inf"), ers_score=float("inf"),
            obfuscation_detected=True, block_history=999,
            tool_tier=5, content_entropy=float("inf"),
        )
        assert isinstance(result, CausalResult)
        assert isinstance(result.is_high_risk, bool)


# ── Backdoor correction ────────────────────────────────────────────────────────

class TestBackdoorCorrection:
    def test_obfuscation_independent_of_ers_confounding(self):
        """
        Verify that obfuscation raises risk even when ERS is 0
        (spurious correlation removed via backdoor correction).
        """
        no_obf_low_ers = arbitrate(**_clean_args(ers_score=0.0, obfuscation_detected=False))
        obf_low_ers    = arbitrate(**_clean_args(ers_score=0.0, obfuscation_detected=True))
        assert obf_low_ers.risk_probability > no_obf_low_ers.risk_probability

    def test_block_history_contributes_independently(self):
        """Block history raises risk even with clean ERS and no obfuscation."""
        clean    = arbitrate(**_clean_args(block_history=0))
        repeated = arbitrate(**_clean_args(block_history=5))
        assert repeated.risk_probability > clean.risk_probability
