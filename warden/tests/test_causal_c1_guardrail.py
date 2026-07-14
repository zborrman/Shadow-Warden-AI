"""
C1 shared-file guardrail (docs/unified-modernization-roadmap.md).

`causal_arbiter.py` is touched by both tracks:
  - DE-5: online Robbins–Monro CPT calibration (`online_update`) — the DAG *learns*.
  - SR-3: the 25%/zero-prior drift gate in `calibrate_from_logs` — anti-poisoning.

The registry's rule: the first shared-file change must add a test asserting **both hold
simultaneously** — i.e. adding online learning did not open a slow-burn poisoning path,
and the two mechanisms share one bound. These tests fail loudly if a future edit to
either side breaks the other.
"""
from __future__ import annotations

import json

import pytest

from warden import causal_arbiter as ca


@pytest.fixture(autouse=True)
def _restore_cpt():
    c = ca._cpt
    saved = (c.obfusc_pos, c.obfusc_neg, c.n_obfusc_pos, c.n_obfusc_neg,
             c.ers_center, c.entropy_center, c.calibration_n)
    ca._reliability_buffer.clear()
    yield
    (c.obfusc_pos, c.obfusc_neg, c.n_obfusc_pos, c.n_obfusc_neg,
     c.ers_center, c.entropy_center, c.calibration_n) = saved
    ca._reliability_buffer.clear()


class TestSharedBound:
    def test_online_and_batch_use_the_same_25pct_constant(self):
        """A single knob. If someone loosens one path, this pins the other to it."""
        # online per-step clamp
        assert ca._ONLINE_MAX_STEP == 0.25
        # batch per-calibration gate — read the literal out of calibrate_from_logs so a
        # drift of the two apart is caught (it is defined as `max_drift = 0.25`).
        import inspect
        src = inspect.getsource(ca.calibrate_from_logs)
        assert "max_drift = 0.25" in src, "batch drift gate no longer 25% — realign with _ONLINE_MAX_STEP"


class TestOnlineLearnsButIsBounded:
    def test_online_update_learns(self):
        """DE-5 lives: repeated positive labels move obfusc_pos toward 1.0."""
        start = ca._cpt.obfusc_pos
        for _ in range(300):
            ca.online_update(obfuscation_detected=True, predicted_p=0.9, observed_high_risk=True)
        assert ca._cpt.obfusc_pos > start          # it learned
        assert ca._cpt.obfusc_pos > 0.9            # toward the empirical mean of 1.0

    def test_no_single_online_step_exceeds_25pct(self):
        """SR-3 bound holds on the online path — worst case is a fresh cell (n=0, eta=1)."""
        for obf in (True, False):
            for label in (True, False):
                before = ca._cpt.obfusc_pos if obf else ca._cpt.obfusc_neg
                ca.online_update(obfuscation_detected=obf, predicted_p=0.5, observed_high_risk=label)
                after = ca._cpt.obfusc_pos if obf else ca._cpt.obfusc_neg
                if before > 0 and after != before:
                    assert abs(after - before) / before <= 0.25 + 1e-9

    def test_slow_burn_many_steps_cannot_invert_ordering(self):
        """
        The poisoning concern with online learning: could many small (<25%) steps walk a
        cell past the gate over time? They converge to the empirical mean (bounded in
        [0,1]) and can never invert obfusc_pos > obfusc_neg — the anti-poisoning ordering
        invariant survives an adversarial all-wrong-direction stream.
        """
        for _ in range(5000):
            ca.online_update(obfuscation_detected=False, predicted_p=0.5, observed_high_risk=True)
            ca.online_update(obfuscation_detected=True, predicted_p=0.5, observed_high_risk=False)
        assert 0.0 <= ca._cpt.obfusc_neg <= 1.0
        assert 0.0 <= ca._cpt.obfusc_pos <= 1.0
        assert ca._cpt.obfusc_pos > ca._cpt.obfusc_neg


class TestBatchGateSurvivesOnline:
    def _logs(self, entries, tmp_path):
        p = tmp_path / "logs.json"
        p.write_text("".join(json.dumps(e) + "\n" for e in entries))
        return str(p)

    def test_batch_drift_gate_still_rejects_after_online_updates(self, tmp_path):
        """
        Running online updates must not disable the batch 25% gate. Drive obfusc_pos to a
        known value online, then feed batch logs implying a >25% swing → rejected.
        """
        # Pin obfusc_pos high via online learning.
        for _ in range(200):
            ca.online_update(obfuscation_detected=True, predicted_p=0.9, observed_high_risk=True)
        anchored = ca._cpt.obfusc_pos
        assert anchored > 0.9

        # Batch logs whose MLE wants obfusc_pos ≈ 0.10 (31/302): a >85% drop from
        # `anchored`. Crucially obfusc HIGH-rate (~10%) still exceeds the clean HIGH-rate
        # (~1%), so the pos>neg ordering sanity check PASSES and we actually reach — and
        # trip — the 25% drift gate, not an earlier bail-out.
        entries = [{"flags": ["OBFUSCATION"], "risk_level": "HIGH", "payload_len": 50}
                   for _ in range(30)]
        entries += [{"flags": ["OBFUSCATION"], "risk_level": "LOW", "payload_len": 50}
                    for _ in range(270)]
        entries += [{"flags": [], "risk_level": "HIGH", "payload_len": 50} for _ in range(3)]
        entries += [{"flags": [], "risk_level": "LOW", "payload_len": 50} for _ in range(297)]
        ca.calibrate_from_logs(self._logs(entries, tmp_path), min_samples=100)

        assert ca._cpt.obfusc_pos == anchored, "batch gate let a >25% drift through after online updates"

    def test_zero_prior_is_safe_on_both_paths(self, tmp_path):
        """
        Zero-prior handling must not divide-by-zero or move unboundedly on either side.
        """
        # Batch: _drift_ok(old=0, ...) returns True (no division). Force obfusc_neg to 0
        # then calibrate — must not raise.
        ca._cpt.obfusc_neg = 0.0
        entries = [{"flags": ["OBFUSCATION"], "risk_level": "HIGH", "payload_len": 50}
                   for _ in range(150)]
        entries += [{"flags": [], "risk_level": "LOW", "payload_len": 50} for _ in range(150)]
        ca.calibrate_from_logs(self._logs(entries, tmp_path), min_samples=100)  # no exception

        # Online: theta=0 uses the absolute step cap, never an unbounded jump.
        ca._cpt.obfusc_neg = 0.0
        ca._cpt.n_obfusc_neg = 0
        ca.online_update(obfuscation_detected=False, predicted_p=0.5, observed_high_risk=True)
        assert 0.0 <= ca._cpt.obfusc_neg <= ca._ONLINE_MAX_STEP + 1e-9
