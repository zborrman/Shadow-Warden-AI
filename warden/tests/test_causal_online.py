"""
Phase 5 — Causal Arbiter online calibration (Robbins–Monro CPT updates).

Property-style tests (no hypothesis dependency) covering:
  - online_update keeps CPT cells in [0, 1]
  - convergence: η_t = 1/(1+n) drives θ toward the empirical mean label rate
  - 25%-per-step drift clamp is never exceeded (poisoning guarantee preserved)
  - obfusc_pos > obfusc_neg ordering invariant is preserved
  - fail-open: bad input never raises
  - reliability_curve bins are well-formed and reflect observed labels
  - online_state snapshot shape
"""
from __future__ import annotations

import pytest

from warden import causal_arbiter as ca


@pytest.fixture(autouse=True)
def _reset_online_state():
    """Restore the module-level CPT cells + counters + buffer around each test."""
    c = ca._cpt
    saved = (c.obfusc_pos, c.obfusc_neg, c.n_obfusc_pos, c.n_obfusc_neg)
    ca._reliability_buffer.clear()
    yield
    c.obfusc_pos, c.obfusc_neg, c.n_obfusc_pos, c.n_obfusc_neg = saved
    ca._reliability_buffer.clear()


# ── Bounds ──────────────────────────────────────────────────────────────────

class TestBounds:
    @pytest.mark.parametrize("obf", [True, False])
    @pytest.mark.parametrize("label", [True, False])
    def test_cell_stays_in_unit_interval(self, obf, label):
        for _ in range(500):
            ca.online_update(
                obfuscation_detected=obf, predicted_p=0.5, observed_high_risk=label
            )
        assert 0.0 <= ca._cpt.obfusc_pos <= 1.0
        assert 0.0 <= ca._cpt.obfusc_neg <= 1.0


# ── Convergence ─────────────────────────────────────────────────────────────

class TestConvergence:
    def test_all_positive_labels_push_obfusc_pos_up(self):
        start = ca._cpt.obfusc_pos
        for _ in range(200):
            ca.online_update(
                obfuscation_detected=True, predicted_p=0.9, observed_high_risk=True
            )
        assert ca._cpt.obfusc_pos > start
        assert ca._cpt.obfusc_pos > 0.9  # converges toward label mean of 1.0

    def test_mixed_labels_converge_near_empirical_mean(self):
        # 70% positive labels → obfusc_pos should approach ~0.7
        for i in range(1000):
            ca.online_update(
                obfuscation_detected=True,
                predicted_p=0.5,
                observed_high_risk=(i % 10 < 7),
            )
        assert 0.6 <= ca._cpt.obfusc_pos <= 0.8

    def test_step_size_decays_with_count(self):
        ca.online_update(obfuscation_detected=False, predicted_p=0.1, observed_high_risk=True)
        first_n = ca._cpt.n_obfusc_neg
        for _ in range(50):
            ca.online_update(
                obfuscation_detected=False, predicted_p=0.1, observed_high_risk=True
            )
        # Counter increments monotonically as samples accrue.
        assert ca._cpt.n_obfusc_neg > first_n


# ── Drift clamp (poisoning guarantee) ────────────────────────────────────────

class TestDriftClamp:
    def test_single_step_never_exceeds_25pct(self):
        for label in (True, False):
            for obf in (True, False):
                before = ca._cpt.obfusc_pos if obf else ca._cpt.obfusc_neg
                ca.online_update(
                    obfuscation_detected=obf, predicted_p=0.5, observed_high_risk=label
                )
                after = ca._cpt.obfusc_pos if obf else ca._cpt.obfusc_neg
                if before > 0 and after != before:
                    drift = abs(after - before) / before
                    assert drift <= 0.25 + 1e-6, f"drift {drift:.3f} exceeds 25% clamp"

    def test_ordering_invariant_preserved(self):
        # Hammer obfusc_neg upward and obfusc_pos downward; they must not cross.
        for _ in range(2000):
            ca.online_update(obfuscation_detected=False, predicted_p=0.5, observed_high_risk=True)
            ca.online_update(obfuscation_detected=True, predicted_p=0.5, observed_high_risk=False)
        assert ca._cpt.obfusc_pos > ca._cpt.obfusc_neg


# ── Fail-open ────────────────────────────────────────────────────────────────

class TestFailOpen:
    def test_nan_predicted_does_not_raise(self):
        ok = ca.online_update(
            obfuscation_detected=True,
            predicted_p=float("nan"),
            observed_high_risk=True,
        )
        assert isinstance(ok, bool)

    def test_none_label_coerced_not_raised(self):
        # observed_high_risk is truth-tested; any object works, never raises.
        ok = ca.online_update(
            obfuscation_detected=False, predicted_p=0.3, observed_high_risk=0
        )
        assert isinstance(ok, bool)


# ── Reliability curve ────────────────────────────────────────────────────────

class TestReliabilityCurve:
    def test_bins_wellformed(self):
        for i in range(100):
            ca.online_update(
                obfuscation_detected=True,
                predicted_p=i / 100.0,
                observed_high_risk=(i % 2 == 0),
            )
        bins = ca.reliability_curve(n_bins=10)
        assert len(bins) == 10
        total = sum(b["count"] for b in bins)
        assert total == 100
        for b in bins:
            assert 0.0 <= b["mean_predicted"] <= 1.0
            assert 0.0 <= b["mean_observed"] <= 1.0
            assert b["bin_lo"] < b["bin_hi"]

    def test_perfect_calibration_tracks_diagonal(self):
        # Feed p=0.05 with 5% positives, p=0.95 with 95% positives → near-diagonal.
        for i in range(100):
            ca.online_update(
                obfuscation_detected=True, predicted_p=0.05, observed_high_risk=(i < 5)
            )
            ca.online_update(
                obfuscation_detected=True, predicted_p=0.95, observed_high_risk=(i < 95)
            )
        bins = ca.reliability_curve(n_bins=10)
        low_bin = bins[0]
        high_bin = bins[9]
        assert abs(low_bin["mean_observed"] - low_bin["mean_predicted"]) < 0.15
        assert abs(high_bin["mean_observed"] - high_bin["mean_predicted"]) < 0.15

    def test_upper_edge_included_in_last_bin(self):
        ca.online_update(obfuscation_detected=True, predicted_p=1.0, observed_high_risk=True)
        bins = ca.reliability_curve(n_bins=10)
        assert bins[-1]["count"] == 1


# ── State snapshot ───────────────────────────────────────────────────────────

class TestOnlineState:
    def test_state_shape(self):
        ca.online_update(obfuscation_detected=True, predicted_p=0.6, observed_high_risk=True)
        st = ca.online_state()
        for key in ("obfusc_pos", "obfusc_neg", "n_obfusc_pos", "n_obfusc_neg", "samples"):
            assert key in st
        assert st["samples"] >= 1


# ── Fail-open error paths (SR-7.2) ────────────────────────────────────────────
#
# The arbiter is a detection component: every internal error must fail OPEN
# (never block a legitimate request) and, where applicable, record a failopen
# telemetry event. These pin the four exception handlers.

class TestFailOpenPaths:
    def test_online_update_bad_input_returns_false_and_records_failopen(self, monkeypatch):
        """A non-numeric predicted_p raises inside online_update → caught, False, telemetry."""
        seen = {}
        monkeypatch.setattr(
            ca, "record_failopen",
            lambda stage, reason, exc: seen.update(stage=stage),
        )
        # object() is not float-convertible → TypeError inside the try block.
        result = ca.online_update(
            obfuscation_detected=True, predicted_p=object(), observed_high_risk=True  # type: ignore[arg-type]
        )
        assert result is False
        assert seen.get("stage") == "causal_online"

    def test_calibrate_skips_malformed_json_lines(self, tmp_path):
        """A corrupt NDJSON line is skipped (continue), valid lines still counted."""
        p = tmp_path / "logs.json"
        good = '{"flags": ["OBFUSCATION"], "risk_level": "BLOCK", "payload_len": 300}'
        clean = '{"flags": [], "risk_level": "LOW", "payload_len": 20}'
        lines = [good, good, "{ not valid json", clean, clean]
        p.write_text("\n".join(lines) + "\n")
        # min_samples=4: the 4 valid entries clear the bar; the bad line is skipped.
        # Returns True or False depending on the drift gate, but must not raise.
        result = ca.calibrate_from_logs(str(p), min_samples=4)
        assert result in (True, False)

    def test_calibrate_directory_path_fails_open(self, tmp_path):
        """A path that exists but can't be read as a file → caught, returns False."""
        # tmp_path is a directory: exists() is True, open('r') raises → outer except.
        assert ca.calibrate_from_logs(str(tmp_path), min_samples=1) is False

    def test_arbitrate_fails_open_on_internal_error(self, monkeypatch):
        """If a node mechanism raises, arbitrate returns a safe not-high-risk result."""
        seen = {}
        monkeypatch.setattr(
            ca, "record_failopen",
            lambda stage, reason, exc: seen.update(stage=stage),
        )

        def _boom(_x):
            raise RuntimeError("sigmoid exploded")

        monkeypatch.setattr(ca, "_sigmoid", _boom)
        res = ca.arbitrate(
            ml_score=0.9, ers_score=0.9, obfuscation_detected=True,
            block_history=5, tool_tier=2, content_entropy=5.0,
        )
        assert res.is_high_risk is False        # fail-open: never block on error
        assert res.risk_probability == 0.0
        assert "fail-open" in res.detail
        assert seen.get("stage") == "causal"
