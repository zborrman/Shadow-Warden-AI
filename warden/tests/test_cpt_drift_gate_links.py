"""
warden/tests/test_cpt_drift_gate_links.py

The CPT anti-poisoning gate, tested link by link.

`causal_arbiter.calibrate_from_logs` ends in a short-circuiting `and` chain:

    _drift_ok(obfusc_pos) and _drift_ok(obfusc_neg)
    and _drift_ok(ers_center) and _drift_ok(entropy_center)

SR-7.3's first mutation sweep left 405 survivors in this module, and the
concrete finding (recorded in CLAUDE.md) was that **every argument of every
call in that chain could be replaced with `None`, relabelled, or reordered
without a single test noticing** — because no test ever reached a state where
an earlier link passes and a *later* parameter's specific drift value is what
rejects. Short-circuit evaluation means one test that trips the first link
exercises nothing after it.

That is exactly the scenario the gate documents itself as existing to stop:
a coordinated slow-burn attacker nudging one CPT parameter past 25% while
holding the others inside it.

Each test below uses the **same corpus** and varies only the priors, so the
parameter under test is unambiguously the one that rejects.

    corpus: 6 obfuscated (3 HIGH) + 14 clean (1 HIGH), 20 entries
      obfusc_pos_new = (3+1)/(6+2)   = 0.500
      obfusc_neg_new = (1+1)/(14+2)  = 0.125
      block_rate     = 4/20 = 0.20 → ers shift = (0.20-0.05)*0.5 = 0.075
      median blocked payload_len = 200 = the log1p(200) anchor → entropy shift 0
"""
from __future__ import annotations

import json
import math

import pytest

from warden.causal_arbiter import _cpt, calibrate_from_logs

#: 20 entries in the real journal schema — top-level `flags` / `risk_level` /
#: `payload_len`, all of which `analytics/logger.build_entry()` actually writes.
_CORPUS = (
    [{"flags": ["OBFUSCATION"], "risk_level": "HIGH", "payload_len": 200}] * 3
    + [{"flags": ["OBFUSCATION"], "risk_level": "LOW", "payload_len": 50}] * 3
    + [{"flags": [], "risk_level": "HIGH", "payload_len": 200}]
    + [{"flags": [], "risk_level": "LOW", "payload_len": 50}] * 13
)

_NEW_POS = 0.5
_NEW_NEG = 0.125
_ERS_SHIFT = 0.075


@pytest.fixture()
def corpus(tmp_path):
    path = tmp_path / "logs.json"
    path.write_text("\n".join(json.dumps(e) for e in _CORPUS) + "\n", encoding="utf-8")
    return str(path)


def _priors(monkeypatch, *, pos: float, neg: float, ers: float, entropy: float = 4.5):
    monkeypatch.setattr(_cpt, "obfusc_pos", pos)
    monkeypatch.setattr(_cpt, "obfusc_neg", neg)
    monkeypatch.setattr(_cpt, "ers_center", ers)
    monkeypatch.setattr(_cpt, "entropy_center", entropy)


# ── The reachable links, one at a time ────────────────────────────────────────

def test_all_four_within_threshold_is_accepted(corpus, monkeypatch):
    """The control. Without this, a test that rejects proves nothing about
    *which* link rejected — the whole chain could be inert."""
    _priors(monkeypatch, pos=0.55, neg=0.15, ers=0.35)

    assert calibrate_from_logs(corpus, min_samples=20) is True
    assert _cpt.obfusc_pos == _NEW_POS
    assert _cpt.obfusc_neg == _NEW_NEG
    assert _cpt.ers_center == round(0.35 - _ERS_SHIFT, 4)


def test_link1_obfusc_pos_drift_rejects(corpus, monkeypatch, caplog):
    """0.500 against a 0.39 prior = 28.2% drift.

    The prior is deliberately *below* the new value. Drift is relative to the
    old value, so a swapped-argument mutation computes 0.11/0.5 = 22% and
    accepts — this prior makes the argument order observable, which a
    symmetric case like 0.80→0.50 (37.5% either way) does not.
    """
    _priors(monkeypatch, pos=0.39, neg=0.15, ers=0.35)

    with caplog.at_level("WARNING"):
        assert calibrate_from_logs(corpus, min_samples=20) is False
    # Bracketed, not a bare substring: the log format is `CPT[%s] drift`, and
    # `"obfusc_pos" in text` also passes against a mutated label such as
    # `XXobfusc_posXX`. Verified — that mutant survived the bare check.
    assert "CPT[obfusc_pos]" in caplog.text, (
        "the operator must be told which parameter tripped"
    )
    assert _cpt.obfusc_pos == 0.39, "a rejected update must leave the CPT untouched"
    assert _cpt.obfusc_neg == 0.15
    assert _cpt.ers_center == 0.35


def test_link2_obfusc_neg_drift_rejects_while_pos_is_fine(corpus, monkeypatch, caplog):
    """The first link passes (9.1%), the second does not (27.6%).

    This is the case the mutation sweep proved no test reached: rejection
    attributable to the *second* argument pair, with the first satisfied.
    """
    _priors(monkeypatch, pos=0.55, neg=0.098, ers=0.35)

    with caplog.at_level("WARNING"):
        assert calibrate_from_logs(corpus, min_samples=20) is False
    assert "CPT[obfusc_neg]" in caplog.text
    assert "CPT[obfusc_pos]" not in caplog.text, "link 1 passed; naming it would mislead"
    assert _cpt.obfusc_pos == 0.55
    assert _cpt.obfusc_neg == 0.098
    assert _cpt.ers_center == 0.35


def test_link3_ers_center_drift_rejects_while_both_obfusc_are_fine(corpus, monkeypatch, caplog):
    """Links 1 and 2 pass (9.1%, 16.7%); `ers_center` does not.

    0.22 - 0.075 = 0.145, clamped up to the 0.15 floor → 31.8% drift.

    Note: this link's new value is always *below* the prior (the shift is
    positive whenever the block rate exceeds the 5% assumption), so a
    swapped-argument mutation here computes a larger drift and still rejects.
    That mutant is not killable through this path; it would need a corpus with
    a below-prior block rate, which cannot be built without also collapsing the
    obfuscation buckets this same corpus feeds.
    """
    _priors(monkeypatch, pos=0.55, neg=0.15, ers=0.22)

    with caplog.at_level("WARNING"):
        assert calibrate_from_logs(corpus, min_samples=20) is False
    assert "CPT[ers_center]" in caplog.text
    assert "CPT[obfusc" not in caplog.text, "links 1 and 2 passed"
    assert _cpt.ers_center == 0.22
    assert _cpt.obfusc_pos == 0.55
    assert _cpt.obfusc_neg == 0.15


def test_a_rejected_run_records_no_provenance(corpus, monkeypatch):
    """`calibrated_from` / `calibration_n` are written after the gate. If a
    rejected run stamped them, an operator reading the CPT would believe a
    poisoned batch had been applied."""
    _priors(monkeypatch, pos=0.80, neg=0.15, ers=0.35)
    monkeypatch.setattr(_cpt, "calibrated_from", "")
    monkeypatch.setattr(_cpt, "calibration_n", 0)

    assert calibrate_from_logs(corpus, min_samples=20) is False
    assert _cpt.calibrated_from == ""
    assert _cpt.calibration_n == 0


# ── Link 4 is unreachable, and that is a finding ──────────────────────────────

def test_entropy_center_link_can_never_reject():
    """**The fourth link of the anti-poisoning gate is dead.**

    `entropy_center` is clamped to [3.5, 5.5] and its shift is
    `(log1p(median_len)/log1p(200) - 1) * 0.3`, which is bounded to roughly
    ±0.3 no matter what payload lengths an attacker submits. Against a prior
    anywhere in the legal band, the largest achievable drift is **13.76%** —
    the gate's threshold is 25%, so `_drift_ok(entropy_center, ...)` can never
    return False.

    That does not make `entropy_center` unpoisonable; it makes it bounded by
    the **clamp** rather than by the gate. An attacker can move it up to 13.76%
    per calibration run, every run, unopposed, until it sits at whichever clamp
    edge suits them — and at 5.5 a high-entropy payload stops looking unusual.
    Per-run drift caps do not stop a walk; that is a design question for the
    detection-math owner (Track B), recorded here rather than decided.

    This test is the tripwire: if the shift widens or the clamp band changes so
    the link becomes reachable, it fails and the comment above must be revisited.
    """
    lo, hi, max_drift, shift_scale, anchor = 3.5, 5.5, 0.25, 0.3, 200

    worst = 0.0
    prior = lo
    while prior <= hi + 1e-9:
        for median_len in (0, 1, 5, 20, 100, 200, 1_000, 10_000, 10**6):
            ratio = math.log1p(median_len) / math.log1p(anchor)
            new = max(lo, min(hi, prior + (ratio - 1.0) * shift_scale))
            worst = max(worst, abs(new - prior) / prior)
        prior += 0.05

    assert worst < max_drift, (
        f"entropy_center can now drift {worst:.1%}, at or past the {max_drift:.0%} "
        "gate — the fourth link is live. Re-read the docstring: the reasoning "
        "that called it dead no longer holds."
    )
    assert worst == pytest.approx(0.1376, abs=5e-4), (
        f"the reachable bound moved to {worst:.4f}; the clamp band or the shift "
        "scale changed, so the poisoning envelope for entropy_center changed too"
    )
