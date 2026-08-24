"""warden/tests/test_latency_buckets_resolve.py — the histogram must be able to answer.

A latency histogram can only report values its bucket edges bracket. Two ways to
lose that, and this repo has now hit both:

*Too coarse at the bottom.* Stock instrumentator buckets start at 0.1 s against a
documented P99 < 50 ms SLO (docs/sla.md), so every observation landed in the
first bucket and `histogram_quantile` could only interpolate inside it. Fixed by
OB-F5.

*Too short at the top.* With 2.5 s as the last finite edge, production reported
P99 = exactly 2500 ms for hours. That is the edge, not a measurement — the true
value could have been 3 s or 30 s and the metric could not distinguish them,
while an SLO alert fired on it.

Both are the same defect: a number that looks like an answer and is really the
shape of the instrument.
"""
from __future__ import annotations

import math

from warden.main import _LATENCY_BUCKETS

_SLO_SECONDS = 0.05  # docs/sla.md — P99 < 50 ms


def test_last_bucket_is_infinite() -> None:
    assert math.isinf(_LATENCY_BUCKETS[-1]), "prometheus requires a +Inf bucket"


def test_edges_are_sorted_and_unique() -> None:
    finite = [b for b in _LATENCY_BUCKETS if not math.isinf(b)]
    assert finite == sorted(set(finite)), f"bucket edges must ascend uniquely: {finite}"


def test_slo_is_resolvable() -> None:
    """Enough edges below the SLO to place a quantile, not just bracket it."""
    below = [b for b in _LATENCY_BUCKETS if b <= _SLO_SECONDS]
    assert len(below) >= 3, (
        f"only {len(below)} bucket edges at or below the {_SLO_SECONDS*1000:.0f} ms "
        "SLO. With too few, histogram_quantile interpolates inside one bucket and "
        "reports a number the histogram cannot actually resolve."
    )


def test_tail_is_resolvable() -> None:
    """The top finite edge must sit well above the SLO, or P99 pins to it.

    Measured on production 2026-08-24: 2.6% of /filter requests exceeded 2.5 s
    while P50 was 19 ms. With 2.5 s as the top finite edge, P99 read exactly
    2500 ms — the edge itself — for hours.
    """
    top = max(b for b in _LATENCY_BUCKETS if not math.isinf(b))
    assert top >= 10.0, (
        f"top finite bucket is {top}s. A request slower than that is "
        "indistinguishable from one that took a minute, and any quantile landing "
        "in the tail reports the edge rather than a latency."
    )
