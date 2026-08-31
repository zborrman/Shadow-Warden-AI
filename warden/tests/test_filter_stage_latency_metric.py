"""
warden/tests/test_filter_stage_latency_metric.py — the instrument behind the number.

`docs/capability-matrix.md` ruled per-stage latency `UNMEASURED`: the site
publishes `<2ms` for the topology gate and `<8ms` for the brain, and nothing
aggregated either figure. The pipeline was measuring them the whole time — every
stage writes into the `timings` dict returned as `processing_ms` — but the
numbers lived for the length of one response and were then dropped.

`warden_filter_stage_duration_seconds` is that aggregation, and this file exists
because of a failure this repository has already had twice: a metric nothing
writes still exports cleanly. `warden_corpus_canary_failures` read 0 for months
and a `critical` alert rule sat on it, green, because no code path ever touched
the gauge (OB-F12). So these tests do not check that the metric is *registered*
— they check that running the pipeline's timings through the observer moves it.
"""
from __future__ import annotations

import pytest

prometheus_client = pytest.importorskip("prometheus_client")


def _samples(metric_name: str) -> dict[tuple[tuple[str, str], ...], float]:
    """Every sample of a metric family, keyed by its label values."""
    from prometheus_client import REGISTRY

    out: dict[tuple[tuple[str, str], ...], float] = {}
    for family in REGISTRY.collect():
        for sample in family.samples:
            if sample.name == metric_name:
                out[tuple(sorted(sample.labels.items()))] = sample.value
    return out


def _count_for(stage: str, source: str = "filter") -> float:
    key: tuple[tuple[str, str], ...] = (
        ("le", "+Inf"), ("source", source), ("stage", stage),
    )
    return _samples("warden_filter_stage_duration_seconds_bucket").get(key, 0.0)


# ── The metric exists and is shaped for the claims it checks ─────────────────


def test_the_metric_is_registered_with_a_stage_label():
    from warden.metrics import FILTER_STAGE_DURATION_SECONDS

    assert FILTER_STAGE_DURATION_SECONDS is not None
    assert hasattr(FILTER_STAGE_DURATION_SECONDS, "labels")


def test_buckets_can_resolve_a_single_digit_millisecond_claim():
    """
    The published figures are 1–8 ms. A default bucket set starts at 5 ms and
    cannot tell `<2ms` from `<5ms` — which is the only question being asked.
    """
    from prometheus_client import REGISTRY

    collector = REGISTRY._names_to_collectors.get("warden_filter_stage_duration_seconds")
    assert collector is not None, "the histogram is not registered"
    upper_bounds = list(getattr(collector, "_upper_bounds", []))
    assert upper_bounds, "cannot read the bucket bounds — re-check this guard"
    sub_10ms = [b for b in upper_bounds if b <= 0.010]
    assert len(sub_10ms) >= 5, (
        f"only {len(sub_10ms)} buckets at or below 10ms: {sub_10ms}. "
        "The claims being checked are 1-8ms."
    )
    assert min(upper_bounds) <= 0.001, "no sub-millisecond bucket"


# ── Something actually writes it ─────────────────────────────────────────────


class TestTheObserverMovesTheMetric:
    def test_a_timings_dict_lands_in_the_histogram(self):
        from warden.main import _observe_stage_timings

        before = _count_for("topology")
        _observe_stage_timings({"topology": 1.5, "ml": 8.0, "total": 12.0})
        assert _count_for("topology") == before + 1

    def test_every_stage_gets_its_own_series(self):
        from warden.main import _observe_stage_timings

        before = {s: _count_for(s) for s in ("obfuscation", "redaction", "rules")}
        _observe_stage_timings({"obfuscation": 0.4, "redaction": 2.0, "rules": 0.9})
        for stage, was in before.items():
            assert _count_for(stage) == was + 1, f"{stage} was not observed"

    def test_milliseconds_are_converted_to_seconds(self):
        """A histogram in the wrong unit is worse than none: it reads plausible."""
        from prometheus_client import REGISTRY

        from warden.main import _observe_stage_timings

        _observe_stage_timings({"unit_probe": 2.0})
        sums = _samples("warden_filter_stage_duration_seconds_sum")
        total = sums.get((("source", "filter"), ("stage", "unit_probe")))
        assert total is not None, "the probe stage did not record"
        assert abs(total - 0.002) < 1e-9, f"2ms recorded as {total}s — check the /1000"
        assert REGISTRY is not None

    def test_total_feeds_the_metric_the_sla_names(self):
        """
        `docs/sla.md` cited `warden_filter_duration_seconds` as the evidence for
        three objectives before anything registered it. A test that only checked
        registration would have passed on the day it was still a ghost, so this
        checks the observer moves it.
        """
        from warden.main import _observe_stage_timings

        key: tuple[tuple[str, str], ...] = (("le", "+Inf"), ("source", "filter"))
        before = _samples("warden_filter_duration_seconds_bucket").get(key, 0.0)
        _observe_stage_timings({"topology": 1.0, "total": 12.0})
        after = _samples("warden_filter_duration_seconds_bucket").get(key, 0.0)
        assert after == before + 1, "the SLA metric did not record the request"

    def test_the_sla_metric_is_in_seconds_too(self):
        from warden.main import _observe_stage_timings

        key: tuple[tuple[str, str], ...] = (("source", "sla_unit_probe"),)
        _observe_stage_timings({"total": 12.0}, "sla_unit_probe")
        got = _samples("warden_filter_duration_seconds_sum").get(key)
        assert got is not None and abs(got - 0.012) < 1e-9, f"12ms recorded as {got}s"

    def test_total_does_not_also_land_in_the_per_stage_series(self):
        """A total among the stages would dwarf every real one."""
        from warden.main import _observe_stage_timings

        before = _count_for("total")
        _observe_stage_timings({"total": 99.0})
        assert _count_for("total") == before

    def test_entry_points_do_not_share_a_series(self):
        """
        `_run_filter_pipeline` serves REST /filter, batch, multimodal and the
        /ws/stream socket. Unlabelled, a socket burst would land in a panel
        titled "/filter" and read as REST latency.
        """
        from warden.main import _observe_stage_timings

        before_rest = _count_for("topology", "filter")
        before_ws = _count_for("topology", "ws")
        _observe_stage_timings({"topology": 1.0}, "ws")
        assert _count_for("topology", "ws") == before_ws + 1
        assert _count_for("topology", "filter") == before_rest, (
            "WebSocket traffic landed in the REST series"
        )

    @pytest.mark.parametrize(
        "timings",
        [
            {},
            {"total": 5.0},
            {"weird": None},
            {"weird": "not a number"},
            {"nested": {"a": 1}},
        ],
    )
    def test_a_malformed_timings_dict_never_raises(self, timings):
        """Instrumentation must never be able to fail a filter decision."""
        from warden.main import _observe_stage_timings

        _observe_stage_timings(timings)  # must not raise


# ── The pipeline calls it ────────────────────────────────────────────────────


class TestThePipelineIsWired:
    """
    A correct observer nobody calls is the same defect in a different place, so
    these read the call sites rather than trusting that they exist.
    """

    def _source(self) -> str:
        from pathlib import Path

        return (Path(__file__).resolve().parents[1] / "main.py").read_text(
            encoding="utf-8", errors="ignore"
        )

    def test_every_finalised_timings_dict_is_observed(self):
        src = self._source().splitlines()
        finalisers = [
            n for n, line in enumerate(src)
            if 'timings["total"] =' in line
        ]
        assert finalisers, "no filter path finalises a timings dict — re-check this guard"
        for n in finalisers:
            following = "".join(src[n + 1 : n + 3])
            assert "_observe_stage_timings(timings" in following, (
                f"main.py:{n + 1} finalises timings without observing them"
            )

    def test_the_helper_is_imported_from_the_shared_registry(self):
        """
        warden/metrics.py exists so a metric is registered once per process.
        Instantiating a Histogram in main.py would raise "Duplicated timeseries"
        on the second import under pytest.
        """
        src = self._source()
        assert "FILTER_STAGE_DURATION_SECONDS" in src
        assert 'Histogram(\n            "warden_filter_stage_duration_seconds"' not in src
