"""
warden/business_intelligence/benchmarking.py  (CM-39)
───────────────────────────────────────────────────────
Community-level metric benchmarking — computes percentile rank for a
tenant's metric against anonymised peer data pulled from the BI cache.
"""
from __future__ import annotations

import math
from collections.abc import Sequence


def percentile(values: Sequence[float], pct: float) -> float:
    """Return the p-th percentile (0–100) of a sorted sequence."""
    if not values:
        return 0.0
    sv = sorted(values)
    n = len(sv)
    idx = (pct / 100.0) * (n - 1)
    lo = math.floor(idx)
    hi = math.ceil(idx)
    if lo == hi:
        return sv[lo]
    return sv[lo] + (sv[hi] - sv[lo]) * (idx - lo)


def percentile_rank(value: float, population: Sequence[float]) -> float:
    """Return the percentage of population values below `value` (0–100)."""
    if not population:
        return 50.0
    below = sum(1 for v in population if v < value)
    return round(below / len(population) * 100, 1)


def benchmark_metric(
    tenant_value: float,
    peer_values: list[float],
    metric: str,
    tenant_id: str,
) -> dict:
    """Return a BenchmarkResult-compatible dict for one metric."""
    if not peer_values:
        return {
            "tenant_id": tenant_id,
            "metric": metric,
            "tenant_value": tenant_value,
            "community_avg": tenant_value,
            "community_p25": tenant_value,
            "community_p75": tenant_value,
            "percentile_rank": 50.0,
            "status": "average",
        }
    avg = sum(peer_values) / len(peer_values)
    p25 = percentile(peer_values, 25)
    p75 = percentile(peer_values, 75)
    rank = percentile_rank(tenant_value, peer_values)
    if rank >= 75:
        status = "above"
    elif rank <= 25:
        status = "below"
    else:
        status = "average"
    return {
        "tenant_id": tenant_id,
        "metric": metric,
        "tenant_value": round(tenant_value, 4),
        "community_avg": round(avg, 4),
        "community_p25": round(p25, 4),
        "community_p75": round(p75, 4),
        "percentile_rank": rank,
        "status": status,
    }


def build_benchmarks(
    tenant_id: str,
    tenant_metrics: dict[str, float],
    peer_metrics_list: list[dict[str, float]],
) -> list[dict]:
    results = []
    for metric, value in tenant_metrics.items():
        peers = [p[metric] for p in peer_metrics_list if metric in p]
        results.append(benchmark_metric(value, peers, metric, tenant_id))
    return results
