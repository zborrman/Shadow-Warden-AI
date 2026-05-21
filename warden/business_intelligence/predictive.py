"""
warden/business_intelligence/predictive.py  (CM-39)
─────────────────────────────────────────────────────
Moving-average + linear extrapolation for incident prediction.
Pure Python — no numpy/scipy required.
"""
from __future__ import annotations

from collections.abc import Sequence


def moving_average(values: Sequence[float], window: int = 3) -> list[float]:
    if not values or window < 1:
        return []
    result: list[float] = []
    for i in range(len(values)):
        start = max(0, i - window + 1)
        chunk = list(values[start : i + 1])
        result.append(sum(chunk) / len(chunk))
    return result


def linear_trend(values: Sequence[float]) -> tuple[float, float]:
    """Return (slope, intercept) for a simple OLS regression on the series."""
    n = len(values)
    if n < 2:
        return 0.0, float(values[0]) if values else 0.0
    xs = list(range(n))
    mx = sum(xs) / n
    my = sum(values) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, values, strict=True))
    den = sum((x - mx) ** 2 for x in xs)
    slope = num / den if den else 0.0
    intercept = my - slope * mx
    return slope, intercept


def predict_next(values: Sequence[float], steps: int = 30) -> list[float]:
    if not values:
        return [0.0] * steps
    slope, intercept = linear_trend(values)
    n = len(values)
    return [max(0.0, intercept + slope * (n + i)) for i in range(steps)]


def r_squared(values: Sequence[float]) -> float:
    """Coefficient of determination — proxy for prediction confidence."""
    if len(values) < 2:
        return 0.0
    slope, intercept = linear_trend(values)
    n = len(values)
    predicted = [intercept + slope * i for i in range(n)]
    mean = sum(values) / n
    ss_res = sum((y - y_hat) ** 2 for y, y_hat in zip(values, predicted, strict=True))
    ss_tot = sum((y - mean) ** 2 for y in values)
    if ss_tot == 0.0:
        return 1.0
    return max(0.0, 1.0 - ss_res / ss_tot)


def trend_direction(values: Sequence[float]) -> str:
    if len(values) < 2:
        return "stable"
    slope, _ = linear_trend(values)
    if slope > 0.1:
        return "rising"
    if slope < -0.1:
        return "falling"
    return "stable"


def predict_incidents(
    historical_counts: list[int],
    horizon_days: int = 30,
) -> dict:
    if not historical_counts:
        return {
            "predicted_count": 0,
            "confidence": 0.0,
            "trend_direction": "stable",
        }
    floats = [float(v) for v in historical_counts]
    smoothed = moving_average(floats, window=min(3, len(floats)))
    future = predict_next(smoothed, steps=horizon_days)
    total_predicted = int(round(sum(future)))
    confidence = round(r_squared(smoothed), 2)
    direction = trend_direction(smoothed)
    return {
        "predicted_count": max(0, total_predicted),
        "confidence": confidence,
        "trend_direction": direction,
    }
