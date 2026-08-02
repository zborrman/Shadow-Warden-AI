"""
warden/financial/metrics_reader.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MetricsReader — reads real production data from Shadow Warden's data sources
to feed the DollarImpactCalculator.

Data sources (in priority order):
  1. logs.json (NDJSON analytics) — threat flags, PII redactions, request volume
  2. Redis ERS — shadow-banned entity count
  3. Prometheus text endpoint — warden_shadow_ban_cost_saved_usd_total

All sources fail-open: missing data returns 0/empty instead of raising.
"""
from __future__ import annotations

import contextlib
import logging
import os
from collections import Counter
from datetime import UTC, datetime, timedelta

log = logging.getLogger("warden.financial.metrics_reader")

# Flag → ThreatCategory mapping (log flag strings → ThreatCategory enum values)
_FLAG_TO_CATEGORY: dict[str, str] = {
    "prompt_injection":     "prompt_injection",
    "injection_chain":      "prompt_injection",
    "tool_injection":       "tool_abuse",
    "indirect_injection":   "prompt_injection",
    "jailbreak":            "jailbreak",
    "jailbreak_attempt":    "jailbreak",
    "pii_detected":         "pii_leakage",
    "pii_leakage":          "pii_leakage",
    "secret_detected":      "pii_leakage",
    "api_abuse":            "api_abuse",
    "credential_stuffing":  "api_abuse",
    "tool_abuse":           "tool_abuse",
    "data_exfiltration":    "data_exfiltration",
    "topological_noise":    "api_abuse",
    "causal_high_risk":     "data_exfiltration",
    "service_denial":       "service_denial",
    "compliance_violation": "compliance_violation",
}


class MetricsReader:
    """
    Reads live metrics from Shadow Warden's production data sources.

    Parameters
    ----------
    logs_path        : Path to logs.json (NDJSON). Defaults to LOGS_PATH env var.
    prometheus_url   : Prometheus metrics endpoint. Defaults to PROMETHEUS_URL env var.
    redis_url        : Redis connection URL. Defaults to REDIS_URL env var.
    lookback_days    : How many days of logs to include (default: 30).
    """

    def __init__(
        self,
        logs_path:      str | None = None,
        prometheus_url: str | None = None,
        redis_url:      str | None = None,
        lookback_days:  int        = 30,
    ) -> None:
        self._logs_path      = logs_path or os.getenv("LOGS_PATH", "/warden/data/logs.json")
        self._prom_url       = prometheus_url or os.getenv("PROMETHEUS_URL", "http://prometheus:9090")
        self._redis_url      = redis_url or os.getenv("REDIS_URL", "redis://redis:6379/0")
        self._lookback_days  = lookback_days
        self._entries: list[dict] | None = None  # lazy-loaded

    # ── Lazy log loader ────────────────────────────────────────────────────────

    def _load_entries(self) -> list[dict]:
        if self._entries is not None:
            return self._entries
        from pathlib import Path
        path = Path(self._logs_path)
        if not path.exists():
            log.debug("logs.json not found at %s — returning empty", path)
            self._entries = []
            return self._entries

        cutoff = datetime.now(UTC) - timedelta(days=self._lookback_days)
        entries: list[dict] = []
        import json
        try:
            with path.open("r", encoding="utf-8") as f:
                for raw in f:
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        entry = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    ts_str = entry.get("ts", "")
                    if ts_str:
                        try:
                            ts = datetime.fromisoformat(ts_str)
                            if ts < cutoff:
                                continue
                        except ValueError:
                            pass
                    entries.append(entry)
        except OSError as exc:
            log.warning("Could not read logs.json: %s", exc)
        self._entries = entries
        return self._entries

    # ── Public interface (used by DollarImpactCalculator.load_live_metrics) ───

    # ── SQL read path (D-3) ────────────────────────────────────────────────────
    # These three counters were each derived by scanning the whole NDJSON journal
    # for the lookback window. When the filter_events mirror is populated the
    # same numbers come from one aggregate query; when it is not, the original
    # scan runs unchanged. `_sql_summary` returning None is the only signal —
    # there is no separate "is it enabled" branch in the callers.

    def _cutoff(self) -> datetime:
        return datetime.now(UTC) - timedelta(days=self._lookback_days)

    def _sql_summary(self) -> dict | None:
        try:
            from warden.analytics import events_store
            return events_store.summary(self._cutoff())
        except Exception as exc:
            log.debug("filter_events summary unavailable: %s", exc)
            return None

    def monthly_requests(self) -> int:
        """Total requests in the lookback window, scaled to 30 days."""
        scale = 30 / max(self._lookback_days, 1)

        s = self._sql_summary()
        if s is not None:
            return int(int(s["total"]) * scale)

        entries = self._load_entries()
        if not entries:
            return 0
        return int(len(entries) * scale)

    def threats_blocked_by_category(self) -> dict:
        """
        Returns a dict mapping ThreatCategory → blocked count.
        Parsed from the 'flags' field of BLOCK/HIGH risk log entries.
        """
        from warden.financial.impact_calculator import ThreatCategory
        tally: Counter[str] = Counter()

        sql_flags: dict[str, int] | None = None
        try:
            from warden.analytics import events_store
            sql_flags = events_store.blocked_flag_counts(self._cutoff())
        except Exception as exc:
            log.debug("filter_events blocked_flag_counts unavailable: %s", exc)

        if sql_flags is not None:
            for flag, n in sql_flags.items():
                cat = _FLAG_TO_CATEGORY.get(flag.lower())
                if cat:
                    tally[cat] += n
        else:
            for entry in self._load_entries():
                if entry.get("allowed", True):
                    continue  # only count blocked/high-risk events
                for flag in entry.get("flags", []):
                    cat = _FLAG_TO_CATEGORY.get(flag.lower())
                    if cat:
                        tally[cat] += 1

        result: dict[ThreatCategory, int] = {}
        for cat_val, count in tally.items():
            with contextlib.suppress(ValueError):
                result[ThreatCategory(cat_val)] = count
        return result

    def shadow_banned_count(self) -> int:
        """
        Returns the number of shadow-banned entities in the lookback window.

        Tries Redis ERS first (warden:ers:shadow_ban:* keys), then falls back
        to counting SHADOW_BAN log entries.
        """
        count = self._redis_shadow_ban_count()
        if count > 0:
            return count
        # Fallback: count log entries flagged as shadow-banned (if logged that way)
        return sum(
            1 for e in self._load_entries()
            if e.get("shadow_banned") is True
        )

    def _redis_shadow_ban_count(self) -> int:
        if "memory://" in self._redis_url:
            return 0
        try:
            import redis
            r = redis.from_url(self._redis_url, socket_connect_timeout=1, socket_timeout=1)
            keys = r.keys("warden:ers:shadow_ban:*")
            return len(keys)  # type: ignore[arg-type]
        except Exception as exc:
            log.debug("Redis shadow ban count failed: %s", exc)
            return 0

    def pii_redactions_count(self) -> int:
        """Number of log entries where masking was applied."""
        s = self._sql_summary()
        if s is not None:
            return int(s["masked"])
        return sum(1 for e in self._load_entries() if e.get("masked") is True)

    def shadow_ban_cost_saved_usd(self) -> float:
        """
        Reads warden_shadow_ban_cost_saved_usd_total from Prometheus.
        Returns 0.0 if Prometheus is unreachable.
        """
        try:
            import urllib.request
            url = f"{self._prom_url.rstrip('/')}/api/v1/query"
            query = "warden_shadow_ban_cost_saved_usd_total"
            with urllib.request.urlopen(
                f"{url}?query={query}", timeout=2
            ) as resp:
                import json
                data = json.loads(resp.read())
            result = data.get("data", {}).get("result", [])
            if result:
                return float(result[0]["value"][1])
        except Exception as exc:
            log.debug("Prometheus shadow_ban_cost query failed: %s", exc)
        return 0.0

    def summary(self) -> dict:
        """Convenience method returning all metrics as a single dict."""
        return {
            "monthly_requests":         self.monthly_requests(),
            "threats_blocked":          {k.value: v for k, v in self.threats_blocked_by_category().items()},
            "shadow_banned_entities":   self.shadow_banned_count(),
            "pii_redactions":           self.pii_redactions_count(),
            "shadow_ban_cost_saved_usd": self.shadow_ban_cost_saved_usd(),
        }
