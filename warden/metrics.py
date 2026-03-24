"""
warden/metrics.py
─────────────────
Shared Prometheus metric singletons for the Warden gateway.

Import from here — never instantiate metrics in individual modules —
to guarantee a single registration per process and avoid
ValueError("Duplicated timeseries") when modules are reloaded in tests.

All metrics use the ``try/except`` registry guard pattern so the module
is safe to import multiple times (pytest reimports between test files).
"""
from __future__ import annotations

try:
    from prometheus_client import REGISTRY, Counter, Gauge, Histogram  # noqa: F401

    # ── Tool block counter ────────────────────────────────────────────────────
    # Incremented by openai_proxy.py on every ToolCallGuard block (Phase A + B).
    #
    # Labels:
    #   direction  "call" (Phase B — outgoing) | "result" (Phase A — incoming)
    #   tool_name  name of the blocked tool function
    #   threat     first threat kind (e.g. "shell_destruction", "prompt_injection")
    try:
        TOOL_BLOCKS = Counter(
            "warden_tool_blocks_total",
            "Number of tool calls/results blocked by ToolCallGuard",
            ["direction", "tool_name", "threat"],
        )
    except ValueError:
        # Already registered (e.g. test re-import) — retrieve existing
        TOOL_BLOCKS = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_tool_blocks_total"
        )

    # ── Agent session metrics ─────────────────────────────────────────────────
    # Populated by AgentMonitor in warden/agent_monitor.py.

    try:
        AGENT_SESSIONS_ACTIVE = Gauge(
            "warden_agent_sessions_active",
            "Active agent sessions within the TTL window",
        )
    except ValueError:
        AGENT_SESSIONS_ACTIVE = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_agent_sessions_active"
        )

    try:
        AGENT_ANOMALIES_TOTAL = Counter(
            "warden_agent_anomalies_total",
            "Session-level anomalies detected by AgentMonitor",
            ["pattern_type", "severity"],
        )
    except ValueError:
        AGENT_ANOMALIES_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_agent_anomalies_total"
        )

    try:
        AGENT_SESSION_BLOCKS = Counter(
            "warden_agent_session_blocks_total",
            "Blocked events in agent sessions per tenant",
            ["tenant_id"],
        )
    except ValueError:
        AGENT_SESSION_BLOCKS = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_agent_session_blocks_total"
        )

    # ── Resilience event counters ─────────────────────────────────────────────
    # Incremented by main.py inside _run_filter_pipeline().
    #
    # FILTER_BYPASSES_TOTAL  — fail-open fired (asyncio timeout, WARDEN_FAIL_STRATEGY=open)
    # FILTER_UNCERTAIN_TOTAL — ML score in gray zone [lower_threshold, semantic_threshold)
    # FILTER_HONEYTRAP_TOTAL — HoneyEngine deception trap served to attacker
    #
    # Labels:
    #   tenant_id  — resolved tenant (or "default" / "demo")

    try:
        FILTER_BYPASSES_TOTAL = Counter(
            "warden_filter_bypasses_total",
            "Fail-open bypass events (pipeline timeout, WARDEN_FAIL_STRATEGY=open)",
            ["tenant_id"],
        )
    except ValueError:
        FILTER_BYPASSES_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_filter_bypasses_total"
        )

    try:
        FILTER_UNCERTAIN_TOTAL = Counter(
            "warden_filter_uncertain_total",
            "ML gray-zone events where score is in [uncertainty_lower, semantic_threshold)",
            ["tenant_id"],
        )
    except ValueError:
        FILTER_UNCERTAIN_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_filter_uncertain_total"
        )

    try:
        FILTER_HONEYTRAP_TOTAL = Counter(
            "warden_filter_honeytrap_total",
            "HoneyEngine deception traps served (attacker fed fake response)",
            ["tenant_id"],
        )
    except ValueError:
        FILTER_HONEYTRAP_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_filter_honeytrap_total"
        )

    # ── EvolutionEngine skip counter ──────────────────────────────────────────
    # Incremented by brain/evolve.py whenever process_blocked() returns early.
    #
    # Label:
    #   reason  "low_risk"    — risk below EVOLUTION_MIN_RISK threshold
    #           "corpus_cap"  — MAX_CORPUS_RULES reached
    #           "duplicate"   — content SHA-256 already processed this session
    #           "rate_limited"— EVOLUTION_RATE_MAX calls/window exceeded
    try:
        EVOLUTION_SKIPPED_TOTAL = Counter(
            "warden_evolution_skipped_total",
            "EvolutionEngine calls skipped before reaching the Claude Opus API",
            ["reason"],
        )
    except ValueError:
        EVOLUTION_SKIPPED_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_evolution_skipped_total"
        )

    # ── Filter-stage latency (optional extension point) ───────────────────────
    # Already covered by prometheus-fastapi-instrumentator for HTTP-level
    # latency.  No extra histogram needed here yet.

    # ── Data Poisoning Detection metrics ──────────────────────────────────────

    try:
        POISONING_ATTEMPTS_TOTAL = Counter(
            "warden_poisoning_attempts_total",
            "Data poisoning attempts detected by DataPoisoningGuard",
            ["tenant_id", "attack_vector"],
        )
    except ValueError:
        POISONING_ATTEMPTS_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_poisoning_attempts_total"
        )

    try:
        CORPUS_DRIFT_SCORE = Gauge(
            "warden_corpus_drift_score",
            "Current cosine distance of corpus centroid from baseline (0=healthy)",
        )
    except ValueError:
        CORPUS_DRIFT_SCORE = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_corpus_drift_score"
        )

    try:
        CORPUS_CANARY_MIN_SCORE = Gauge(
            "warden_corpus_canary_min_score",
            "Minimum cosine similarity of canary examples against corpus (should stay ≥0.70)",
        )
    except ValueError:
        CORPUS_CANARY_MIN_SCORE = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_corpus_canary_min_score"
        )

    try:
        CORPUS_CANARY_FAILING = Gauge(
            "warden_corpus_canary_failing",
            "Number of canary examples scoring below minimum threshold",
        )
    except ValueError:
        CORPUS_CANARY_FAILING = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_corpus_canary_failing"
        )

    # ── WalletShield metrics ──────────────────────────────────────────────────
    # Populated by wallet_shield.py on every /v1/chat/completions call.

    try:
        WALLET_TOKENS_CONSUMED = Counter(
            "warden_wallet_tokens_consumed_total",
            "Estimated input tokens consumed per tenant (WalletShield)",
            ["tenant_id"],
        )
    except ValueError:
        WALLET_TOKENS_CONSUMED = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_wallet_tokens_consumed_total"
        )

    try:
        WALLET_BUDGET_EXCEEDED = Counter(
            "warden_wallet_budget_exceeded_total",
            "Token budget exceeded events per tenant",
            ["tenant_id", "limit_type"],
        )
    except ValueError:
        WALLET_BUDGET_EXCEEDED = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_wallet_budget_exceeded_total"
        )

    # ── OutputGuard business-layer metrics ───────────────────────────────────
    # Populated by output_guard.py on every /v1/chat/completions response scan.

    try:
        OUTPUT_GUARD_BLOCKS = Counter(
            "warden_output_guard_blocks_total",
            "OutputGuard business-rule violations detected per tenant and risk type",
            ["tenant_id", "risk"],
        )
    except ValueError:
        OUTPUT_GUARD_BLOCKS = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_output_guard_blocks_total"
        )

    try:
        OUTPUT_GUARD_SANITIZATIONS = Counter(
            "warden_output_guard_sanitizations_total",
            "OutputGuard sanitizations applied to LLM responses per tenant",
            ["tenant_id"],
        )
    except ValueError:
        OUTPUT_GUARD_SANITIZATIONS = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_output_guard_sanitizations_total"
        )

    # ── v1.3 Global Sync metrics ──────────────────────────────────────────────
    # Labels:
    #   source_region  region that originally generated the rule/block/snapshot

    try:
        SYNC_RULES_PUBLISHED_TOTAL = Counter(
            "warden_sync_rules_published_total",
            "Rules published to the global threat stream by this node",
        )
    except ValueError:
        SYNC_RULES_PUBLISHED_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_sync_rules_published_total"
        )

    try:
        SYNC_RULES_APPLIED_TOTAL = Counter(
            "warden_sync_rules_applied_total",
            "Rules received and applied from remote regions",
            ["source_region"],
        )
    except ValueError:
        SYNC_RULES_APPLIED_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_sync_rules_applied_total"
        )

    try:
        SYNC_CORPUS_UPLOADS_TOTAL = Counter(
            "warden_sync_corpus_uploads_total",
            "Corpus snapshots uploaded to S3 by this node",
        )
    except ValueError:
        SYNC_CORPUS_UPLOADS_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_sync_corpus_uploads_total"
        )

    try:
        SYNC_CORPUS_DOWNLOADS_TOTAL = Counter(
            "warden_sync_corpus_downloads_total",
            "Corpus snapshots downloaded and hot-reloaded from remote regions",
            ["source_region"],
        )
    except ValueError:
        SYNC_CORPUS_DOWNLOADS_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_sync_corpus_downloads_total"
        )

    try:
        SYNC_BLOCKS_PROPAGATED_TOTAL = Counter(
            "warden_sync_blocks_propagated_total",
            "IP block events published to the global blocklist stream",
            ["blocked_by"],
        )
    except ValueError:
        SYNC_BLOCKS_PROPAGATED_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_sync_blocks_propagated_total"
        )

    try:
        SYNC_BLOCKS_APPLIED_TOTAL = Counter(
            "warden_sync_blocks_applied_total",
            "IP block events received and applied from remote regions",
            ["source_region"],
        )
    except ValueError:
        SYNC_BLOCKS_APPLIED_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_sync_blocks_applied_total"
        )

    METRICS_ENABLED = True

except ImportError:
    METRICS_ENABLED = False

    class _Noop:  # type: ignore[no-redef]
        """Silent no-op for environments without prometheus_client."""
        def labels(self, **_kw):
            return self
        def inc(self, _amount: float = 1) -> None:
            pass
        def observe(self, _amount: float) -> None:
            pass
        def set(self, _value: float) -> None:
            pass

    TOOL_BLOCKS                 = _Noop()  # type: ignore[assignment]
    AGENT_SESSIONS_ACTIVE       = _Noop()  # type: ignore[assignment]
    AGENT_ANOMALIES_TOTAL       = _Noop()  # type: ignore[assignment]
    AGENT_SESSION_BLOCKS        = _Noop()  # type: ignore[assignment]
    FILTER_BYPASSES_TOTAL       = _Noop()  # type: ignore[assignment]
    FILTER_UNCERTAIN_TOTAL      = _Noop()  # type: ignore[assignment]
    FILTER_HONEYTRAP_TOTAL      = _Noop()  # type: ignore[assignment]
    EVOLUTION_SKIPPED_TOTAL     = _Noop()  # type: ignore[assignment]
    POISONING_ATTEMPTS_TOTAL    = _Noop()  # type: ignore[assignment]
    CORPUS_DRIFT_SCORE          = _Noop()  # type: ignore[assignment]
    CORPUS_CANARY_MIN_SCORE     = _Noop()  # type: ignore[assignment]
    CORPUS_CANARY_FAILING       = _Noop()  # type: ignore[assignment]
    WALLET_TOKENS_CONSUMED          = _Noop()  # type: ignore[assignment]
    WALLET_BUDGET_EXCEEDED          = _Noop()  # type: ignore[assignment]
    OUTPUT_GUARD_BLOCKS             = _Noop()  # type: ignore[assignment]
    OUTPUT_GUARD_SANITIZATIONS      = _Noop()  # type: ignore[assignment]
    SYNC_RULES_PUBLISHED_TOTAL      = _Noop()  # type: ignore[assignment]
    SYNC_RULES_APPLIED_TOTAL        = _Noop()  # type: ignore[assignment]
    SYNC_CORPUS_UPLOADS_TOTAL       = _Noop()  # type: ignore[assignment]
    SYNC_CORPUS_DOWNLOADS_TOTAL     = _Noop()  # type: ignore[assignment]
    SYNC_BLOCKS_PROPAGATED_TOTAL    = _Noop()  # type: ignore[assignment]
    SYNC_BLOCKS_APPLIED_TOTAL       = _Noop()  # type: ignore[assignment]
