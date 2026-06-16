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

    # ── Sandbox capability violations ────────────────────────────────────────
    # Incremented by ToolCallGuard when SandboxRegistry denies a tool call.
    #
    # Labels:
    #   agent_id  — agent that attempted the call
    #   reason    — denial reason key (no_manifest, tool_not_allowed,
    #               param_not_allowed, quota_exceeded, network_egress_denied)
    try:
        SANDBOX_VIOLATIONS_TOTAL = Counter(
            "warden_sandbox_violations_total",
            "Tool calls denied by the Zero-Trust Agent Sandbox",
            ["agent_id", "reason"],
        )
    except ValueError:
        SANDBOX_VIOLATIONS_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_sandbox_violations_total"
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

    try:
        AGENT_SESSIONS_REVOKED_TOTAL = Counter(
            "warden_agent_sessions_revoked_total",
            "Agent sessions terminated via kill-switch (DELETE /api/agent/session)",
        )
    except ValueError:
        AGENT_SESSIONS_REVOKED_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_agent_sessions_revoked_total"
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

    # ── Nemotron Evolution Engine counter ────────────────────────────────────
    # Tracks which backend (nemotron | claude) is active at startup via
    # build_evolution_engine() and how many rules were generated per engine.
    #
    # Label:
    #   engine  "nemotron" — NVIDIA NIM (Nemotron Super)
    #           "claude"   — Anthropic Claude Opus
    try:
        NEMOTRON_EVOLUTION_TOTAL = Counter(
            "warden_nemotron_evolution_total",
            "Evolution Engine rule generation calls, labelled by backend",
            ["engine"],
        )
    except ValueError:
        NEMOTRON_EVOLUTION_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_nemotron_evolution_total"
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

    # ── v1.4 Multi-Modal Guard metrics ───────────────────────────────────────────

    try:
        IMAGE_GUARD_BLOCKS_TOTAL = Counter(
            "warden_image_guard_blocks_total",
            "Visual jailbreaks detected by ImageGuard (CLIP)",
            ["reason"],   # "visual_jailbreak" | "pii_detected"
        )
    except ValueError:
        IMAGE_GUARD_BLOCKS_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_image_guard_blocks_total"
        )

    try:
        AUDIO_GUARD_BLOCKS_TOTAL = Counter(
            "warden_audio_guard_blocks_total",
            "Audio injection attempts detected by AudioGuard (Whisper)",
            ["reason"],   # "semantic_injection" | "ultrasound"
        )
    except ValueError:
        AUDIO_GUARD_BLOCKS_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_audio_guard_blocks_total"
        )

    try:
        MULTIMODAL_REQUESTS_TOTAL = Counter(
            "warden_multimodal_requests_total",
            "Total multi-modal filter requests",
            ["modalities"],  # "image" | "audio" | "image+audio"
        )
    except ValueError:
        MULTIMODAL_REQUESTS_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_multimodal_requests_total"
        )

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

    # ── Business metrics (v2.2) ───────────────────────────────────────────────
    # These metrics translate security actions into Dollar Impact — answering
    # "what ROI is Warden delivering?" for CISOs and enterprise customers.
    #
    # SHADOW_BAN_TOTAL        — shadow ban events by strategy and attack type
    # SHADOW_BAN_COST_SAVED_USD — cumulative LLM inference cost saved (shadow
    #                            banned requests never reach the upstream LLM)

    try:
        SHADOW_BAN_TOTAL = Counter(
            "warden_shadow_ban_total",
            "Shadow ban events served to confirmed attackers",
            ["strategy", "last_flag"],
        )
    except ValueError:
        SHADOW_BAN_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_shadow_ban_total"
        )

    try:
        SHADOW_BAN_COST_SAVED_USD = Counter(
            "warden_shadow_ban_cost_saved_usd_total",
            "Cumulative LLM inference cost saved (USD) by shadow-banning attackers",
        )
    except ValueError:
        SHADOW_BAN_COST_SAVED_USD = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_shadow_ban_cost_saved_usd_total"
        )

    # ── Document Intelligence (FE-50) ─────────────────────────────────────────
    try:
        DOC_INTEL_CONVERT_TOTAL = Counter(
            "warden_doc_intel_convert_total",
            "Document Intelligence conversions",
            ["ext", "data_class"],
        )
    except ValueError:
        DOC_INTEL_CONVERT_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_doc_intel_convert_total"
        )

    try:
        DOC_INTEL_CONVERT_ERRORS_TOTAL = Counter(
            "warden_doc_intel_convert_errors_total",
            "Document Intelligence conversion errors",
            ["ext", "error"],
        )
    except ValueError:
        DOC_INTEL_CONVERT_ERRORS_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_doc_intel_convert_errors_total"
        )

    try:
        DOC_INTEL_CACHE_HITS_TOTAL = Counter(
            "warden_doc_intel_cache_hits_total",
            "Document Intelligence Redis cache hits",
        )
    except ValueError:
        DOC_INTEL_CACHE_HITS_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_doc_intel_cache_hits_total"
        )

    # ── Mobile SOC push notifications (MO-01) ──────────────────────────────────
    try:
        PUSH_NOTIFICATIONS_SENT = Counter(
            "warden_push_notifications_sent_total",
            "FCM push notifications successfully delivered to mobile SOC devices",
            ["risk_level"],
        )
    except ValueError:
        PUSH_NOTIFICATIONS_SENT = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_push_notifications_sent_total"
        )

    # ── Marketplace metrics (v5.6) ────────────────────────────────────────────
    try:
        MARKETPLACE_LISTINGS_TOTAL = Counter(
            "warden_marketplace_listings_total",
            "Total marketplace listings created",
            ["asset_type"],
        )
    except ValueError:
        MARKETPLACE_LISTINGS_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_marketplace_listings_total"
        )

    try:
        MARKETPLACE_PURCHASES_TOTAL = Counter(
            "warden_marketplace_purchases_total",
            "Total completed marketplace purchases",
            ["asset_type"],
        )
    except ValueError:
        MARKETPLACE_PURCHASES_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_marketplace_purchases_total"
        )

    try:
        MARKETPLACE_TRADE_VOLUME_USD = Counter(
            "warden_marketplace_trade_volume_usd",
            "Cumulative marketplace trade volume in USD",
        )
    except ValueError:
        MARKETPLACE_TRADE_VOLUME_USD = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_marketplace_trade_volume_usd"
        )

    try:
        MARKETPLACE_ESCROW_ACTIVE = Gauge(
            "warden_marketplace_escrow_active",
            "Escrows in a non-terminal state",
        )
    except ValueError:
        MARKETPLACE_ESCROW_ACTIVE = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_marketplace_escrow_active"
        )

    try:
        MARKETPLACE_AGENTS_ACTIVE = Gauge(
            "warden_marketplace_agents_active",
            "Registered marketplace agents with status=active",
        )
    except ValueError:
        MARKETPLACE_AGENTS_ACTIVE = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_marketplace_agents_active"
        )

    try:
        MARKETPLACE_NEGOTIATIONS_ACTIVE = Gauge(
            "warden_marketplace_negotiations_active",
            "Open marketplace negotiations",
        )
    except ValueError:
        MARKETPLACE_NEGOTIATIONS_ACTIVE = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_marketplace_negotiations_active"
        )

    # ── Compliance metrics (v5.6) ─────────────────────────────────────────────
    try:
        COMPLIANCE_OVERALL_SCORE = Gauge(
            "warden_compliance_overall_score",
            "Overall compliance posture score (0-100)",
            ["tenant_id"],
        )
    except ValueError:
        COMPLIANCE_OVERALL_SCORE = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_compliance_overall_score"
        )

    try:
        COMPLIANCE_GAPS_OPEN = Gauge(
            "warden_compliance_gaps_open",
            "Number of open compliance gaps",
            ["tenant_id"],
        )
    except ValueError:
        COMPLIANCE_GAPS_OPEN = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_compliance_gaps_open"
        )

    try:
        COMPLIANCE_CONTROLS_PASSED = Gauge(
            "warden_compliance_controls_passed",
            "Number of compliance controls currently passing",
            ["tenant_id"],
        )
    except ValueError:
        COMPLIANCE_CONTROLS_PASSED = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_compliance_controls_passed"
        )

    try:
        COMPLIANCE_FRAMEWORK_SCORE = Gauge(
            "warden_compliance_framework_score",
            "Per-framework compliance score (0-100)",
            ["tenant_id", "framework"],
        )
    except ValueError:
        COMPLIANCE_FRAMEWORK_SCORE = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_compliance_framework_score"
        )

    # ── Community metrics (v5.6) ──────────────────────────────────────────────
    try:
        COMMUNITY_MEMBERS_TOTAL = Gauge(
            "warden_community_members_total",
            "Active community members across all communities",
        )
    except ValueError:
        COMMUNITY_MEMBERS_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_community_members_total"
        )

    try:
        COMMUNITY_COMMUNITIES_ACTIVE = Gauge(
            "warden_community_communities_active",
            "Number of active communities",
        )
    except ValueError:
        COMMUNITY_COMMUNITIES_ACTIVE = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_community_communities_active"
        )

    try:
        COMMUNITY_PEERING_CONNECTIONS = Gauge(
            "warden_community_peering_connections",
            "Active inter-community peering connections",
        )
    except ValueError:
        COMMUNITY_PEERING_CONNECTIONS = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_community_peering_connections"
        )

    try:
        COMMUNITY_SEP_TRANSFERS_TOTAL = Counter(
            "warden_community_sep_transfers_total",
            "Total SEP entity transfers",
            ["status"],
        )
    except ValueError:
        COMMUNITY_SEP_TRANSFERS_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_community_sep_transfers_total"
        )

    try:
        COMMUNITY_DOCUMENTS_SCANNED = Counter(
            "warden_community_documents_scanned_total",
            "Documents scanned via community document intelligence",
        )
    except ValueError:
        COMMUNITY_DOCUMENTS_SCANNED = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_community_documents_scanned_total"
        )

    # ── Infrastructure preflight metrics (INFRA-01, v6.4) ────────────────────
    try:
        TUNNEL_PREFLIGHT_TOTAL = Counter(
            "warden_tunnel_preflight_total",
            "Preflight check outcomes for MASQUE tunnel creation",
            ["region", "status"],
        )
    except ValueError:
        TUNNEL_PREFLIGHT_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_tunnel_preflight_total"
        )

    try:
        ESCROW_RPC_CHECK_TOTAL = Counter(
            "warden_escrow_rpc_check_total",
            "RPC node reachability check outcomes before escrow contract deployment",
            ["chain", "status"],
        )
    except ValueError:
        ESCROW_RPC_CHECK_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_escrow_rpc_check_total"
        )

    # ── MAESTRO Threat Detection (MKT-09, v6.5) ──────────────────────────────────
    try:
        MAESTRO_MISALIGNMENT_TOTAL = Counter(
            "warden_maestro_misalignment_total",
            "Goal misalignment detections in M2M marketplace agents",
        )
    except ValueError:
        MAESTRO_MISALIGNMENT_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_maestro_misalignment_total"
        )

    try:
        MAESTRO_COLLUSION_TOTAL = Counter(
            "warden_maestro_collusion_total",
            "Collusion pattern detections in M2M marketplace negotiation pairs",
        )
    except ValueError:
        MAESTRO_COLLUSION_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_maestro_collusion_total"
        )

    try:
        MAESTRO_POISONING_TOTAL = Counter(
            "warden_maestro_poisoning_total",
            "Model/rule poisoning detections during marketplace asset import",
        )
    except ValueError:
        MAESTRO_POISONING_TOTAL = REGISTRY._names_to_collectors.get(  # type: ignore[attr-defined, assignment]
            "warden_maestro_poisoning_total"
        )

    # ── Event Streaming (MKT-10, v6.6) ──────────────────────────────────────
    try:
        STREAMS_EVENTS_TOTAL = Counter(
            "warden_streams_events_total",
            "Total events produced/consumed by the Kafka/Flink event bus",
            ["topic", "direction"],
        )
    except ValueError:
        STREAMS_EVENTS_TOTAL = REGISTRY._names_to_collectors.get("warden_streams_events_total")  # type: ignore[attr-defined, assignment]

    # ── Tokenomics (MKT-11, v6.6) ───────────────────────────────────────────
    try:
        WAT_TRANSFERS_TOTAL = Counter(
            "warden_wat_transfers_total",
            "Total WAT token transfers (on-chain + simulation)",
            ["rail"],
        )
    except ValueError:
        WAT_TRANSFERS_TOTAL = REGISTRY._names_to_collectors.get("warden_wat_transfers_total")  # type: ignore[attr-defined, assignment]

    # ── USDC Payments (MKT-12, v6.6) ─────────────────────────────────────────
    try:
        USDC_INTENTS_TOTAL = Counter(
            "warden_usdc_intents_total",
            "Total USDC payment intents created",
            ["chain", "status"],
        )
    except ValueError:
        USDC_INTENTS_TOTAL = REGISTRY._names_to_collectors.get("warden_usdc_intents_total")  # type: ignore[attr-defined, assignment]

    # ── ANS Certificates (MKT-13, v6.6) ──────────────────────────────────────
    try:
        ANS_CERTS_ISSUED_TOTAL = Counter(
            "warden_ans_certs_issued_total",
            "Total ANS X.509 certificates issued",
        )
    except ValueError:
        ANS_CERTS_ISSUED_TOTAL = REGISTRY._names_to_collectors.get("warden_ans_certs_issued_total")  # type: ignore[attr-defined, assignment]

    try:
        ANS_CERTS_REVOKED_TOTAL = Counter(
            "warden_ans_certs_revoked_total",
            "Total ANS X.509 certificates revoked",
        )
    except ValueError:
        ANS_CERTS_REVOKED_TOTAL = REGISTRY._names_to_collectors.get("warden_ans_certs_revoked_total")  # type: ignore[attr-defined, assignment]

    # ── Edge Agent Packs (MKT-14, v6.6) ──────────────────────────────────────
    try:
        EDGE_PACK_ANALYZE_TOTAL = Counter(
            "warden_edge_pack_analyze_total",
            "Total edge agent pack analyze() calls",
            ["pack"],
        )
    except ValueError:
        EDGE_PACK_ANALYZE_TOTAL = REGISTRY._names_to_collectors.get("warden_edge_pack_analyze_total")  # type: ignore[attr-defined, assignment]

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

    SANDBOX_VIOLATIONS_TOTAL        = _Noop()  # type: ignore[assignment]
    AGENT_SESSIONS_REVOKED_TOTAL    = _Noop()  # type: ignore[assignment]
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
    IMAGE_GUARD_BLOCKS_TOTAL        = _Noop()  # type: ignore[assignment]
    AUDIO_GUARD_BLOCKS_TOTAL        = _Noop()  # type: ignore[assignment]
    MULTIMODAL_REQUESTS_TOTAL       = _Noop()  # type: ignore[assignment]
    SYNC_RULES_PUBLISHED_TOTAL      = _Noop()  # type: ignore[assignment]
    SYNC_RULES_APPLIED_TOTAL        = _Noop()  # type: ignore[assignment]
    SYNC_CORPUS_UPLOADS_TOTAL       = _Noop()  # type: ignore[assignment]
    SYNC_CORPUS_DOWNLOADS_TOTAL     = _Noop()  # type: ignore[assignment]
    SYNC_BLOCKS_PROPAGATED_TOTAL    = _Noop()  # type: ignore[assignment]
    SYNC_BLOCKS_APPLIED_TOTAL       = _Noop()  # type: ignore[assignment]
    SHADOW_BAN_TOTAL                = _Noop()  # type: ignore[assignment]
    SHADOW_BAN_COST_SAVED_USD       = _Noop()  # type: ignore[assignment]
    NEMOTRON_EVOLUTION_TOTAL        = _Noop()  # type: ignore[assignment]
    DOC_INTEL_CONVERT_TOTAL         = _Noop()  # type: ignore[assignment]
    DOC_INTEL_CONVERT_ERRORS_TOTAL  = _Noop()  # type: ignore[assignment]
    DOC_INTEL_CACHE_HITS_TOTAL      = _Noop()  # type: ignore[assignment]
    PUSH_NOTIFICATIONS_SENT         = _Noop()  # type: ignore[assignment]
    MARKETPLACE_LISTINGS_TOTAL      = _Noop()  # type: ignore[assignment]
    MARKETPLACE_PURCHASES_TOTAL     = _Noop()  # type: ignore[assignment]
    MARKETPLACE_TRADE_VOLUME_USD    = _Noop()  # type: ignore[assignment]
    MARKETPLACE_ESCROW_ACTIVE       = _Noop()  # type: ignore[assignment]
    MARKETPLACE_AGENTS_ACTIVE       = _Noop()  # type: ignore[assignment]
    MARKETPLACE_NEGOTIATIONS_ACTIVE = _Noop()  # type: ignore[assignment]
    COMPLIANCE_OVERALL_SCORE        = _Noop()  # type: ignore[assignment]
    COMPLIANCE_GAPS_OPEN            = _Noop()  # type: ignore[assignment]
    COMPLIANCE_CONTROLS_PASSED      = _Noop()  # type: ignore[assignment]
    COMPLIANCE_FRAMEWORK_SCORE      = _Noop()  # type: ignore[assignment]
    COMMUNITY_MEMBERS_TOTAL         = _Noop()  # type: ignore[assignment]
    COMMUNITY_COMMUNITIES_ACTIVE    = _Noop()  # type: ignore[assignment]
    COMMUNITY_PEERING_CONNECTIONS   = _Noop()  # type: ignore[assignment]
    COMMUNITY_SEP_TRANSFERS_TOTAL   = _Noop()  # type: ignore[assignment]
    COMMUNITY_DOCUMENTS_SCANNED     = _Noop()  # type: ignore[assignment]
    TUNNEL_PREFLIGHT_TOTAL          = _Noop()  # type: ignore[assignment]
    ESCROW_RPC_CHECK_TOTAL          = _Noop()  # type: ignore[assignment]
    MAESTRO_MISALIGNMENT_TOTAL      = _Noop()  # type: ignore[assignment]
    MAESTRO_COLLUSION_TOTAL         = _Noop()  # type: ignore[assignment]
    MAESTRO_POISONING_TOTAL         = _Noop()  # type: ignore[assignment]
    STREAMS_EVENTS_TOTAL            = _Noop()  # type: ignore[assignment]
    WAT_TRANSFERS_TOTAL             = _Noop()  # type: ignore[assignment]
    USDC_INTENTS_TOTAL              = _Noop()  # type: ignore[assignment]
    ANS_CERTS_ISSUED_TOTAL          = _Noop()  # type: ignore[assignment]
    ANS_CERTS_REVOKED_TOTAL         = _Noop()  # type: ignore[assignment]
    EDGE_PACK_ANALYZE_TOTAL         = _Noop()  # type: ignore[assignment]
