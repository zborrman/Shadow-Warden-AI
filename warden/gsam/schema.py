"""
GSAM observation schema — pydantic model + ClickHouse DDL.

GDPR hard rule: observations carry METADATA ONLY. There is deliberately no
content/prompt/body field — `payload_kind` is a short label (e.g. "tool_call",
"drift_update"), never payload text. Any new field added here must be a
counter, identifier, enum, or score.
"""
from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field, field_validator

# Field names that must never appear in externally submitted observations —
# they indicate someone is trying to ship content into the analytics stream.
FORBIDDEN_FIELD_HINTS = ("content", "prompt", "body", "text", "message", "payload_json")

SCAN_VERDICTS = ("CLEAN", "WARNING", "COMPROMISED")
AGENT_ROLES = ("ASSISTANT", "SERVICE")


class Observation(BaseModel):
    """One row of the gsam_observations wide table (metadata only)."""

    ts: datetime = Field(default_factory=lambda: datetime.now(UTC))
    trace_id: str = ""
    span_id: str = ""
    parent_span_id: str = ""
    session_id: str = ""

    # Marketplace context
    tenant_id: str = ""
    agent_id: str = ""
    project_id: str = ""
    contract_id: str = ""
    role: str = "SERVICE"

    # Event
    event: str = ""            # e.g. tool_call, billing_event, marketplace_action
    payload_kind: str = ""     # short label — NEVER content
    status: str = ""

    # LLM resource consumption
    model: str = ""
    provider: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0     # prompt-cache read hits (billed at ~10% of input rate)
    execution_cost: float = 0.0
    latency_ms: float = 0.0

    # System security (external sensors — SAC adaptation)
    syscalls_count: int = 0
    unauthorized_commands_flag: bool = False
    network_calls_count: int = 0
    resolved_domains: list[str] = Field(default_factory=list)

    # Compliance / risk scores
    drift_score: float = 0.0
    trust_score: float = 0.0
    scan_verdict: str = "CLEAN"

    @field_validator("role")
    @classmethod
    def _role_ok(cls, v: str) -> str:
        return v if v in AGENT_ROLES else "SERVICE"

    @field_validator("scan_verdict")
    @classmethod
    def _verdict_ok(cls, v: str) -> str:
        return v if v in SCAN_VERDICTS else "CLEAN"

    @field_validator("resolved_domains")
    @classmethod
    def _domains_cap(cls, v: list[str]) -> list[str]:
        # Cap cardinality; domain names only (no URLs with paths/queries).
        return [d.split("/")[0][:253] for d in v[:50]]

    def to_row(self) -> dict:
        """Flat dict ready for the collector queue / ClickHouse insert."""
        row = self.model_dump()
        row["ts"] = self.ts.isoformat()
        row["unauthorized_commands_flag"] = int(self.unauthorized_commands_flag)
        return row


# Column order for ClickHouse batch inserts (must match DDL below).
CLICKHOUSE_COLUMNS: tuple[str, ...] = (
    "ts", "trace_id", "span_id", "parent_span_id", "session_id",
    "tenant_id", "agent_id", "project_id", "contract_id", "role",
    "event", "payload_kind", "status",
    "model", "provider", "input_tokens", "output_tokens", "cached_tokens",
    "execution_cost", "latency_ms",
    "syscalls_count", "unauthorized_commands_flag", "network_calls_count",
    "resolved_domains",
    "drift_score", "trust_score", "scan_verdict",
)

CLICKHOUSE_DATABASE_DDL = "CREATE DATABASE IF NOT EXISTS gsam"

CLICKHOUSE_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS gsam.gsam_observations
(
    ts DateTime64(3, 'UTC') CODEC(Delta, ZSTD(1)),
    date Date DEFAULT toDate(ts),
    trace_id String CODEC(ZSTD(1)),
    span_id String CODEC(ZSTD(1)),
    parent_span_id String CODEC(ZSTD(1)),
    session_id String CODEC(ZSTD(1)),

    tenant_id LowCardinality(String) CODEC(ZSTD(1)),
    agent_id LowCardinality(String) CODEC(ZSTD(1)),
    project_id LowCardinality(String) CODEC(ZSTD(1)),
    contract_id String CODEC(ZSTD(1)),
    role Enum8('ASSISTANT' = 1, 'SERVICE' = 2) DEFAULT 'SERVICE' CODEC(ZSTD(1)),

    event LowCardinality(String) CODEC(ZSTD(1)),
    payload_kind LowCardinality(String) CODEC(ZSTD(1)),
    status LowCardinality(String) CODEC(ZSTD(1)),

    model LowCardinality(String) CODEC(ZSTD(1)),
    provider LowCardinality(String) CODEC(ZSTD(1)),
    input_tokens UInt32 CODEC(ZSTD(1)),
    output_tokens UInt32 CODEC(ZSTD(1)),
    cached_tokens UInt32 DEFAULT 0 CODEC(ZSTD(1)),
    execution_cost Float64 CODEC(ZSTD(1)),
    latency_ms Float64 CODEC(ZSTD(1)),

    syscalls_count UInt32 CODEC(ZSTD(1)),
    unauthorized_commands_flag UInt8 CODEC(ZSTD(1)),
    network_calls_count UInt16 CODEC(ZSTD(1)),
    resolved_domains Array(String) CODEC(ZSTD(3)),

    drift_score Float64 CODEC(ZSTD(1)),
    trust_score Float64 CODEC(ZSTD(1)),
    scan_verdict Enum8('CLEAN' = 1, 'WARNING' = 2, 'COMPROMISED' = 3) DEFAULT 'CLEAN' CODEC(ZSTD(1)),

    INDEX idx_resolved_domains resolved_domains TYPE set(50) GRANULARITY 1,
    INDEX idx_session_id session_id TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_trace_id trace_id TYPE bloom_filter(0.01) GRANULARITY 1
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(date)
ORDER BY (tenant_id, agent_id, toUnixTimestamp(ts), trace_id)
TTL date + INTERVAL 30 DAY
SETTINGS ttl_only_drop_parts = 1
"""

# Idempotent, additive migrations for tables created before a column existed.
# `CREATE TABLE IF NOT EXISTS` never alters an existing table, so a column added
# to the DDL above must also be back-filled here with `ADD COLUMN IF NOT EXISTS`.
# Run after the CREATE in ensure_schema(); each is idempotent and safe to re-run
# (the caller swallows + counts any failure — see clickhouse.py).
CLICKHOUSE_MIGRATIONS: tuple[str, ...] = (
    "ALTER TABLE gsam.gsam_observations "
    "ADD COLUMN IF NOT EXISTS cached_tokens UInt32 DEFAULT 0 AFTER output_tokens",
)

# ── FM-2 real-time cost rating: billing ledger ────────────────────────────────
# A SummingMergeTree pre-aggregation of raw token counts per
# (date, tenant, agent, model, provider). It stores UNITS ONLY — the price book
# lives in warden.finops.rating and is applied at read time, so a price change
# never requires a ClickHouse rewrite. The materialized view folds each new
# observation insert into the ledger (it does not backfill history). Applied by
# clickhouse.py::ensure_schema, each statement swallowed + counted like the migrations.
CLICKHOUSE_BILLING_DDL: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS gsam.billing_session_ledger
    (
        date Date,
        tenant_id LowCardinality(String),
        agent_id LowCardinality(String),
        model LowCardinality(String),
        provider LowCardinality(String),
        calls UInt64,
        input_tokens UInt64,
        output_tokens UInt64,
        cached_tokens UInt64,
        execution_cost Float64
    )
    ENGINE = SummingMergeTree()
    PARTITION BY toYYYYMM(date)
    ORDER BY (tenant_id, agent_id, model, provider, date)
    """,
    """
    CREATE MATERIALIZED VIEW IF NOT EXISTS gsam.billing_session_ledger_mv
    TO gsam.billing_session_ledger
    AS SELECT
        toDate(ts) AS date,
        tenant_id,
        agent_id,
        model,
        provider,
        count() AS calls,
        sum(input_tokens) AS input_tokens,
        sum(output_tokens) AS output_tokens,
        sum(cached_tokens) AS cached_tokens,
        sum(execution_cost) AS execution_cost
    FROM gsam.gsam_observations
    WHERE (input_tokens > 0) OR (output_tokens > 0) OR (cached_tokens > 0)
    GROUP BY date, tenant_id, agent_id, model, provider
    """,
)
