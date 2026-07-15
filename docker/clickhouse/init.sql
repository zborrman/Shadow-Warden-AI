-- GSAM observations OLAP store (v7.7).
-- Mirrors warden/gsam/schema.py CLICKHOUSE_TABLE_DDL — keep both in sync.
-- The warden app also runs CREATE ... IF NOT EXISTS lazily (self-healing),
-- so this file only speeds up first boot.

CREATE DATABASE IF NOT EXISTS gsam;

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
SETTINGS ttl_only_drop_parts = 1;
