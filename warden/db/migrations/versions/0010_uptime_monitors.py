"""Uptime monitoring — monitors table + probe_results hypertable + continuous aggregates

Revision ID: 0010
Revises: 0001
Create Date: 2026-04-12
"""
from __future__ import annotations

from alembic import op

revision = "0010"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Enable TimescaleDB extension ──────────────────────────────────────────
    op.execute("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE")

    # ── monitors — one row per configured check ───────────────────────────────
    op.execute("""
        CREATE TABLE IF NOT EXISTS warden_core.monitors (
            id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id   TEXT        NOT NULL,
            name        TEXT        NOT NULL DEFAULT '',
            url         TEXT        NOT NULL,
            interval_s  INT         NOT NULL DEFAULT 60,
            check_type  TEXT        NOT NULL DEFAULT 'http',  -- http|ssl|dns|tcp
            is_active   BOOL        NOT NULL DEFAULT TRUE,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_monitors_tenant
            ON warden_core.monitors(tenant_id)
    """)

    # ── probe_results — TimescaleDB hypertable ────────────────────────────────
    op.execute("""
        CREATE TABLE IF NOT EXISTS warden_core.probe_results (
            time        TIMESTAMPTZ NOT NULL,
            monitor_id  UUID        NOT NULL REFERENCES warden_core.monitors(id) ON DELETE CASCADE,
            tenant_id   TEXT        NOT NULL,
            is_up       BOOL        NOT NULL,
            status_code INT,
            latency_ms  DOUBLE PRECISION,
            error       TEXT
        )
    """)

    # Convert to hypertable (1-day chunks — fits in RAM for active data)
    op.execute("""
        SELECT create_hypertable(
            'warden_core.probe_results', 'time',
            chunk_time_interval => INTERVAL '1 day',
            if_not_exists => TRUE
        )
    """)

    # Composite index: fast lookup of latest result per monitor
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_probe_results_monitor_time
            ON warden_core.probe_results(monitor_id, time DESC)
    """)

    # BRIN index for range scans on large archive slices
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_probe_results_brin
            ON warden_core.probe_results USING BRIN(time)
    """)

    # ── Continuous aggregate: 1-hour uptime/latency buckets ──────────────────
    op.execute("""
        CREATE MATERIALIZED VIEW IF NOT EXISTS warden_core.probe_hourly
        WITH (timescaledb.continuous) AS
        SELECT
            time_bucket('1 hour', time)  AS bucket,
            monitor_id,
            tenant_id,
            ROUND(AVG(latency_ms)::numeric, 2)       AS avg_latency_ms,
            ROUND((AVG(is_up::int) * 100)::numeric, 2) AS uptime_pct,
            COUNT(*)                                  AS checks
        FROM warden_core.probe_results
        GROUP BY bucket, monitor_id, tenant_id
        WITH NO DATA
    """)

    # Refresh policy: recompute last 3 hours every 30 minutes
    op.execute("""
        SELECT add_continuous_aggregate_policy(
            'warden_core.probe_hourly',
            start_offset => INTERVAL '3 hours',
            end_offset   => INTERVAL '1 minute',
            schedule_interval => INTERVAL '30 minutes',
            if_not_exists => TRUE
        )
    """)

    # ── Retention policies ────────────────────────────────────────────────────
    # Raw probes: 30 days; hourly aggregates: 2 years
    op.execute("""
        SELECT add_retention_policy(
            'warden_core.probe_results',
            INTERVAL '30 days',
            if_not_exists => TRUE
        )
    """)
    op.execute("""
        SELECT add_retention_policy(
            'warden_core.probe_hourly',
            INTERVAL '730 days',
            if_not_exists => TRUE
        )
    """)

    # ── Compression (columnar storage, ~90% ratio after 7 days) ──────────────
    op.execute("""
        ALTER TABLE warden_core.probe_results
            SET (
                timescaledb.compress,
                timescaledb.compress_orderby   = 'time DESC',
                timescaledb.compress_segmentby = 'monitor_id'
            )
    """)
    op.execute("""
        SELECT add_compression_policy(
            'warden_core.probe_results',
            INTERVAL '7 days',
            if_not_exists => TRUE
        )
    """)


def downgrade() -> None:
    op.execute("DROP MATERIALIZED VIEW IF EXISTS warden_core.probe_hourly CASCADE")
    op.execute("DROP TABLE IF EXISTS warden_core.probe_results CASCADE")
    op.execute("DROP TABLE IF EXISTS warden_core.monitors CASCADE")
