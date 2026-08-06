"""filter_events hypertable — SQL read path for the /filter decision journal (D-3)

`data/logs.json` (NDJSON) is the write-side journal for every `/filter` decision,
and **25 modules read it back by scanning the whole file**: the Streamlit and MSP
dashboards, BI, XAI (`build_chain()` per record), compliance posture, Art.30,
SOC 2, public stats, billing, tenant impact, onboarding, the portal. Several call
`load_entries()` with no window at all, so their cost grows linearly in total
history, forever — the file is only ever trimmed by GDPR retention.

This table is the SQL read path for the same data. The NDJSON file stays the
authority: it is what `append()` writes first, what the S3 evidence ship reads,
and what the GDPR erasure machinery owns.

GDPR
────
`build_entry()` records **metadata only** — never content, never decoded text,
never secret values; `secrets_found` and `entities_detected` hold type *names*.
This table mirrors exactly those fields and adds no others. Do not add a column
that could carry payload text.

Retention is deliberately **not** a Timescale policy here. It is owned by
`GDPR_LOG_RETENTION_DAYS` via `logger.purge_old_entries()`, which now purges this
table in the same call — one retention authority instead of an env var and a
hardcoded SQL interval that would silently drift apart. Compression (no data
loss) is policy-driven; deletion is not.

Revision ID: 0013
Revises: 0012
"""
from __future__ import annotations

from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE")

    # (request_id, ts) primary key: a hypertable's unique index must include the
    # partitioning column, and this shape gives the mirror the same idempotency
    # the NDJSON writer has via its seen-request_id set — a retried append is an
    # ON CONFLICT DO NOTHING, not a duplicate row.
    op.execute("""
        CREATE TABLE IF NOT EXISTS warden_core.filter_events (
            ts                TIMESTAMPTZ   NOT NULL,
            request_id        TEXT          NOT NULL,
            tenant_id         TEXT          NOT NULL DEFAULT 'default',
            allowed           BOOLEAN       NOT NULL,
            risk_level        TEXT          NOT NULL,
            flags             TEXT[]        NOT NULL DEFAULT '{}',
            secrets_found     TEXT[]        NOT NULL DEFAULT '{}',
            payload_len       INTEGER       NOT NULL DEFAULT 0,
            payload_tokens    INTEGER       NOT NULL DEFAULT 0,
            attack_cost_usd   NUMERIC(14,6) NOT NULL DEFAULT 0,
            elapsed_ms        NUMERIC(10,2),
            strict            BOOLEAN       NOT NULL DEFAULT FALSE,
            session_id        TEXT,
            entities_detected TEXT[]        NOT NULL DEFAULT '{}',
            entity_count      INTEGER       NOT NULL DEFAULT 0,
            masked            BOOLEAN       NOT NULL DEFAULT FALSE,
            PRIMARY KEY (request_id, ts)
        )
    """)

    op.execute("""
        SELECT create_hypertable(
            'warden_core.filter_events', 'ts',
            chunk_time_interval => INTERVAL '1 day',
            if_not_exists => TRUE
        )
    """)

    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_filter_events_ts
            ON warden_core.filter_events (ts DESC)
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_filter_events_tenant_ts
            ON warden_core.filter_events (tenant_id, ts DESC)
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_filter_events_risk_ts
            ON warden_core.filter_events (risk_level, ts DESC)
    """)

    # ── Hourly rollup — what the dashboards actually plot ─────────────────────
    # This is the point of the slice: a dashboard reads a bucket count instead of
    # parsing every line ever written.
    op.execute("""
        CREATE MATERIALIZED VIEW IF NOT EXISTS warden_core.filter_events_hourly
        WITH (timescaledb.continuous) AS
        SELECT
            time_bucket('1 hour', ts)                        AS bucket,
            tenant_id,
            COUNT(*)                                         AS total,
            COUNT(*) FILTER (WHERE allowed)                  AS allowed,
            COUNT(*) FILTER (WHERE NOT allowed)              AS blocked,
            COUNT(*) FILTER (WHERE risk_level = 'HIGH')      AS high,
            COUNT(*) FILTER (WHERE risk_level = 'BLOCK')     AS block,
            COUNT(*) FILTER (WHERE masked)                   AS masked,
            SUM(attack_cost_usd)                             AS attack_cost_usd,
            AVG(elapsed_ms)                                  AS avg_elapsed_ms,
            MAX(elapsed_ms)                                  AS max_elapsed_ms
        FROM warden_core.filter_events
        GROUP BY bucket, tenant_id
        WITH NO DATA
    """)

    op.execute("""
        SELECT add_continuous_aggregate_policy(
            'warden_core.filter_events_hourly',
            start_offset      => INTERVAL '3 hours',
            end_offset        => INTERVAL '1 minute',
            schedule_interval => INTERVAL '15 minutes',
            if_not_exists     => TRUE
        )
    """)

    # Compression only — it reorganises storage, it never drops rows, so it
    # cannot conflict with GDPR retention being owned elsewhere.
    op.execute("""
        ALTER TABLE warden_core.filter_events
            SET (
                timescaledb.compress,
                timescaledb.compress_orderby   = 'ts DESC',
                timescaledb.compress_segmentby = 'tenant_id'
            )
    """)
    op.execute("""
        SELECT add_compression_policy(
            'warden_core.filter_events',
            INTERVAL '7 days',
            if_not_exists => TRUE
        )
    """)


def downgrade() -> None:
    op.execute("DROP MATERIALIZED VIEW IF EXISTS warden_core.filter_events_hourly CASCADE")
    op.execute("DROP TABLE IF EXISTS warden_core.filter_events CASCADE")
