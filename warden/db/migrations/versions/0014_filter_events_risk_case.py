"""filter_events: canonical upper-case risk_level, and an aggregate that agrees

Revision ID: 0014
Revises: 0013
Create Date: 2026-08-08

`0013` compares `risk_level` against the literals `'HIGH'` and `'BLOCK'`, in the
hypertable's continuous aggregate and in every reader built on it. The `/filter`
journal writes those values **lower-case** — measured in production on
2026-08-08, the whole mirror was `block` 2027 / `high` 1013 / `low` 272 — so
every one of those comparisons matched nothing.

The result was not an error. `total` and `blocked` are computed from `COUNT(*)`
and `NOT allowed`, which do not depend on the casing, so they stayed correct;
only the severity split collapsed. `filter_events_hourly` reported
`high = 0, block = 0` over 3 040 real threat events, and reported it with the
same confidence as the numbers that were right.

This revision does three things:

  1. normalises the rows already stored (`risk_level = upper(risk_level)`),
  2. rebuilds `filter_events_hourly` so its own definition compares
     `upper(risk_level)` — a continuous aggregate stores the query text it was
     created with, so the literals cannot be fixed in place, and
  3. re-materialises it over the full range, because a freshly created
     aggregate holds nothing and its refresh policy only reaches back 3 hours.

`events_store._params()` upper-cases on write from this revision on, so (1) is
a one-off; the readers use `upper(risk_level)` anyway, so a row written by an
older build is still counted correctly.

Dropping and recreating the aggregate is safe: it is derived state, rebuilt
here from the hypertable, which is itself a mirror of the NDJSON journal that
remains the authority.
"""
from __future__ import annotations

from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


_CAGG_BODY = """
    SELECT
        time_bucket('1 hour', ts)                               AS bucket,
        tenant_id,
        COUNT(*)                                                AS total,
        COUNT(*) FILTER (WHERE allowed)                         AS allowed,
        COUNT(*) FILTER (WHERE NOT allowed)                     AS blocked,
        COUNT(*) FILTER (WHERE upper(risk_level) = 'HIGH')      AS high,
        COUNT(*) FILTER (WHERE upper(risk_level) = 'BLOCK')     AS block,
        COUNT(*) FILTER (WHERE masked)                          AS masked,
        SUM(attack_cost_usd)                                    AS attack_cost_usd,
        AVG(elapsed_ms)                                         AS avg_elapsed_ms,
        MAX(elapsed_ms)                                         AS max_elapsed_ms
    FROM warden_core.filter_events
    GROUP BY bucket, tenant_id
"""


def upgrade() -> None:
    # 1. Canonicalise what is already stored. Cheap and idempotent.
    op.execute("""
        UPDATE warden_core.filter_events
           SET risk_level = upper(risk_level)
         WHERE risk_level <> upper(risk_level)
    """)

    # 2. Rebuild the aggregate. CASCADE also drops its refresh policy, which is
    #    recreated below with the same parameters 0013 used.
    op.execute("DROP MATERIALIZED VIEW IF EXISTS warden_core.filter_events_hourly CASCADE")
    op.execute(f"""
        CREATE MATERIALIZED VIEW IF NOT EXISTS warden_core.filter_events_hourly
        WITH (timescaledb.continuous) AS
        {_CAGG_BODY}
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

    # 3. Materialise the history. `CALL refresh_continuous_aggregate` cannot run
    #    inside a transaction block, and Alembic wraps this migration in one, so
    #    it is committed first. Deliberately not fatal: the rows are in the
    #    hypertable either way, and `events_store.refresh_hourly_aggregate()`
    #    performs exactly this call if it has to be done by hand later.
    op.execute("COMMIT")
    op.execute(
        "CALL refresh_continuous_aggregate('warden_core.filter_events_hourly', NULL, NULL)"
    )


def downgrade() -> None:
    op.execute("DROP MATERIALIZED VIEW IF EXISTS warden_core.filter_events_hourly CASCADE")
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
