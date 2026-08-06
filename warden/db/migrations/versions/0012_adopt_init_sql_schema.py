"""Adopt data/init.sql's schema into Alembic (D-1b)

`data/init.sql` is mounted at `/docker-entrypoint-initdb.d/init.sql`, so Postgres
runs it **only when initialising an empty data directory** — first `docker compose
up` on a fresh volume, and never again. Any object added to it afterwards never
reaches an existing deployment, and any object it creates is invisible to the
migration tree. That split left two concrete gaps:

  * Six tables lived only in init.sql — `api_keys`, `filter_audit`,
    `dynamic_rules`, `hourly_stats` (unreferenced today) and `cert_applications`,
    `waitlist` (both queried by shipped code).

  * The `portal_users` TOTP/reset columns were patched in by init.sql via
    `ALTER TABLE IF EXISTS warden_core.portal_users ADD COLUMN IF NOT EXISTS …`.
    On a fresh volume that `ALTER` is a **no-op**: at Postgres-init time
    `portal_users` does not exist yet — it is created later by the application's
    `create_schema()` during the FastAPI lifespan. `create_schema()` defines
    `reset_token`/`reset_expires` but **not** `totp_secret`/`totp_enabled`, and
    neither did any migration. So on such a deployment those two columns exist
    nowhere, while `warden/portal_router.py` reads and writes them in eight
    places (`/portal/totp/*`, and the login path branches on `totp_enabled`) —
    portal MFA fails with "column does not exist".

Running the `ALTER` here fixes the ordering: 0001 creates `portal_users`, and
this revision patches it afterwards. Everything is `IF NOT EXISTS`, so a
deployment that already has these objects (from an early init.sql run) is
adopted unchanged.

init.sql itself is intentionally left in place — it still gives a brand-new
container its schema before the app's first boot. Alembic is now a strict
superset of it, which `warden/tests/test_db_migrate.py` asserts, so the two can
no longer drift.

Revision ID: 0012
Revises: 0011
"""
from __future__ import annotations

from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS warden_core")
    op.execute("CREATE SCHEMA IF NOT EXISTS warden_analytics")

    # ── Service-to-service auth tokens ────────────────────────────────────────
    op.execute("""
        CREATE TABLE IF NOT EXISTS warden_core.api_keys (
            id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            name        TEXT        NOT NULL,
            key_hash    TEXT        NOT NULL UNIQUE,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            expires_at  TIMESTAMPTZ,
            revoked     BOOLEAN     NOT NULL DEFAULT FALSE
        )
    """)

    # ── /filter decision audit — metadata only, content is NEVER stored (GDPR) ─
    op.execute("""
        CREATE TABLE IF NOT EXISTS warden_core.filter_audit (
            id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            request_id   TEXT        NOT NULL,
            ts           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            allowed      BOOLEAN     NOT NULL,
            risk_level   TEXT        NOT NULL,
            flags        TEXT[]      NOT NULL DEFAULT '{}',
            secrets_kind TEXT[]      NOT NULL DEFAULT '{}',
            content_len  INTEGER     NOT NULL,
            elapsed_ms   NUMERIC(10,2),
            strict       BOOLEAN     NOT NULL DEFAULT FALSE
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS filter_audit_ts_idx   ON warden_core.filter_audit (ts DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS filter_audit_risk_idx ON warden_core.filter_audit (risk_level)")

    # ── Evolution-Loop generated rules ────────────────────────────────────────
    op.execute("""
        CREATE TABLE IF NOT EXISTS warden_core.dynamic_rules (
            id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            source_hash     TEXT        NOT NULL UNIQUE,
            attack_type     TEXT        NOT NULL,
            rule_type       TEXT        NOT NULL,
            rule_value      TEXT        NOT NULL,
            description     TEXT,
            severity        TEXT        NOT NULL,
            times_triggered INTEGER     NOT NULL DEFAULT 0
        )
    """)

    # ── Pre-computed hourly metrics ───────────────────────────────────────────
    op.execute("""
        CREATE TABLE IF NOT EXISTS warden_analytics.hourly_stats (
            hour          TIMESTAMPTZ NOT NULL,
            total         INTEGER     NOT NULL DEFAULT 0,
            allowed       INTEGER     NOT NULL DEFAULT 0,
            blocked       INTEGER     NOT NULL DEFAULT 0,
            high_severity INTEGER     NOT NULL DEFAULT 0,
            avg_ms        NUMERIC(10,2),
            PRIMARY KEY (hour)
        )
    """)

    # ── Red-team certification applications ───────────────────────────────────
    op.execute("""
        CREATE TABLE IF NOT EXISTS warden_core.cert_applications (
            id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            full_name       TEXT        NOT NULL,
            email           TEXT        NOT NULL UNIQUE,
            company         TEXT,
            role            TEXT        NOT NULL,
            experience      TEXT        NOT NULL,
            motivation      TEXT        NOT NULL,
            linkedin_url    TEXT,
            github_url      TEXT,
            cohort          TEXT        NOT NULL DEFAULT 'pilot-2025',
            status          TEXT        NOT NULL DEFAULT 'pending',
            score           INTEGER,
            reviewer_notes  TEXT,
            applied_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            reviewed_at     TIMESTAMPTZ,
            notified_at     TIMESTAMPTZ
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS cert_app_email_idx   ON warden_core.cert_applications (email)")
    op.execute("CREATE INDEX IF NOT EXISTS cert_app_status_idx  ON warden_core.cert_applications (status)")
    op.execute("CREATE INDEX IF NOT EXISTS cert_app_cohort_idx  ON warden_core.cert_applications (cohort)")
    op.execute("CREATE INDEX IF NOT EXISTS cert_app_applied_idx ON warden_core.cert_applications (applied_at DESC)")

    # ── Early-access waitlist ─────────────────────────────────────────────────
    op.execute("""
        CREATE TABLE IF NOT EXISTS warden_core.waitlist (
            id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            email        TEXT        NOT NULL UNIQUE,
            full_name    TEXT        NOT NULL,
            company      TEXT,
            modules      TEXT[]      NOT NULL DEFAULT '{}',
            source       TEXT        NOT NULL DEFAULT 'early-access',
            ip_hash      TEXT,
            created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            confirmed_at TIMESTAMPTZ,
            status       TEXT        NOT NULL DEFAULT 'pending'
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS waitlist_email_idx   ON warden_core.waitlist (email)")
    op.execute("CREATE INDEX IF NOT EXISTS waitlist_status_idx  ON warden_core.waitlist (status)")
    op.execute("CREATE INDEX IF NOT EXISTS waitlist_created_idx ON warden_core.waitlist (created_at DESC)")

    # ── portal_users MFA + password-reset columns ─────────────────────────────
    # The gap this closes: init.sql's identical ALTER is a no-op on a fresh
    # volume because portal_users does not exist yet at Postgres-init time.
    # Here 0001 has already created it.
    op.execute("""
        ALTER TABLE IF EXISTS warden_core.portal_users
            ADD COLUMN IF NOT EXISTS totp_secret   TEXT,
            ADD COLUMN IF NOT EXISTS totp_enabled  BOOLEAN NOT NULL DEFAULT FALSE,
            ADD COLUMN IF NOT EXISTS reset_token   TEXT,
            ADD COLUMN IF NOT EXISTS reset_expires TIMESTAMPTZ
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS warden_core.waitlist CASCADE")
    op.execute("DROP TABLE IF EXISTS warden_core.cert_applications CASCADE")
    op.execute("DROP TABLE IF EXISTS warden_analytics.hourly_stats CASCADE")
    op.execute("DROP TABLE IF EXISTS warden_core.dynamic_rules CASCADE")
    op.execute("DROP TABLE IF EXISTS warden_core.filter_audit CASCADE")
    op.execute("DROP TABLE IF EXISTS warden_core.api_keys CASCADE")
    # portal_users columns are deliberately not dropped — they hold live MFA
    # secrets, and 0011→0012 is not a data-destroying boundary.
