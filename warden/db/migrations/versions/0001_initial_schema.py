"""Initial schema — all tables from create_schema()

Revision ID: 0001
Revises:
Create Date: 2026-04-06

"""
from __future__ import annotations

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS warden_core")

    op.execute("""
        CREATE TABLE IF NOT EXISTS warden_core.threat_intel_items (
            id                  TEXT        PRIMARY KEY,
            source              TEXT        NOT NULL,
            title               TEXT        NOT NULL,
            url                 TEXT        NOT NULL,
            source_url_hash     TEXT        UNIQUE NOT NULL,
            published_at        TEXT,
            raw_description     TEXT,
            relevance_score     NUMERIC(4,3),
            owasp_category      TEXT,
            attack_pattern      TEXT,
            detection_hint      TEXT,
            countermeasure      TEXT,
            status              TEXT        NOT NULL DEFAULT 'new',
            rules_generated     INTEGER     NOT NULL DEFAULT 0,
            created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            analyzed_at         TIMESTAMPTZ
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS warden_core.threat_intel_countermeasures (
            id              BIGSERIAL   PRIMARY KEY,
            threat_item_id  TEXT        NOT NULL
                            REFERENCES warden_core.threat_intel_items(id),
            rule_id         TEXT        NOT NULL,
            rule_type       TEXT        NOT NULL,
            rule_value      TEXT        NOT NULL,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS warden_core.rule_ledger (
            rule_id         TEXT        PRIMARY KEY,
            source          TEXT        NOT NULL,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            pattern_snippet TEXT,
            rule_type       TEXT,
            status          TEXT        NOT NULL DEFAULT 'active'
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS warden_core.billing_usage (
            id          BIGSERIAL     PRIMARY KEY,
            tenant_id   TEXT          NOT NULL,
            period      TEXT          NOT NULL,
            requests    INTEGER       NOT NULL DEFAULT 0,
            tokens_in   BIGINT        NOT NULL DEFAULT 0,
            tokens_out  BIGINT        NOT NULL DEFAULT 0,
            cost_usd    NUMERIC(10,6) NOT NULL DEFAULT 0,
            updated_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
            UNIQUE (tenant_id, period)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS threat_intel_status_idx ON warden_core.threat_intel_items(status)")
    op.execute("CREATE INDEX IF NOT EXISTS threat_intel_source_idx ON warden_core.threat_intel_items(source)")
    op.execute("CREATE INDEX IF NOT EXISTS rule_ledger_source_idx  ON warden_core.rule_ledger(source)")
    op.execute("CREATE INDEX IF NOT EXISTS billing_tenant_idx      ON warden_core.billing_usage(tenant_id)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS warden_core.portal_users (
            id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            email           TEXT        UNIQUE NOT NULL,
            password_hash   TEXT        NOT NULL,
            display_name    TEXT        NOT NULL DEFAULT '',
            tenant_id       TEXT        NOT NULL,
            role            TEXT        NOT NULL DEFAULT 'owner',
            email_verified  BOOLEAN     NOT NULL DEFAULT false,
            verify_token    TEXT,
            reset_token     TEXT,
            reset_expires   TIMESTAMPTZ,
            notify_high     BOOLEAN     NOT NULL DEFAULT true,
            notify_block    BOOLEAN     NOT NULL DEFAULT true,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_login_at   TIMESTAMPTZ
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS warden_core.portal_api_keys (
            id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            tenant_id   TEXT        NOT NULL,
            label       TEXT        NOT NULL DEFAULT 'Default',
            key_hash    TEXT        UNIQUE NOT NULL,
            key_prefix  TEXT        NOT NULL,
            rate_limit  INTEGER     NOT NULL DEFAULT 60,
            active      BOOLEAN     NOT NULL DEFAULT true,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            created_by  UUID        REFERENCES warden_core.portal_users(id),
            revoked_at  TIMESTAMPTZ
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS portal_users_email_idx  ON warden_core.portal_users(email)")
    op.execute("CREATE INDEX IF NOT EXISTS portal_users_tenant_idx ON warden_core.portal_users(tenant_id)")
    op.execute("CREATE INDEX IF NOT EXISTS portal_keys_tenant_idx  ON warden_core.portal_api_keys(tenant_id)")
    op.execute("CREATE INDEX IF NOT EXISTS portal_keys_hash_idx    ON warden_core.portal_api_keys(key_hash)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS warden_core.syndicates (
            syndicate_id    TEXT        PRIMARY KEY,
            tenant_id       TEXT        UNIQUE NOT NULL,
            display_name    TEXT        NOT NULL DEFAULT '',
            public_key_b64  TEXT        NOT NULL,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS warden_core.syndicate_links (
            link_id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            initiator_sid       TEXT        NOT NULL
                                REFERENCES warden_core.syndicates(syndicate_id),
            responder_sid       TEXT,
            status              TEXT        NOT NULL DEFAULT 'PENDING',
            is_ephemeral        BOOLEAN     NOT NULL DEFAULT TRUE,
            ttl_hours           INTEGER     NOT NULL DEFAULT 24,
            expires_at          TIMESTAMPTZ NOT NULL
                                DEFAULT (NOW() + INTERVAL '24 hours'),
            last_notified_at    TIMESTAMPTZ,
            safety_number       TEXT,
            peer_endpoint       TEXT,
            permissions         JSONB       NOT NULL DEFAULT '{}',
            created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            established_at      TIMESTAMPTZ
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS warden_core.syndicate_members (
            wid             TEXT        PRIMARY KEY,
            syndicate_id    TEXT        NOT NULL
                            REFERENCES warden_core.syndicates(syndicate_id),
            internal_email  TEXT        NOT NULL,
            role            TEXT        NOT NULL DEFAULT 'MEMBER',
            expires_at      TIMESTAMPTZ,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS warden_core.syndicate_invitations (
            invite_code     UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            invite_type     TEXT        NOT NULL,
            creator_sid     TEXT        NOT NULL
                            REFERENCES warden_core.syndicates(syndicate_id),
            target_email    TEXT,
            target_group    TEXT,
            metadata        JSONB       NOT NULL DEFAULT '{}',
            is_used         BOOLEAN     NOT NULL DEFAULT FALSE,
            expires_at      TIMESTAMPTZ NOT NULL
                            DEFAULT (NOW() + INTERVAL '24 hours'),
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS syndicate_links_initiator_idx ON warden_core.syndicate_links(initiator_sid)")
    op.execute("CREATE INDEX IF NOT EXISTS syndicate_links_status_idx    ON warden_core.syndicate_links(status)")
    op.execute("CREATE INDEX IF NOT EXISTS syndicate_members_sid_idx     ON warden_core.syndicate_members(syndicate_id)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS warden_core.communities (
            community_id    TEXT        PRIMARY KEY,
            tenant_id       TEXT        NOT NULL,
            display_name    TEXT        NOT NULL DEFAULT '',
            description     TEXT        NOT NULL DEFAULT '',
            tier            TEXT        NOT NULL DEFAULT 'business',
            active_kid      TEXT        NOT NULL DEFAULT 'v1',
            status          TEXT        NOT NULL DEFAULT 'ACTIVE',
            created_by      TEXT        NOT NULL,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS warden_core.community_members (
            member_id       TEXT        PRIMARY KEY,
            community_id    TEXT        NOT NULL
                            REFERENCES warden_core.communities(community_id),
            tenant_id       TEXT        NOT NULL,
            external_id     TEXT        NOT NULL,
            display_name    TEXT        NOT NULL DEFAULT '',
            clearance       TEXT        NOT NULL DEFAULT 'PUBLIC',
            role            TEXT        NOT NULL DEFAULT 'MEMBER',
            status          TEXT        NOT NULL DEFAULT 'ACTIVE',
            invited_by      TEXT,
            joined_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS warden_core.community_key_archive (
            community_id    TEXT        NOT NULL,
            kid             TEXT        NOT NULL,
            status          TEXT        NOT NULL DEFAULT 'ACTIVE',
            ed25519_pub_b64 TEXT        NOT NULL,
            x25519_pub_b64  TEXT        NOT NULL,
            ed_priv_enc_b64 TEXT,
            x_priv_enc_b64  TEXT,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            shredded_at     TIMESTAMPTZ,
            PRIMARY KEY (community_id, kid)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS communities_tenant_idx   ON warden_core.communities(tenant_id)")
    op.execute("CREATE INDEX IF NOT EXISTS cm_community_idx         ON warden_core.community_members(community_id)")
    op.execute("CREATE INDEX IF NOT EXISTS cm_tenant_idx            ON warden_core.community_members(tenant_id)")
    op.execute("CREATE INDEX IF NOT EXISTS cka_community_status_idx ON warden_core.community_key_archive(community_id, status)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS warden_core.community_key_archive CASCADE")
    op.execute("DROP TABLE IF EXISTS warden_core.community_members CASCADE")
    op.execute("DROP TABLE IF EXISTS warden_core.communities CASCADE")
    op.execute("DROP TABLE IF EXISTS warden_core.syndicate_invitations CASCADE")
    op.execute("DROP TABLE IF EXISTS warden_core.syndicate_members CASCADE")
    op.execute("DROP TABLE IF EXISTS warden_core.syndicate_links CASCADE")
    op.execute("DROP TABLE IF EXISTS warden_core.syndicates CASCADE")
    op.execute("DROP TABLE IF EXISTS warden_core.portal_api_keys CASCADE")
    op.execute("DROP TABLE IF EXISTS warden_core.portal_users CASCADE")
    op.execute("DROP TABLE IF EXISTS warden_core.billing_usage CASCADE")
    op.execute("DROP TABLE IF EXISTS warden_core.rule_ledger CASCADE")
    op.execute("DROP TABLE IF EXISTS warden_core.threat_intel_countermeasures CASCADE")
    op.execute("DROP TABLE IF EXISTS warden_core.threat_intel_items CASCADE")
    op.execute("DROP SCHEMA IF EXISTS warden_core CASCADE")
