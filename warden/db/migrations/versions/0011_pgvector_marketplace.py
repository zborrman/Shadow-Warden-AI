"""pgvector extension + marketplace_embeddings table for semantic listing search

Revision ID: 0011
Revises: 0010
Create Date: 2026-06-24

Enables Layer 3 of the three-layer marketplace DB architecture:
  Layer 1 — Redis/SQLite     (session cache, local agent state)
  Layer 2 — Redis/SQLite     (AgentHandoffMemory context offloading)
  Layer 3 — PostgreSQL       (long-term records, TrustRank, pgvector search)

The marketplace_embeddings table stores 384-dim all-MiniLM-L6-v2 vectors for
semantic listing discovery.  IVFFlat index with lists=100 gives ~10ms cosine
search over 1M rows on a 2-core Postgres instance.
"""
from __future__ import annotations

from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # pgvector extension — included in TimescaleDB image, no extra install needed
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    op.execute("""
        CREATE TABLE IF NOT EXISTS marketplace_embeddings (
            listing_id  TEXT        PRIMARY KEY,
            embedding   vector(384),
            asset_type  TEXT        NOT NULL DEFAULT 'general',
            title       TEXT        NOT NULL DEFAULT '',
            updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    # IVFFlat cosine index — lists=100 is appropriate for up to ~1M rows.
    # Rebuild with higher lists value if row count exceeds 500k.
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_mkt_embeddings_cosine
        ON marketplace_embeddings
        USING ivfflat (embedding vector_cosine_ops)
        WITH (lists = 100)
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS marketplace_embeddings")
    # Leave the vector extension — other tables may use it.
