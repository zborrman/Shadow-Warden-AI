"""
warden/marketplace/vector_search.py
─────────────────────────────────────
Layer 3: Semantic listing search via pgvector.

Uses the already-loaded all-MiniLM-L6-v2 model (384-dim) that the brain
layer loaded at startup — no extra download, no separate model process.

Storage: PostgreSQL marketplace_embeddings table (see migration 0011).
Gate:    MARKETPLACE_VECTOR_SEARCH=true  (default: false — SQLite keyword
         search so cold-start works without a Postgres connection).

Cost impact:
  • Agents can find relevant listings with ONE semantic query instead of
    enumerating hundreds of rows in context.
  • Eliminates need for a dedicated vector DB (Pinecone, Weaviate, etc.)
    at early/mid-scale — pgvector on the existing Postgres handles ~1M rows.

Fallback chain:
  pgvector (MARKETPLACE_VECTOR_SEARCH=true + DATABASE_URL set)
    → SQLite LIKE keyword search (always available, zero extra deps)
"""
from __future__ import annotations

import logging
import os
from typing import Any

from warden.config import data_path

log = logging.getLogger("warden.marketplace.vector_search")

_VECTOR_ENABLED = os.getenv("MARKETPLACE_VECTOR_SEARCH", "false").lower() == "true"
_PG_DSN         = os.getenv("DATABASE_URL", "")
_SQLITE_DB      = data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")
_EMBED_DIM      = 384   # all-MiniLM-L6-v2 output dimension


# ── Embedding helper ───────────────────────────────────────────────────────────

def _get_model():
    try:
        from warden.brain.semantic import _load_model  # noqa: PLC0415
        return _load_model()
    except Exception as exc:
        log.warning("vector_search: model unavailable (%s) — keyword fallback", exc)
        return None


def embed_text(text: str) -> list[float] | None:
    """Return normalized 384-dim embedding, or None when model unavailable."""
    model = _get_model()
    if model is None:
        return None
    return model.encode(text, normalize_embeddings=True).tolist()


# ── PostgreSQL layer ───────────────────────────────────────────────────────────

def _vec_literal(vec: list[float]) -> str:
    """Convert Python list to PostgreSQL vector literal: '[0.1,0.2,...]'"""
    return "[" + ",".join(f"{v:.8f}" for v in vec) + "]"


async def upsert_listing_embedding(
    listing_id: str,
    title: str,
    description: str = "",
    asset_type: str = "general",
) -> bool:
    """Compute embedding and upsert into marketplace_embeddings.

    Called by api_listings.py after a listing is created or updated.
    Fail-open: returns False when pgvector is unavailable or disabled.
    """
    if not _VECTOR_ENABLED or not _PG_DSN:
        return False
    combined = f"{asset_type}: {title}. {description}".strip()
    vec = embed_text(combined)
    if vec is None:
        return False
    try:
        import asyncpg  # noqa: PLC0415
        conn = await asyncpg.connect(_PG_DSN, timeout=5)
        await conn.execute(
            """
            INSERT INTO marketplace_embeddings
                (listing_id, embedding, asset_type, title)
            VALUES ($1, $2::vector, $3, $4)
            ON CONFLICT (listing_id) DO UPDATE
                SET embedding  = EXCLUDED.embedding,
                    asset_type = EXCLUDED.asset_type,
                    title      = EXCLUDED.title,
                    updated_at = NOW()
            """,
            listing_id,
            _vec_literal(vec),
            asset_type,
            title,
        )
        await conn.close()
        log.debug("upsert_listing_embedding: %s ok", listing_id)
        return True
    except Exception as exc:
        log.warning("upsert_listing_embedding: %s", exc)
        return False


async def delete_listing_embedding(listing_id: str) -> bool:
    """Remove embedding when a listing is delisted."""
    if not _VECTOR_ENABLED or not _PG_DSN:
        return False
    try:
        import asyncpg  # noqa: PLC0415
        conn = await asyncpg.connect(_PG_DSN, timeout=5)
        await conn.execute(
            "DELETE FROM marketplace_embeddings WHERE listing_id=$1", listing_id
        )
        await conn.close()
        return True
    except Exception as exc:
        log.warning("delete_listing_embedding: %s", exc)
        return False


# ── Semantic search — pgvector path ───────────────────────────────────────────

_SPONSORED_BOOST = 0.15   # applied in Python to keep HNSW index active
_INDEX_PREFETCH  = 100    # fetch this many via pure index, then re-rank in Python


async def _pgvector_search(
    query: str,
    limit: int,
    asset_type: str | None,
) -> list[dict[str, Any]]:
    vec = embed_text(query)
    if vec is None:
        return []
    # Fetch a larger candidate set using the pure vector operator so pgvector
    # can use the HNSW/IVFFlat index.  Applying the sponsored boost here in SQL
    # would create a computed expression in ORDER BY and disable the index.
    prefetch = max(limit * 10, _INDEX_PREFETCH)
    params: list[Any] = [_vec_literal(vec), prefetch]
    type_clause = ""
    if asset_type:
        type_clause = "AND l.asset_type = $3"
        params.append(asset_type)
    try:
        import asyncpg  # noqa: PLC0415
        conn = await asyncpg.connect(_PG_DSN, timeout=5)
        rows = await conn.fetch(
            f"""
            SELECT e.listing_id,
                   l.title,
                   l.asset_type,
                   1 - (e.embedding <=> $1::vector) AS similarity,
                   COALESCE(l.is_sponsored, 0)      AS is_sponsored
            FROM   marketplace_embeddings e
            JOIN   marketplace_listings   l USING (listing_id)
            WHERE  1=1 {type_clause}
            ORDER  BY e.embedding <=> $1::vector
            LIMIT  $2
            """,
            *params,
        )
        await conn.close()
        # Apply sponsored boost in Python (preserves index usage above)
        results: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            d["similarity"] = float(d["similarity"]) + (
                _SPONSORED_BOOST if d.get("is_sponsored") else 0.0
            )
            d["sponsored"] = bool(d.pop("is_sponsored", 0))
            results.append(d)
        results.sort(key=lambda x: x["similarity"], reverse=True)
        return results[:limit]
    except Exception as exc:
        log.warning("_pgvector_search: %s", exc)
        return []


# ── Semantic search — SQLite fallback path ────────────────────────────────────

def _sqlite_fallback(
    query: str,
    limit: int,
    asset_type: str | None,
) -> list[dict[str, Any]]:
    """LIKE keyword search against marketplace_listings in SQLite.

    Used when MARKETPLACE_VECTOR_SEARCH=false or Postgres is unreachable.
    Returns similarity=0.5 for all results (unranked but functional).
    Reads MARKETPLACE_DB_PATH at call time so test monkeypatching works.
    """
    import contextlib  # noqa: PLC0415
    import sqlite3  # noqa: PLC0415

    db_path = data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")
    # Ensure sponsored columns exist (additive migration — no-op on current DBs)
    try:
        _mig = sqlite3.connect(db_path)
        with contextlib.suppress(Exception):
            _mig.execute("ALTER TABLE marketplace_listings ADD COLUMN is_sponsored INTEGER NOT NULL DEFAULT 0")
        with contextlib.suppress(Exception):
            _mig.execute("ALTER TABLE marketplace_listings ADD COLUMN sponsored_until TEXT")
        _mig.commit()
        _mig.close()
    except Exception:
        pass
    terms = [t.strip() for t in query.lower().split() if t.strip()]
    if not terms:
        return []
    like = "%" + "%".join(terms) + "%"
    params: list[Any] = [like, like, like]
    type_clause = ""
    if asset_type:
        type_clause = "AND asset_type = ?"
        params.append(asset_type)
    params.append(limit)
    try:
        con = sqlite3.connect(db_path)
        con.row_factory = sqlite3.Row
        rows = con.execute(
            f"""
            SELECT listing_id, title, asset_type, price_usd,
                   COALESCE(is_sponsored, 0) AS is_sponsored,
                   0.5 AS similarity
            FROM   marketplace_listings
            WHERE  (
                LOWER(title)       LIKE ? OR
                LOWER(description) LIKE ? OR
                LOWER(asset_type)  LIKE ?
            ) {type_clause}
            ORDER  BY is_sponsored DESC, ROWID DESC
            LIMIT ?
            """,
            params,
        ).fetchall()
        con.close()
        results: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            is_sp = bool(d.pop("is_sponsored", 0))
            d["similarity"] = 0.5 + (_SPONSORED_BOOST if is_sp else 0.0)
            d["sponsored"]  = is_sp
            results.append(d)
        return results
    except Exception as exc:
        log.warning("_sqlite_fallback: %s", exc)
        return []


# ── Public API ─────────────────────────────────────────────────────────────────

async def semantic_search(
    query: str,
    limit: int = 10,
    asset_type: str | None = None,
) -> list[dict[str, Any]]:
    """Find listings by semantic similarity.

    Falls back to SQLite keyword search automatically when pgvector is
    unavailable.  Returns list of dicts with keys:
      listing_id, title, asset_type, similarity (0.0–1.0).
    """
    if _VECTOR_ENABLED and _PG_DSN:
        results = await _pgvector_search(query, limit, asset_type)
        if results:
            return results
    return _sqlite_fallback(query, limit, asset_type)
