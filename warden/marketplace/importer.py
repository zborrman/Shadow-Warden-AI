"""
warden/marketplace/importer.py
─────────────────────────────────
AssetImporter — auto-integrates purchased assets into warden modules
after escrow confirmation.

Import chains
─────────────
  rule     → EvolutionEngine.inject_rule()   (hot-reload into semantic corpus)
  model    → SemanticEngine.register_model() (Semantic Layer hot-reload)
  signals  → ingest_marketplace_signals()    (semantic corpus + Redis store)
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

log = logging.getLogger("warden.marketplace.importer")

_DB_PATH = os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")
_db_lock = threading.RLock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS marketplace_imports (
    import_id   TEXT PRIMARY KEY,
    purchase_id TEXT NOT NULL,
    asset_id    TEXT NOT NULL,
    asset_type  TEXT NOT NULL,
    buyer_agent TEXT NOT NULL DEFAULT '',
    tenant_id   TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'success',
    error       TEXT NOT NULL DEFAULT '',
    module      TEXT NOT NULL DEFAULT '',
    imported_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mi_purchase ON marketplace_imports(purchase_id);
CREATE INDEX IF NOT EXISTS idx_mi_buyer    ON marketplace_imports(buyer_agent);
CREATE INDEX IF NOT EXISTS idx_mi_type     ON marketplace_imports(asset_type);
"""


@contextmanager
def _conn(db_path: str = _DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    con = sqlite3.connect(db_path, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(_SCHEMA)
    try:
        yield con
        con.commit()
    finally:
        con.close()


# ── Result ────────────────────────────────────────────────────────────────────

@dataclass
class ImportResult:
    import_id:   str
    purchase_id: str
    asset_id:    str
    asset_type:  str
    buyer_agent: str
    tenant_id:   str
    status:      str   # success | failed
    error:       str
    module:      str   # evolution | semantic_layer | intel_bridge
    imported_at: str

    def to_dict(self) -> dict:
        return asdict(self)


def _row_to_result(row: sqlite3.Row) -> ImportResult:
    return ImportResult(
        import_id=row["import_id"],
        purchase_id=row["purchase_id"],
        asset_id=row["asset_id"],
        asset_type=row["asset_type"],
        buyer_agent=row["buyer_agent"],
        tenant_id=row["tenant_id"],
        status=row["status"],
        error=row["error"],
        module=row["module"],
        imported_at=row["imported_at"],
    )


# ── AssetImporter ─────────────────────────────────────────────────────────────

class AssetImporter:
    """
    Routes purchased assets to the correct warden module.
    All methods are fail-open — exceptions are caught and recorded; they never
    block escrow confirmation.
    """

    def __init__(self, db_path: str = _DB_PATH) -> None:
        self.db_path = db_path
        with _conn(db_path):  # ensure schema exists
            pass

    # ── Public ────────────────────────────────────────────────────────────────

    def import_asset(
        self,
        purchase_id: str,
        asset_id:    str,
        asset_type:  str,
        asset_data:  dict,
        buyer_agent: str = "",
        tenant_id:   str = "",
    ) -> ImportResult:
        """
        Import an asset into the relevant warden module.
        Always returns an ImportResult — never raises.
        """
        import_id   = f"IMP-{uuid.uuid4().hex[:12].upper()}"
        now         = datetime.now(UTC).isoformat()
        status, error, module = "failed", "", ""

        try:
            if asset_type == "rule":
                module = "evolution"
                self._import_rule(asset_data, source=f"marketplace:{purchase_id}")
                status = "success"
            elif asset_type == "model":
                module = "semantic_layer"
                self._import_model(asset_data, tenant_id=tenant_id)
                status = "success"
            elif asset_type == "signals":
                module = "intel_bridge"
                self._import_signals(asset_data, tenant_id=tenant_id)
                status = "success"
            else:
                error = f"Unknown asset_type: {asset_type!r}"
        except Exception as exc:  # noqa: BLE001
            error = str(exc)[:500]
            log.warning(
                "AssetImporter: import failed purchase=%s type=%s error=%s",
                purchase_id, asset_type, error,
            )

        result = ImportResult(
            import_id=import_id,
            purchase_id=purchase_id,
            asset_id=asset_id,
            asset_type=asset_type,
            buyer_agent=buyer_agent,
            tenant_id=tenant_id,
            status=status,
            error=error,
            module=module,
            imported_at=now,
        )
        self._record(result)
        log.info(
            "AssetImporter: %s purchase=%s type=%s module=%s",
            status, purchase_id, asset_type, module,
        )
        return result

    def get_imports(
        self,
        buyer_agent: str | None = None,
        asset_type:  str | None = None,
        limit:       int = 50,
    ) -> list[ImportResult]:
        query  = "SELECT * FROM marketplace_imports WHERE 1=1"
        params: list = []
        if buyer_agent:
            query += " AND buyer_agent=?"
            params.append(buyer_agent)
        if asset_type:
            query += " AND asset_type=?"
            params.append(asset_type)
        query += " ORDER BY imported_at DESC LIMIT ?"
        params.append(limit)
        with _conn(self.db_path) as con:
            rows = con.execute(query, params).fetchall()
        return [_row_to_result(r) for r in rows]

    # ── Import chains ─────────────────────────────────────────────────────────

    def _import_rule(self, asset_data: dict, source: str) -> None:
        """Inject rule into EvolutionEngine corpus via inject_rule()."""
        payload   = asset_data.get("payload", asset_data)
        rule_text = str(
            payload.get("value")
            or payload.get("rule_text")
            or (payload.get("new_rule") or {}).get("value", "")
            or ""
        )
        if not rule_text:
            raise ValueError("rule asset has no extractable text")

        metadata = {
            "rule_type":        payload.get("rule_type", "semantic_example"),
            "attack_type":      payload.get("attack_type", source),
            "explanation":      payload.get("explanation", ""),
            "evasion_variants": payload.get("evasion_variants", []),
            "description":      payload.get("description", ""),
            "severity":         payload.get("severity", "medium"),
        }
        engine   = _get_evolve_engine()
        ok, reason = engine.inject_rule(rule_text, source=source, metadata=metadata)
        if not ok:
            raise ValueError(f"inject_rule rejected: {reason}")

    def _import_model(self, asset_data: dict, tenant_id: str) -> None:
        """Register a semantic model into SemanticEngine."""
        try:
            from warden.semantic_layer.models import SemanticModel  # noqa: PLC0415
        except ImportError as exc:
            raise RuntimeError(f"SemanticLayer unavailable: {exc}") from exc

        payload    = asset_data.get("payload", asset_data)
        model_dict = dict(payload.get("model") or payload)

        for field in ("id", "metrics", "dimensions"):
            if field not in model_dict:
                raise ValueError(f"OSI model missing required field: {field!r}")

        # Prefix with tenant to prevent collisions with built-in model ids
        model_id = str(model_dict.get("id", ""))
        if tenant_id and not model_id.startswith(f"{tenant_id}_"):
            model_dict["id"] = f"{tenant_id}_{model_id}"

        model  = SemanticModel.model_validate(model_dict)
        engine = _get_semantic_engine()
        engine.register_model(model)

    def _import_signals(self, asset_data: dict, tenant_id: str) -> None:
        """Ingest threat signals into the intel bridge."""
        payload = asset_data.get("payload", asset_data)
        signals: list = (
            payload.get("signals")
            or (payload if isinstance(payload, list) else [])
        )
        if not signals:
            raise ValueError("signals asset has no signal entries")
        count = ingest_marketplace_signals(signals, tenant_id=tenant_id)
        if count == 0:
            raise ValueError("no valid signals extracted from asset data")

    # ── DB ────────────────────────────────────────────────────────────────────

    def _record(self, result: ImportResult) -> None:
        with _db_lock, _conn(self.db_path) as con:
            con.execute(
                """INSERT OR REPLACE INTO marketplace_imports
                   (import_id, purchase_id, asset_id, asset_type, buyer_agent,
                    tenant_id, status, error, module, imported_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    result.import_id, result.purchase_id, result.asset_id,
                    result.asset_type, result.buyer_agent, result.tenant_id,
                    result.status, result.error, result.module, result.imported_at,
                ),
            )


# ── Module-level singletons ───────────────────────────────────────────────────

def _get_evolve_engine():
    """Return global EvolutionEngine singleton; fall back to a fresh instance."""
    try:
        import warden.main as _main  # noqa: PLC0415
        engine = getattr(_main, "_evolve", None)
        if engine is not None:
            return engine
    except ImportError:
        pass
    from warden.brain.evolve import EvolutionEngine  # noqa: PLC0415
    return EvolutionEngine()


def _get_semantic_engine():
    """Return global SemanticEngine singleton; fall back to a fresh instance."""
    try:
        import warden.main as _main  # noqa: PLC0415
        engine = getattr(_main, "_semantic_engine", None)
        if engine is not None:
            return engine
    except ImportError:
        pass
    from warden.semantic_layer.engine import SemanticEngine  # noqa: PLC0415
    return SemanticEngine()


# ── Standalone signals ingestor ───────────────────────────────────────────────

def ingest_marketplace_signals(signals: list[dict], tenant_id: str = "") -> int:
    """
    Store threat signals from a marketplace purchase.

    Each signal dict should have at least one of: value / text / pattern.
    Signals are added to the semantic corpus via add_examples() and
    optionally stored in Redis `marketplace:signals:{tenant_id}` (fail-open).

    Returns the count of successfully ingested signals.
    """
    ingested = 0
    texts: list[str] = []

    for sig in signals:
        if not isinstance(sig, dict):
            continue
        text = str(
            sig.get("value") or sig.get("text") or sig.get("pattern") or ""
        ).strip()
        if text:
            texts.append(text)
            ingested += 1

    if not texts:
        return 0

    # Hot-reload into semantic corpus (fail-open)
    try:
        engine = _get_evolve_engine()
        engine.add_examples(texts)
    except Exception as exc:  # noqa: BLE001
        log.warning("ingest_marketplace_signals: add_examples failed: %s", exc)

    # Persist to Redis for future sessions (fail-open)
    if tenant_id:
        try:
            from warden.cache import _get_client  # noqa: PLC0415
            r = _get_client()
            if r:
                key  = f"marketplace:signals:{tenant_id}"
                pipe = r.pipeline()
                for t in texts:
                    pipe.lpush(
                        key,
                        json.dumps({"text": t, "ts": datetime.now(UTC).isoformat()}),
                    )
                pipe.ltrim(key, 0, 999)
                pipe.expire(key, 86_400 * 7)  # 7-day TTL
                pipe.execute()
        except Exception as exc:  # noqa: BLE001
            log.debug("ingest_marketplace_signals: Redis store skipped: %s", exc)

    return ingested
