"""
GSAM ClickHouse client — thin fail-open wrapper over clickhouse-connect.

Every method swallows errors and returns a falsy value on failure; the
collector decides whether to spool. `clickhouse_connect` is an optional
dependency: when missing, `is_available()` is False and all ops no-op.
"""
from __future__ import annotations

import logging
import threading

from warden.config import settings
from warden.gsam.schema import (
    CLICKHOUSE_COLUMNS,
    CLICKHOUSE_DATABASE_DDL,
    CLICKHOUSE_TABLE_DDL,
)
from warden.observability import Reason, record_failopen

log = logging.getLogger("warden.gsam.clickhouse")

try:  # optional dependency — guarded import
    import clickhouse_connect
    _CH_AVAILABLE = True
except Exception:  # any import failure means "not available"
    clickhouse_connect = None
    _CH_AVAILABLE = False


class GsamClickHouse:
    """Lazy, thread-safe ClickHouse connection with self-healing schema."""

    def __init__(self) -> None:
        self._client = None
        self._schema_ready = False
        self._lock = threading.Lock()

    def is_enabled(self) -> bool:
        return bool(settings.gsam_clickhouse_enabled) and _CH_AVAILABLE

    def _connect(self):
        """Return a live client or None. Never raises."""
        if not self.is_enabled():
            return None
        with self._lock:
            if self._client is not None:
                return self._client
            try:
                url = settings.gsam_clickhouse_url
                # clickhouse-connect wants host/port, accept full http URL
                host = url.replace("http://", "").replace("https://", "")
                port = 8123
                if ":" in host:
                    host, port_s = host.rsplit(":", 1)
                    port = int(port_s.split("/")[0])
                self._client = clickhouse_connect.get_client(
                    host=host,
                    port=port,
                    username=settings.gsam_clickhouse_user or "default",
                    password=settings.gsam_clickhouse_password,
                    connect_timeout=3,
                    send_receive_timeout=5,
                )
                return self._client
            except Exception as exc:
                log.debug("GSAM ClickHouse connect failed (fail-open): %s", exc)
                record_failopen("gsam_clickhouse", Reason.BACKEND_ERROR, exc)
                self._client = None
                return None

    def ensure_schema(self) -> bool:
        """Lazy CREATE DATABASE/TABLE IF NOT EXISTS. Never raises."""
        if self._schema_ready:
            return True
        client = self._connect()
        if client is None:
            return False
        try:
            client.command(CLICKHOUSE_DATABASE_DDL)
            client.command(CLICKHOUSE_TABLE_DDL)
            self._schema_ready = True
            log.info("GSAM ClickHouse schema ready")
            return True
        except Exception as exc:
            log.debug("GSAM ClickHouse schema init failed (fail-open): %s", exc)
            record_failopen("gsam_clickhouse", Reason.BACKEND_ERROR, exc)
            self._reset()
            return False

    def insert_rows(self, rows: list[dict]) -> bool:
        """Batch-insert observation rows. Returns False on any failure."""
        if not rows or not self.ensure_schema():
            return False
        client = self._connect()
        if client is None:
            return False
        try:
            data = [[row.get(col) for col in CLICKHOUSE_COLUMNS] for row in rows]
            client.insert(
                "gsam.gsam_observations",
                data,
                column_names=list(CLICKHOUSE_COLUMNS),
            )
            return True
        except Exception as exc:
            log.debug("GSAM ClickHouse insert failed (spooling): %s", exc)
            self._reset()
            return False

    def query(self, sql: str, parameters: dict | None = None) -> list[dict]:
        """Read query for /gsam analytics endpoints. Returns [] on failure."""
        if not self.ensure_schema():
            return []
        client = self._connect()
        if client is None:
            return []
        try:
            result = client.query(sql, parameters=parameters or {})
            cols = result.column_names
            return [dict(zip(cols, row, strict=False)) for row in result.result_rows]
        except Exception as exc:
            log.debug("GSAM ClickHouse query failed (fail-open): %s", exc)
            record_failopen("gsam_clickhouse", Reason.BACKEND_ERROR, exc)
            self._reset()
            return []

    def ping(self) -> bool:
        client = self._connect()
        if client is None:
            return False
        try:
            client.command("SELECT 1")
            return True
        except Exception:
            self._reset()
            return False

    def _reset(self) -> None:
        with self._lock:
            self._client = None
            self._schema_ready = False


_instance: GsamClickHouse | None = None
_instance_lock = threading.Lock()


def get_clickhouse() -> GsamClickHouse:
    global _instance
    with _instance_lock:
        if _instance is None:
            _instance = GsamClickHouse()
        return _instance
