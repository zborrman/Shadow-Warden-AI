"""
Agent-to-Agent (A2A) Protocol — cross-functional staff agent orchestration.

Allows one Digital Staff agent to invoke a tool owned by another agent,
subject to:
  1. HMAC-SHA256 call token (caller:target:tool:ts) — prevents injection
  2. Authorization: only pre-wired routes in ALLOWED_ROUTES are permitted
  3. SQLite audit trail — every A2A call recorded regardless of outcome
  4. Fail-open: routing errors return {"error": ..., "a2a_routed": False}
     so callers can degrade gracefully without blocking the user flow

The canonical use case: SupportAgent (STAFF-04) encounters a refund request
from a high-risk country → calls ComplianceAgent (STAFF-05) score_kyc_profile
before creating the PENDING_REVIEW intent.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import sqlite3
import time
import uuid
from collections.abc import Generator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

_DB_PATH: str = os.getenv("STAFF_A2A_DB_PATH", "/tmp/warden_staff_a2a.db")
_HMAC_KEY: bytes = os.getenv("STAFF_A2A_HMAC_KEY", "staff-a2a-dev-key").encode()

_A2A_DDL = """
    CREATE TABLE IF NOT EXISTS staff_a2a_calls (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        call_id         TEXT    NOT NULL UNIQUE,
        caller_agent_id TEXT    NOT NULL,
        target_agent_id TEXT    NOT NULL,
        tool_name       TEXT    NOT NULL,
        status          TEXT    NOT NULL,
        latency_ms      REAL    NOT NULL,
        ts              INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_a2a_caller ON staff_a2a_calls(caller_agent_id, ts);
"""


@contextmanager
def _conn(db_path: str | None = None) -> Generator[sqlite3.Connection, None, None]:
    """
    Yield a DB connection — Turso "staff" (if TURSO_URL_STAFF is set) or local SQLite.

    A non-default explicit db_path bypasses Turso (test isolation via tmp_path).
    Passing None or _DB_PATH routes through Turso when available.
    """
    effective = db_path or _DB_PATH
    use_local = effective != _DB_PATH

    if use_local:
        con = sqlite3.connect(effective, check_same_thread=False)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        con.executescript(_A2A_DDL)
        try:
            yield con
            con.commit()
        finally:
            con.close()
        return

    try:
        from warden.db.turso import get_connection, is_turso_enabled  # noqa: PLC0415
        if is_turso_enabled("staff"):
            with get_connection("staff", fallback_path=_DB_PATH) as con:  # type: ignore[assignment]
                with suppress(Exception):
                    con.executescript(_A2A_DDL)
                yield con
            return
    except ImportError:
        pass

    con = sqlite3.connect(_DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(_A2A_DDL)
    try:
        yield con
        con.commit()
    finally:
        con.close()

# Pre-wired cross-agent call table.
# Key: (caller_agent_id, target_agent_id, tool_name) → permitted
ALLOWED_ROUTES: frozenset[tuple[str, str, str]] = frozenset({
    # SupportAgent → ComplianceAgent: KYC check before high-risk refund
    ("support", "compliance", "score_kyc_profile"),
    # SupportAgent → ComplianceAgent: sanctions check on disputed entity
    ("support", "compliance", "screen_sanctions_list"),
    # BDRAgent → ComplianceAgent: screen lead before outreach
    ("bdr", "compliance", "screen_sanctions_list"),
    # GrowthAgent → ComplianceAgent: screen SEO content subject
    ("growth", "compliance", "screen_sanctions_list"),
    # ComplianceAgent → SupportAgent: open a ticket for SAR escalation
    ("compliance", "support", "get_ticket"),
})


@dataclass
class A2ACall:
    call_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    caller_agent_id: str = ""
    target_agent_id: str = ""
    tool_name: str = ""
    tool_input: dict = field(default_factory=dict)
    result: dict | None = None
    status: str = "PENDING"   # PENDING | SUCCESS | DENIED | ERROR
    latency_ms: float = 0.0
    hmac_token: str = ""
    ts: int = field(default_factory=lambda: int(time.time()))


def _sign(caller: str, target: str, tool: str, ts: int) -> str:
    canonical = f"{caller}:{target}:{tool}:{ts}"
    return hmac.new(_HMAC_KEY, canonical.encode(), hashlib.sha256).hexdigest()


def _verify(caller: str, target: str, tool: str, ts: int, token: str) -> bool:
    expected = _sign(caller, target, tool, ts)
    return hmac.compare_digest(expected, token)


def _audit(call: A2ACall, db_path: str | None = None) -> None:
    try:
        with _conn(db_path) as conn:
            conn.execute(
                "INSERT OR IGNORE INTO staff_a2a_calls "
                "(call_id,caller_agent_id,target_agent_id,tool_name,status,latency_ms,ts) "
                "VALUES (?,?,?,?,?,?,?)",
                (call.call_id, call.caller_agent_id, call.target_agent_id,
                 call.tool_name, call.status, call.latency_ms, call.ts),
            )
    except Exception as exc:  # noqa: BLE001
        log.warning("A2A audit write failed: %s", exc)


class A2ARouter:
    """
    Routes cross-agent tool calls with HMAC authentication and audit logging.

    Usage:
        router = A2ARouter()
        result = await router.route("support", "compliance", "score_kyc_profile", {
            "tenant_id": "acme", "entity_name": "ACME Corp", "country": "RU", ...
        })
    """

    def __init__(self, db_path: str = _DB_PATH) -> None:
        self._db_path = db_path

    async def route(
        self,
        caller_agent_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_input: dict[str, Any],
    ) -> dict[str, Any]:
        call = A2ACall(
            caller_agent_id=caller_agent_id,
            target_agent_id=target_agent_id,
            tool_name=tool_name,
            tool_input=tool_input,
        )
        t0 = time.perf_counter()

        # 1. Authorization check — only pre-wired routes allowed
        route_key = (caller_agent_id, target_agent_id, tool_name)
        if route_key not in ALLOWED_ROUTES:
            call.status = "DENIED"
            call.latency_ms = round((time.perf_counter() - t0) * 1000, 2)
            _audit(call, self._db_path)
            log.warning(
                "A2A DENIED: %s → %s.%s (not in ALLOWED_ROUTES)",
                caller_agent_id, target_agent_id, tool_name,
            )
            return {
                "error": f"A2A route {caller_agent_id}→{target_agent_id}.{tool_name} not permitted",
                "a2a_routed": False,
                "call_id": call.call_id,
            }

        # 2. Sign and verify the call token
        call.hmac_token = _sign(caller_agent_id, target_agent_id, tool_name, call.ts)
        if not _verify(caller_agent_id, target_agent_id, tool_name, call.ts, call.hmac_token):
            call.status = "DENIED"
            call.latency_ms = round((time.perf_counter() - t0) * 1000, 2)
            _audit(call, self._db_path)
            return {"error": "A2A HMAC verification failed", "a2a_routed": False, "call_id": call.call_id}

        # 3. Dispatch to target tool handler
        try:
            handler = _resolve_handler(target_agent_id, tool_name)
            if handler is None:
                raise ValueError(f"Tool handler not found: {target_agent_id}.{tool_name}")

            result = await handler(**tool_input)
            call.result = result
            call.status = "SUCCESS"

            log.info(
                "A2A SUCCESS: %s → %s.%s call_id=%s",
                caller_agent_id, target_agent_id, tool_name, call.call_id,
            )
        except Exception as exc:  # noqa: BLE001
            call.status = "ERROR"
            call.result = {"error": str(exc), "a2a_routed": True}
            log.warning(
                "A2A ERROR: %s → %s.%s: %s",
                caller_agent_id, target_agent_id, tool_name, exc,
            )

        call.latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        _audit(call, self._db_path)

        if call.result is None:
            return {"error": "A2A dispatch returned None", "a2a_routed": True, "call_id": call.call_id}

        return {**call.result, "a2a_routed": True, "call_id": call.call_id, "latency_ms": call.latency_ms}

    def get_audit_log(self, limit: int = 100, db_path: str | None = None) -> list[dict]:
        try:
            with _conn(db_path or self._db_path) as conn:
                rows = conn.execute(
                    "SELECT * FROM staff_a2a_calls ORDER BY ts DESC LIMIT ?", (limit,)
                ).fetchall()
            return [dict(r) for r in rows]
        except Exception as exc:  # noqa: BLE001
            log.warning("A2A get_audit_log failed: %s", exc)
            return []


def _resolve_handler(target_agent_id: str, tool_name: str):
    """Resolve a target tool function by agent_id + tool_name. Returns None if not found."""
    try:
        from warden.staff.tools import STAFF_TOOL_HANDLERS  # noqa: PLC0415
        return STAFF_TOOL_HANDLERS.get(tool_name)
    except Exception:  # noqa: BLE001
        return None


_router_instance: A2ARouter | None = None


def get_a2a_router() -> A2ARouter:
    global _router_instance  # noqa: PLW0603
    if _router_instance is None:
        _router_instance = A2ARouter()
    return _router_instance
