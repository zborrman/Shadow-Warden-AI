"""
warden/marketplace/autonomy.py
────────────────────────────────
Progressive Autonomy Levels (L1/L2/L3) for M2M marketplace agents.

Enterprises deploy AI agents through a governance ramp:
  L1 — Shadow mode: all actions reported, none executed (read-only, zero risk)
  L2 — Supervised: low-value actions auto-approved; large spend → human review
  L3 — Autonomous: hard spend caps enforce limits; no human in the loop

The check_action() function is the single authority for routing decisions.
x402_gate.py calls it before payment deductions.
MasterAgent calls it instead of text-scanning for REQUIRES_APPROVAL.

Default for agents without a registered policy: L1 (safe default).

Storage
───────
  SQLite `marketplace_autonomy_policies` in MARKETPLACE_DB_PATH
  Redis  `marketplace:autonomy:{agent_id}` JSON blob (24h TTL)
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from typing import Literal

from warden.config import data_path
from warden.db.connect import open_db
from warden.db.ddl_registry import register

log = logging.getLogger("warden.marketplace.autonomy")

_DB_PATH   = data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")
_DB_PATH_AT_IMPORT = _DB_PATH   # pristine; never monkeypatched

def _db_path() -> str:
    """Resolve the DB path on every call (DE-6 P2).

    A module-level constant freezes the first value the process sees, so a test
    or worker that sets the env later silently reads someone else's database.
    ``_DB_PATH`` is kept for callers that reference it directly.
    """
    # An explicit override wins. Tests across this repo use
    # `monkeypatch.setattr(module, "_DB_PATH", ...)`, and callers may assign
    # it directly; re-reading the env unconditionally would silently ignore
    # both. Only when _DB_PATH is still the pristine import-time value do we
    # resolve fresh -- which is what unfreezes the parameter defaults.
    if _DB_PATH != _DB_PATH_AT_IMPORT:
        return _DB_PATH
    return data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")

_db_lock   = threading.RLock()
_REDIS_TTL = 86400   # 24 hours

_VALID_LEVELS = frozenset({1, 2, 3})
# "purchase" is the action string listing.py::_authorize_purchase() passes to
# authorize_payment(). It was missing here, so even an explicitly-configured L2
# policy rejected every listing purchase ("action not in allowed_actions") and an
# L3 policy hard-BLOCKed it — a mismatch between the gate's vocabulary and the
# caller's that no test covered, because nothing enforced the gate.
_DEFAULT_ALLOWED_ACTIONS = ["search", "negotiate", "purchase", "clear"]


# ── Dataclass ──────────────────────────────────────────────────────────────────

@dataclass
class AutonomyPolicy:
    agent_id:                 str
    level:                    int          # 1 | 2 | 3
    max_spend_usd:            float        # per-session ceiling (hard block at L3)
    daily_spend_usd:          float        # 24h rolling limit (enforced by ERS/clearing)
    allowed_actions:          list[str] = field(default_factory=lambda: list(_DEFAULT_ALLOWED_ACTIONS))
    require_approval_above_usd: float = 0.01   # L2: route to human if amount ≥ this
    expires_at:               str | None = None
    created_by:               str = ""    # tenant_id that set the policy

    def to_dict(self) -> dict:
        return asdict(self)

    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return self.expires_at < now


# ── Schema ─────────────────────────────────────────────────────────────────────

_AUTONOMY_DDL = """
    CREATE TABLE IF NOT EXISTS marketplace_autonomy_policies (
        agent_id                   TEXT PRIMARY KEY,
        level                      INTEGER NOT NULL DEFAULT 1,
        max_spend_usd              REAL    NOT NULL DEFAULT 0.0,
        daily_spend_usd            REAL    NOT NULL DEFAULT 0.0,
        allowed_actions            TEXT    NOT NULL DEFAULT '["search","negotiate","clear"]',
        require_approval_above_usd REAL    NOT NULL DEFAULT 0.01,
        expires_at                 TEXT,
        created_by                 TEXT    NOT NULL DEFAULT '',
        updated_at                 TEXT    NOT NULL
    );
"""
register("marketplace", "warden.marketplace.autonomy", _AUTONOMY_DDL)


@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    with open_db(
        "marketplace", _db_path(), turso_name="marketplace", module_default_path=_db_path()
    ) as con:
        yield con


# ── Redis helpers ──────────────────────────────────────────────────────────────

def _redis():
    try:
        import redis as _r
        url = os.getenv("REDIS_URL", "redis://localhost:6379")
        if url.startswith("memory://"):
            return None
        return _r.from_url(url, decode_responses=True, socket_connect_timeout=5, socket_timeout=3)
    except Exception:
        return None


def _cache_set(policy: AutonomyPolicy) -> None:
    try:
        r = _redis()
        if r:
            key = f"marketplace:autonomy:{policy.agent_id}"
            r.setex(key, _REDIS_TTL, json.dumps(policy.to_dict()))
    except Exception as exc:
        log.debug("autonomy redis set error: %s", exc)


def _cache_get(agent_id: str) -> AutonomyPolicy | None:
    try:
        r = _redis()
        if r:
            raw = r.get(f"marketplace:autonomy:{agent_id}")
            if raw:
                return _dict_to_policy(json.loads(raw))
    except Exception as exc:
        log.debug("autonomy redis get error: %s", exc)
    return None


def _cache_del(agent_id: str) -> None:
    try:
        r = _redis()
        if r:
            r.delete(f"marketplace:autonomy:{agent_id}")
    except Exception as exc:
        log.debug("autonomy redis del error: %s", exc)


# ── Internal helpers ───────────────────────────────────────────────────────────

def _row_to_policy(row: sqlite3.Row) -> AutonomyPolicy:
    try:
        actions = json.loads(row["allowed_actions"] or "[]")
    except Exception:
        actions = list(_DEFAULT_ALLOWED_ACTIONS)
    return AutonomyPolicy(
        agent_id=row["agent_id"],
        level=int(row["level"]),
        max_spend_usd=float(row["max_spend_usd"]),
        daily_spend_usd=float(row["daily_spend_usd"]),
        allowed_actions=actions,
        require_approval_above_usd=float(row["require_approval_above_usd"]),
        expires_at=row["expires_at"],
        created_by=row["created_by"],
    )


def _dict_to_policy(d: dict) -> AutonomyPolicy:
    return AutonomyPolicy(
        agent_id=d.get("agent_id", ""),
        level=int(d.get("level", 1)),
        max_spend_usd=float(d.get("max_spend_usd", 0.0)),
        daily_spend_usd=float(d.get("daily_spend_usd", 0.0)),
        allowed_actions=d.get("allowed_actions", list(_DEFAULT_ALLOWED_ACTIONS)),
        require_approval_above_usd=float(d.get("require_approval_above_usd", 0.01)),
        expires_at=d.get("expires_at"),
        created_by=d.get("created_by", ""),
    )


# ── Public API ─────────────────────────────────────────────────────────────────

def set_policy(policy: AutonomyPolicy) -> AutonomyPolicy:
    """Persist autonomy policy for an agent. Overwrites any existing policy."""
    if policy.level not in _VALID_LEVELS:
        raise ValueError(f"level must be 1, 2, or 3; got {policy.level}")
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    actions_json = json.dumps(policy.allowed_actions)
    with _db_lock, _conn() as con:
        con.execute(
            """INSERT INTO marketplace_autonomy_policies
               (agent_id, level, max_spend_usd, daily_spend_usd, allowed_actions,
                require_approval_above_usd, expires_at, created_by, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT(agent_id) DO UPDATE SET
                 level=excluded.level,
                 max_spend_usd=excluded.max_spend_usd,
                 daily_spend_usd=excluded.daily_spend_usd,
                 allowed_actions=excluded.allowed_actions,
                 require_approval_above_usd=excluded.require_approval_above_usd,
                 expires_at=excluded.expires_at,
                 created_by=excluded.created_by,
                 updated_at=excluded.updated_at""",
            (
                policy.agent_id, policy.level, policy.max_spend_usd, policy.daily_spend_usd,
                actions_json, policy.require_approval_above_usd, policy.expires_at,
                policy.created_by, now,
            ),
        )
    _cache_set(policy)
    log.info("autonomy: set_policy agent=%s level=L%d max_spend=%.4f",
             policy.agent_id[:32], policy.level, policy.max_spend_usd)
    return policy


def get_policy(agent_id: str) -> AutonomyPolicy | None:
    """Return policy for agent, or None if not registered (caller should default to L1)."""
    cached = _cache_get(agent_id)
    if cached is not None:
        return cached if not cached.is_expired() else None

    try:
        with _conn() as con:
            row = con.execute(
                "SELECT * FROM marketplace_autonomy_policies WHERE agent_id=?", (agent_id,)
            ).fetchone()
        if row:
            policy = _row_to_policy(row)
            if not policy.is_expired():
                _cache_set(policy)
                return policy
    except Exception as exc:
        log.debug("autonomy: get_policy SQLite error: %s", exc)
    return None


def delete_policy(agent_id: str) -> bool:
    """Remove autonomy policy. Agent falls back to L1 default."""
    with _db_lock, _conn() as con:
        cur = con.execute(
            "DELETE FROM marketplace_autonomy_policies WHERE agent_id=?", (agent_id,)
        )
        deleted = cur.rowcount > 0
    _cache_del(agent_id)
    if deleted:
        log.info("autonomy: deleted policy agent=%s", agent_id[:32])
    return deleted


def _default_level() -> int:
    """Autonomy level granted to a newly-VERIFIED agent. 0 disables the grant.

    Read per call, never snapshotted at import — a module-level constant would
    freeze whatever the env held when the first module imported this one.
    """
    try:
        level = int(os.getenv("KYA_DEFAULT_AUTONOMY_LEVEL", "2"))
    except ValueError:
        return 2
    return level if level in _VALID_LEVELS or level == 0 else 2


def _default_float(env_name: str, fallback: float) -> float:
    try:
        return float(os.getenv(env_name, str(fallback)))
    except ValueError:
        return fallback


def build_default_policy(agent_id: str, created_by: str = "kya_auto") -> AutonomyPolicy:
    """The conservative starting policy for an agent that passed KYA screening.

    L2 (Supervised): the standard marketplace actions are allowed below a spend
    threshold, and anything at or above it routes to a human. That is the level
    the autonomy model was designed around — L1 means "can do nothing", which is
    correct as a *safe default for an unknown agent* but wrong as a permanent
    state for one the system has verified.
    """
    return AutonomyPolicy(
        agent_id=agent_id,
        level=_default_level() or 2,
        max_spend_usd=_default_float("KYA_DEFAULT_MAX_SPEND_USD", 10.0),
        daily_spend_usd=_default_float("KYA_DEFAULT_DAILY_USD", 100.0),
        allowed_actions=list(_DEFAULT_ALLOWED_ACTIONS),
        require_approval_above_usd=_default_float("KYA_DEFAULT_APPROVAL_ABOVE_USD", 10.0),
        expires_at=None,
        created_by=created_by,
    )


def ensure_default_policy(agent_id: str, created_by: str = "kya_auto") -> bool:
    """Install the default policy iff the agent has none. Returns True if written.

    Never overwrites: an operator's explicit policy — including a deliberate
    lock-down to L1 — always wins over this onboarding grant.

    Fail-soft. This runs inside KYA screening, and failing to grant autonomy must
    never fail the screening itself; the agent simply stays at the L1 default,
    which is the restrictive direction.
    """
    if _default_level() == 0:
        return False
    try:
        if get_policy(agent_id) is not None:
            return False
        set_policy(build_default_policy(agent_id, created_by))
        log.info("autonomy: granted default L%d policy to verified agent=%s",
                 _default_level(), agent_id[:32])
        return True
    except Exception as exc:
        log.warning("autonomy: ensure_default_policy failed for %s (agent stays L1): %s",
                    agent_id[:32], exc)
        return False


def _owner_kyb_unverified(agent_id: str) -> bool:
    """True when KYB_ENFORCEMENT_ENABLED and the agent's owner isn't VERIFIED.

    Two separate try blocks on purpose: if enforcement is off (default) or
    the flag can't even be read, this must return False no matter what —
    zero behavior change for deployments that haven't opted in. Only once
    enforcement is confirmed on does a lookup failure count as unverified
    (the conservative direction, not silently allowing). Lazy imports avoid
    a module-load cycle with kya.py/kyb.py.
    """
    try:
        from warden.marketplace import kyb  # noqa: PLC0415
        if not kyb.enforcement_enabled():
            return False
    except Exception:
        return False

    try:
        from warden.marketplace import kya  # noqa: PLC0415
        record = kya.get_kya_record(agent_id)
        owner_tenant_id = record.owner_tenant_id if record else ""
        return kyb.get_kyb_status(owner_tenant_id) != "VERIFIED"
    except Exception as exc:
        log.debug("autonomy: KYB lookup failed for agent=%s: %s", agent_id[:32], exc)
        return True


def check_action(
    agent_id: str,
    action: str,
    amount_usd: float = 0.0,
) -> Literal["ALLOW", "REQUIRE_APPROVAL", "BLOCK"]:
    """Evaluate whether an agent may execute *action* for *amount_usd*.

    Decision matrix:
      L1 (Shadow):    all actions → REQUIRE_APPROVAL
      L2 (Supervised): action in allowed_actions AND amount < threshold → ALLOW
                        else → REQUIRE_APPROVAL
      L3 (Autonomous): action in allowed_actions AND amount <= max_spend → ALLOW
                        else → BLOCK
      No policy:       default L1 → REQUIRE_APPROVAL (safe default)

    KYB gate (FT-5, opt-in via KYB_ENFORCEMENT_ENABLED): when enabled, an
    agent whose owning tenant is not KYB-VERIFIED is capped at L1 behavior
    regardless of its configured policy level — the agent inherits the
    owner's compliance status. Off by default so existing deployments are
    not retroactively capped the moment this ships.

    Fail-open: exceptions → REQUIRE_APPROVAL (never BLOCK on error).
    """
    try:
        policy = get_policy(agent_id)

        if policy is None:
            log.debug("autonomy: no policy for agent=%s → default L1 REQUIRE_APPROVAL",
                      agent_id[:32])
            return "REQUIRE_APPROVAL"

        if _owner_kyb_unverified(agent_id):
            log.debug("autonomy: owner KYB unverified for agent=%s → capped REQUIRE_APPROVAL",
                       agent_id[:32])
            return "REQUIRE_APPROVAL"

        level = policy.level
        action_allowed = action in policy.allowed_actions

        if level == 1:
            return "REQUIRE_APPROVAL"

        if level == 2:
            if action_allowed and amount_usd < policy.require_approval_above_usd:
                return "ALLOW"
            return "REQUIRE_APPROVAL"

        if level == 3:
            if action_allowed and amount_usd <= policy.max_spend_usd:
                return "ALLOW"
            return "BLOCK"

        # Unknown level — safe default
        return "REQUIRE_APPROVAL"

    except Exception as exc:
        log.warning("autonomy: check_action fail-open for agent=%s: %s", agent_id[:32], exc)
        return "REQUIRE_APPROVAL"
