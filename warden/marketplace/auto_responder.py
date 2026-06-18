"""
warden/marketplace/auto_responder.py  (SEC-03)
──────────────────────────────────────────────
Autonomous Threat Response — isolate/restore marketplace agents.

When MAESTRO returns threat_level='high', AutoResponder.isolate_agent() is
called (non-blocking) to:
  1. Suspend agent capabilities in the DB.
  2. Cancel all active listings.
  3. Cancel pending escrows.
  4. Lock HSM keys.
  5. Notify admin via Slack.
  6. Log to STIX audit.
  7. Emit Kafka event.

Restoration is gated on a DAO proposal (optional) passed via
restore_agent(agent_id, dao_proposal_id).

All steps are fail-open — a partial failure does not prevent the remaining
steps from executing.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
import uuid
from datetime import UTC, datetime

log = logging.getLogger("warden.marketplace.auto_responder")

_DB_PATH = os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")
_db_lock = threading.RLock()


# ── Helpers ────────────────────────────────────────────────────────────────────

def _conn(path: str = _DB_PATH) -> sqlite3.Connection:
    con = sqlite3.connect(path, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    return con


def _ensure_isolation_table(con: sqlite3.Connection) -> None:
    con.execute("""
        CREATE TABLE IF NOT EXISTS agent_isolation_log (
            isolation_id  TEXT PRIMARY KEY,
            agent_id      TEXT NOT NULL,
            reason        TEXT NOT NULL,
            isolated_at   TEXT NOT NULL,
            restored_at   TEXT,
            dao_proposal  TEXT
        )
    """)
    con.commit()


# ── AutoResponder ─────────────────────────────────────────────────────────────

class AutoResponder:
    """Autonomous threat response for marketplace agents."""

    def __init__(self, db_path: str = _DB_PATH) -> None:
        self.db_path = db_path

    # ── Isolation ─────────────────────────────────────────────────────────────

    async def isolate_agent(self, agent_id: str, reason: str) -> dict:
        """
        Isolate a marketplace agent immediately.

        Steps (all fail-open):
          1. Suspend capabilities (empty capabilities[])
          2. Cancel active listings
          3. Cancel pending escrows
          4. Lock HSM keys
          5. Notify admin via Slack
          6. Log to STIX audit
          7. Emit Kafka event

        Returns summary of actions taken.
        """
        log.warning("AutoResponder: isolating agent=%s reason=%s", agent_id, reason)
        isolation_id = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        actions: dict[str, bool] = {}

        # 1. Suspend capabilities
        actions["capabilities_suspended"] = self._suspend_capabilities(agent_id)

        # 2. Cancel listings
        actions["listings_cancelled"] = self._cancel_listings(agent_id)

        # 3. Cancel escrows
        actions["escrows_cancelled"] = self._cancel_escrows(agent_id)

        # 4. Lock HSM keys
        actions["hsm_keys_locked"] = self._lock_hsm_keys(agent_id)

        # 5. Slack notification
        actions["slack_notified"] = self._notify_slack(agent_id, reason)

        # 6. STIX audit log
        actions["stix_logged"] = self._stix_log(agent_id, reason, "isolate", isolation_id)

        # 7. Kafka event
        actions["kafka_emitted"] = await self._emit_kafka(agent_id, "isolated", reason)

        # Persist isolation record
        try:
            with _db_lock:
                con = _conn(self.db_path)
                _ensure_isolation_table(con)
                con.execute(
                    """INSERT OR REPLACE INTO agent_isolation_log
                       (isolation_id, agent_id, reason, isolated_at)
                       VALUES (?,?,?,?)""",
                    (isolation_id, agent_id, reason, now),
                )
                con.commit()
                con.close()
        except Exception as exc:
            log.warning("AutoResponder: could not persist isolation record: %s", exc)

        return {"isolation_id": isolation_id, "agent_id": agent_id, "actions": actions}

    # ── Restoration ───────────────────────────────────────────────────────────

    async def restore_agent(self, agent_id: str, dao_proposal_id: str = "") -> dict:
        """
        Restore an isolated agent (optionally gated on a DAO proposal).

        Steps:
          1. Restore default capabilities
          2. Unlock HSM keys
          3. Emit Kafka event
          4. Update isolation log
        """
        log.info("AutoResponder: restoring agent=%s dao=%s", agent_id, dao_proposal_id)
        now = datetime.now(UTC).isoformat()
        actions: dict[str, bool] = {}

        actions["capabilities_restored"] = self._restore_capabilities(agent_id)
        actions["hsm_keys_unlocked"] = self._unlock_hsm_keys(agent_id)
        actions["kafka_emitted"] = await self._emit_kafka(agent_id, "restored", "dao_approved")
        actions["stix_logged"] = self._stix_log(agent_id, "DAO restoration", "restore", "")

        # Update isolation log
        try:
            with _db_lock:
                con = _conn(self.db_path)
                _ensure_isolation_table(con)
                con.execute(
                    """UPDATE agent_isolation_log
                       SET restored_at=?, dao_proposal=?
                       WHERE agent_id=? AND restored_at IS NULL""",
                    (now, dao_proposal_id, agent_id),
                )
                con.commit()
                con.close()
        except Exception as exc:
            log.warning("AutoResponder: could not update isolation log on restore: %s", exc)

        return {"agent_id": agent_id, "status": "restored", "actions": actions}

    # ── Private steps ─────────────────────────────────────────────────────────

    def _suspend_capabilities(self, agent_id: str) -> bool:
        try:
            with _db_lock:
                con = _conn(self.db_path)
                con.execute(
                    "UPDATE marketplace_agents SET capabilities='[]', status='suspended' WHERE agent_id=?",
                    (agent_id,),
                )
                con.commit()
                con.close()
            return True
        except Exception as exc:
            log.warning("AutoResponder._suspend_capabilities: %s", exc)
            return False

    def _restore_capabilities(self, agent_id: str) -> bool:
        try:
            with _db_lock:
                con = _conn(self.db_path)
                con.execute(
                    "UPDATE marketplace_agents SET capabilities='[\"buy\",\"sell\",\"negotiate\"]', status='active' WHERE agent_id=?",
                    (agent_id,),
                )
                con.commit()
                con.close()
            return True
        except Exception as exc:
            log.warning("AutoResponder._restore_capabilities: %s", exc)
            return False

    def _cancel_listings(self, agent_id: str) -> bool:
        try:
            with _db_lock:
                con = _conn(self.db_path)
                con.execute(
                    "UPDATE marketplace_listings SET status='cancelled' WHERE seller_agent_id=? AND status='active'",
                    (agent_id,),
                )
                con.commit()
                con.close()
            return True
        except Exception as exc:
            log.warning("AutoResponder._cancel_listings: %s", exc)
            return False

    def _cancel_escrows(self, agent_id: str) -> bool:
        try:
            with _db_lock:
                con = _conn(self.db_path)
                con.execute(
                    """UPDATE marketplace_escrows SET status='cancelled'
                       WHERE (buyer_agent=? OR seller_agent=?) AND status IN ('pending','funded')""",
                    (agent_id, agent_id),
                )
                con.commit()
                con.close()
            return True
        except Exception as exc:
            log.warning("AutoResponder._cancel_escrows: %s", exc)
            return False

    def _lock_hsm_keys(self, agent_id: str) -> bool:
        try:
            from warden.crypto.hsm import get_signer
            signer = get_signer()
            if hasattr(signer, "lock_key"):
                signer.lock_key(agent_id)
            return True
        except Exception as exc:
            log.debug("AutoResponder._lock_hsm_keys: %s", exc)
            return False

    def _unlock_hsm_keys(self, agent_id: str) -> bool:
        try:
            from warden.crypto.hsm import get_signer
            signer = get_signer()
            if hasattr(signer, "unlock_key"):
                signer.unlock_key(agent_id)
            return True
        except Exception as exc:
            log.debug("AutoResponder._unlock_hsm_keys: %s", exc)
            return False

    def _notify_slack(self, agent_id: str, reason: str) -> bool:
        try:
            from warden.alerting import send_alert
            send_alert(
                f":rotating_light: AutoResponder: Agent `{agent_id}` isolated. "
                f"Reason: {reason}"
            )
            return True
        except Exception:
            return False

    def _stix_log(self, agent_id: str, reason: str, action: str, isolation_id: str) -> bool:
        try:
            from warden.communities.stix_audit import append_transfer
            append_transfer(
                transfer_id=f"isolation-{agent_id}-{action}",
                source_community_id="system",
                target_community_id="system",
                entity_ueciid=isolation_id or agent_id,
                initiator_mid=f"auto_responder:{agent_id}",
                purpose=f"agent_{action}",
                ctp_hmac_signature="",
            )
            return True
        except Exception:
            return False

    async def _emit_kafka(self, agent_id: str, event_type: str, reason: str) -> bool:
        try:
            from warden.streams.event_bus import get_event_bus
            bus = get_event_bus()
            await bus.produce(
                "marketplace.agents",
                agent_id,
                {"event": event_type, "agent_id": agent_id, "reason": reason},
            )
            return True
        except Exception:
            return False


# ── Module singleton ───────────────────────────────────────────────────────────

_responder: AutoResponder | None = None


def get_auto_responder() -> AutoResponder:
    global _responder
    if _responder is None:
        _responder = AutoResponder()
    return _responder
