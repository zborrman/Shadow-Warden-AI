"""
GSAM JIT credential lease (Hermes-style short-lived, human-approved).

An agent requests a scoped credential lease; a human approves it out-of-band
(Slack → approval token); approval mints an HMAC-SHA256 signature over
``lease_id|agent_id|scope|expires_at``; the agent redeems (lease_id, signature)
exactly once before it expires.

Security posture (deliberate exception to GSAM's fail-OPEN rule):
  • Leasing is FAIL-CLOSED. With ``settings.gsam_lease_secret`` unset, every
    request/approve/redeem raises LeaseUnavailableError → HTTP 503. A credential
    path must never "fail open".
  • The signing secret is resolved server-side and is NEVER placed in any
    response body (only the derived signature — the bearer credential — is
    returned, and only to the approved requester).
  • redeem() is single-use: the ``used_at`` write is atomic (guarded UPDATE),
    so a replayed signature is rejected. Expired or tampered signatures fail
    hmac.compare_digest.

State: gsam_leases (SQLite ``gsam`` DB) + approval-token→lease_id map in Redis
(``gsam:lease:approval:{token}``, 1h TTL) with an in-process fallback. Every
state change emits a metadata-only observation.
"""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import logging
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime

from warden.config import settings

log = logging.getLogger("warden.gsam.jit_lease")

_APPROVAL_PREFIX = "gsam:lease:approval:"
_APPROVAL_TTL_S = 3600  # 1h window to approve (master.py convention)

_DDL = """
    CREATE TABLE IF NOT EXISTS gsam_leases (
        lease_id   TEXT PRIMARY KEY,
        agent_id   TEXT NOT NULL,
        tenant_id  TEXT NOT NULL,
        scope      TEXT NOT NULL,
        status     TEXT NOT NULL DEFAULT 'PENDING',
        hmac_sig   TEXT NOT NULL DEFAULT '',
        expires_at TEXT NOT NULL DEFAULT '',
        used_at    TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
    );
"""

# In-process fallback for the approval-token map: token -> (lease_id, expiry).
_mem_tokens: dict[str, tuple[str, float]] = {}
_mem_lock = threading.RLock()


class LeaseUnavailableError(RuntimeError):
    """gsam_lease_secret is unset — leasing is fail-CLOSED (maps to HTTP 503)."""


@dataclass
class LeaseRequest:
    lease_id: str
    status: str
    approval_token: str  # for Slack / internal use — never sent to the requester


# ── secret + signing (fail-closed) ───────────────────────────────────────────────

def _require_secret() -> str:
    secret = settings.gsam_lease_secret
    if not secret:
        raise LeaseUnavailableError(
            "GSAM leasing disabled: gsam_lease_secret is unset (fail-closed)."
        )
    return secret


def _sign(lease_id: str, agent_id: str, scope: str, expires_at: str) -> str:
    secret = _require_secret()
    payload = f"{lease_id}|{agent_id}|{scope}|{expires_at}"
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


# ── approval-token map (Redis with in-process fallback) ──────────────────────────

def _redis():
    try:
        from warden.cache import _get_client  # noqa: PLC0415
        return _get_client()
    except Exception:  # noqa: BLE001
        return None


def _store_token(token: str, lease_id: str) -> None:
    r = _redis()
    if r is not None:
        try:
            r.setex(_APPROVAL_PREFIX + token, _APPROVAL_TTL_S, lease_id)
            return
        except Exception:  # noqa: BLE001
            pass
    with _mem_lock:
        _mem_tokens[token] = (lease_id, time.time() + _APPROVAL_TTL_S)


def _resolve_token(token: str, *, consume: bool) -> str | None:
    r = _redis()
    if r is not None:
        try:
            lease_id = r.get(_APPROVAL_PREFIX + token)
            if lease_id and consume:
                with contextlib.suppress(Exception):
                    r.delete(_APPROVAL_PREFIX + token)
            return str(lease_id) if lease_id else None
        except Exception:  # noqa: BLE001
            pass
    with _mem_lock:
        rec = _mem_tokens.get(token)
        if rec is None:
            return None
        lease_id, expiry = rec
        if expiry <= time.time():
            _mem_tokens.pop(token, None)
            return None
        if consume:
            _mem_tokens.pop(token, None)
        return lease_id


# ── DB helpers ───────────────────────────────────────────────────────────────────

def _conn():
    from warden.db.turso import get_connection  # noqa: PLC0415
    return get_connection("gsam", fallback_path=settings.gsam_db_path)


def _load(con, lease_id: str) -> dict | None:
    cur = con.execute(
        "SELECT lease_id, agent_id, tenant_id, scope, status, hmac_sig, "
        "expires_at, used_at, created_at FROM gsam_leases WHERE lease_id = ?",
        (lease_id,),
    )
    row = cur.fetchone()
    if row is None:
        return None
    return {
        "lease_id":   str(row[0]),
        "agent_id":   str(row[1]),
        "tenant_id":  str(row[2]),
        "scope":      str(row[3]),
        "status":     str(row[4]),
        "hmac_sig":   str(row[5]),
        "expires_at": str(row[6]),
        "used_at":    str(row[7]),
        "created_at": str(row[8]),
    }


# ── Public API ───────────────────────────────────────────────────────────────────

def request_lease(agent_id: str, tenant_id: str, scope: str) -> LeaseRequest:
    """Create a PENDING lease and an approval token (posted to Slack).

    Fail-closed: raises LeaseUnavailableError when no signing secret is set.
    """
    _require_secret()  # fail-closed early — no PENDING rows without a secret
    if not agent_id or not scope:
        raise ValueError("agent_id and scope are required")

    lease_id = "lease-" + secrets.token_hex(12)
    token = secrets.token_urlsafe(24)
    now = datetime.now(UTC).isoformat()

    with _conn() as con:
        with contextlib.suppress(Exception):
            con.executescript(_DDL)
        con.execute(
            "INSERT INTO gsam_leases "
            "(lease_id, agent_id, tenant_id, scope, status, created_at) "
            "VALUES (?,?,?,?, 'PENDING', ?)",
            (lease_id, agent_id, tenant_id, scope, now),
        )
        with contextlib.suppress(Exception):
            con.commit()

    _store_token(token, lease_id)
    _post_slack(lease_id, agent_id, scope, token)
    _emit(agent_id, tenant_id, scope, "lease_request")
    log.info("gsam: lease requested id=%s agent=%s scope=%s", lease_id, agent_id, scope)
    return LeaseRequest(lease_id=lease_id, status="PENDING", approval_token=token)


def approve(token: str) -> dict | None:
    """Approve a pending lease by token; mint + return the HMAC signature.

    Returns the signature payload (bearer credential) or None if the token is
    unknown/expired/already used. Fail-closed on missing secret.
    """
    _require_secret()
    lease_id = _resolve_token(token, consume=True)
    if not lease_id:
        return None

    with _conn() as con:
        with contextlib.suppress(Exception):
            con.executescript(_DDL)
        lease = _load(con, lease_id)
        if lease is None or lease["status"] != "PENDING":
            return None
        expires_at = datetime.fromtimestamp(
            time.time() + settings.gsam_lease_ttl_s, tz=UTC
        ).isoformat()
        sig = _sign(lease_id, lease["agent_id"], lease["scope"], expires_at)
        con.execute(
            "UPDATE gsam_leases SET status='APPROVED', hmac_sig=?, expires_at=? "
            "WHERE lease_id=? AND status='PENDING'",
            (sig, expires_at, lease_id),
        )
        with contextlib.suppress(Exception):
            con.commit()

    _emit(lease["agent_id"], lease["tenant_id"], lease["scope"], "lease_approve")
    log.info("gsam: lease approved id=%s", lease_id)
    return {
        "lease_id":   lease_id,
        "status":     "APPROVED",
        "signature":  sig,
        "expires_at": expires_at,
    }


def deny(token: str) -> bool:
    """Deny a pending lease by token."""
    lease_id = _resolve_token(token, consume=True)
    if not lease_id:
        return False
    with _conn() as con:
        with contextlib.suppress(Exception):
            con.executescript(_DDL)
        con.execute(
            "UPDATE gsam_leases SET status='DENIED' "
            "WHERE lease_id=? AND status='PENDING'",
            (lease_id,),
        )
        with contextlib.suppress(Exception):
            con.commit()
    log.info("gsam: lease denied id=%s", lease_id)
    return True


def redeem(lease_id: str, signature: str) -> dict:
    """Redeem an approved lease exactly once. Returns {redeemed, ...}.

    Rejects unknown, unapproved, expired, tampered, or already-used leases.
    Fail-closed on missing secret.
    """
    _require_secret()
    if not lease_id or not signature:
        return {"redeemed": False, "reason": "missing_params"}

    with _conn() as con:
        with contextlib.suppress(Exception):
            con.executescript(_DDL)
        lease = _load(con, lease_id)
        if lease is None:
            return {"redeemed": False, "reason": "not_found"}
        # used_at is checked before status so a replayed (REDEEMED) lease reports
        # already_used rather than not_approved.
        if lease["used_at"]:
            return {"redeemed": False, "reason": "already_used"}
        if lease["status"] != "APPROVED":
            return {"redeemed": False, "reason": "not_approved"}
        if _is_expired(lease["expires_at"]):
            return {"redeemed": False, "reason": "expired"}

        expected = _sign(lease_id, lease["agent_id"], lease["scope"], lease["expires_at"])
        if not (hmac.compare_digest(signature, expected)
                and hmac.compare_digest(lease["hmac_sig"], expected)):
            return {"redeemed": False, "reason": "bad_signature"}

        now = datetime.now(UTC).isoformat()
        cur = con.execute(
            "UPDATE gsam_leases SET status='REDEEMED', used_at=? "
            "WHERE lease_id=? AND used_at=''",
            (now, lease_id),
        )
        with contextlib.suppress(Exception):
            con.commit()
        if cur.rowcount != 1:
            # Lost the single-use race — another redeem consumed it first.
            return {"redeemed": False, "reason": "already_used"}

    _emit(lease["agent_id"], lease["tenant_id"], lease["scope"], "lease_redeem")
    log.info("gsam: lease redeemed id=%s", lease_id)
    return {"redeemed": True, "lease_id": lease_id, "agent_id": lease["agent_id"], "scope": lease["scope"]}


def get_status(lease_id: str) -> dict | None:
    """Return lease metadata (never the signature/secret)."""
    with _conn() as con:
        with contextlib.suppress(Exception):
            con.executescript(_DDL)
        lease = _load(con, lease_id)
    if lease is None:
        return None
    return {
        "lease_id":   lease["lease_id"],
        "agent_id":   lease["agent_id"],
        "scope":      lease["scope"],
        "status":     lease["status"],
        "expires_at": lease["expires_at"],
        "redeemed":   bool(lease["used_at"]),
    }


# ── helpers ──────────────────────────────────────────────────────────────────────

def _is_expired(expires_at: str) -> bool:
    if not expires_at:
        return True
    try:
        return datetime.fromisoformat(expires_at) <= datetime.now(UTC)
    except ValueError:
        return True


def _post_slack(lease_id: str, agent_id: str, scope: str, token: str) -> None:
    webhook = settings.slack_webhook_url
    if not webhook:
        return

    def _send() -> None:
        with contextlib.suppress(Exception):
            import httpx  # noqa: PLC0415

            base = settings.warden_base_url.rstrip("/")
            text = (
                f"🔐 GSAM lease request `{lease_id}`\n"
                f"agent=`{agent_id}` scope=`{scope}`\n"
                f"Approve: POST {base}/gsam/lease/approve/{token}"
            )
            httpx.post(webhook, json={"text": text}, timeout=5.0)

    with contextlib.suppress(Exception):
        threading.Thread(target=_send, daemon=True).start()


def _emit(agent_id: str, tenant_id: str, scope: str, event: str) -> None:
    with contextlib.suppress(Exception):
        from warden.gsam.collector import gsam_emit  # noqa: PLC0415
        from warden.gsam.schema import Observation  # noqa: PLC0415

        gsam_emit(Observation(
            agent_id=agent_id,
            tenant_id=tenant_id,
            event=event,
            payload_kind=scope[:64],
        ).to_row())
