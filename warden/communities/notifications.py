"""
warden/communities/notifications.py
─────────────────────────────────────
Community Event Notification Service — email / Slack / Teams

Events
──────
  member_joined        new member joined a community
  transfer_completed   SEP entity transfer finished (includes REJECTED)
  compliance_changed   compliance posture score changed ≥ threshold
  evolution_published  new evolution bundle shared to community

Channels
────────
  slack   Incoming Webhook URL
  teams   Teams Incoming Webhook URL (Adaptive Card)
  email   SMTP — reads SMTP_* env vars

Env vars
────────
  COMMUNITY_NOTIF_DB_PATH   SQLite path (default /tmp/warden_notif.db)
  SMTP_HOST                 SMTP server hostname
  SMTP_PORT                 SMTP port (default 587)
  SMTP_USER                 SMTP auth username
  SMTP_PASS                 SMTP auth password
  SMTP_FROM                 From address (default noreply@shadow-warden.ai)
  SMTP_TLS                  true/false starttls (default true)
"""
from __future__ import annotations

import asyncio
import logging
import smtplib
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

import httpx

from warden.config import settings

log = logging.getLogger("warden.communities.notifications")

_DB_PATH = settings.community_notif_db_path
_db_lock = threading.RLock()

# SMTP config
_SMTP_HOST = settings.smtp_host
_SMTP_PORT = settings.smtp_port
_SMTP_USER = settings.smtp_user
_SMTP_PASS = settings.smtp_pass
_SMTP_FROM = settings.smtp_from
_SMTP_TLS  = settings.smtp_tls

VALID_EVENTS   = {"member_joined", "transfer_completed", "compliance_changed", "evolution_published"}
VALID_CHANNELS = {"slack", "teams", "email"}


# ── Schema ────────────────────────────────────────────────────────────────────

def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(_DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("""
        CREATE TABLE IF NOT EXISTS community_notification_subs (
            sub_id       TEXT PRIMARY KEY,
            community_id TEXT NOT NULL,
            tenant_id    TEXT NOT NULL,
            channel      TEXT NOT NULL,     -- slack | teams | email
            target       TEXT NOT NULL,     -- webhook URL or email address
            label        TEXT NOT NULL DEFAULT '',
            events       TEXT NOT NULL DEFAULT 'member_joined,transfer_completed,compliance_changed,evolution_published',
            active       INTEGER NOT NULL DEFAULT 1,
            created_at   TEXT NOT NULL
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_cns_community ON community_notification_subs(community_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_cns_tenant   ON community_notification_subs(tenant_id)")
    c.commit()
    return c


@dataclass
class NotificationSub:
    sub_id:       str
    community_id: str
    tenant_id:    str
    channel:      str
    target:       str
    label:        str
    events:       list[str]
    active:       bool
    created_at:   str

    def to_dict(self) -> dict[str, Any]:
        return {
            "sub_id":       self.sub_id,
            "community_id": self.community_id,
            "tenant_id":    self.tenant_id,
            "channel":      self.channel,
            "target":       self.target,
            "label":        self.label,
            "events":       self.events,
            "active":       self.active,
            "created_at":   self.created_at,
        }


def _row_to_sub(row: sqlite3.Row) -> NotificationSub:
    return NotificationSub(
        sub_id       = row["sub_id"],
        community_id = row["community_id"],
        tenant_id    = row["tenant_id"],
        channel      = row["channel"],
        target       = row["target"],
        label        = row["label"] or "",
        events       = [e.strip() for e in (row["events"] or "").split(",") if e.strip()],
        active       = bool(row["active"]),
        created_at   = row["created_at"],
    )


# ── CRUD ──────────────────────────────────────────────────────────────────────

def subscribe(
    community_id: str,
    tenant_id:    str,
    channel:      str,
    target:       str,
    label:        str = "",
    events:       list[str] | None = None,
) -> NotificationSub:
    if channel not in VALID_CHANNELS:
        raise ValueError(f"Invalid channel '{channel}'. Must be one of {VALID_CHANNELS}")
    if not target:
        raise ValueError("target (URL or email) is required")
    evts = [e for e in (events or list(VALID_EVENTS)) if e in VALID_EVENTS]
    if not evts:
        raise ValueError("At least one valid event is required")

    sub = NotificationSub(
        sub_id       = str(uuid.uuid4()),
        community_id = community_id,
        tenant_id    = tenant_id,
        channel      = channel,
        target       = target,
        label        = label,
        events       = evts,
        active       = True,
        created_at   = datetime.now(UTC).isoformat(),
    )
    with _db_lock:
        c = _conn()
        c.execute(
            """INSERT INTO community_notification_subs
               (sub_id, community_id, tenant_id, channel, target, label, events, active, created_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (sub.sub_id, community_id, tenant_id, channel, target,
             label, ",".join(evts), 1, sub.created_at),
        )
        c.commit()
    return sub


def list_subscriptions(community_id: str, tenant_id: str | None = None) -> list[NotificationSub]:
    with _db_lock:
        c = _conn()
        if tenant_id:
            rows = c.execute(
                "SELECT * FROM community_notification_subs WHERE community_id=? AND tenant_id=? ORDER BY created_at DESC",
                (community_id, tenant_id),
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT * FROM community_notification_subs WHERE community_id=? ORDER BY created_at DESC",
                (community_id,),
            ).fetchall()
    return [_row_to_sub(r) for r in rows]


def unsubscribe(sub_id: str, tenant_id: str) -> bool:
    with _db_lock:
        c = _conn()
        cur = c.execute(
            "DELETE FROM community_notification_subs WHERE sub_id=? AND tenant_id=?",
            (sub_id, tenant_id),
        )
        c.commit()
        return cur.rowcount > 0


def set_active(sub_id: str, tenant_id: str, active: bool) -> bool:
    with _db_lock:
        c = _conn()
        cur = c.execute(
            "UPDATE community_notification_subs SET active=? WHERE sub_id=? AND tenant_id=?",
            (1 if active else 0, sub_id, tenant_id),
        )
        c.commit()
        return cur.rowcount > 0


# ── Dispatch ──────────────────────────────────────────────────────────────────

async def fire_event(
    community_id: str,
    event_type:   str,
    payload:      dict[str, Any],
    community_name: str = "",
) -> int:
    """Dispatch event to all active subscriptions. Returns number of sends attempted."""
    if event_type not in VALID_EVENTS:
        return 0

    subs = list_subscriptions(community_id)
    active = [s for s in subs if s.active and event_type in s.events]
    if not active:
        return 0

    tasks = [_dispatch(s, event_type, payload, community_name) for s in active]
    await asyncio.gather(*tasks, return_exceptions=True)
    return len(active)


async def _dispatch(
    sub:            NotificationSub,
    event_type:     str,
    payload:        dict[str, Any],
    community_name: str,
) -> None:
    try:
        if sub.channel == "slack":
            await _send_slack(sub.target, event_type, payload, community_name)
        elif sub.channel == "teams":
            await _send_teams(sub.target, event_type, payload, community_name)
        elif sub.channel == "email":
            await asyncio.get_event_loop().run_in_executor(
                None, _send_email_sync, sub.target, event_type, payload, community_name
            )
    except Exception as exc:
        log.warning("Notification dispatch failed sub=%s channel=%s: %s", sub.sub_id, sub.channel, exc)


# ── Slack ─────────────────────────────────────────────────────────────────────

_EVENT_EMOJI = {
    "member_joined":       "👤",
    "transfer_completed":  "📦",
    "compliance_changed":  "🛡️",
    "evolution_published": "🧬",
}

_EVENT_LABEL = {
    "member_joined":       "New Member Joined",
    "transfer_completed":  "Transfer Completed",
    "compliance_changed":  "Compliance Changed",
    "evolution_published": "Evolution Bundle Published",
}


def _build_summary(event_type: str, payload: dict[str, Any]) -> str:
    if event_type == "member_joined":
        name = payload.get("display_name") or payload.get("tenant_id", "unknown")
        role = payload.get("role", "member")
        return f"`{name}` joined as *{role}*"
    if event_type == "transfer_completed":
        status  = payload.get("status", "completed")
        ueciid  = payload.get("ueciid") or payload.get("entity_id", "")
        target  = payload.get("target_community_id", "")
        risk    = payload.get("risk_score")
        s = f"Entity `{ueciid}` → `{target}` — *{status}*"
        if risk is not None:
            s += f"  (risk {risk:.2f})"
        return s
    if event_type == "compliance_changed":
        old = payload.get("old_score", 0)
        new = payload.get("new_score", 0)
        delta = new - old
        arrow = "↑" if delta >= 0 else "↓"
        return f"Score {old:.0f} → {new:.0f}  {arrow}{abs(delta):.0f}  |  status: *{payload.get('status', '')}*"
    if event_type == "evolution_published":
        title = payload.get("title") or payload.get("rule_type", "rule")
        score = payload.get("threat_score")
        s = f"Bundle `{title}`"
        if score is not None:
            s += f"  threat score {score:.2f}"
        return s
    return str(payload)


async def _send_slack(url: str, event_type: str, payload: dict[str, Any], community_name: str) -> None:
    emoji   = _EVENT_EMOJI.get(event_type, "🔔")
    label   = _EVENT_LABEL.get(event_type, event_type)
    summary = _build_summary(event_type, payload)
    body = {
        "text": f"{emoji} *{label}* — {community_name or payload.get('community_id', '')}",
        "attachments": [{
            "color":  "#818cf8",
            "fields": [{"title": "Details", "value": summary, "short": False}],
            "footer": "Shadow Warden Community",
            "ts":     int(datetime.now(UTC).timestamp()),
        }],
    }
    from warden.net_guard import assert_public_url
    assert_public_url(url)  # SSRF guard: subscriber-controlled webhook target
    async with httpx.AsyncClient(timeout=8, follow_redirects=False) as client:
        r = await client.post(url, json=body)
        r.raise_for_status()


# ── Teams ─────────────────────────────────────────────────────────────────────

async def _send_teams(url: str, event_type: str, payload: dict[str, Any], community_name: str) -> None:
    label   = _EVENT_LABEL.get(event_type, event_type)
    emoji   = _EVENT_EMOJI.get(event_type, "🔔")
    summary = _build_summary(event_type, payload)
    body = {
        "@type":      "MessageCard",
        "@context":   "https://schema.org/extensions",
        "themeColor": "818cf8",
        "summary":    f"{label} — {community_name}",
        "sections": [{
            "activityTitle":    f"{emoji} **{label}**",
            "activitySubtitle": community_name or payload.get("community_id", ""),
            "activityText":     summary,
            "markdown":         True,
        }],
    }
    from warden.net_guard import assert_public_url
    assert_public_url(url)  # SSRF guard: subscriber-controlled webhook target
    async with httpx.AsyncClient(timeout=8, follow_redirects=False) as client:
        r = await client.post(url, json=body)
        r.raise_for_status()


# ── Email ─────────────────────────────────────────────────────────────────────

def _send_email_sync(
    to_addr:        str,
    event_type:     str,
    payload:        dict[str, Any],
    community_name: str,
) -> None:
    if not _SMTP_HOST:
        log.debug("SMTP_HOST not set — skipping email notification")
        return

    label   = _EVENT_LABEL.get(event_type, event_type)
    summary = _build_summary(event_type, payload)
    subject = f"[Shadow Warden] {label} — {community_name or payload.get('community_id', '')}"

    html = f"""<!DOCTYPE html>
<html><body style="font-family:sans-serif;background:#0b1120;color:#e2e8f0;padding:24px">
<div style="max-width:520px;margin:0 auto">
  <div style="background:#0f172a;border:1px solid rgba(129,140,248,.2);border-radius:12px;padding:24px">
    <h2 style="margin:0 0 8px;color:#818cf8;font-size:16px">{_EVENT_EMOJI.get(event_type,'')} {label}</h2>
    <p style="margin:0 0 16px;color:#94a3b8;font-size:13px">
      Community: <strong style="color:#e2e8f0">{community_name or payload.get('community_id','')}</strong>
    </p>
    <div style="background:rgba(129,140,248,.06);border-radius:8px;padding:12px 16px;font-size:13px;color:#cbd5e1">
      {summary}
    </div>
    <p style="margin:16px 0 0;font-size:11px;color:#475569">
      Shadow Warden AI — Community Notifications
    </p>
  </div>
</div>
</body></html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = _SMTP_FROM
    msg["To"]      = to_addr
    msg.attach(MIMEText(summary, "plain"))
    msg.attach(MIMEText(html, "html"))

    with smtplib.SMTP(_SMTP_HOST, _SMTP_PORT, timeout=10) as s:
        if _SMTP_TLS:
            s.starttls()
        if _SMTP_USER:
            s.login(_SMTP_USER, _SMTP_PASS)
        s.sendmail(_SMTP_FROM, [to_addr], msg.as_string())
