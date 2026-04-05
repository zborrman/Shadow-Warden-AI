"""
warden/workers/weekly_report.py
────────────────────────────────
Weekly ROI Impact Report — ARQ task.

Runs every Friday at 08:00 UTC (configured in settings.py).
For every tenant with an active subscription (startup / growth / msp)
it generates a beautiful HTML email summarising the past 7 days of
protection and sends it to the billing admin email on file.

Key design decisions
─────────────────────
  • Data comes from _build_impact() (same source as /tenant/impact) —
    single source of truth, no separate aggregation pipeline.
  • HTML is 100% inline-CSS for maximum email client compatibility
    (Gmail, Outlook, Apple Mail, mobile).  Dark-mode via @media query.
  • Delivery is via SMTP (same config as portal password reset emails).
    Fails silently per-tenant — one bad address never blocks others.
  • Free-tier tenants are excluded (no billing admin email stored).
  • The task can also be triggered manually via POST /admin/weekly-report
    (useful for testing or ad-hoc re-sends).

Environment variables
─────────────────────
  SMTP_HOST                  — e.g. smtp.sendgrid.net
  SMTP_PORT                  — default 587
  SMTP_USER                  — SMTP username / API key
  SMTP_PASS                  — SMTP password
  WEEKLY_REPORT_FROM         — "Shadow Warden <noreply@shadow-warden.io>"
  WEEKLY_REPORT_REPLY_TO     — optional reply-to address
  PORTAL_URL                 — used for CTA button link
  IMPACT_COST_PER_BLOCK_USD  — cost per blocked request (default $100)
"""
from __future__ import annotations

import logging
import os
import smtplib
from datetime import UTC, datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

log = logging.getLogger("warden.workers.weekly_report")

_SMTP_HOST     = os.getenv("SMTP_HOST", "")
_SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
_SMTP_USER     = os.getenv("SMTP_USER", "")
_SMTP_PASS     = os.getenv("SMTP_PASS", "")
_FROM_ADDR     = os.getenv("WEEKLY_REPORT_FROM", f"Shadow Warden <{_SMTP_USER}>")
_REPLY_TO      = os.getenv("WEEKLY_REPORT_REPLY_TO", "")
_PORTAL_URL    = os.getenv("PORTAL_URL", "https://app.shadow-warden.io")


# ── HTML template ─────────────────────────────────────────────────────────────

def _render_html(data: dict, tenant_id: str) -> str:
    """
    Render a self-contained HTML email from impact data.
    All CSS is inlined.  No external images or fonts — loads in any client.
    """
    blocked       = data.get("requests_blocked", 0)
    pii           = data.get("pii_masked", 0)
    dollar_saved  = data.get("dollar_saved", 0.0)
    total         = data.get("requests_total", 0)
    block_pct     = data.get("block_rate_pct", 0.0)
    plan          = (data.get("plan") or "free").capitalize()
    threats       = data.get("top_threats", [])[:5]
    annual        = data.get("annual_projection", 0.0)

    def _fmtd(n: float) -> str:
        if n >= 1_000_000:
            return f"${n/1_000_000:.1f}M"
        if n >= 1_000:
            return f"${n/1_000:.1f}K"
        return f"${int(n):,}"

    def _fmtn(n: int) -> str:
        if n >= 1_000:
            return f"{n/1_000:.1f}K"
        return f"{n:,}"

    now        = datetime.now(UTC)
    week_label = now.strftime("Week of %B") + f" {now.day}, {now.year}"

    # Threat rows
    threat_rows = ""
    for t in threats:
        pct    = t.get("pct", 0)
        label  = t.get("label", "Unknown")
        count  = t.get("count", 0)
        threat_rows += f"""
        <tr>
          <td style="padding:6px 0;font-size:13px;color:#d1d5db">{label}</td>
          <td style="padding:6px 0;text-align:right;font-size:13px;color:#9ca3af">{count}</td>
          <td style="padding:6px 0 6px 12px;width:90px">
            <div style="background:#374151;border-radius:3px;height:5px;overflow:hidden">
              <div style="background:#ef4444;width:{min(pct,100):.0f}%;height:5px"></div>
            </div>
          </td>
        </tr>"""

    if not threat_rows:
        threat_rows = """
        <tr>
          <td colspan="3" style="padding:8px 0;font-size:13px;color:#6b7280;text-align:center">
            No threats blocked this week — quiet week!
          </td>
        </tr>"""

    # Highlight colour for the dollar saved card
    dollar_color = "#22c55e" if dollar_saved > 0 else "#6b7280"

    portal_link = f"{_PORTAL_URL}/impact?tenant={tenant_id}"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Shadow Warden Weekly Report</title>
<style>
  @media (prefers-color-scheme: dark) {{
    .email-body  {{ background:#0f1117 !important }}
    .email-card  {{ background:#1f2937 !important; border-color:#374151 !important }}
    .email-text  {{ color:#e5e7eb !important }}
    .email-muted {{ color:#9ca3af !important }}
  }}
</style>
</head>
<body class="email-body" style="margin:0;padding:0;background:#f3f4f6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif">

<table width="100%" cellpadding="0" cellspacing="0" role="presentation">
<tr><td align="center" style="padding:32px 16px">

  <!-- Card -->
  <table class="email-card" width="560" cellpadding="0" cellspacing="0" role="presentation"
    style="background:#ffffff;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden;max-width:100%">

    <!-- Header -->
    <tr>
      <td style="background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);padding:28px 32px">
        <table width="100%" cellpadding="0" cellspacing="0">
          <tr>
            <td>
              <div style="font-size:24px;line-height:1">🛡️</div>
              <div style="margin-top:8px;font-size:18px;font-weight:700;color:#ffffff;letter-spacing:-0.02em">Shadow Warden AI</div>
              <div style="margin-top:2px;font-size:12px;color:#6b7280">Weekly Protection Report</div>
            </td>
            <td align="right" valign="top">
              <div style="font-size:11px;color:#4b5563;white-space:nowrap">{week_label}</div>
              <div style="margin-top:4px;background:#1e3a5f;color:#60a5fa;font-size:10px;font-weight:700;padding:3px 8px;border-radius:4px;display:inline-block;text-transform:uppercase;letter-spacing:0.06em">{plan} Plan</div>
            </td>
          </tr>
        </table>
      </td>
    </tr>

    <!-- Intro -->
    <tr>
      <td style="padding:24px 32px 0">
        <p class="email-text" style="margin:0;font-size:15px;color:#111827;line-height:1.6">
          Here's what Shadow Warden did for <strong>{tenant_id}</strong> this week.
          Your team stayed protected while working with AI tools — here's the proof.
        </p>
      </td>
    </tr>

    <!-- KPI row -->
    <tr>
      <td style="padding:20px 32px">
        <table width="100%" cellpadding="0" cellspacing="0">
          <tr>
            <!-- Dollar saved -->
            <td width="33%" style="padding-right:8px">
              <div style="background:#052e16;border:1px solid #166534;border-radius:10px;padding:16px 12px;text-align:center">
                <div style="font-size:26px;font-weight:800;color:{dollar_color};line-height:1">{_fmtd(dollar_saved)}</div>
                <div style="margin-top:4px;font-size:10px;color:#6b7280;text-transform:uppercase;letter-spacing:0.07em">Value Protected</div>
              </div>
            </td>
            <!-- Blocked -->
            <td width="33%" style="padding-right:8px">
              <div style="background:#2d0a0a;border:1px solid #7f1d1d;border-radius:10px;padding:16px 12px;text-align:center">
                <div style="font-size:26px;font-weight:800;color:#f87171;line-height:1">{_fmtn(blocked)}</div>
                <div style="margin-top:4px;font-size:10px;color:#6b7280;text-transform:uppercase;letter-spacing:0.07em">Threats Blocked</div>
              </div>
            </td>
            <!-- PII masked -->
            <td width="33%">
              <div style="background:#1c2a1c;border:1px solid #365314;border-radius:10px;padding:16px 12px;text-align:center">
                <div style="font-size:26px;font-weight:800;color:#86efac;line-height:1">{_fmtn(pii)}</div>
                <div style="margin-top:4px;font-size:10px;color:#6b7280;text-transform:uppercase;letter-spacing:0.07em">PII Masked</div>
              </div>
            </td>
          </tr>
        </table>
      </td>
    </tr>

    <!-- Stats belt -->
    <tr>
      <td style="padding:0 32px 20px">
        <div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:12px 16px">
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td style="font-size:12px;color:#6b7280">Total requests scanned</td>
              <td align="right" style="font-size:13px;font-weight:600;color:#111827">{_fmtn(total)}</td>
            </tr>
            <tr>
              <td style="font-size:12px;color:#6b7280;padding-top:4px">Block rate</td>
              <td align="right" style="font-size:13px;font-weight:600;color:#111827;padding-top:4px">{block_pct:.1f}%</td>
            </tr>
            <tr>
              <td style="font-size:12px;color:#6b7280;padding-top:4px">Annual projection</td>
              <td align="right" style="font-size:13px;font-weight:600;color:#22c55e;padding-top:4px">{_fmtd(annual)} / yr</td>
            </tr>
          </table>
        </div>
      </td>
    </tr>

    <!-- Threat breakdown -->
    <tr>
      <td style="padding:0 32px 20px">
        <div style="font-size:11px;color:#6b7280;font-weight:600;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:10px">
          Top Threats Blocked
        </div>
        <table width="100%" cellpadding="0" cellspacing="0">
          {threat_rows}
        </table>
      </td>
    </tr>

    <!-- CTA -->
    <tr>
      <td style="padding:0 32px 28px;text-align:center">
        <a href="{portal_link}"
           style="display:inline-block;background:#3b82f6;color:#ffffff;font-size:14px;font-weight:600;text-decoration:none;border-radius:8px;padding:12px 28px">
          View Full Impact Dashboard →
        </a>
      </td>
    </tr>

    <!-- Divider -->
    <tr>
      <td style="padding:0 32px">
        <div style="border-top:1px solid #e5e7eb"></div>
      </td>
    </tr>

    <!-- Tip section -->
    <tr>
      <td style="padding:20px 32px">
        <table width="100%" cellpadding="0" cellspacing="0">
          <tr>
            <td width="32" valign="top" style="font-size:20px">💡</td>
            <td style="padding-left:10px">
              <div style="font-size:12px;font-weight:600;color:#374151;margin-bottom:3px">Did you know?</div>
              <div style="font-size:12px;color:#6b7280;line-height:1.5">
                Each blocked prompt protects your team from potential data breaches.
                The IBM Cost of a Data Breach Report 2024 puts the average incident
                cost at $4.88M — Shadow Warden stops leaks before they happen.
              </div>
            </td>
          </tr>
        </table>
      </td>
    </tr>

    <!-- Footer -->
    <tr>
      <td style="background:#f9fafb;border-top:1px solid #e5e7eb;padding:16px 32px;text-align:center">
        <p style="margin:0;font-size:11px;color:#9ca3af;line-height:1.6">
          Shadow Warden AI · AI Data Protection for Business<br>
          You're receiving this because you're an admin for <strong>{tenant_id}</strong>.<br>
          <a href="{_PORTAL_URL}/unsubscribe?tenant={tenant_id}"
             style="color:#6b7280">Unsubscribe from weekly reports</a>
        </p>
      </td>
    </tr>

  </table>
</td></tr>
</table>

</body>
</html>"""


def _render_plaintext(data: dict, tenant_id: str) -> str:
    """Plain-text fallback for email clients that can't render HTML."""
    blocked      = data.get("requests_blocked", 0)
    pii          = data.get("pii_masked", 0)
    dollar_saved = data.get("dollar_saved", 0.0)
    total        = data.get("requests_total", 0)
    now          = datetime.now(UTC)
    week_label   = now.strftime("Week of %B") + f" {now.day}, {now.year}"

    return f"""
Shadow Warden AI — Weekly Protection Report
{week_label} · Tenant: {tenant_id}
{'─' * 48}

VALUE PROTECTED THIS WEEK:   ${dollar_saved:,.2f}
Threats blocked:             {blocked:,}
PII intercepts:              {pii:,}
Total requests scanned:      {total:,}

View your full impact dashboard:
{_PORTAL_URL}/impact?tenant={tenant_id}

──────────────────────────────────────────────
Shadow Warden AI · AI Data Protection for Business
Unsubscribe: {_PORTAL_URL}/unsubscribe?tenant={tenant_id}
""".strip()


# ── Email delivery ────────────────────────────────────────────────────────────

def _send_report_email(to_addr: str, tenant_id: str, html: str, plain: str) -> None:
    """
    Send the weekly HTML email via SMTP.
    Raises on network / auth errors — caller catches and logs.
    """
    msg = MIMEMultipart("alternative")
    _now = datetime.now(UTC)
    msg["Subject"] = f"Your Shadow Warden Weekly Report — {_now.strftime('%b')} {_now.day}"
    msg["From"]    = _FROM_ADDR
    msg["To"]      = to_addr
    if _REPLY_TO:
        msg["Reply-To"] = _REPLY_TO

    msg.attach(MIMEText(plain, "plain", "utf-8"))
    msg.attach(MIMEText(html,  "html",  "utf-8"))

    with smtplib.SMTP(_SMTP_HOST, _SMTP_PORT, timeout=15) as srv:
        srv.starttls()
        srv.login(_SMTP_USER, _SMTP_PASS)
        srv.sendmail(_FROM_ADDR, [to_addr], msg.as_string())


# ── Core report builder ───────────────────────────────────────────────────────

def build_report_for_tenant(tenant_id: str, admin_email: str, period_days: int = 7) -> bool:
    """
    Build and send the weekly report for a single tenant.
    Returns True on success, False on delivery failure.
    """
    from warden.api.tenant_impact import _build_impact  # noqa: PLC0415

    try:
        data = _build_impact(tenant_id=tenant_id, period_days=period_days)
    except Exception as exc:
        log.warning("weekly_report: impact fetch failed for %s: %s", tenant_id, exc)
        return False

    html  = _render_html(data, tenant_id)
    plain = _render_plaintext(data, tenant_id)

    if not _SMTP_HOST or not _SMTP_USER:
        # SMTP not configured — log the would-be email (dev/test mode)
        log.info(
            "weekly_report [DRY RUN — SMTP not configured]: "
            "would send to %s for tenant %s: blocks=%d dollar_saved=$%.2f",
            admin_email, tenant_id,
            data.get("requests_blocked", 0),
            data.get("dollar_saved", 0.0),
        )
        return True

    try:
        _send_report_email(admin_email, tenant_id, html, plain)
        log.info(
            "weekly_report: sent to %s for tenant %s (blocks=%d, saved=$%.2f)",
            admin_email, tenant_id,
            data.get("requests_blocked", 0),
            data.get("dollar_saved", 0.0),
        )
        return True
    except Exception as exc:
        log.error("weekly_report: delivery failed for %s (%s): %s", tenant_id, admin_email, exc)
        return False


# ── ARQ task ──────────────────────────────────────────────────────────────────

async def send_weekly_reports(ctx: dict) -> dict:
    """
    ARQ task: send weekly ROI emails to all active paid tenants.

    Scheduled every Friday at 08:00 UTC via arq cron in settings.py.
    Can also be triggered manually via POST /admin/weekly-report.

    Returns a summary dict: {sent, skipped, failed, tenant_ids_sent}
    """
    sent    = 0
    skipped = 0
    failed  = 0
    sent_to: list[str] = []

    try:
        from warden.stripe_billing import get_stripe_billing  # noqa: PLC0415
        billing = get_stripe_billing()
    except Exception as exc:
        log.error("weekly_report: billing unavailable: %s", exc)
        return {"sent": 0, "skipped": 0, "failed": 0, "error": str(exc)}

    # Fetch all active paid tenants with their admin email
    with billing._lock:
        rows = billing._conn.execute(
            """
            SELECT tenant_id, admin_email, plan
            FROM subscriptions
            WHERE status IN ('active', 'trialing')
              AND plan != 'free'
              AND admin_email IS NOT NULL
              AND admin_email != ''
            """
        ).fetchall()

    log.info("weekly_report: found %d active paid tenants to notify.", len(rows))

    for row in rows:
        tenant_id   = row["tenant_id"]
        admin_email = row["admin_email"]
        ok = build_report_for_tenant(tenant_id, admin_email, period_days=7)
        if ok:
            sent += 1
            sent_to.append(tenant_id)
        else:
            failed += 1

    log.info(
        "weekly_report: complete — sent=%d failed=%d skipped=%d",
        sent, failed, skipped,
    )
    return {
        "sent":             sent,
        "skipped":          skipped,
        "failed":           failed,
        "tenant_ids_sent":  sent_to,
        "generated_at":     datetime.now(UTC).isoformat(),
    }
