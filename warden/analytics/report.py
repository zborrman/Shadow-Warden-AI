"""
warden/analytics/report.py
━━━━━━━━━━━━━━━━━━━━━━━━━━
Monthly Compliance Report Generator for MSP tenants.

Produces a print-ready HTML document (open in any browser → File → Print →
Save as PDF) covering:

  • Executive Summary     — KPIs: requests, blocks, block rate, cost deflected
  • Security Posture      — risk-level breakdown with colour coding
  • Threat Intelligence   — top attack types (flag distribution)
  • Data Protection       — PII entity types intercepted (GDPR evidence)
  • Daily Activity        — 7-day rolling table + full-month summary
  • Recommendations       — auto-generated from metrics

Also supports JSON export (`fmt="json"`) for programmatic / API consumers.

Usage::

    from warden.analytics.report import ReportEngine
    engine  = ReportEngine()
    html    = engine.render_html("acme_corp", "2026-02")
    payload = engine.render_json("acme_corp", "2026-02")
"""
from __future__ import annotations

import calendar
import collections
import html as _html
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from warden.analytics.logger import load_entries

# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class DailyStats:
    date:     str   # YYYY-MM-DD
    requests: int   = 0
    blocked:  int   = 0
    masked:   int   = 0


@dataclass
class ReportData:
    tenant_id:    str
    month:        str          # YYYY-MM
    month_label:  str          # "February 2026"
    generated_at: str          # ISO-8601

    # ── Volume ────────────────────────────────────────────────────────
    total_requests:   int   = 0
    total_blocked:    int   = 0
    total_allowed:    int   = 0
    total_masked:     int   = 0     # entity occurrences masked
    attack_cost_usd:  float = 0.0   # sum of attack_cost_usd in blocked rows

    # ── Risk level breakdown ──────────────────────────────────────────
    risk_counts: dict[str, int] = field(default_factory=dict)  # low/medium/high/block

    # ── Attack flags ──────────────────────────────────────────────────
    flag_counts: dict[str, int] = field(default_factory=dict)

    # ── PII entity types ──────────────────────────────────────────────
    entity_counts: dict[str, int] = field(default_factory=dict)

    # ── Time-series (one row per day in the month) ────────────────────
    daily: list[DailyStats] = field(default_factory=list)

    # ── Derived ───────────────────────────────────────────────────────
    @property
    def block_rate_pct(self) -> float:
        if not self.total_requests:
            return 0.0
        return round(self.total_blocked / self.total_requests * 100, 1)

    @property
    def posture(self) -> str:
        """GREEN / YELLOW / RED based on block rate."""
        r = self.block_rate_pct
        if r < 2:
            return "GREEN"
        if r < 8:
            return "YELLOW"
        return "RED"

    @property
    def posture_label(self) -> str:
        mapping = {"GREEN": "Secure", "YELLOW": "Monitor", "RED": "Under Attack"}
        return mapping.get(self.posture, "Unknown")


# ── Engine ────────────────────────────────────────────────────────────────────

class ReportEngine:
    """
    Builds compliance reports from the NDJSON event log.

    ``tenant_id`` must match the ``tenant_id`` field written by the gateway.
    Use ``"default"`` for single-tenant deployments.
    """

    # ── Public API ────────────────────────────────────────────────────

    def build(self, tenant_id: str, month: str) -> ReportData:
        """
        Aggregate log entries for *tenant_id* during *month* (``"YYYY-MM"``).
        Returns a :class:`ReportData` ready for rendering.
        """
        year_int, mon_int = map(int, month.split("-"))
        _, days_in_month  = calendar.monthrange(year_int, mon_int)
        month_label       = datetime(year_int, mon_int, 1).strftime("%B %Y")

        # Load last 366 days (covers any requested month within the past year)
        all_entries = load_entries(days=366)

        # Filter to this tenant + this month
        prefix   = f"{month}-"
        entries  = [
            e for e in all_entries
            if e.get("tenant_id", "default") == tenant_id
            and e.get("ts", "").startswith(prefix)
        ]

        # ── Per-day buckets ────────────────────────────────────────────
        day_map: dict[str, DailyStats] = {}
        for d in range(1, days_in_month + 1):
            key = f"{month}-{d:02d}"
            day_map[key] = DailyStats(date=key)

        # ── Aggregation ────────────────────────────────────────────────
        risk_counts: dict[str, int]   = collections.Counter()
        flag_counts: dict[str, int]   = collections.Counter()
        entity_counts: dict[str, int] = collections.Counter()
        total_requests  = 0
        total_blocked   = 0
        total_masked    = 0
        attack_cost_usd = 0.0

        for entry in entries:
            total_requests += 1
            blocked = not entry.get("allowed", True)
            if blocked:
                total_blocked += 1

            risk = entry.get("risk_level", "low")
            risk_counts[risk] += 1

            for flag in entry.get("flags", []):
                flag_counts[flag] += 1

            ec = entry.get("entity_count", 0)
            if ec:
                total_masked += ec
                for et in entry.get("entities_detected", []):
                    entity_counts[et] += 1

            if blocked:
                attack_cost_usd += entry.get("attack_cost_usd", 0.0)

            day_key = entry.get("ts", "")[:10]
            if day_key in day_map:
                day_map[day_key].requests += 1
                if blocked:
                    day_map[day_key].blocked += 1
                if ec:
                    day_map[day_key].masked += ec

        return ReportData(
            tenant_id    = tenant_id,
            month        = month,
            month_label  = month_label,
            generated_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
            total_requests  = total_requests,
            total_blocked   = total_blocked,
            total_allowed   = total_requests - total_blocked,
            total_masked    = total_masked,
            attack_cost_usd = round(attack_cost_usd, 4),
            risk_counts     = dict(risk_counts),
            flag_counts     = dict(flag_counts),
            entity_counts   = dict(entity_counts),
            daily           = list(day_map.values()),
        )

    def render_html(self, tenant_id: str, month: str) -> str:
        """Return a self-contained HTML string (inline CSS, no external assets)."""
        data = self.build(tenant_id, month)
        return _render_html(data)

    def render_json(self, tenant_id: str, month: str) -> dict[str, Any]:
        """Return a JSON-serialisable dict of the report data."""
        data = self.build(tenant_id, month)
        return {
            "tenant_id":    data.tenant_id,
            "month":        data.month,
            "month_label":  data.month_label,
            "generated_at": data.generated_at,
            "summary": {
                "total_requests":   data.total_requests,
                "total_blocked":    data.total_blocked,
                "total_allowed":    data.total_allowed,
                "total_masked":     data.total_masked,
                "block_rate_pct":   data.block_rate_pct,
                "attack_cost_usd":  data.attack_cost_usd,
                "posture":          data.posture,
                "posture_label":    data.posture_label,
            },
            "risk_breakdown":  data.risk_counts,
            "threat_flags":    data.flag_counts,
            "entity_types":    data.entity_counts,
            "daily":           [
                {"date": d.date, "requests": d.requests,
                 "blocked": d.blocked, "masked": d.masked}
                for d in data.daily
            ],
            "recommendations": _recommendations(data),
        }


# ── Module-level singleton ─────────────────────────────────────────────────────

_engine: ReportEngine | None = None


def get_engine() -> ReportEngine:
    global _engine
    if _engine is None:
        _engine = ReportEngine()
    return _engine


# ── HTML renderer ─────────────────────────────────────────────────────────────

_POSTURE_COLOR = {"GREEN": "#22c55e", "YELLOW": "#eab308", "RED": "#ef4444"}
_RISK_COLOR    = {"low": "#22c55e", "medium": "#eab308", "high": "#f97316", "block": "#ef4444"}
_FLAG_LABEL    = {
    "prompt_injection":   "Prompt Injection",
    "secret_detected":    "Secret / Credential Leak",
    "harmful_content":    "Harmful Content",
    "pii_detected":       "PII Detected",
    "policy_violation":   "Policy Violation",
    "indirect_injection": "Indirect Injection (LLM01)",
    "insecure_output":    "Insecure Output (LLM05)",
    "excessive_agency":   "Excessive Agency (LLM06)",
}
_ENTITY_LABEL = {
    "PERSON": "Person Names",
    "EMAIL":  "Email Addresses",
    "PHONE":  "Phone Numbers",
    "MONEY":  "Financial Amounts",
    "DATE":   "Dates",
    "ORG":    "Organisations",
    "ID":     "ID Numbers",
}


def _e(text: str) -> str:
    """HTML-escape helper."""
    return _html.escape(str(text))


def _bar(value: int, total: int, color: str) -> str:
    pct = round(value / total * 100) if total else 0
    return (
        f'<div style="background:#2d3748;border-radius:4px;height:10px;width:100%;">'
        f'<div style="background:{_e(color)};border-radius:4px;height:10px;'
        f'width:{pct}%;transition:width .3s;"></div></div>'
    )


def _kpi(label: str, value: str, sub: str = "", color: str = "#e2e8f0") -> str:
    return (
        f'<div class="kpi">'
        f'<div class="kpi-val" style="color:{_e(color)};">{_e(value)}</div>'
        f'<div class="kpi-lbl">{_e(label)}</div>'
        + (f'<div class="kpi-sub">{_e(sub)}</div>' if sub else "")
        + "</div>"
    )


def _recommendations(data: ReportData) -> list[str]:
    recs: list[str] = []
    if data.block_rate_pct >= 8:
        recs.append(
            "Block rate exceeds 8% — consider enabling strict mode and reviewing "
            "user AI access policies."
        )
    if data.flag_counts.get("prompt_injection", 0) > 5:
        recs.append(
            "Multiple prompt injection attempts detected. Ensure system prompts are "
            "protected and input validation is enforced."
        )
    if data.flag_counts.get("secret_detected", 0) > 0:
        recs.append(
            "Credential / secret leaks were intercepted this month. Audit internal "
            "API key management practices and rotate any exposed keys."
        )
    if data.entity_counts.get("PHONE", 0) > 10:
        recs.append(
            "High volume of phone number interceptions. Review whether AI workflows "
            "require access to contact data and apply data minimisation."
        )
    if data.entity_counts.get("MONEY", 0) > 10:
        recs.append(
            "Financial amounts were frequently intercepted. Confirm that financial "
            "data handling meets your DPA and internal data classification policy."
        )
    if not recs:
        recs.append(
            "Security posture is healthy this month. Continue monitoring and ensure "
            "incident response procedures are reviewed quarterly."
        )
    return recs


def _render_html(data: ReportData) -> str:  # noqa: C901
    posture_color = _POSTURE_COLOR.get(data.posture, "#e2e8f0")

    # ── Flags table rows ──────────────────────────────────────────────
    flags_rows = ""
    total_flags = sum(data.flag_counts.values()) or 1
    for flag, count in sorted(data.flag_counts.items(), key=lambda x: -x[1])[:10]:
        label = _FLAG_LABEL.get(flag, flag.replace("_", " ").title())
        flags_rows += (
            f"<tr><td>{_e(label)}</td><td style='text-align:right;font-weight:600;'>"
            f"{count}</td><td style='width:140px;padding-left:12px;'>"
            f"{_bar(count, total_flags, '#f97316')}</td></tr>"
        )
    if not flags_rows:
        flags_rows = "<tr><td colspan='3' style='color:#718096;'>No threats detected</td></tr>"

    # ── Entity table rows ─────────────────────────────────────────────
    entity_rows = ""
    total_entities = sum(data.entity_counts.values()) or 1
    for etype, count in sorted(data.entity_counts.items(), key=lambda x: -x[1]):
        label = _ENTITY_LABEL.get(etype, etype)
        entity_rows += (
            f"<tr><td>{_e(label)}</td><td style='text-align:right;font-weight:600;'>"
            f"{count}</td><td style='width:140px;padding-left:12px;'>"
            f"{_bar(count, total_entities, '#eab308')}</td></tr>"
        )
    if not entity_rows:
        entity_rows = "<tr><td colspan='3' style='color:#718096;'>No PII intercepted</td></tr>"

    # ── Risk breakdown rows ───────────────────────────────────────────
    risk_rows = ""
    total_risk = sum(data.risk_counts.values()) or 1
    for level in ("block", "high", "medium", "low"):
        count = data.risk_counts.get(level, 0)
        color = _RISK_COLOR.get(level, "#e2e8f0")
        risk_rows += (
            f"<tr><td style='color:{_e(color)};font-weight:600;'>"
            f"{_e(level.upper())}</td>"
            f"<td style='text-align:right;font-weight:600;'>{count}</td>"
            f"<td style='width:140px;padding-left:12px;'>"
            f"{_bar(count, total_risk, color)}</td></tr>"
        )

    # ── Daily table (last 14 days of month only, reverse-chrono) ─────
    daily_rows = ""
    for d in reversed(data.daily[-14:]):
        br = f"{d.blocked / d.requests * 100:.1f}%" if d.requests else "—"
        row_bg = "#2d1b1b" if d.blocked else ""
        daily_rows += (
            f"<tr style='background:{row_bg};'>"
            f"<td>{_e(d.date)}</td>"
            f"<td style='text-align:right;'>{d.requests}</td>"
            f"<td style='text-align:right;color:#fc8181;'>{d.blocked}</td>"
            f"<td style='text-align:right;color:#f6e05e;'>{d.masked}</td>"
            f"<td style='text-align:right;'>{br}</td></tr>"
        )
    if not daily_rows:
        daily_rows = "<tr><td colspan='5' style='color:#718096;'>No data</td></tr>"

    # ── Recommendations ───────────────────────────────────────────────
    recs_html = "".join(
        f"<li>{_e(r)}</li>" for r in _recommendations(data)
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Shadow Warden AI — Compliance Report — {_e(data.tenant_id)} — {_e(data.month)}</title>
<style>
  /* ── Base ── */
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, 'Helvetica Neue',
                 Arial, sans-serif;
    background: #0f1117;
    color: #e2e8f0;
    font-size: 13px;
    line-height: 1.6;
  }}
  .page {{ max-width: 900px; margin: 0 auto; padding: 0 24px 48px; }}

  /* ── Cover ── */
  .cover {{
    background: linear-gradient(135deg, #1a237e 0%, #0d47a1 50%, #1565c0 100%);
    border-radius: 12px;
    padding: 48px 40px;
    margin: 32px 0;
    position: relative;
    overflow: hidden;
  }}
  .cover::before {{
    content: '';
    position: absolute; top: -40px; right: -40px;
    width: 200px; height: 200px;
    border-radius: 50%;
    background: rgba(255,255,255,.05);
  }}
  .cover-badge {{
    display: inline-block;
    background: rgba(255,255,255,.15);
    border: 1px solid rgba(255,255,255,.3);
    border-radius: 20px;
    padding: 4px 14px;
    font-size: 11px;
    letter-spacing: .08em;
    text-transform: uppercase;
    color: #90caf9;
    margin-bottom: 20px;
  }}
  .cover h1 {{ font-size: 28px; font-weight: 700; color: #fff; margin-bottom: 8px; }}
  .cover h2 {{ font-size: 18px; font-weight: 400; color: #90caf9; margin-bottom: 28px; }}
  .cover-meta {{ font-size: 12px; color: rgba(255,255,255,.6); }}
  .cover-meta span {{ color: rgba(255,255,255,.85); }}

  /* ── Section ── */
  .section {{ margin: 32px 0; }}
  .section-title {{
    font-size: 14px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: .08em;
    color: #90caf9;
    border-bottom: 1px solid #2d3748;
    padding-bottom: 8px;
    margin-bottom: 20px;
  }}

  /* ── KPI grid ── */
  .kpi-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }}
  .kpi {{
    background: #1a1f2e;
    border: 1px solid #2d3748;
    border-radius: 10px;
    padding: 20px 18px;
    text-align: center;
  }}
  .kpi-val {{ font-size: 28px; font-weight: 700; margin-bottom: 4px; }}
  .kpi-lbl {{ font-size: 11px; color: #718096; text-transform: uppercase;
              letter-spacing: .06em; }}
  .kpi-sub {{ font-size: 11px; color: #a0aec0; margin-top: 4px; }}

  /* ── Posture banner ── */
  .posture-banner {{
    background: #1a1f2e;
    border: 2px solid {_e(posture_color)};
    border-radius: 10px;
    padding: 18px 24px;
    display: flex;
    align-items: center;
    gap: 20px;
    margin-top: 16px;
  }}
  .posture-dot {{
    width: 18px; height: 18px;
    border-radius: 50%;
    background: {_e(posture_color)};
    flex-shrink: 0;
    box-shadow: 0 0 8px {_e(posture_color)};
  }}
  .posture-label {{
    font-size: 18px;
    font-weight: 700;
    color: {_e(posture_color)};
  }}
  .posture-desc {{ font-size: 12px; color: #a0aec0; }}

  /* ── Tables ── */
  table {{ width: 100%; border-collapse: collapse; }}
  th {{
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .06em;
    color: #718096;
    border-bottom: 1px solid #2d3748;
    padding: 8px 10px;
    text-align: left;
  }}
  td {{ padding: 9px 10px; border-bottom: 1px solid #1a202c; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #1a2035; }}

  /* ── Two-col layout ── */
  .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }}
  .card {{
    background: #1a1f2e;
    border: 1px solid #2d3748;
    border-radius: 10px;
    padding: 20px;
  }}
  .card-title {{ font-size: 12px; font-weight: 600; color: #a0aec0;
                 text-transform: uppercase; letter-spacing: .06em;
                 margin-bottom: 14px; }}

  /* ── Recommendations ── */
  .recs {{
    background: #0d1b2a;
    border-left: 3px solid #3182ce;
    border-radius: 0 8px 8px 0;
    padding: 16px 20px;
  }}
  .recs ul {{ padding-left: 18px; }}
  .recs li {{ padding: 5px 0; color: #cbd5e0; font-size: 12.5px; }}

  /* ── Footer ── */
  .footer {{
    text-align: center;
    color: #4a5568;
    font-size: 11px;
    border-top: 1px solid #2d3748;
    padding-top: 20px;
    margin-top: 40px;
  }}

  /* ── Print ── */
  @media print {{
    body {{ background: #fff; color: #1a202c; }}
    .cover {{ background: #1565c0; -webkit-print-color-adjust: exact; }}
    .kpi, .card, .posture-banner, .recs {{ background: #f7fafc !important; }}
    .section-title {{ color: #2b6cb0; }}
    .cover-meta, .posture-desc {{ color: #4a5568; }}
    a {{ color: #2b6cb0; }}
  }}
</style>
</head>
<body>
<div class="page">

  <!-- ── Cover ── -->
  <div class="cover">
    <div class="cover-badge">Monthly Security Compliance Report</div>
    <h1>Shadow Warden AI</h1>
    <h2>{_e(data.month_label)} · {_e(data.tenant_id)}</h2>
    <div class="cover-meta">
      Generated: <span>{_e(data.generated_at)}</span> &nbsp;|&nbsp;
      Period: <span>{_e(data.month)}-01 → {_e(data.month)}-{calendar.monthrange(*map(int, data.month.split("-")))[1]:02d}</span>
      &nbsp;|&nbsp; Confidential — for authorised recipients only
    </div>
  </div>

  <!-- ── Executive Summary ── -->
  <div class="section">
    <div class="section-title">Executive Summary</div>
    <div class="kpi-grid">
      {_kpi("Requests Processed", f"{data.total_requests:,}")}
      {_kpi("Threats Blocked", f"{data.total_blocked:,}",
            f"{data.block_rate_pct}% block rate",
            "#fc8181" if data.total_blocked else "#22c55e")}
      {_kpi("Requests Allowed", f"{data.total_allowed:,}")}
      {_kpi("PII Intercepts", f"{data.total_masked:,}",
            "entity occurrences masked", "#f6e05e" if data.total_masked else "#e2e8f0")}
      {_kpi("Attack Cost Deflected", f"${data.attack_cost_usd:.4f}",
            "est. LLM token cost", "#68d391")}
      {_kpi("Security Posture", data.posture_label, data.posture,
            posture_color)}
    </div>
    <div class="posture-banner">
      <div class="posture-dot"></div>
      <div>
        <div class="posture-label">{_e(data.posture)} — {_e(data.posture_label)}</div>
        <div class="posture-desc">
          {"Block rate is below 2% — environment is secure." if data.posture == "GREEN" else
           "Block rate is between 2–8% — continue monitoring for escalation." if data.posture == "YELLOW" else
           "Block rate exceeds 8% — elevated threat activity detected. Immediate review recommended."}
        </div>
      </div>
    </div>
  </div>

  <!-- ── Threat Intelligence + Data Protection ── -->
  <div class="section">
    <div class="section-title">Threat Intelligence &amp; Data Protection</div>
    <div class="two-col">
      <div class="card">
        <div class="card-title">🔴 Top Threat Types</div>
        <table>
          <thead><tr><th>Attack Type</th><th style="text-align:right;">Count</th>
          <th style="width:140px;"></th></tr></thead>
          <tbody>{flags_rows}</tbody>
        </table>
      </div>
      <div class="card">
        <div class="card-title">🟡 PII Entity Types Intercepted</div>
        <table>
          <thead><tr><th>Entity Type</th><th style="text-align:right;">Count</th>
          <th style="width:140px;"></th></tr></thead>
          <tbody>{entity_rows}</tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- ── Risk Level Breakdown ── -->
  <div class="section">
    <div class="section-title">Risk Level Breakdown</div>
    <div class="card">
      <table>
        <thead><tr><th>Risk Level</th><th style="text-align:right;">Requests</th>
        <th style="width:200px;"></th></tr></thead>
        <tbody>{risk_rows}</tbody>
      </table>
    </div>
  </div>

  <!-- ── Daily Activity (last 14 days) ── -->
  <div class="section">
    <div class="section-title">Daily Activity — Last 14 Days of Period</div>
    <div class="card">
      <table>
        <thead><tr>
          <th>Date</th>
          <th style="text-align:right;">Requests</th>
          <th style="text-align:right;color:#fc8181;">Blocked</th>
          <th style="text-align:right;color:#f6e05e;">Masked</th>
          <th style="text-align:right;">Block Rate</th>
        </tr></thead>
        <tbody>{daily_rows}</tbody>
      </table>
    </div>
  </div>

  <!-- ── Recommendations ── -->
  <div class="section">
    <div class="section-title">Recommendations</div>
    <div class="recs">
      <ul>{recs_html}</ul>
    </div>
  </div>

  <!-- ── Footer ── -->
  <div class="footer">
    <strong>Shadow Warden AI</strong> — AI Security Gateway &nbsp;|&nbsp;
    Report generated {_e(data.generated_at)} &nbsp;|&nbsp;
    Tenant: {_e(data.tenant_id)} &nbsp;|&nbsp; Period: {_e(data.month)}<br>
    <em>This document contains security-sensitive information.
    Handle in accordance with your organisation's data classification policy.</em>
  </div>

</div>
</body>
</html>"""
