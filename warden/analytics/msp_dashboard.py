"""
Shadow Warden AI — MSP Single Pane of Glass
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Run with:
    streamlit run analytics/msp_dashboard.py

Shows all client tenants in one real-time view:
  • Fleet KPIs          — Blocked 🔴 / Masked 🟡 / Active Clients / Cost
  • Audit Log           — unified timeline of Red + Yellow zone events (last 30)
  • Data Class Donut    — what PII types were intercepted across the fleet
  • Per-Tenant Table    — requests, blocked, masked entities, quota
  • Provision Section   — one-click PowerShell script for RMM deployment
  • 30-Day Trend        — requests + blocked + masked entities over time

Reads from:
  • GET /msp/overview   (Warden gateway API — fleet stats)
  • LOGS_PATH           (NDJSON log file — raw events for audit log & charts)
"""
from __future__ import annotations

import os
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import requests
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from warden.analytics.logger import load_entries

# ── Config ────────────────────────────────────────────────────────────────────

_GATEWAY  = os.getenv("GATEWAY_URL",    "http://localhost:8001").rstrip("/")
_API_KEY  = os.getenv("WARDEN_API_KEY", "")
_REFRESH  = 30   # seconds

st.set_page_config(
    page_title="Shadow Warden — MSP Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Dark CSS ──────────────────────────────────────────────────────────────────

st.markdown("""
<style>
  .kpi-card {
    background: #1a1f2e;
    border: 1px solid #2d3748;
    border-radius: 10px;
    padding: 18px 22px;
    text-align: center;
  }
  .kpi-value { font-size: 2.2rem; font-weight: 700; color: #e2e8f0; }
  .kpi-label { font-size: 0.78rem; color: #718096; letter-spacing: .06em;
                text-transform: uppercase; margin-top: 4px; }
  .kpi-red    .kpi-value { color: #fc8181; }
  .kpi-green  .kpi-value { color: #68d391; }
  .kpi-yellow .kpi-value { color: #f6e05e; }
  .kpi-blue   .kpi-value { color: #63b3ed; }

  .section-hdr {
    font-size: 0.84rem; font-weight: 600; color: #a0aec0;
    letter-spacing: .1em; text-transform: uppercase;
    margin: 1.4rem 0 .5rem;
  }

  /* Unified audit log items */
  .audit-item {
    border-radius: 4px;
    padding: 6px 12px;
    margin-bottom: 5px;
    font-size: 0.82rem;
    color: #e2e8f0;
    line-height: 1.4;
  }
  .audit-red    { background:#2d1a1a; border-left: 3px solid #fc8181; }
  .audit-yellow { background:#2d2a1a; border-left: 3px solid #f6e05e; }
  .audit-green  { background:#1a2d1a; border-left: 3px solid #68d391; }
  .audit-ts     { color:#718096; font-size:0.75rem; }
  .audit-zone   { font-weight:700; margin: 0 6px; }
  .zone-red     { color:#fc8181; }
  .zone-yellow  { color:#f6e05e; }
  .zone-green   { color:#68d391; }

  .provision-box {
    background: #1a1f2e;
    border: 1px solid #2d3748;
    border-radius: 8px;
    padding: 16px 20px;
  }
</style>
""", unsafe_allow_html=True)

# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("### 🛡️ Shadow Warden AI")
    st.caption("MSP Single Pane of Glass")
    st.divider()

    gateway_url = st.text_input("Gateway URL", value=_GATEWAY)
    api_key_val = st.text_input("API Key", value=_API_KEY, type="password")

    st.divider()
    auto_refresh = st.toggle("Auto-refresh (30 s)", value=True)
    if st.button("🔄  Refresh now", use_container_width=True):
        st.rerun()

    st.divider()
    st.caption(f"Last refresh: {datetime.now(UTC).strftime('%H:%M:%S UTC')}")

# ── Fetch MSP overview ────────────────────────────────────────────────────────

@st.cache_data(ttl=_REFRESH)
def _fetch_overview(url: str, key: str) -> dict | None:
    try:
        r = requests.get(
            f"{url}/msp/overview",
            headers={"X-API-Key": key} if key else {},
            timeout=6,
        )
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        return {"_error": str(exc)}


overview = _fetch_overview(gateway_url, api_key_val)

if overview is None or "_error" in (overview or {}):
    err = (overview or {}).get("_error", "Cannot connect")
    st.error(f"Cannot reach gateway at `{gateway_url}` — {err}")
    st.info("Set `GATEWAY_URL` and `WARDEN_API_KEY` env vars, or edit the sidebar.")
    st.stop()

fleet   = overview.get("fleet", {})
tenants = overview.get("tenants", [])
month   = overview.get("month", datetime.now(UTC).strftime("%Y-%m"))

# ── Fleet KPI row — Red + Yellow side by side ─────────────────────────────────

st.markdown(f"## MSP Dashboard — {month}")

c1, c2, c3, c4, c5, c6 = st.columns(6)
_kpis = [
    (c1, str(fleet.get("tenants", 0)),
     "Active Clients",       "kpi-green"),
    (c2, f"{fleet.get('requests', 0):,}",
     "Requests This Month",  "kpi-blue"),
    (c3, f"{fleet.get('blocked', 0):,}",
     "🔴 Blocked",           "kpi-red"),
    (c4, f"{fleet.get('masked_entities', 0):,}",
     "🟡 Entities Masked",   "kpi-yellow"),
    (c5, f"{fleet.get('block_rate', 0)*100:.1f}%",
     "Block Rate",           ""),
    (c6, f"${fleet.get('cost_usd', 0):.4f}",
     "Token Cost (USD)",     ""),
]
for col, val, label, cls in _kpis:
    with col:
        st.markdown(
            f'<div class="kpi-card {cls}">'
            f'<div class="kpi-value">{val}</div>'
            f'<div class="kpi-label">{label}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

st.markdown("")

# ── Unified Audit Log + Data Class Donut ─────────────────────────────────────

st.markdown('<div class="section-hdr">Unified Audit Log — Last 7 Days</div>',
            unsafe_allow_html=True)

@st.cache_data(ttl=_REFRESH)
def _load_recent() -> list[dict]:
    return load_entries(days=7)

entries_7 = _load_recent()
# Sort newest first
entries_7_sorted = sorted(entries_7, key=lambda e: e.get("ts", ""), reverse=True)

col_log, col_charts = st.columns([3, 2])

with col_log:
    shown = 0
    for ev in entries_7_sorted:
        if shown >= 30:
            break
        ts        = ev.get("ts", "")[:19].replace("T", " ")
        tenant    = ev.get("tenant_id", "default")
        allowed   = ev.get("allowed", True)
        risk      = ev.get("risk_level", "low").upper()
        flags     = ev.get("flags", [])
        secrets   = ev.get("secrets_found", [])
        entities  = ev.get("entities_detected", [])
        ec        = ev.get("entity_count", 0)

        if not allowed:
            # RED ZONE — blocked
            zone_cls  = "audit-red"
            zone_html = '<span class="audit-zone zone-red">RED</span>'
            detail    = " · ".join(flags or secrets or [f"risk:{risk}"])
            desc      = f"{detail}"
        elif ec > 0:
            # YELLOW ZONE — PII entities detected (masked or could be masked)
            zone_cls  = "audit-yellow"
            zone_html = '<span class="audit-zone zone-yellow">YELLOW</span>'
            types_str = ", ".join(sorted(set(entities)))
            desc      = f"{ec} entit{'y' if ec == 1 else 'ies'} detected: {types_str}"
        else:
            # GREEN ZONE — clean pass
            continue   # don't clutter the log with boring clean requests

        st.markdown(
            f'<div class="audit-item {zone_cls}">'
            f'<span class="audit-ts">{ts}</span>'
            f'{zone_html}'
            f'<b>{tenant}</b> — {desc}'
            f'</div>',
            unsafe_allow_html=True,
        )
        shown += 1

    if shown == 0:
        st.success("No blocked or PII-detected events in the last 7 days. Fleet is clean. ✅")

with col_charts:
    # ── Data class donut ────────────────────────────────────────────────────
    top_entities = fleet.get("top_entities", {})
    if top_entities:
        entity_labels = list(top_entities.keys())
        entity_values = list(top_entities.values())
        _ENTITY_COLORS = {
            "PERSON": "#f6e05e",
            "MONEY":  "#68d391",
            "EMAIL":  "#63b3ed",
            "DATE":   "#b794f4",
            "ORG":    "#fc8181",
            "PHONE":  "#fbd38d",
            "ID":     "#76e4f7",
        }
        colors = [_ENTITY_COLORS.get(lbl, "#a0aec0") for lbl in entity_labels]
        fig_entity = go.Figure(go.Pie(
            labels=entity_labels,
            values=entity_values,
            hole=0.52,
            marker_colors=colors,
            textinfo="label+percent",
        ))
        fig_entity.update_layout(
            paper_bgcolor="#0f1117",
            font_color="#e2e8f0",
            showlegend=False,
            margin=dict(l=10, r=10, t=40, b=10),
            title=dict(text="🟡 PII Entity Types Detected", font_color="#a0aec0", font_size=13),
            height=280,
        )
        st.plotly_chart(fig_entity, use_container_width=True)

    # ── Risk donut ──────────────────────────────────────────────────────────
    block_events = [e for e in entries_7 if not e.get("allowed", True)]
    risk_counts: dict[str, int] = {}
    for ev in block_events:
        r = ev.get("risk_level", "unknown").upper()
        risk_counts[r] = risk_counts.get(r, 0) + 1

    if risk_counts:
        fig_risk = go.Figure(go.Pie(
            labels=list(risk_counts.keys()),
            values=list(risk_counts.values()),
            hole=0.52,
            marker_colors=["#fc8181", "#f6e05e", "#68d391", "#a0aec0"],
        ))
        fig_risk.update_layout(
            paper_bgcolor="#0f1117",
            font_color="#e2e8f0",
            showlegend=True,
            margin=dict(l=10, r=10, t=40, b=10),
            title=dict(text="🔴 Block Events by Risk", font_color="#a0aec0", font_size=13),
            height=250,
        )
        st.plotly_chart(fig_risk, use_container_width=True)


# ── Per-tenant table ───────────────────────────────────────────────────────────

st.markdown('<div class="section-hdr">Per-Client Breakdown</div>', unsafe_allow_html=True)

if tenants:
    df_t = pd.DataFrame(tenants)
    display_cols = {
        "tenant_id":       "Tenant ID",
        "label":           "Company",
        "plan":            "Plan",
        "active":          "Active",
        "requests":        "Requests",
        "blocked":         "🔴 Blocked",
        "masked_entities": "🟡 Masked",
        "block_rate":      "Block Rate",
        "cost_usd":        "Cost (USD)",
        "quota_usd":       "Quota (USD)",
        "quota_pct":       "Quota Used %",
    }
    df_disp = df_t[[c for c in display_cols if c in df_t.columns]].rename(columns=display_cols)

    if "Block Rate" in df_disp.columns:
        df_disp["Block Rate"] = df_disp["Block Rate"].apply(lambda x: f"{x*100:.1f}%")
    if "Cost (USD)" in df_disp.columns:
        df_disp["Cost (USD)"] = df_disp["Cost (USD)"].apply(lambda x: f"${x:.6f}")
    if "Quota Used %" in df_disp.columns:
        df_disp["Quota Used %"] = df_disp["Quota Used %"].apply(
            lambda x: f"{x:.1f}%" if x is not None else "—"
        )
    if "Quota (USD)" in df_disp.columns:
        df_disp["Quota (USD)"] = df_disp["Quota (USD)"].apply(
            lambda x: f"${x:.2f}" if x is not None else "Unlimited"
        )

    st.dataframe(df_disp, use_container_width=True, hide_index=True)

    # ── Block rate + masked entities bar chart ──────────────────────────────
    st.markdown('<div class="section-hdr">Block Rate & Masked Entities by Client</div>',
                unsafe_allow_html=True)
    df_chart = pd.DataFrame([
        {
            "Company":  t.get("label", t["tenant_id"]),
            "Blocked":  t.get("blocked", 0),
            "Masked":   t.get("masked_entities", 0),
        }
        for t in tenants if t.get("requests", 0) > 0
    ])
    if not df_chart.empty and (df_chart["Blocked"].sum() + df_chart["Masked"].sum()) > 0:
        fig_stacked = go.Figure()
        fig_stacked.add_trace(go.Bar(
            name="🔴 Blocked",
            x=df_chart["Company"],
            y=df_chart["Blocked"],
            marker_color="#fc8181",
        ))
        fig_stacked.add_trace(go.Bar(
            name="🟡 Masked Entities",
            x=df_chart["Company"],
            y=df_chart["Masked"],
            marker_color="#f6e05e",
        ))
        fig_stacked.update_layout(
            paper_bgcolor="#0f1117",
            plot_bgcolor="#0f1117",
            font_color="#e2e8f0",
            barmode="group",
            height=280,
            margin=dict(l=10, r=10, t=20, b=40),
            legend=dict(orientation="h", yanchor="bottom", y=1.02),
            xaxis=dict(gridcolor="#2d3748"),
            yaxis=dict(gridcolor="#2d3748"),
        )
        st.plotly_chart(fig_stacked, use_container_width=True)

else:
    st.info("No tenants yet. Deploy your first client with `POST /onboard`.")


# ── Provision section — RMM one-click ────────────────────────────────────────

st.markdown('<div class="section-hdr">Provision New Client</div>', unsafe_allow_html=True)

with st.container():
    st.markdown('<div class="provision-box">', unsafe_allow_html=True)

    col_p1, col_p2, col_p3 = st.columns(3)
    with col_p1:
        prov_company = st.text_input("Company Name", placeholder="Riverside Dental")
    with col_p2:
        prov_email   = st.text_input("Contact Email", placeholder="it@riverside.com")
    with col_p3:
        prov_plan    = st.selectbox("Plan", ["starter", "professional", "enterprise"])

    col_g, col_k = st.columns([2, 1])
    with col_g:
        prov_gateway = st.text_input("Gateway URL", value=gateway_url, key="prov_gw")
    with col_k:
        prov_msp_key = st.text_input("MSP API Key", value=api_key_val, type="password", key="prov_key")

    if prov_company and prov_email:
        _safe_company = prov_company.replace('"', '').replace("'", "")
        _safe_email   = prov_email.replace('"', '').replace("'", "")
        _ps1_cmd = (
            f'.\\deploy\\Invoke-WardenProvision.ps1 '
            f'-GatewayUrl "{prov_gateway}" '
            f'-MspApiKey $env:MSP_WARDEN_KEY '
            f'-CompanyName "{_safe_company}" '
            f'-ContactEmail "{_safe_email}" '
            f'-Plan {prov_plan}'
        )
        _sh_cmd = (
            f'GATEWAY_URL="{prov_gateway}" '
            f'MSP_API_KEY="$MSP_WARDEN_KEY" '
            f'COMPANY_NAME="{_safe_company}" '
            f'CONTACT_EMAIL="{_safe_email}" '
            f'PLAN="{prov_plan}" '
            f'bash deploy/invoke-warden-provision.sh'
        )
        st.caption("Windows RMM (PowerShell):")
        st.code(_ps1_cmd, language="powershell")
        st.caption("macOS / Linux RMM (Bash):")
        st.code(_sh_cmd, language="bash")
    else:
        st.caption("Fill in Company Name and Contact Email to generate the deployment script.")

    st.markdown('</div>', unsafe_allow_html=True)


# ── 30-day trend ──────────────────────────────────────────────────────────────

st.markdown('<div class="section-hdr">30-Day Fleet Trend — Blocked + Masked Entities</div>',
            unsafe_allow_html=True)

@st.cache_data(ttl=_REFRESH)
def _load_30() -> list[dict]:
    return load_entries(days=30)

entries_30 = _load_30()
if entries_30:
    df_all = pd.DataFrame(entries_30)
    df_all["date"]   = pd.to_datetime(df_all["ts"], utc=True).dt.date
    df_all["is_blocked"] = ~df_all["allowed"].astype(bool)
    df_all["entities"]   = df_all.get("entity_count", 0) if "entity_count" in df_all.columns else 0

    daily_fleet = (
        df_all.groupby("date")
        .agg(
            requests  = ("allowed",    "count"),
            blocked   = ("is_blocked", "sum"),
            masked    = ("entities",   "sum"),
        )
        .reset_index()
    )
    daily_fleet["block_rate_pct"] = (
        daily_fleet["blocked"] / daily_fleet["requests"].clip(lower=1) * 100
    )

    fig_trend = go.Figure()
    fig_trend.add_trace(go.Bar(
        x=daily_fleet["date"], y=daily_fleet["requests"],
        name="Requests", marker_color="#4299e1", opacity=0.5,
    ))
    fig_trend.add_trace(go.Bar(
        x=daily_fleet["date"], y=daily_fleet["blocked"],
        name="🔴 Blocked", marker_color="#fc8181",
    ))
    fig_trend.add_trace(go.Bar(
        x=daily_fleet["date"], y=daily_fleet["masked"],
        name="🟡 Masked Entities", marker_color="#f6e05e", opacity=0.8,
    ))
    fig_trend.add_trace(go.Scatter(
        x=daily_fleet["date"], y=daily_fleet["block_rate_pct"],
        name="Block Rate %", yaxis="y2",
        line=dict(color="#fc8181", width=2, dash="dot"),
        mode="lines+markers",
    ))
    fig_trend.update_layout(
        paper_bgcolor="#0f1117",
        plot_bgcolor="#0f1117",
        font_color="#e2e8f0",
        barmode="overlay",
        height=340,
        margin=dict(l=10, r=80, t=20, b=40),
        legend=dict(orientation="h", yanchor="bottom", y=1.02),
        xaxis=dict(gridcolor="#2d3748"),
        yaxis=dict(title="Count", gridcolor="#2d3748"),
        yaxis2=dict(
            title="Block Rate %",
            overlaying="y",
            side="right",
            gridcolor="#2d3748",
            range=[0, max(daily_fleet["block_rate_pct"].max() * 1.5, 20)],
        ),
    )
    st.plotly_chart(fig_trend, use_container_width=True)
else:
    st.info("No data for the past 30 days yet.")


# ── Monthly Compliance Reports ────────────────────────────────────────────────

st.divider()
st.subheader("📥 Monthly Compliance Reports")

with st.expander("Generate & Download Report", expanded=False):
    _col_tenant, _col_month, _col_fmt = st.columns([2, 1, 1])

    with _col_tenant:
        _all_tenant_ids = [t["tenant_id"] for t in (overview.get("tenants") or [])]
        _report_tenant = st.selectbox(
            "Tenant",
            options=_all_tenant_ids or ["default"],
            key="report_tenant",
        )

    with _col_month:
        _now_dt = datetime.now(UTC)
        # Build last 12 months
        _month_opts = [
            (_now_dt - timedelta(days=30 * i)).strftime("%Y-%m")
            for i in range(12)
        ]
        _report_month = st.selectbox("Month", options=_month_opts, key="report_month")

    with _col_fmt:
        _report_fmt = st.radio("Format", options=["HTML", "JSON"], horizontal=True,
                               key="report_fmt")

    if st.button("Generate Report", type="primary"):
        _fmt_param = _report_fmt.lower()
        _report_url = (
            f"{gateway_url}/msp/report/{_report_tenant}"
            f"?month={_report_month}&fmt={_fmt_param}"
        )
        try:
            _headers = {"X-API-Key": _API_KEY} if _API_KEY else {}
            _resp = requests.get(_report_url, headers=_headers, timeout=15)
            _resp.raise_for_status()

            if _fmt_param == "html":
                _filename  = f"warden-report-{_report_tenant}-{_report_month}.html"
                _mime      = "text/html"
                _data      = _resp.content
                _open_hint = "💡 Open in browser → File → Print → Save as PDF"
            else:
                _filename  = f"warden-report-{_report_tenant}-{_report_month}.json"
                _mime      = "application/json"
                _data      = _resp.content
                _open_hint = ""

            st.download_button(
                label    = f"⬇️ Download {_filename}",
                data     = _data,
                file_name= _filename,
                mime     = _mime,
            )
            if _open_hint:
                st.caption(_open_hint)

        except Exception as _exc:
            st.error(f"Failed to generate report: {_exc}")

    st.caption(
        "Reports summarise threats blocked, PII intercepted, risk levels, "
        "and security recommendations for the selected tenant and month."
    )


# ── Footer ────────────────────────────────────────────────────────────────────

st.divider()
st.caption(
    f"Shadow Warden AI — MSP Dashboard · "
    f"Gateway: `{gateway_url}` · "
    f"Updated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}"
)

if auto_refresh:
    time.sleep(_REFRESH)
    st.rerun()
