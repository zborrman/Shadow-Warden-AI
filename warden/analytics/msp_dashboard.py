"""
Shadow Warden AI — MSP Sales Dashboard
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Run with:
    streamlit run warden/analytics/msp_dashboard.py

Or as a page inside the existing dashboard (pages/ multi-page mode).

Shows all client tenants in one real-time view:
  • Fleet KPIs — total requests, blocks, cost this month
  • Per-tenant table — sortable, color-coded by block rate
  • Live threat feed — last 50 block events across all tenants
  • Block rate trend chart — last 30 days per tenant

Reads data from:
  • GET /msp/overview  (Warden gateway API)
  • LOGS_PATH          (NDJSON log file, for the threat feed)
"""
from __future__ import annotations

import os
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from warden.analytics.logger import LOGS_PATH, load_entries

# ── Config ────────────────────────────────────────────────────────────────────

_GATEWAY = os.getenv("GATEWAY_URL", "http://localhost:8001").rstrip("/")
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
  .kpi-value { font-size: 2.4rem; font-weight: 700; color: #e2e8f0; }
  .kpi-label { font-size: 0.8rem; color: #718096; letter-spacing: .06em;
                text-transform: uppercase; margin-top: 4px; }
  .kpi-red   .kpi-value { color: #fc8181; }
  .kpi-green .kpi-value { color: #68d391; }
  .kpi-yellow .kpi-value { color: #f6e05e; }

  .section-hdr {
    font-size: 0.85rem; font-weight: 600; color: #a0aec0;
    letter-spacing: .1em; text-transform: uppercase;
    margin: 1.4rem 0 .5rem;
  }
  .alert-item {
    background: #2d1a1a;
    border-left: 3px solid #fc8181;
    border-radius: 4px;
    padding: 6px 12px;
    margin-bottom: 6px;
    font-size: 0.82rem;
    color: #e2e8f0;
  }
  .alert-item.yellow {
    background: #2d2a1a;
    border-left-color: #f6e05e;
  }
</style>
""", unsafe_allow_html=True)

# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("### 🛡️ Shadow Warden AI")
    st.caption("MSP Operations Dashboard")
    st.divider()

    gateway_url = st.text_input("Gateway URL", value=_GATEWAY)
    api_key_val = st.text_input("API Key", value=_API_KEY, type="password")

    st.divider()
    auto_refresh = st.toggle("Auto-refresh (30 s)", value=True)
    if st.button("🔄  Refresh now", use_container_width=True):
        st.rerun()

    st.divider()
    st.caption(f"Last refresh: {datetime.now(UTC).strftime('%H:%M:%S UTC')}")

# ── Fetch MSP overview from API ───────────────────────────────────────────────

@st.cache_data(ttl=_REFRESH)
def _fetch_overview(url: str, key: str) -> dict | None:
    try:
        r = requests.get(
            f"{url}/msp/overview",
            headers={"X-API-Key": key} if key else {},
            timeout=5,
        )
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        return {"_error": str(exc)}


overview = _fetch_overview(gateway_url, api_key_val)

if overview is None or "_error" in (overview or {}):
    err = (overview or {}).get("_error", "Unknown error")
    st.error(f"Cannot reach Warden gateway at `{gateway_url}` — {err}")
    st.info("Set `GATEWAY_URL` and `WARDEN_API_KEY` environment variables, "
            "or edit the fields in the sidebar.")
    st.stop()

fleet   = overview.get("fleet", {})
tenants = overview.get("tenants", [])
month   = overview.get("month", datetime.now(UTC).strftime("%Y-%m"))

# ── Fleet KPI row ─────────────────────────────────────────────────────────────

st.markdown(f"## MSP Overview — {month}")

c1, c2, c3, c4, c5 = st.columns(5)
_kpis = [
    (c1, str(fleet.get("tenants", 0)),   "Active Clients",     "kpi-green"),
    (c2, f"{fleet.get('requests', 0):,}", "Requests This Month", ""),
    (c3, f"{fleet.get('blocked', 0):,}",  "Blocked",            "kpi-red"),
    (c4, f"{fleet.get('block_rate', 0)*100:.1f}%", "Block Rate", "kpi-yellow"),
    (c5, f"${fleet.get('cost_usd', 0):.4f}", "Token Cost",      ""),
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

st.markdown("")   # spacer

# ── Per-tenant table ───────────────────────────────────────────────────────────

st.markdown('<div class="section-hdr">Per-Client Breakdown</div>', unsafe_allow_html=True)

if tenants:
    df_t = pd.DataFrame(tenants)

    # Friendly column order + rename
    display_cols = {
        "tenant_id":  "Tenant ID",
        "label":      "Company",
        "plan":       "Plan",
        "active":     "Active",
        "requests":   "Requests",
        "blocked":    "Blocked",
        "block_rate": "Block Rate",
        "cost_usd":   "Cost (USD)",
        "quota_usd":  "Quota (USD)",
        "quota_pct":  "Quota Used %",
    }
    df_disp = df_t[[c for c in display_cols if c in df_t.columns]].rename(columns=display_cols)

    # Format numeric columns
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

    st.dataframe(
        df_disp,
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info("No tenants found. Create your first tenant with `POST /onboard`.")

# ── Block rate bar chart ───────────────────────────────────────────────────────

if tenants:
    st.markdown('<div class="section-hdr">Block Rate by Client</div>', unsafe_allow_html=True)
    df_chart = pd.DataFrame([
        {
            "Company": t.get("label", t["tenant_id"]),
            "Block Rate %": round(t.get("block_rate", 0) * 100, 2),
            "Requests": t.get("requests", 0),
        }
        for t in tenants if t.get("requests", 0) > 0
    ])
    if not df_chart.empty:
        fig = px.bar(
            df_chart.sort_values("Block Rate %", ascending=True),
            x="Block Rate %",
            y="Company",
            orientation="h",
            color="Block Rate %",
            color_continuous_scale=["#22543d", "#f6e05e", "#fc8181"],
            range_color=[0, max(df_chart["Block Rate %"].max(), 10)],
            text="Block Rate %",
            custom_data=["Requests"],
        )
        fig.update_traces(
            texttemplate="%{text:.1f}%",
            textposition="outside",
            hovertemplate="<b>%{y}</b><br>Block Rate: %{x:.1f}%<br>Requests: %{customdata[0]:,}",
        )
        fig.update_layout(
            paper_bgcolor="#0f1117",
            plot_bgcolor="#0f1117",
            font_color="#e2e8f0",
            height=max(250, len(df_chart) * 40 + 80),
            margin=dict(l=10, r=80, t=20, b=20),
            showlegend=False,
            coloraxis_showscale=False,
            xaxis=dict(gridcolor="#2d3748", range=[0, max(df_chart["Block Rate %"].max() * 1.3, 15)]),
            yaxis=dict(gridcolor="#2d3748"),
        )
        st.plotly_chart(fig, use_container_width=True)

# ── Live threat feed ──────────────────────────────────────────────────────────

st.markdown('<div class="section-hdr">Live Threat Feed — Last 50 Block Events</div>',
            unsafe_allow_html=True)

entries = load_entries(days=7)
block_events = [e for e in entries if not e.get("allowed", True)]
block_events = sorted(block_events, key=lambda e: e.get("ts", ""), reverse=True)[:50]

if block_events:
    col_feed, col_pie = st.columns([3, 2])

    with col_feed:
        for ev in block_events[:20]:
            ts        = ev.get("ts", "")[:19].replace("T", " ")
            tenant    = ev.get("tenant_id", "default")
            risk      = ev.get("risk_level", "?").upper()
            flags     = ", ".join(ev.get("flags", []))
            secrets   = ", ".join(ev.get("secrets_found", []))
            data_cls  = ev.get("data_class", "")
            cls_html  = "yellow" if data_cls == "yellow" else ""
            label     = f"[{risk}] {tenant} — {flags or secrets or data_cls or 'blocked'}"
            st.markdown(
                f'<div class="alert-item {cls_html}">'
                f'<span style="color:#718096">{ts}</span> &nbsp; {label}'
                f'</div>',
                unsafe_allow_html=True,
            )

    with col_pie:
        # Risk level distribution
        risk_counts: dict[str, int] = {}
        for ev in block_events:
            r = ev.get("risk_level", "unknown").upper()
            risk_counts[r] = risk_counts.get(r, 0) + 1

        if risk_counts:
            fig_pie = go.Figure(go.Pie(
                labels=list(risk_counts.keys()),
                values=list(risk_counts.values()),
                hole=0.5,
                marker_colors=["#fc8181", "#f6e05e", "#68d391", "#a0aec0"],
            ))
            fig_pie.update_layout(
                paper_bgcolor="#0f1117",
                font_color="#e2e8f0",
                showlegend=True,
                margin=dict(l=10, r=10, t=30, b=10),
                title=dict(text="Block Events by Risk", font_color="#a0aec0"),
                height=280,
            )
            st.plotly_chart(fig_pie, use_container_width=True)

        # Top flagged tenants
        tenant_block_counts: dict[str, int] = {}
        for ev in block_events:
            tid = ev.get("tenant_id", "default")
            tenant_block_counts[tid] = tenant_block_counts.get(tid, 0) + 1

        if len(tenant_block_counts) > 1:
            df_tbc = pd.DataFrame(
                [{"Tenant": k, "Blocks": v} for k, v in
                 sorted(tenant_block_counts.items(), key=lambda x: -x[1])]
            )
            fig_bar = px.bar(
                df_tbc, x="Tenant", y="Blocks",
                color="Blocks",
                color_continuous_scale=["#22543d", "#fc8181"],
            )
            fig_bar.update_layout(
                paper_bgcolor="#0f1117",
                plot_bgcolor="#0f1117",
                font_color="#e2e8f0",
                height=200,
                margin=dict(l=10, r=10, t=30, b=30),
                showlegend=False,
                coloraxis_showscale=False,
                title=dict(text="Blocks per Tenant", font_color="#a0aec0"),
                xaxis=dict(gridcolor="#2d3748"),
                yaxis=dict(gridcolor="#2d3748"),
            )
            st.plotly_chart(fig_bar, use_container_width=True)

else:
    st.info("No block events in the last 7 days. The fleet is clean. ✅")

# ── 30-day trend (all tenants combined) ──────────────────────────────────────

st.markdown('<div class="section-hdr">30-Day Block Trend — All Clients</div>',
            unsafe_allow_html=True)

entries_30 = load_entries(days=30)
if entries_30:
    df_all = pd.DataFrame(entries_30)
    df_all["date"] = pd.to_datetime(df_all["ts"], utc=True).dt.date
    daily = (
        df_all.groupby(["date", df_all.get("tenant_id", "default") if "tenant_id" in df_all.columns else "date"])
        .agg(requests=("allowed", "count"), blocked=("allowed", lambda x: (~x).sum()))
        .reset_index()
    )
    # Simpler: just aggregate by date for the fleet view
    daily_fleet = (
        df_all.groupby("date")
        .agg(requests=("allowed", "count"), blocked=("allowed", lambda x: (~x).sum()))
        .reset_index()
    )
    daily_fleet["block_rate_pct"] = daily_fleet["blocked"] / daily_fleet["requests"] * 100

    fig_trend = go.Figure()
    fig_trend.add_trace(go.Bar(
        x=daily_fleet["date"], y=daily_fleet["requests"],
        name="Requests", marker_color="#4299e1", opacity=0.6,
    ))
    fig_trend.add_trace(go.Bar(
        x=daily_fleet["date"], y=daily_fleet["blocked"],
        name="Blocked", marker_color="#fc8181",
    ))
    fig_trend.add_trace(go.Scatter(
        x=daily_fleet["date"], y=daily_fleet["block_rate_pct"],
        name="Block Rate %", yaxis="y2", line=dict(color="#f6e05e", width=2),
        mode="lines+markers",
    ))
    fig_trend.update_layout(
        paper_bgcolor="#0f1117",
        plot_bgcolor="#0f1117",
        font_color="#e2e8f0",
        barmode="overlay",
        height=320,
        margin=dict(l=10, r=80, t=20, b=40),
        legend=dict(orientation="h", yanchor="bottom", y=1.02),
        xaxis=dict(gridcolor="#2d3748"),
        yaxis=dict(title="Requests", gridcolor="#2d3748"),
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

# ── Footer + auto-refresh ─────────────────────────────────────────────────────

st.divider()
st.caption(
    f"Shadow Warden AI — MSP Dashboard · "
    f"Gateway: `{gateway_url}` · "
    f"Updated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}"
)

if auto_refresh:
    time.sleep(_REFRESH)
    st.rerun()
