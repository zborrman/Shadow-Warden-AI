"""
Shadow Warden AI — Analytics Dashboard
Run with:  streamlit run warden/analytics/dashboard.py
"""
from __future__ import annotations

import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Allow running from repo root without installing the package
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from warden.analytics.auth import require_auth
from warden.analytics.logger import load_entries

# ── Page config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="Shadow Warden AI — Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Auth gate — must come before any content is rendered ─────────────────────
# Shows a login screen and calls st.stop() if the session is not authenticated.
# Returns immediately (and injects the sidebar logout widget) if auth is valid.

require_auth()

# ── Minimal dark-mode CSS ─────────────────────────────────────────────────────

st.markdown("""
<style>
  /* card boxes */
  .metric-card {
    background: #1a1f2e;
    border: 1px solid #2d3748;
    border-radius: 10px;
    padding: 18px 22px;
    text-align: center;
  }
  .metric-value { font-size: 2.4rem; font-weight: 700; color: #e2e8f0; }
  .metric-label { font-size: 0.85rem; color: #718096; letter-spacing: .05em; }
  .metric-delta-good { color: #48bb78; font-size: .8rem; }
  .metric-delta-bad  { color: #fc8181; font-size: .8rem; }
  /* section headers */
  .section-title {
    font-size: 1.1rem; font-weight: 600; color: #a0aec0;
    margin: 1.2rem 0 .4rem; letter-spacing: .08em;
    text-transform: uppercase;
  }
</style>
""", unsafe_allow_html=True)

# ── Sidebar — controls ────────────────────────────────────────────────────────

with st.sidebar:
    st.image("https://raw.githubusercontent.com/feathericons/feather/master/icons/shield.svg",
             width=48)
    st.title("Shadow Warden AI")
    st.caption("Security Analytics Dashboard")
    st.divider()

    time_window = st.selectbox(
        "Time window",
        ["Last 1 hour", "Last 24 hours", "Last 7 days", "Last 30 days", "All time"],
        index=1,
    )
    _window_days = {
        "Last 1 hour":    1 / 24,
        "Last 24 hours":  1,
        "Last 7 days":    7,
        "Last 30 days":   30,
        "All time":       None,
    }[time_window]

    auto_refresh = st.toggle("Auto-refresh (30 s)", value=True)
    if auto_refresh:
        st.caption("Dashboard refreshes every 30 seconds.")

    st.divider()
    if st.button("🔄  Refresh now", use_container_width=True):
        st.rerun()

# ── Load data ─────────────────────────────────────────────────────────────────

entries = load_entries(days=_window_days)

if not entries:
    st.warning("No log entries found yet. Make some requests through the Warden gateway to populate the dashboard.")
    st.info("Logs are written to: `data/logs.json`")
    if auto_refresh:
        import time  # noqa: PLC0415
        time.sleep(30)
        st.rerun()
    st.stop()

df = pd.DataFrame(entries)
df["ts"]         = pd.to_datetime(df["ts"], utc=True)
df["risk_level"] = df["risk_level"].str.upper()
df["hour"]       = df["ts"].dt.floor("h")
df["date"]       = df["ts"].dt.date

# ── KPI cards ─────────────────────────────────────────────────────────────────

total    = len(df)
blocked  = int((~df["allowed"]).sum())
allowed  = int(df["allowed"].sum())
block_rt = round(blocked / total * 100, 1) if total else 0
avg_ms   = round(df["elapsed_ms"].mean(), 1) if "elapsed_ms" in df.columns else 0
high_sev = int(df["risk_level"].isin(["HIGH", "BLOCK"]).sum())

st.markdown('<p class="section-title">Overview</p>', unsafe_allow_html=True)
c1, c2, c3, c4, c5 = st.columns(5)

def _card(col, value, label, delta="", delta_good=True):
    delta_cls = "metric-delta-good" if delta_good else "metric-delta-bad"
    col.markdown(f"""
    <div class="metric-card">
      <div class="metric-value">{value}</div>
      <div class="metric-label">{label}</div>
      {'<div class="' + delta_cls + '">' + delta + '</div>' if delta else ''}
    </div>""", unsafe_allow_html=True)

_card(c1, f"{total:,}",     "TOTAL REQUESTS")
_card(c2, f"{allowed:,}",   "ALLOWED",          delta_good=True)
_card(c3, f"{blocked:,}",   "BLOCKED",          delta_good=False)
_card(c4, f"{block_rt}%",   "BLOCK RATE",       delta_good=(block_rt < 20))
_card(c5, f"{avg_ms} ms",   "AVG FILTER TIME",  delta_good=(avg_ms < 100))

st.divider()

# ── Row 2: Threat Radar + Attack Timeline ─────────────────────────────────────

col_radar, col_timeline = st.columns([1, 2], gap="large")

# ── Threat Radar ──────────────────────────────────────────────────────────────

with col_radar:
    st.markdown('<p class="section-title">Threat Radar</p>', unsafe_allow_html=True)

    RADAR_CATEGORIES = {
        "prompt_injection": "Prompt\nInjection",
        "harmful_content":  "Harmful\nContent",
        "pii_detected":     "PII /\nSecrets",
        "policy_violation": "Policy\nViolation",
        "secret_detected":  "Credential\nLeak",
    }

    all_flags = [f for row in df["flags"].dropna() for f in (row if isinstance(row, list) else [])]
    flag_counts = Counter(all_flags)

    radar_labels = list(RADAR_CATEGORIES.values())
    radar_values = [flag_counts.get(k, 0) for k in RADAR_CATEGORIES]

    # Close the polygon
    radar_labels += [radar_labels[0]]
    radar_values += [radar_values[0]]

    fig_radar = go.Figure()
    fig_radar.add_trace(go.Scatterpolar(
        r=radar_values,
        theta=radar_labels,
        fill="toself",
        name="Threats",
        line=dict(color="#E53E3E", width=2),
        fillcolor="rgba(229, 62, 62, 0.18)",
        marker=dict(size=6, color="#E53E3E"),
    ))
    fig_radar.update_layout(
        polar=dict(
            bgcolor="#1a1f2e",
            radialaxis=dict(
                visible=True,
                showticklabels=True,
                gridcolor="#2d3748",
                linecolor="#2d3748",
                tickfont=dict(color="#718096", size=10),
            ),
            angularaxis=dict(
                gridcolor="#2d3748",
                linecolor="#2d3748",
                tickfont=dict(color="#a0aec0", size=11),
            ),
        ),
        paper_bgcolor="#111827",
        plot_bgcolor="#111827",
        font=dict(color="#e2e8f0"),
        showlegend=False,
        margin=dict(l=40, r=40, t=30, b=30),
        height=380,
    )
    st.plotly_chart(fig_radar, use_container_width=True)

# ── Attack Timeline ───────────────────────────────────────────────────────────

with col_timeline:
    st.markdown('<p class="section-title">Attack Timeline</p>', unsafe_allow_html=True)

    RISK_COLORS = {
        "LOW":    "#48BB78",
        "MEDIUM": "#ECC94B",
        "HIGH":   "#ED8936",
        "BLOCK":  "#E53E3E",
    }

    blocked_df = df[~df["allowed"]].copy()

    if blocked_df.empty:
        st.info("No blocked requests in this time window — all clear.")
    else:
        # Choose bucket size based on window
        if _window_days and _window_days <= 1:
            blocked_df["bucket"] = blocked_df["ts"].dt.floor("10min")
            bucket_label = "10-minute buckets"
        elif _window_days and _window_days <= 7:
            blocked_df["bucket"] = blocked_df["ts"].dt.floor("h")
            bucket_label = "hourly buckets"
        else:
            blocked_df["bucket"] = blocked_df["ts"].dt.floor("D")
            bucket_label = "daily buckets"

        timeline = (
            blocked_df.groupby(["bucket", "risk_level"])
            .size()
            .reset_index(name="count")
        )

        fig_tl = px.area(
            timeline,
            x="bucket", y="count",
            color="risk_level",
            color_discrete_map=RISK_COLORS,
            labels={"bucket": "", "count": "Blocked requests", "risk_level": "Risk"},
            template="plotly_dark",
            category_orders={"risk_level": ["BLOCK", "HIGH", "MEDIUM", "LOW"]},
        )
        fig_tl.update_layout(
            paper_bgcolor="#111827",
            plot_bgcolor="#111827",
            legend=dict(
                orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1,
                font=dict(size=11),
            ),
            xaxis=dict(gridcolor="#2d3748", showgrid=True),
            yaxis=dict(gridcolor="#2d3748", showgrid=True),
            margin=dict(l=10, r=10, t=40, b=10),
            height=380,
            hovermode="x unified",
        )
        fig_tl.update_traces(line=dict(width=1.5))
        st.plotly_chart(fig_tl, use_container_width=True)
        st.caption(f"Showing blocked requests in {bucket_label}.")

st.divider()

# ── Row 3: Secrets breakdown + Top flags table ────────────────────────────────

col_secrets, col_flags = st.columns(2, gap="large")

with col_secrets:
    st.markdown('<p class="section-title">Secrets & PII Detected</p>', unsafe_allow_html=True)

    all_secrets = [
        s for row in df["secrets_found"].dropna()
        for s in (row if isinstance(row, list) else [])
    ]
    if all_secrets:
        sec_counts = (
            pd.Series(all_secrets)
            .value_counts()
            .reset_index()
            .rename(columns={"index": "kind", 0: "count"})
        )
        sec_counts.columns = ["kind", "count"]
        fig_sec = px.bar(
            sec_counts, x="count", y="kind",
            orientation="h",
            color="count",
            color_continuous_scale="Reds",
            template="plotly_dark",
            labels={"kind": "", "count": "Occurrences"},
        )
        fig_sec.update_layout(
            paper_bgcolor="#111827", plot_bgcolor="#111827",
            coloraxis_showscale=False,
            margin=dict(l=10, r=10, t=10, b=10),
            height=280,
            yaxis=dict(categoryorder="total ascending"),
        )
        st.plotly_chart(fig_sec, use_container_width=True)
    else:
        st.success("No secrets or PII detected in this time window.")

with col_flags:
    st.markdown('<p class="section-title">Top Threat Flags</p>', unsafe_allow_html=True)

    if flag_counts:
        flag_df = (
            pd.DataFrame.from_dict(flag_counts, orient="index", columns=["count"])
            .sort_values("count", ascending=False)
            .head(10)
            .reset_index()
            .rename(columns={"index": "Flag"})
        )
        flag_df["Flag"] = flag_df["Flag"].str.replace("_", " ").str.title()
        flag_df["Share"] = (flag_df["count"] / flag_df["count"].sum() * 100).round(1).astype(str) + "%"
        st.dataframe(
            flag_df.rename(columns={"count": "Count", "Share": "Share"}),
            use_container_width=True,
            hide_index=True,
            height=280,
        )
    else:
        st.info("No threat flags recorded yet.")

st.divider()

# ── Row 4: Recent blocked events ──────────────────────────────────────────────

st.markdown('<p class="section-title">Recent Blocked Events</p>', unsafe_allow_html=True)

recent = (
    df[~df["allowed"]]
    .sort_values("ts", ascending=False)
    .head(20)
    [["ts", "request_id", "risk_level", "flags", "secrets_found", "elapsed_ms"]]
    .copy()
)

if recent.empty:
    st.success("No blocked events in this time window.")
else:
    recent["ts"] = recent["ts"].dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    recent["flags"] = recent["flags"].apply(
        lambda x: ", ".join(x) if isinstance(x, list) else ""
    )
    recent["secrets_found"] = recent["secrets_found"].apply(
        lambda x: ", ".join(x) if isinstance(x, list) else ""
    )
    recent["elapsed_ms"] = recent["elapsed_ms"].round(1).astype(str) + " ms"
    recent.columns = ["Timestamp", "Request ID", "Risk", "Flags", "Secrets", "Latency"]
    st.dataframe(recent, use_container_width=True, hide_index=True, height=320)

# ── Footer ────────────────────────────────────────────────────────────────────

st.caption(
    f"Shadow Warden AI • {total:,} events loaded • "
    f"Window: {time_window} • "
    f"Last updated: {datetime.now(UTC).strftime('%H:%M:%S UTC')}"
)

# ── Auto-refresh ──────────────────────────────────────────────────────────────

if auto_refresh:
    import time
    time.sleep(30)
    st.rerun()
