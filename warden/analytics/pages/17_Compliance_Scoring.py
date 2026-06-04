"""
Streamlit page: Continuous Compliance Scoring Dashboard — CP-25

Tabs
────
  Posture     — real-time overall score + per-standard breakdown
  Timeline    — 24h / 7d score history chart
  Standards   — drilldown cards: SOC 2 / GDPR / ISO 27001 / HIPAA / NIS2
  Evidence    — report download links + audit integrity statement
"""
from __future__ import annotations

import os
import time
from datetime import datetime

import requests
import streamlit as st

st.set_page_config(
    page_title="Compliance Scoring",
    page_icon="🛡️",
    layout="wide",
)

_BASE    = os.getenv("WARDEN_INTERNAL_URL", "http://localhost:8001")
_API_KEY = os.getenv("WARDEN_API_KEY", "")
_HEADERS = {"X-API-Key": _API_KEY, "X-Tenant-Tier": "pro"} if _API_KEY else {"X-Tenant-Tier": "pro"}

# ── CSS ───────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
.score-ring-wrap { display:flex; flex-direction:column; align-items:center; gap:8px; }
.compliance-badge {
    display:inline-block; border-radius:12px; padding:3px 12px;
    font-size:0.75rem; font-weight:700; letter-spacing:.05em;
}
.badge-pass    { background:#16a34a22; color:#4ade80; border:1px solid #4ade8040; }
.badge-partial { background:#ca8a0422; color:#fbbf24; border:1px solid #fbbf2440; }
.badge-fail    { background:#dc262622; color:#f87171; border:1px solid #f8717140; }
.std-card {
    background:#0f172a; border:1px solid #1e293b; border-radius:10px;
    padding:16px; height:100%;
}
.std-score {
    font-size:2.2rem; font-weight:900; font-family:monospace; line-height:1;
}
.bar-track {
    background:#1e293b; border-radius:6px; height:8px; overflow:hidden;
    display:flex;
}
.bar-pass    { background:#22c55e; height:100%; transition: width .7s; }
.bar-partial { background:#f59e0b; height:100%; transition: width .7s; }
.bar-fail    { background:#ef4444; height:100%; transition: width .7s; }
.stat-label { font-size:0.7rem; color:#64748b; text-transform:uppercase; letter-spacing:.08em; }
.stat-val   { font-size:1.1rem; font-weight:700; }
</style>
""", unsafe_allow_html=True)

# ── Helpers ───────────────────────────────────────────────────────────────────

_STD_COLOR = {
    "soc2":     "#6366f1",
    "gdpr":     "#10b981",
    "iso27001": "#f59e0b",
    "hipaa":    "#ef4444",
    "nis2":     "#06b6d4",
}
_STD_DESC = {
    "soc2":     "CC6.1–CC9.2 Trust Service Criteria",
    "gdpr":     "Art.5 Principles · Art.30 ROPA · Art.35 DPIA",
    "iso27001": "ISO/IEC 27001:2022 Annex A Controls",
    "hipaa":    "HIPAA Security Rule Safeguards",
    "nis2":     "EU NIS2 Directive Security Measures",
}


def _badge(status: str) -> str:
    css = {"PASS": "badge-pass", "PARTIAL": "badge-partial", "FAIL": "badge-fail"}.get(status, "badge-partial")
    return f'<span class="compliance-badge {css}">{status}</span>'


def _score_color(score: float) -> str:
    return "#22c55e" if score >= 90 else "#f59e0b" if score >= 70 else "#ef4444"


def _score_ring_svg(score: float, status: str) -> str:
    r      = 56
    circ   = 2 * 3.14159 * r
    fill   = circ * score / 100
    gap    = circ - fill
    color  = _score_color(score)
    label  = "Compliant" if score >= 90 else "Partial" if score >= 70 else "At Risk"
    badge_css = {"Compliant": "badge-pass", "Partial": "badge-partial", "At Risk": "badge-fail"}[label]
    return f"""
<div class="score-ring-wrap">
  <svg width="144" height="144" viewBox="0 0 144 144">
    <circle cx="72" cy="72" r="{r}" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="10"/>
    <circle cx="72" cy="72" r="{r}" fill="none" stroke="{color}" stroke-width="10"
      stroke-dasharray="{fill:.1f} {gap:.1f}" stroke-linecap="round"
      transform="rotate(-90 72 72)" style="transition:stroke-dasharray .8s ease"/>
    <text x="72" y="68" text-anchor="middle" fill="white" font-size="28" font-weight="700" font-family="monospace">{score:.0f}</text>
    <text x="72" y="84" text-anchor="middle" fill="rgba(255,255,255,0.4)" font-size="11">/ 100</text>
  </svg>
  <span class="compliance-badge {badge_css}">{label}</span>
</div>"""


def _fetch_posture(days: int) -> dict | None:
    try:
        r = requests.get(f"{_BASE}/compliance/posture", params={"days": days},
                         headers=_HEADERS, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        st.error(f"Failed to fetch compliance posture: {exc}")
        return None


def _fetch_history(hours: int) -> dict | None:
    try:
        r = requests.get(f"{_BASE}/compliance/history", params={"hours": hours},
                         headers=_HEADERS, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


# ── Page header ───────────────────────────────────────────────────────────────

st.markdown("## 🛡️ Continuous Compliance Scoring")
st.markdown(
    '<span class="compliance-badge badge-pass" style="font-size:.7rem">CP-25</span> &nbsp;'
    '<span style="color:#64748b;font-size:.85rem">Real-time SOC 2 · GDPR · ISO 27001 · HIPAA · NIS2 posture · Pro+</span>',
    unsafe_allow_html=True,
)
st.divider()

# ── Controls ──────────────────────────────────────────────────────────────────

col_period, col_refresh, col_auto = st.columns([2, 1, 1])

with col_period:
    days = st.selectbox("Period", [1, 7, 30, 90],
                        format_func=lambda d: {1: "24h", 7: "7 days", 30: "30 days", 90: "90 days"}[d],
                        index=1, key="cp25_days")

with col_refresh:
    if st.button("↻ Refresh", key="cp25_refresh"):
        st.cache_data.clear()

with col_auto:
    auto = st.checkbox("Auto-refresh 30s", value=False, key="cp25_auto")

# ── Data fetch ────────────────────────────────────────────────────────────────

posture = _fetch_posture(days)

if posture is None:
    st.warning("Compliance posture data unavailable — ensure the Warden API is running.")
    st.stop()

standards    = posture.get("standards", [])
overall      = posture.get("overall_score", 0.0)
ov_status    = posture.get("overall_status", "PARTIAL")
generated_at = posture.get("generated_at", "")

try:
    ts_label = datetime.fromisoformat(generated_at).strftime("%Y-%m-%d %H:%M:%S UTC")
except Exception:
    ts_label = generated_at[:19] if generated_at else "—"

# ── Tabs ──────────────────────────────────────────────────────────────────────

tab_posture, tab_timeline, tab_standards, tab_evidence = st.tabs([
    "📊 Posture", "📈 Timeline", "🗂️ Standards", "📁 Evidence",
])

# ═══════════════════════════════════════════════════════════════════════════════
# Tab 1 — Posture
# ═══════════════════════════════════════════════════════════════════════════════
with tab_posture:
    st.caption(f"Generated at {ts_label}  ·  Period: {days}d")

    # Row 1: ring + summary counts + bar comparison
    ring_col, counts_col, bar_col = st.columns([1, 1, 2])

    with ring_col:
        st.markdown(_score_ring_svg(overall, ov_status), unsafe_allow_html=True)
        st.markdown(
            '<div style="text-align:center;color:#64748b;font-size:.75rem;margin-top:4px">'
            f'{posture.get("org_name","")}</div>', unsafe_allow_html=True,
        )

    with counts_col:
        total_pass    = sum(s["passed"]  for s in standards)
        total_partial = sum(s["partial"] for s in standards)
        total_fail    = sum(s["failed"]  for s in standards)
        total_ctrl    = sum(s["total"]   for s in standards)

        st.markdown(
            f"""
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:16px">
              <div>
                <div class="stat-label">Pass</div>
                <div class="stat-val" style="color:#22c55e">{total_pass}</div>
              </div>
              <div>
                <div class="stat-label">Partial</div>
                <div class="stat-val" style="color:#f59e0b">{total_partial}</div>
              </div>
              <div>
                <div class="stat-label">Fail</div>
                <div class="stat-val" style="color:#ef4444">{total_fail}</div>
              </div>
              <div>
                <div class="stat-label">Controls</div>
                <div class="stat-val" style="color:#94a3b8">{total_ctrl}</div>
              </div>
            </div>
            <div style="color:#64748b;font-size:.75rem;margin-top:12px">{len(standards)} standards evaluated</div>
            """,
            unsafe_allow_html=True,
        )

    with bar_col:
        try:
            import altair as alt
            import pandas as pd
            df = pd.DataFrame([
                {"Standard": s["short"].upper(), "Score": s["score"], "Color": _STD_COLOR.get(s["short"], "#6b7280")}
                for s in standards
            ])
            chart = (
                alt.Chart(df)
                .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4)
                .encode(
                    x=alt.X("Standard:N", axis=alt.Axis(labelColor="#6b7280", domainColor="transparent", tickColor="transparent")),
                    y=alt.Y("Score:Q", scale=alt.Scale(domain=[0, 100]),
                            axis=alt.Axis(labelColor="#6b7280", domainColor="transparent", tickColor="transparent", grid=False)),
                    color=alt.Color("Color:N", scale=None, legend=None),
                    tooltip=["Standard", "Score"],
                )
                .properties(height=180, background="transparent")
                .configure_view(strokeWidth=0)
            )
            st.altair_chart(chart, use_container_width=True)
        except ImportError:
            for s in standards:
                st.write(f"**{s['short'].upper()}** — {s['score']:.0f}%")

    st.divider()

    # Row 2: quick status table
    st.subheader("Standards at a glance")
    rows = []
    for s in standards:
        attest = s["attestation"]
        icon   = "✅" if attest == "PASS" else "⚠️" if attest == "PARTIAL" else "❌"
        rows.append({
            "Standard":    s["standard"],
            "Score":       f"{s['score']:.1f}%",
            "Pass":        s["passed"],
            "Partial":     s["partial"],
            "Fail":        s["failed"],
            "Total":       s["total"],
            "Attestation": f"{icon} {attest}",
        })
    try:
        import pandas as pd
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    except ImportError:
        st.table(rows)

# ═══════════════════════════════════════════════════════════════════════════════
# Tab 2 — Timeline
# ═══════════════════════════════════════════════════════════════════════════════
with tab_timeline:
    hours_opts = {24: "24h", 48: "48h", 72: "72h", 168: "7 days"}
    hours = st.selectbox("History window", list(hours_opts.keys()),
                         format_func=lambda h: hours_opts[h], index=0, key="cp25_hours")

    history = _fetch_history(hours)

    if history and history.get("count", 0) > 0:
        snapshots = history["snapshots"]
        try:
            import altair as alt
            import pandas as pd
            rows_h = []
            for snap in snapshots:
                ts = datetime.fromisoformat(snap["ts"]).strftime("%H:%M")
                rows_h.append({"Time": ts, "Overall": snap["overall_score"]})
                for std, score in snap.get("scores", {}).items():
                    rows_h.append({"Time": ts, std.upper(): score})

            # Overall trend
            df_overall = pd.DataFrame([
                {"Time": datetime.fromisoformat(s["ts"]).strftime("%H:%M"),
                 "Score": s["overall_score"]}
                for s in snapshots
            ])
            chart_overall = (
                alt.Chart(df_overall)
                .mark_area(line=True, color="#6366f1", opacity=0.2)
                .encode(
                    x=alt.X("Time:N", axis=alt.Axis(labelColor="#6b7280", domainColor="transparent", tickColor="transparent")),
                    y=alt.Y("Score:Q", scale=alt.Scale(domain=[50, 100]),
                            axis=alt.Axis(labelColor="#6b7280", domainColor="transparent", grid=False)),
                    tooltip=["Time", "Score"],
                )
                .properties(height=220, title="Overall Compliance Score", background="transparent")
                .configure_view(strokeWidth=0)
                .configure_title(color="#94a3b8", fontSize=13)
            )
            st.altair_chart(chart_overall, use_container_width=True)

            # Per-standard sparklines
            st.markdown("**Per-standard score history**")
            std_cols = st.columns(len(standards) or 5)
            for i, s in enumerate(standards):
                key = s["short"]
                color = _STD_COLOR.get(key, "#6b7280")
                df_std = pd.DataFrame([
                    {"Time": datetime.fromisoformat(snap["ts"]).strftime("%H:%M"),
                     "Score": snap.get("scores", {}).get(key, 0)}
                    for snap in snapshots
                ])
                if df_std.empty:
                    continue
                spark = (
                    alt.Chart(df_std)
                    .mark_line(color=color, strokeWidth=2)
                    .encode(
                        x=alt.X("Time:N", axis=None),
                        y=alt.Y("Score:Q", scale=alt.Scale(domain=[50, 100]), axis=None),
                    )
                    .properties(height=60, title=key.upper(), background="transparent")
                    .configure_view(strokeWidth=0)
                    .configure_title(color=color, fontSize=11)
                )
                with std_cols[i]:
                    st.altair_chart(spark, use_container_width=True)

        except ImportError:
            st.info("Install pandas + altair for chart rendering.")
            st.json(history)
    else:
        st.info(
            "No history snapshots yet.  "
            "The ring buffer populates as the Posture tab is polled (up to 168 snapshots / 1 week)."
        )
        if posture:
            st.metric("Current overall score", f"{overall:.1f}%")

# ═══════════════════════════════════════════════════════════════════════════════
# Tab 3 — Standards drilldown
# ═══════════════════════════════════════════════════════════════════════════════
with tab_standards:
    st.subheader("Per-standard breakdown")
    cols = st.columns(len(standards) or 5)

    for i, s in enumerate(standards):
        key   = s["short"]
        color = _STD_COLOR.get(key, "#6b7280")
        desc  = _STD_DESC.get(key, "")
        total = s["total"] or 1
        pass_pct    = s["passed"]  / total * 100
        partial_pct = s["partial"] / total * 100
        fail_pct    = s["failed"]  / total * 100

        with cols[i]:
            st.markdown(
                f"""
                <div class="std-card">
                  <div style="color:{color};font-size:.7rem;font-weight:700;text-transform:uppercase;
                              letter-spacing:.1em;margin-bottom:6px">{s["standard"]}</div>
                  <div style="color:#94a3b8;font-size:.65rem;margin-bottom:10px">{desc}</div>
                  <div class="std-score" style="color:{color}">{s["score"]:.0f}<span style="font-size:.9rem;font-weight:400;color:#64748b">%</span></div>
                  <div style="margin:10px 0">{_badge(s["attestation"])}</div>
                  <div class="bar-track">
                    <div class="bar-pass"    style="width:{pass_pct:.1f}%"></div>
                    <div class="bar-partial" style="width:{partial_pct:.1f}%"></div>
                    <div class="bar-fail"    style="width:{fail_pct:.1f}%"></div>
                  </div>
                  <div style="display:flex;gap:8px;margin-top:8px;font-size:.7rem;color:#64748b">
                    <span>✅ {s["passed"]}</span>
                    <span>⚠️ {s["partial"]}</span>
                    <span>❌ {s["failed"]}</span>
                    <span style="margin-left:auto">{s["total"]} ctrl</span>
                  </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

# ═══════════════════════════════════════════════════════════════════════════════
# Tab 4 — Evidence & reports
# ═══════════════════════════════════════════════════════════════════════════════
with tab_evidence:
    st.subheader("Compliance Evidence & Reports")
    api_url = os.getenv("WARDEN_PUBLIC_URL", _BASE)

    evidence_links = [
        ("SOC 2 Evidence Bundle",  f"{api_url}/compliance/soc2-bundle?days={days}",    "#6366f1"),
        ("GDPR Art.30 Report",     f"{api_url}/compliance/smb-report/html?days={days}", "#10b981"),
        ("ISO 27001 Report",       f"{api_url}/compliance/iso27001/html?days={days}",   "#f59e0b"),
        ("HIPAA Safeguards",       f"{api_url}/compliance/hipaa/html?days={days}",      "#ef4444"),
        ("NIS2 Report",            f"{api_url}/compliance/nis2/html?days={days}",       "#06b6d4"),
        ("Raw Posture JSON",       f"{api_url}/compliance/posture?days={days}",         "#64748b"),
    ]

    ev_cols = st.columns(3)
    for idx, (label, url, color) in enumerate(evidence_links):
        with ev_cols[idx % 3]:
            st.markdown(
                f'<a href="{url}" target="_blank" rel="noopener noreferrer" '
                f'style="display:block;background:{color}18;border:1px solid {color}40;'
                f'border-radius:8px;padding:10px 14px;color:{color};font-size:.82rem;'
                f'font-weight:600;text-decoration:none;margin-bottom:8px">'
                f'↗ {label}</a>',
                unsafe_allow_html=True,
            )

    st.divider()

    # Audit integrity
    st.markdown(
        "**GDPR note:** No prompt or response content is stored in any compliance report — "
        "only metadata (lengths, counts, timestamps). All reports are derived exclusively from "
        "request/response metadata in accordance with GDPR Art.5(1)(c) data minimisation.",
    )

    # Snapshot stats
    with st.expander("Ring buffer stats"):
        history_all = _fetch_history(168)
        snap_count = history_all.get("count", 0) if history_all else 0
        st.write(f"Snapshots in ring buffer (max 168): **{snap_count}**")
        st.write("Buffer window: 1 week (168 hourly snapshots)")
        st.caption("Each call to GET /compliance/posture appends one snapshot.")

# ── Auto-refresh ──────────────────────────────────────────────────────────────

if auto:
    time.sleep(30)
    st.rerun()
