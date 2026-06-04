"""
Streamlit page: ISO/IEC 27001:2022 Annex A Control Mapping — CP-22

Tabs
────
  Overview    — KPI tiles + theme coverage + gap heatmap
  Controls    — searchable/filterable 93-control matrix with evidence
  Themes      — per-theme drilldown (Organizational / People / Physical / Technological)
  Report      — download HTML / JSON report links
"""
from __future__ import annotations

import os

import requests
import streamlit as st

st.set_page_config(
    page_title="ISO 27001",
    page_icon="🔐",
    layout="wide",
)

_BASE    = os.getenv("WARDEN_INTERNAL_URL", "http://localhost:8001")
_API_KEY = os.getenv("WARDEN_API_KEY", "")
_HEADERS = {"X-API-Key": _API_KEY, "X-Tenant-Tier": "enterprise"} if _API_KEY else {"X-Tenant-Tier": "enterprise"}

# ── CSS ───────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
.ctrl-badge {
    display:inline-block; font-family:monospace; font-size:.7rem;
    background:#1e293b; color:#818cf8; border-radius:4px;
    padding:1px 6px; border:1px solid #312e81;
}
.impl-chip  { background:#14532d22; color:#4ade80; border:1px solid #4ade8040; border-radius:10px; padding:2px 8px; font-size:.7rem; font-weight:700; }
.part-chip  { background:#7c2d1222; color:#fb923c; border:1px solid #fb923c40; border-radius:10px; padding:2px 8px; font-size:.7rem; font-weight:700; }
.deleg-chip { background:#1e3a5f22; color:#60a5fa; border:1px solid #60a5fa40; border-radius:10px; padding:2px 8px; font-size:.7rem; font-weight:700; }
.theme-card {
    background:#0f172a; border:1px solid #1e293b; border-radius:10px;
    padding:16px; text-align:center;
}
.kpi-val  { font-size:2rem; font-weight:900; font-family:monospace; line-height:1.1; }
.kpi-lbl  { font-size:.68rem; color:#64748b; text-transform:uppercase; letter-spacing:.08em; margin-top:2px; }
</style>
""", unsafe_allow_html=True)

_THEME_COLOR = {
    "Organizational": "#6366f1",
    "People":         "#10b981",
    "Physical":       "#f59e0b",
    "Technological":  "#ef4444",
}
_STATUS_CHIP = {
    "Implemented": '<span class="impl-chip">Implemented</span>',
    "Partial":     '<span class="part-chip">Partial</span>',
    "Delegated":   '<span class="deleg-chip">Delegated</span>',
}

# ── Fetch ─────────────────────────────────────────────────────────────────────

@st.cache_data(ttl=120)
def _fetch(days: int) -> dict | None:
    try:
        r = requests.get(f"{_BASE}/compliance/iso27001",
                         params={"days": days}, headers=_HEADERS, timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        st.error(f"Could not reach /compliance/iso27001: {exc}")
        return None

# ── Page header ───────────────────────────────────────────────────────────────

st.markdown("## 🔐 ISO/IEC 27001:2022 — Annex A Control Mapping")
st.markdown(
    '<span class="impl-chip" style="font-size:.7rem">CP-22</span> &nbsp;'
    '<span style="color:#64748b;font-size:.85rem">Enterprise · 93 Annex A controls mapped to Shadow Warden platform capabilities</span>',
    unsafe_allow_html=True,
)
st.divider()

col_days, col_refresh = st.columns([2, 1])
with col_days:
    days = st.selectbox("Evidence period", [7, 30, 90, 180, 365],
                        format_func=lambda d: f"{d} days", index=1)
with col_refresh:
    if st.button("↻ Refresh"):
        st.cache_data.clear()

data = _fetch(days)
if data is None:
    st.warning("ISO 27001 data unavailable — ensure Warden API is running at Enterprise tier.")
    st.stop()

controls = data.get("controls", [])
themes   = data.get("themes", {})

# ── Tabs ──────────────────────────────────────────────────────────────────────

tab_overview, tab_controls, tab_themes, tab_report = st.tabs([
    "📊 Overview", "📋 Controls", "🗂️ Themes", "📁 Report"
])

# ═══════════════════════════════════════════════════════════════════════════════
# Tab 1 — Overview
# ═══════════════════════════════════════════════════════════════════════════════
with tab_overview:
    # KPI row
    k1, k2, k3, k4, k5 = st.columns(5)
    kpis = [
        (k1, str(data["controls_total"]),  "Total Controls",    "#818cf8"),
        (k2, str(data["implemented"]),     "Implemented",       "#4ade80"),
        (k3, str(data["partial"]),         "Partial",           "#fb923c"),
        (k4, str(data["delegated"]),       "Delegated",         "#60a5fa"),
        (k5, f"{data['coverage_pct']}%",   "Coverage Score",    "#818cf8"),
    ]
    for col, val, lbl, color in kpis:
        with col:
            st.markdown(
                f'<div style="background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:16px;text-align:center">'
                f'<div class="kpi-val" style="color:{color}">{val}</div>'
                f'<div class="kpi-lbl">{lbl}</div></div>',
                unsafe_allow_html=True,
            )

    st.markdown("")

    # Theme coverage cards
    st.subheader("Coverage by Theme")
    tc = st.columns(4)
    for i, theme in enumerate(["Organizational", "People", "Physical", "Technological"]):
        t     = themes.get(theme, {})
        total = t.get("total", 1)
        impl  = t.get("implemented", 0)
        pct   = round(impl / total * 100) if total else 0
        color = _THEME_COLOR[theme]
        with tc[i]:
            st.markdown(
                f'<div class="theme-card">'
                f'<div style="color:{color};font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px">{theme}</div>'
                f'<div class="kpi-val" style="color:{color}">{pct}%</div>'
                f'<div class="kpi-lbl">{impl}/{total} implemented</div>'
                f'<div style="background:#1e293b;border-radius:4px;height:5px;margin-top:10px;overflow:hidden">'
                f'<div style="width:{pct}%;height:100%;background:{color};border-radius:4px;transition:width .7s"></div>'
                f'</div></div>',
                unsafe_allow_html=True,
            )

    st.markdown("")

    # Status distribution chart
    st.subheader("Status Distribution")
    try:
        import pandas as pd, altair as alt
        dist_data = pd.DataFrame([
            {"Status": "Implemented", "Count": data["implemented"],  "Color": "#4ade80"},
            {"Status": "Partial",     "Count": data["partial"],      "Color": "#fb923c"},
            {"Status": "Delegated",   "Count": data["delegated"],    "Color": "#60a5fa"},
        ])
        bar = (
            alt.Chart(dist_data)
            .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4)
            .encode(
                x=alt.X("Status:N", axis=alt.Axis(labelColor="#6b7280", domainColor="transparent", tickColor="transparent")),
                y=alt.Y("Count:Q", axis=alt.Axis(labelColor="#6b7280", domainColor="transparent", grid=False)),
                color=alt.Color("Color:N", scale=None, legend=None),
                tooltip=["Status", "Count"],
            )
            .properties(height=160, background="transparent")
            .configure_view(strokeWidth=0)
        )
        st.altair_chart(bar, use_container_width=True)
    except ImportError:
        col_i, col_p, col_d = st.columns(3)
        col_i.metric("Implemented", data["implemented"])
        col_p.metric("Partial",     data["partial"])
        col_d.metric("Delegated",   data["delegated"])

# ═══════════════════════════════════════════════════════════════════════════════
# Tab 2 — Controls matrix
# ═══════════════════════════════════════════════════════════════════════════════
with tab_controls:
    f_col, s_col, t_col = st.columns([2, 2, 1])
    with f_col:
        search = st.text_input("Search control ID or keyword", placeholder="e.g. A.8.24 or cryptography")
    with s_col:
        status_filter = st.multiselect("Status", ["Implemented", "Partial", "Delegated"],
                                       default=["Implemented", "Partial", "Delegated"])
    with t_col:
        theme_filter = st.multiselect("Theme", ["Organizational", "People", "Physical", "Technological"],
                                      default=["Organizational", "People", "Physical", "Technological"])

    filtered = [
        c for c in controls
        if c["status"] in status_filter
        and c["theme"] in theme_filter
        and (not search or search.lower() in c["control"].lower()
             or search.lower() in c["domain"].lower()
             or search.lower() in c["evidence"].lower())
    ]

    st.caption(f"Showing {len(filtered)} of {len(controls)} controls")

    for ctrl in filtered:
        color = _THEME_COLOR.get(ctrl["theme"], "#6b7280")
        chip  = _STATUS_CHIP.get(ctrl["status"], ctrl["status"])
        st.markdown(
            f'<div style="background:#0f172a;border:1px solid #1e293b;border-left:3px solid {color};'
            f'border-radius:8px;padding:10px 14px;margin-bottom:6px">'
            f'<div style="display:flex;align-items:center;gap:10px;margin-bottom:4px">'
            f'<span class="ctrl-badge">{ctrl["control"]}</span>'
            f'<span style="font-size:.82rem;font-weight:600;color:#f1f5f9">{ctrl["domain"]}</span>'
            f'<span style="margin-left:auto">{chip}</span></div>'
            f'<div style="font-size:.75rem;color:#64748b">{ctrl["evidence"]}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

# ═══════════════════════════════════════════════════════════════════════════════
# Tab 3 — Per-theme drilldown
# ═══════════════════════════════════════════════════════════════════════════════
with tab_themes:
    selected_theme = st.radio("Theme", list(_THEME_COLOR.keys()), horizontal=True)
    theme_controls = [c for c in controls if c["theme"] == selected_theme]
    t_info         = themes.get(selected_theme, {})
    color          = _THEME_COLOR[selected_theme]

    ti1, ti2, ti3, ti4 = st.columns(4)
    for col, val, lbl in [
        (ti1, str(t_info.get("total", 0)),       "Controls"),
        (ti2, str(t_info.get("implemented", 0)), "Implemented"),
        (ti3, str(t_info.get("partial", 0)),     "Partial"),
        (ti4, str(t_info.get("delegated", 0)),   "Delegated"),
    ]:
        with col:
            st.markdown(
                f'<div style="background:#0f172a;border:1px solid {color}40;border-radius:8px;'
                f'padding:12px;text-align:center">'
                f'<div style="font-size:1.5rem;font-weight:900;color:{color}">{val}</div>'
                f'<div style="font-size:.65rem;color:#64748b;text-transform:uppercase">{lbl}</div></div>',
                unsafe_allow_html=True,
            )

    st.markdown("")

    for ctrl in theme_controls:
        chip = _STATUS_CHIP.get(ctrl["status"], ctrl["status"])
        st.markdown(
            f'<div style="background:#0f172a;border:1px solid #1e293b;border-left:3px solid {color};'
            f'border-radius:8px;padding:10px 14px;margin-bottom:5px">'
            f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:3px">'
            f'<span class="ctrl-badge">{ctrl["control"]}</span>'
            f'<span style="font-size:.82rem;font-weight:600;color:#f1f5f9">{ctrl["domain"]}</span>'
            f'<span style="margin-left:auto">{chip}</span></div>'
            f'<div style="font-size:.74rem;color:#64748b">{ctrl["evidence"]}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

# ═══════════════════════════════════════════════════════════════════════════════
# Tab 4 — Report
# ═══════════════════════════════════════════════════════════════════════════════
with tab_report:
    st.subheader("Download Reports")
    api_url = os.getenv("WARDEN_PUBLIC_URL", _BASE)

    r1, r2 = st.columns(2)
    with r1:
        st.markdown(
            f'<a href="{api_url}/compliance/iso27001/html?days={days}" target="_blank" rel="noopener noreferrer"'
            f' style="display:block;background:#6366f115;border:1px solid #6366f140;border-radius:8px;'
            f'padding:12px 16px;color:#818cf8;font-weight:600;text-decoration:none;margin-bottom:8px">'
            f'↗ Print-ready HTML Report (93 controls)</a>',
            unsafe_allow_html=True,
        )
    with r2:
        st.markdown(
            f'<a href="{api_url}/compliance/iso27001?days={days}" target="_blank" rel="noopener noreferrer"'
            f' style="display:block;background:#10b98115;border:1px solid #10b98140;border-radius:8px;'
            f'padding:12px 16px;color:#34d399;font-weight:600;text-decoration:none;margin-bottom:8px">'
            f'↗ Raw JSON (API)</a>',
            unsafe_allow_html=True,
        )

    st.divider()
    st.markdown("**About this mapping**")
    st.markdown(
        "- **93 controls** from ISO/IEC 27001:2022 Annex A across 4 themes\n"
        "- **Coverage score** = (Implemented + Partial×0.5) / Total\n"
        "- **Delegated** controls are fulfilled by Hetzner GmbH (ISO 27001 certified facility)\n"
        "- Evidence references point to specific platform files, APIs, or configurations\n"
        "- Re-generated on every API call; always reflects current platform state"
    )
    with st.expander("Raw JSON"):
        st.json({k: v for k, v in data.items() if k not in ("controls", "by_theme")})
