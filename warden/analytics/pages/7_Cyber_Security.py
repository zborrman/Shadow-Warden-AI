"""
Cyber Security Hub Dashboard
Tabs: Posture · CVE Feed · SOC Live · Pentest · Compliance
"""
from __future__ import annotations

import os
import sys
import time
from datetime import UTC, datetime

import streamlit as st

sys.path.insert(0, "/warden")

st.set_page_config(
    page_title="Cyber Security Hub",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

try:
    from warden.analytics.accessibility import inject_accessibility_widget
    inject_accessibility_widget()
except Exception:
    pass

# ── Config ────────────────────────────────────────────────────────────────────

_WARDEN_URL = os.environ.get("WARDEN_URL",   "http://warden:8001")
_ADMIN_KEY  = os.environ.get("ADMIN_KEY",    "")
_API_KEY    = os.environ.get("WARDEN_API_KEY", "")

# ── CSS ───────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
  /* ── posture badge ── */
  .badge-green  { background:#1a3a2a; border:2px solid #48bb78; border-radius:12px;
                  padding:14px 28px; text-align:center; }
  .badge-yellow { background:#3a3010; border:2px solid #ecc94b; border-radius:12px;
                  padding:14px 28px; text-align:center; }
  .badge-red    { background:#3a1010; border:2px solid #fc8181; border-radius:12px;
                  padding:14px 28px; text-align:center; }
  .badge-text   { font-size:2.2rem; font-weight:800; letter-spacing:.06em; }
  .badge-sub    { font-size:.8rem;  color:#a0aec0; margin-top:4px; }

  /* ── stat cards ── */
  .sec-card { background:#1a1f2e; border:1px solid #2d3748; border-radius:10px;
              padding:16px 20px; text-align:center; }
  .sec-val  { font-size:2rem; font-weight:700; color:#e2e8f0; }
  .sec-lbl  { font-size:.8rem; color:#718096; text-transform:uppercase;
              letter-spacing:.07em; margin-top:4px; }

  /* ── severity chips ── */
  .sev-CRITICAL { background:#742a2a; color:#fc8181; padding:2px 10px;
                  border-radius:9999px; font-size:.75rem; font-weight:700; }
  .sev-HIGH     { background:#7b341e; color:#f6ad55; padding:2px 10px;
                  border-radius:9999px; font-size:.75rem; font-weight:700; }
  .sev-MEDIUM   { background:#4a3728; color:#f6e05e; padding:2px 10px;
                  border-radius:9999px; font-size:.75rem; font-weight:700; }
  .sev-LOW      { background:#1a3a2a; color:#68d391; padding:2px 10px;
                  border-radius:9999px; font-size:.75rem; font-weight:700; }
  .sev-UNKNOWN  { background:#2d3748; color:#a0aec0; padding:2px 10px;
                  border-radius:9999px; font-size:.75rem; font-weight:700; }

  /* ── SOC status indicators ── */
  .soc-ok   { color:#48bb78; font-weight:700; }
  .soc-warn { color:#ecc94b; font-weight:700; }
  .soc-crit { color:#fc8181; font-weight:700; }

  /* ── control rows ── */
  .ctrl-pass { color:#48bb78; }
  .ctrl-fail { color:#fc8181; }
  .ctrl-prog { color:#ecc94b; }
</style>
""", unsafe_allow_html=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _headers(admin: bool = False) -> dict:
    h: dict = {"Content-Type": "application/json"}
    if _API_KEY:
        h["X-API-Key"] = _API_KEY
    if admin and _ADMIN_KEY:
        h["X-Admin-Key"] = _ADMIN_KEY
    return h


@st.cache_data(ttl=30)
def _get(path: str) -> dict | list | None:
    import httpx
    try:
        r = httpx.get(f"{_WARDEN_URL}{path}", headers=_headers(), timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        return {"_error": str(exc)}


def _post(path: str, body: dict | None = None, admin: bool = False) -> dict | None:
    import httpx
    try:
        r = httpx.post(
            f"{_WARDEN_URL}{path}",
            json=body or {},
            headers=_headers(admin=admin),
            timeout=20,
        )
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        st.error(f"API error: {exc}")
        return None


def _err(data: dict | list | None) -> str | None:
    if isinstance(data, dict) and "_error" in data:
        return data["_error"]
    return None


def _sev_chip(sev: str) -> str:
    return f'<span class="sev-{sev}">{sev}</span>'


def _badge_html(badge: str, cve_counts: dict, last_scan: str | None) -> str:
    colors  = {"GREEN": "#48bb78", "YELLOW": "#ecc94b", "RED": "#fc8181"}
    icons   = {"GREEN": "✅", "YELLOW": "⚠️", "RED": "🚨"}
    css_cls = f"badge-{badge.lower()}"
    color   = colors.get(badge, "#a0aec0")
    icon    = icons.get(badge, "❓")
    crit    = cve_counts.get("critical", 0)
    high    = cve_counts.get("high", 0)
    total   = cve_counts.get("total", 0)
    scan_ts = last_scan[:19].replace("T", " ") if last_scan else "never"
    return f"""
    <div class="{css_cls}" style="margin-bottom:16px">
      <div class="badge-text" style="color:{color}">{icon} {badge}</div>
      <div class="badge-sub">
        {crit} critical · {high} high · {total} total CVEs
      </div>
      <div class="badge-sub">Last scan: {scan_ts} UTC</div>
    </div>
    """


# ── Page header ───────────────────────────────────────────────────────────────

st.title("🛡️ Cyber Security Hub")
st.caption("Posture · CVE monitoring · SOC live · Pentest · Compliance")

TABS = st.tabs(["🟢 Posture", "🐛 CVE Feed", "🖥️ SOC Live", "🔍 Pentest", "📋 Compliance"])


# ══════════════════════════════════════════════════════════════════════════════
# TAB 0 — POSTURE
# ══════════════════════════════════════════════════════════════════════════════
with TABS[0]:
    col_badge, col_certs = st.columns([2, 3])

    with col_badge:
        posture = _get("/security/posture")
        err = _err(posture)
        if err:
            st.error(f"Could not load posture: {err}")
        else:
            badge  = posture.get("badge", "UNKNOWN")
            counts = posture.get("cve_counts", {})
            st.markdown(
                _badge_html(badge, counts, posture.get("last_scan")),
                unsafe_allow_html=True,
            )
            # Mini stat row
            c1, c2, c3 = st.columns(3)
            c1.markdown(
                f'<div class="sec-card"><div class="sec-val soc-crit">{counts.get("critical",0)}</div>'
                f'<div class="sec-lbl">Critical</div></div>', unsafe_allow_html=True,
            )
            c2.markdown(
                f'<div class="sec-card"><div class="sec-val soc-warn">{counts.get("high",0)}</div>'
                f'<div class="sec-lbl">High</div></div>', unsafe_allow_html=True,
            )
            c3.markdown(
                f'<div class="sec-card"><div class="sec-val">{counts.get("total",0)}</div>'
                f'<div class="sec-lbl">Total</div></div>', unsafe_allow_html=True,
            )

            st.divider()
            controls_pass  = posture.get("controls_passing", 0)
            controls_total = posture.get("controls_total",   0)
            if controls_total:
                pct = int(100 * controls_pass / controls_total)
                st.progress(pct / 100, text=f"Controls passing: {controls_pass}/{controls_total} ({pct}%)")

    with col_certs:
        st.subheader("Certifications")
        certs = posture.get("certifications", []) if isinstance(posture, dict) else []
        for cert in certs:
            status = cert.get("status", "")
            icon   = "✅" if status == "compliant" else ("🔄" if status == "in_progress" else "❌")
            link   = cert.get("link", "#")
            name   = cert.get("name", "")
            st.markdown(
                f"{icon} **[{name}]({link})** — `{status}`"
            )

        st.divider()
        st.subheader("Trigger CVE Scan")
        if st.button("🔍 Run CVE scan now", type="primary"):
            with st.spinner("Scanning dependencies against OSV API…"):
                result = _post("/security/cve-scan", admin=True)
                if result:
                    if result.get("queued"):
                        st.success("Scan queued in ARQ worker.")
                    else:
                        findings = result.get("total_findings", 0)
                        new_crit = result.get("new_criticals", 0)
                        st.success(f"Inline scan complete — {findings} findings, {new_crit} new critical.")
                    st.cache_data.clear()
                    st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — CVE FEED
# ══════════════════════════════════════════════════════════════════════════════
with TABS[1]:
    import pandas as pd
    import plotly.express as px

    # Sidebar filters (inline)
    col_f1, col_f2, col_f3 = st.columns([2, 2, 2])
    with col_f1:
        sev_filter = st.selectbox(
            "Severity filter",
            ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            key="cve_sev",
        )
    with col_f2:
        page_size = st.selectbox("Show per page", [25, 50, 100], key="cve_page")
    with col_f3:
        st.write("")  # spacer
        if st.button("🔄 Refresh", key="cve_refresh"):
            st.cache_data.clear()

    sev_param = "" if sev_filter == "All" else f"&severity={sev_filter}"
    feed = _get(f"/security/cve-feed?limit={page_size}&offset=0{sev_param}")
    err  = _err(feed)

    if err:
        st.error(f"CVE feed unavailable: {err}")
        st.info("Run a CVE scan first via the Posture tab.")
    else:
        findings = feed.get("findings", []) if isinstance(feed, dict) else []
        total    = feed.get("total", len(findings))

        if not findings:
            st.info("No CVE findings found. The last scan may not have detected any vulnerabilities, or no scan has run yet.")
        else:
            # Severity donut
            sev_counts: dict[str, int] = {}
            for f in findings:
                sev_counts[f.get("severity", "UNKNOWN")] = sev_counts.get(f.get("severity", "UNKNOWN"), 0) + 1

            col_chart, col_meta = st.columns([2, 3])
            with col_chart:
                color_map = {
                    "CRITICAL": "#fc8181", "HIGH": "#f6ad55",
                    "MEDIUM": "#f6e05e", "LOW": "#68d391", "UNKNOWN": "#a0aec0",
                }
                fig = px.pie(
                    names=list(sev_counts.keys()),
                    values=list(sev_counts.values()),
                    color=list(sev_counts.keys()),
                    color_discrete_map=color_map,
                    hole=0.55,
                    title=f"Severity distribution ({total} total)",
                )
                fig.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    font_color="#e2e8f0", legend_font_color="#a0aec0",
                    margin=dict(t=40, b=0, l=0, r=0),
                    height=260,
                )
                st.plotly_chart(fig, use_container_width=True)

            with col_meta:
                st.metric("Total findings", total)
                scanned_at = feed.get("scanned_at") if isinstance(feed, dict) else None
                if scanned_at:
                    st.caption(f"Last scan: {scanned_at[:19].replace('T',' ')} UTC")

            st.divider()
            # Findings table
            rows = []
            for f in findings:
                aliases = ", ".join(f.get("aliases", [])[:2])
                rows.append({
                    "Severity":  f.get("severity", ""),
                    "Package":   f.get("package", ""),
                    "Version":   f.get("version", ""),
                    "CVE / ID":  f.get("vuln_id", ""),
                    "Aliases":   aliases,
                    "Summary":   f.get("summary", "")[:120],
                    "Link":      f.get("link", ""),
                })
            df = pd.DataFrame(rows)

            # Color severity column
            def _color_sev(val: str) -> str:
                c = {"CRITICAL": "#fc8181", "HIGH": "#f6ad55",
                     "MEDIUM": "#f6e05e", "LOW": "#68d391"}.get(val, "#a0aec0")
                return f"color: {c}; font-weight: 700"

            styled = df.style.applymap(_color_sev, subset=["Severity"])
            st.dataframe(styled, use_container_width=True, hide_index=True,
                         column_config={"Link": st.column_config.LinkColumn("OSV Link")})


# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — SOC LIVE
# ══════════════════════════════════════════════════════════════════════════════
with TABS[2]:
    import plotly.graph_objects as go

    col_soc1, col_soc2 = st.columns([3, 2])

    with col_soc1:
        auto_refresh = st.toggle("Auto-refresh (30s)", value=False, key="soc_auto")
        health = _get("/soc/health")

        if _err(health):
            st.error(f"SOC health unavailable: {_err(health)}")
        else:
            cb     = health.get("circuit_breaker", {})
            cb_st  = cb.get("status", "unknown")
            bypass = health.get("bypass_rate_1m", 0.0)
            bans   = health.get("ers_bans_active", 0)
            rps    = health.get("requests_1m", 0)
            block  = health.get("block_rate_1m", 0.0)
            uptime = health.get("uptime_seconds", 0)
            ver    = health.get("warden_version", "—")

            # Circuit breaker indicator
            cb_color = {"closed": "soc-ok", "open": "soc-crit",
                        "half-open": "soc-warn"}.get(cb_st, "soc-warn")
            st.markdown(
                f'<h3>Circuit Breaker: <span class="{cb_color}">{cb_st.upper()}</span></h3>',
                unsafe_allow_html=True,
            )

            r1, r2, r3, r4 = st.columns(4)
            r1.metric("Bypass rate/min", f"{bypass:.1%}")
            r2.metric("ERS bans", bans)
            r3.metric("Requests/min", rps)
            r4.metric("Block rate/min", f"{block:.1%}")

            st.divider()
            # Bypass rate gauge
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=round(bypass * 100, 2),
                number={"suffix": "%", "font": {"color": "#e2e8f0"}},
                title={"text": "Bypass Rate (1m)", "font": {"color": "#a0aec0"}},
                gauge={
                    "axis": {"range": [0, 25], "tickcolor": "#4a5568"},
                    "bar":  {"color": "#fc8181" if bypass > 0.15 else ("#ecc94b" if bypass > 0.05 else "#48bb78")},
                    "steps": [
                        {"range": [0, 5],    "color": "#1a3a2a"},
                        {"range": [5, 15],   "color": "#3a3010"},
                        {"range": [15, 25],  "color": "#3a1010"},
                    ],
                    "threshold": {"line": {"color": "#fc8181", "width": 3}, "value": 15},
                },
            ))
            fig_gauge.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0",
                height=220, margin=dict(t=30, b=0, l=20, r=20),
            )
            st.plotly_chart(fig_gauge, use_container_width=True)

            st.caption(f"Warden v{ver} · uptime {int(uptime//3600)}h {int((uptime%3600)//60)}m")

    with col_soc2:
        st.subheader("Healer Report")
        healer_data = _get("/soc/healer")
        if _err(healer_data):
            st.warning("WardenHealer unavailable.")
        else:
            issues  = healer_data.get("issues", [])
            actions = healer_data.get("actions", [])
            clf     = healer_data.get("incident_classification")
            ts      = healer_data.get("ts", "")

            if not issues:
                st.success("✅ No anomalies detected")
            else:
                for iss in issues:
                    st.warning(f"⚠️ {iss}")
            if actions:
                st.divider()
                st.caption("Actions taken")
                for act in actions:
                    target = act.get("target", "")
                    kind   = act.get("kind",   "")
                    msg    = act.get("message", "")
                    st.markdown(f"• **{kind}** `{target}` — {msg}")
            if clf:
                st.divider()
                st.info(f"🤖 Haiku classification: {clf}")
            if ts:
                st.caption(f"Report at {ts[:19].replace('T',' ')} UTC")

        st.divider()
        if st.button("⚡ Run Healer now", type="primary", key="soc_heal"):
            with st.spinner("Running WardenHealer…"):
                result = _post("/soc/heal", admin=True)
                if result:
                    n = len(result.get("actions", []))
                    st.success(f"Healer complete. {n} action(s) taken.")
                    st.cache_data.clear()
                    st.rerun()

    if auto_refresh:
        time.sleep(30)
        st.cache_data.clear()
        st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 — PENTEST
# ══════════════════════════════════════════════════════════════════════════════
with TABS[3]:
    import plotly.express as px

    col_pt1, col_pt2 = st.columns([3, 2])

    with col_pt1:
        status_filter = st.selectbox(
            "Status", ["all", "open", "remediated", "accepted"], key="pt_status"
        )
        param = "" if status_filter == "all" else f"?status={status_filter}"
        pentest = _get(f"/security/pentest{param}&redacted=false")

        if _err(pentest):
            st.warning(f"Pentest endpoint unavailable: {_err(pentest)}")
        else:
            findings = pentest.get("findings", []) if isinstance(pentest, dict) else []
            count    = pentest.get("count", len(findings))
            st.caption(f"{count} finding(s)")

            if not findings:
                st.info("No pentest findings recorded yet.")
            else:
                for f in findings:
                    sev    = f.get("severity", "LOW")
                    status = f.get("status", "open")
                    title  = f.get("title", "Untitled")
                    rem_at = f.get("remediated_at") or "—"
                    cve    = f.get("cve_id") or ""
                    summ   = f.get("summary", "")

                    icon = "🔴" if sev == "CRITICAL" else ("🟠" if sev == "HIGH" else ("🟡" if sev == "MEDIUM" else "🟢"))
                    closed = "✅" if status == "remediated" else ("🔒" if status == "accepted" else "🔓")

                    with st.expander(f"{icon} {closed} [{sev}] {title}"):
                        st.markdown(f"**Status:** `{status}` · **Remediated:** `{rem_at}`")
                        if cve:
                            st.markdown(f"**CVE:** `{cve}`")
                        if summ:
                            st.markdown(summ)

    with col_pt2:
        st.subheader("Add Finding")
        with st.form("add_pentest", clear_on_submit=True):
            pt_title = st.text_input("Title")
            pt_sev   = st.selectbox("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
            pt_status_new = st.selectbox("Status", ["open", "remediated", "accepted"])
            pt_summary = st.text_area("Summary", height=120)
            pt_cve   = st.text_input("CVE ID (optional)")
            pt_rem   = st.text_input("Remediated at (ISO date, optional)")
            submitted = st.form_submit_button("➕ Add finding", type="primary")
            if submitted:
                if not pt_title or not pt_summary:
                    st.error("Title and summary are required.")
                else:
                    body = {
                        "title": pt_title, "severity": pt_sev,
                        "status": pt_status_new, "summary": pt_summary,
                        "cve_id": pt_cve or None,
                        "remediated_at": pt_rem or None,
                    }
                    result = _post("/security/pentest", body=body, admin=True)
                    if result:
                        st.success(f"Finding added: `{result.get('id','')[:8]}`")
                        st.cache_data.clear()
                        st.rerun()

        # Timeline chart
        pentest_all = _get("/security/pentest?redacted=false")
        if isinstance(pentest_all, dict):
            all_findings = pentest_all.get("findings", [])
            if all_findings:
                import pandas as pd
                rows = []
                for f in all_findings:
                    rows.append({
                        "Severity": f.get("severity", ""),
                        "Status":   f.get("status", ""),
                        "Date":     f.get("created_at", f.get("remediated_at", ""))[:10] if f.get("created_at") else None,
                    })
                df_pt = pd.DataFrame(rows).dropna(subset=["Date"])
                if not df_pt.empty:
                    st.divider()
                    sev_ct = df_pt.groupby("Severity").size().reset_index(name="Count")
                    color_map = {"CRITICAL": "#fc8181", "HIGH": "#f6ad55",
                                 "MEDIUM": "#f6e05e", "LOW": "#68d391", "INFO": "#a0aec0"}
                    fig_pt = px.bar(sev_ct, x="Severity", y="Count",
                                    color="Severity", color_discrete_map=color_map,
                                    title="Findings by severity")
                    fig_pt.update_layout(
                        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                        font_color="#e2e8f0", showlegend=False,
                        height=220, margin=dict(t=40, b=0, l=0, r=0),
                    )
                    st.plotly_chart(fig_pt, use_container_width=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 4 — COMPLIANCE
# ══════════════════════════════════════════════════════════════════════════════
with TABS[4]:
    compliance = _get("/security/compliance")

    if _err(compliance):
        st.error(f"Compliance data unavailable: {_err(compliance)}")
    else:
        controls = compliance.get("controls", []) if isinstance(compliance, dict) else []
        certs    = compliance.get("certifications", []) if isinstance(compliance, dict) else []

        # Certifications grid
        st.subheader("Certifications")
        cert_cols = st.columns(len(certs) if certs else 1)
        for col, cert in zip(cert_cols, certs):
            status = cert.get("status", "")
            icon   = "✅" if status == "compliant" else ("🔄" if status == "in_progress" else "❌")
            color  = "#48bb78" if status == "compliant" else ("#ecc94b" if status == "in_progress" else "#fc8181")
            col.markdown(
                f"""<div class="sec-card" style="border-color:{color}">
                  <div style="font-size:2rem">{icon}</div>
                  <div style="color:{color};font-weight:700;margin-top:8px">{cert.get("name","")}</div>
                  <div class="sec-lbl">{status}</div>
                </div>""",
                unsafe_allow_html=True,
            )

        st.divider()
        st.subheader("Controls")

        if not controls:
            st.info("No controls configured.")
        else:
            import pandas as pd
            rows = []
            for ctrl in controls:
                status = ctrl.get("status", "unknown")
                icon   = "✅" if status == "passing" else ("❌" if status == "failing" else "🔄")
                rows.append({
                    "": icon,
                    "Framework": ctrl.get("framework", ""),
                    "Control":   ctrl.get("control", ""),
                    "Status":    status,
                    "Evidence":  ctrl.get("evidence", ""),
                })
            df_ctrl = pd.DataFrame(rows)

            def _color_ctrl(val: str) -> str:
                return {"passing": "color:#48bb78", "failing": "color:#fc8181"}.get(val, "color:#ecc94b")

            styled_ctrl = df_ctrl.style.applymap(_color_ctrl, subset=["Status"])
            st.dataframe(styled_ctrl, use_container_width=True, hide_index=True)

        # Pass rate metric
        pass_count = sum(1 for c in controls if c.get("status") == "passing")
        if controls:
            pct = int(100 * pass_count / len(controls))
            color_bar = "#48bb78" if pct >= 90 else ("#ecc94b" if pct >= 70 else "#fc8181")
            st.progress(pct / 100,
                        text=f"Controls passing: {pass_count}/{len(controls)} ({pct}%)")
