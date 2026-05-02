"""
warden/analytics/pages/4_Community.py
────────────────────────────────────────
Community Business Dashboard — Streamlit page.

Tabs
────
  1. Overview       — risk score gauge, key metrics cards
  2. Transfers      — transfer stats, data class breakdown, top partners
  3. Peerings       — active peerins, policy distribution
  4. Governance     — charter status, acceptance rate, pending members
  5. Behavioral     — anomaly feed, baseline metrics
  6. OAuth Agents   — discovered AI agents, risk levels, revoke
  7. Intelligence   — full report JSON export
"""
from __future__ import annotations

import json
import os

import streamlit as st

st.set_page_config(
    page_title="Community Business — Shadow Warden AI",
    page_icon="🏘",
    layout="wide",
)

try:
    from warden.analytics.accessibility import inject_accessibility_widget
    inject_accessibility_widget()
except Exception:
    pass

# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
:root {
    --bg: #0D0D14;
    --card: #16161F;
    --border: #2A2A3A;
    --accent: #30D158;
    --warn: #FF9F0A;
    --danger: #FF2D55;
    --info: #0A84FF;
    --pqc: #BF5AF2;
    --text: #E8E8F0;
    --muted: #7A7A8C;
}
.stApp { background: var(--bg); color: var(--text); font-family: 'SF Mono', monospace; }
.metric-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 18px 22px;
    margin-bottom: 12px;
}
.metric-val { font-size: 2rem; font-weight: 700; }
.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: .04em;
}
.b-safe     { background: #30D15822; color: #30D158; border: 1px solid #30D15855; }
.b-low      { background: #0A84FF22; color: #0A84FF; border: 1px solid #0A84FF55; }
.b-medium   { background: #FF9F0A22; color: #FF9F0A; border: 1px solid #FF9F0A55; }
.b-high     { background: #FF2D5522; color: #FF2D55; border: 1px solid #FF2D5555; }
.b-critical { background: #BF5AF222; color: #BF5AF2; border: 1px solid #BF5AF255; }
.b-comm     { background: #30D15822; color: #30D158; border: 1px solid #30D15855; }
.section-hdr {
    font-size: 0.75rem;
    font-weight: 700;
    letter-spacing: .12em;
    text-transform: uppercase;
    color: var(--muted);
    margin: 20px 0 8px 0;
}
</style>
""", unsafe_allow_html=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

def badge(label: str, level: str) -> str:
    cls = {
        "SAFE": "b-safe", "LOW": "b-low", "MEDIUM": "b-medium",
        "HIGH": "b-high", "CRITICAL": "b-critical",
        "ACTIVE": "b-safe", "REVOKED": "b-high",
        "ALLOW": "b-safe", "MONITOR": "b-medium", "BLOCK": "b-high",
        "DRAFT": "b-medium", "SUPERSEDED": "b-low",
    }.get(level.upper(), "b-low")
    return f'<span class="badge {cls}">{label}</span>'


def card(title: str, value: str, color: str = "#E8E8F0", sub: str = "") -> str:
    return f"""
    <div class="metric-card">
        <div class="section-hdr">{title}</div>
        <div class="metric-val" style="color:{color}">{value}</div>
        {"<div style='color:#7A7A8C;font-size:.8rem;margin-top:4px'>" + sub + "</div>" if sub else ""}
    </div>"""


RISK_COLORS = {
    "SAFE": "#30D158", "LOW": "#0A84FF",
    "MEDIUM": "#FF9F0A", "HIGH": "#FF2D55", "CRITICAL": "#BF5AF2",
}


def _get_report(community_id: str) -> dict:
    try:
        from warden.communities.intelligence import generate_report
        return generate_report(community_id).to_dict()
    except Exception as exc:
        return {"error": str(exc)}


def _get_anomalies(community_id: str) -> list:
    try:
        from warden.communities.behavioral import list_recent_anomalies
        return list_recent_anomalies(community_id, limit=50)
    except Exception:
        return []


def _get_oauth_grants(community_id: str) -> list:
    try:
        from warden.communities.oauth_discovery import list_grants
        return [g.to_dict() for g in list_grants(community_id)]
    except Exception:
        return []


def _get_charter(community_id: str) -> dict | None:
    try:
        from warden.communities.charter import get_active_charter
        rec = get_active_charter(community_id)
        return rec.to_dict() if rec else None
    except Exception:
        return None


# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("### 🏘 Community Business")
    st.markdown(
        '<span class="badge b-comm">COMMUNITY $19</span>',
        unsafe_allow_html=True,
    )
    st.divider()

    community_id = st.text_input(
        "Community ID",
        value=os.getenv("DEFAULT_COMMUNITY_ID", ""),
        placeholder="COM-xxxxxxxxxxxx",
    )
    if st.button("🔄 Refresh", use_container_width=True):
        st.cache_data.clear()

    st.divider()
    st.caption("Shadow Warden AI v4.8")
    st.caption("Community Business · 3 communities · 10 members")

if not community_id:
    st.info("Enter a Community ID in the sidebar to begin.")
    st.stop()

# ── Data loading ──────────────────────────────────────────────────────────────

report    = _get_report(community_id)
anomalies = _get_anomalies(community_id)
oauth     = _get_oauth_grants(community_id)
charter   = _get_charter(community_id)

if "error" in report:
    st.error(f"Failed to generate report: {report['error']}")
    st.stop()

risk      = report.get("risk", {})
transfers = report.get("transfers", {})
peerings  = report.get("peerings", {})
gov       = report.get("governance", {})
recs      = report.get("recommendations", [])

risk_label = risk.get("label", "SAFE")
risk_color = RISK_COLORS.get(risk_label, "#E8E8F0")

# ── Page header ───────────────────────────────────────────────────────────────

st.markdown(
    f"## 🏘 {community_id} &nbsp;"
    f"{badge(risk_label, risk_label)} "
    f"{'&nbsp;' + badge('CHARTER ACTIVE', 'ACTIVE') if gov.get('charter_active') else ''}",
    unsafe_allow_html=True,
)
st.caption(f"Report generated: {report.get('generated_at','')}")
st.divider()

# ── Top KPI row ───────────────────────────────────────────────────────────────

c1, c2, c3, c4, c5 = st.columns(5)
with c1:
    st.markdown(card("Risk Score", f"{risk.get('overall',0)*100:.0f}%", risk_color, risk_label), unsafe_allow_html=True)
with c2:
    st.markdown(card("Transfers", str(transfers.get("total", 0)), "#E8E8F0",
                     f"{transfers.get('rejected',0)} rejected"), unsafe_allow_html=True)
with c3:
    st.markdown(card("Active Peerins", str(peerings.get("active", 0)), "#0A84FF",
                     f"of {peerings.get('total',0)} total"), unsafe_allow_html=True)
with c4:
    acc_rate = gov.get("acceptance_rate", 1.0)
    st.markdown(card("Charter Acceptance", f"{acc_rate*100:.0f}%",
                     "#30D158" if acc_rate >= 0.9 else "#FF9F0A",
                     f"{gov.get('pending_acceptances',0)} pending"), unsafe_allow_html=True)
with c5:
    st.markdown(card("OAuth Agents", str(len(oauth)), "#FF9F0A",
                     f"{sum(1 for g in oauth if g.get('verdict')=='BLOCK')} blocked"), unsafe_allow_html=True)

st.divider()

# ── Tabs ──────────────────────────────────────────────────────────────────────

tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
    "📊 Overview", "🔄 Transfers", "🔗 Peerins",
    "📋 Governance", "🧠 Behavioral", "🤖 OAuth Agents", "📄 Export",
])


# ─── TAB 1: Overview ─────────────────────────────────────────────────────────
with tab1:
    st.subheader("Risk Breakdown")
    rc1, rc2, rc3 = st.columns(3)
    with rc1:
        v = risk.get("anomaly_score", 0)
        st.metric("Anomaly Score", f"{v*100:.1f}%",
                  delta=None, help="Fraction of CRITICAL anomalies in recent window")
        st.progress(v)
    with rc2:
        v = risk.get("transfer_rejection_rate", 0)
        st.metric("Transfer Rejection Rate", f"{v*100:.1f}%",
                  help=">10% warrants investigation")
        st.progress(v)
    with rc3:
        v = risk.get("governance_gap", 0)
        st.metric("Governance Gap", f"{v*100:.1f}%",
                  help="1 − charter acceptance rate")
        st.progress(v)

    if recs:
        st.subheader("Recommendations")
        for r in recs:
            st.info(r)


# ─── TAB 2: Transfers ────────────────────────────────────────────────────────
with tab2:
    st.subheader("Transfer Statistics")
    t1, t2, t3 = st.columns(3)
    t1.metric("Total Transfers", transfers.get("total", 0))
    t2.metric("Accepted", transfers.get("accepted", 0))
    t3.metric("Rejected", transfers.get("rejected", 0))

    dc = transfers.get("by_data_class", {})
    if dc:
        st.subheader("By Data Class")
        st.bar_chart(dc)

    top = transfers.get("top_target_communities", [])
    if top:
        st.subheader("Top Target Communities")
        for item in top:
            st.markdown(f"- `{item['community_id']}` — **{item['count']}** transfers")


# ─── TAB 3: Peerins ──────────────────────────────────────────────────────────
with tab3:
    st.subheader("Peering Registry")
    p1, p2, p3 = st.columns(3)
    p1.metric("Total", peerings.get("total", 0))
    p2.metric("Active", peerings.get("active", 0))
    p3.metric("Revoked", peerings.get("revoked", 0))

    pol = peerings.get("by_policy", {})
    if pol:
        st.subheader("By Policy")
        for p, cnt in pol.items():
            st.markdown(
                f'{badge(p, "ACTIVE" if p != "MIRROR_ONLY" else "LOW")} &nbsp; **{cnt}**',
                unsafe_allow_html=True,
            )


# ─── TAB 4: Governance ───────────────────────────────────────────────────────
with tab4:
    st.subheader("Community Charter")

    if not charter:
        st.warning("No active charter. Publish one to enforce governance rules.")
        with st.expander("Create Charter"), st.form("charter_form"):
                title   = st.text_input("Charter Title", "Community Data Governance Charter v1")
                trans   = st.selectbox("Transparency", ["REQUIRED", "ENCOURAGED", "OPTIONAL"])
                dm      = st.selectbox("Data Minimization", ["STRICT", "STANDARD", "RELAXED"])
                sust    = st.selectbox("Sustainability", ["STANDARD", "ADVANCED", "CERTIFIED"])
                submit  = st.form_submit_button("Create DRAFT Charter")
                if submit:
                    try:
                        from warden.communities.charter import create_charter, publish_charter
                        rec = create_charter(
                            community_id, title, "dashboard-user",
                            transparency=trans,
                            data_minimization=dm,
                            sustainability=sust,
                        )
                        publish_charter(rec.charter_id)
                        st.success(f"Charter {rec.charter_id} created and published.")
                        st.rerun()
                    except Exception as exc:
                        st.error(str(exc))
    else:
        g1, g2, g3 = st.columns(3)
        g1.metric("Charter Version", charter.get("version", 0))
        g2.metric("Acceptance Rate", f"{gov.get('acceptance_rate',1)*100:.0f}%")
        g3.metric("Pending Acceptances", gov.get("pending_acceptances", 0))

        st.markdown("**Charter Details**")
        st.json({
            "title":              charter.get("title"),
            "transparency":       charter.get("transparency"),
            "data_minimization":  charter.get("data_minimization"),
            "sustainability":     charter.get("sustainability"),
            "allowed_data_classes": charter.get("allowed_data_classes"),
            "prohibited_actions": charter.get("prohibited_actions"),
            "auto_block_threshold": charter.get("auto_block_threshold"),
        })


# ─── TAB 5: Behavioral ───────────────────────────────────────────────────────
with tab5:
    st.subheader("Recent Anomalies")

    if not anomalies:
        st.success("No anomalies detected in behavioral history.")
    else:
        for a in anomalies[:20]:
            sev = a.get("severity", "ELEVATED")
            color = "#FF2D55" if sev == "CRITICAL" else "#FF9F0A"
            st.markdown(
                f"{badge(sev, sev)} &nbsp;"
                f"`{a.get('event_type')}` &nbsp; value={a.get('value', 0):.2f} "
                f"z={a.get('z_score', 0):.2f} &nbsp; "
                f"<span style='color:#7A7A8C'>{a.get('recorded_at','')[:19]}</span>",
                unsafe_allow_html=True,
            )

    st.divider()
    st.subheader("Record Behavioral Event")
    with st.form("behavioral_form"):
        evt_type = st.selectbox("Event Type", [
            "request", "transfer", "bulk_transfer",
            "off_hours_access", "new_peering", "file_scan",
        ])
        evt_val  = st.number_input("Value", value=1.0, step=0.1)
        if st.form_submit_button("Record + Detect"):
            try:
                from warden.communities.behavioral import detect_anomaly, record_event
                record_event(community_id, evt_type, evt_val)
                result = detect_anomaly(community_id, evt_type, evt_val)
                r = result.to_dict()
                st.markdown(
                    f"{badge(r['severity'], r['severity'])} &nbsp; z={r['z_score']:.2f} &nbsp; "
                    f"action=**{r['action']}** &nbsp; {r['reason']}",
                    unsafe_allow_html=True,
                )
            except Exception as exc:
                st.error(str(exc))


# ─── TAB 6: OAuth Agents ─────────────────────────────────────────────────────
with tab6:
    st.subheader("Discovered AI OAuth Agents")

    if not oauth:
        st.info("No OAuth agents registered for this community.")
    else:
        for g in oauth:
            rl = g.get("risk_level", "MEDIUM")
            vrd = g.get("verdict", "MONITOR")
            with st.expander(
                f"{g.get('display_name',g.get('provider'))} — {g.get('member_id')}",
                expanded=(rl in ("HIGH", "CRITICAL")),
            ):
                st.markdown(
                    f"{badge(rl, rl)} &nbsp; {badge(vrd, vrd)} &nbsp; "
                    f"scopes: `{', '.join(g.get('scopes',[]))}`",
                    unsafe_allow_html=True,
                )
                st.caption(f"Detected: {g.get('detected_at','')[:19]}")
                if st.button(f"Revoke {g['grant_id']}", key=f"rev_{g['grant_id']}"):
                    try:
                        from warden.communities.oauth_discovery import revoke_grant
                        revoke_grant(g["grant_id"])
                        st.success("Grant revoked.")
                        st.rerun()
                    except Exception as exc:
                        st.error(str(exc))

    st.divider()
    st.subheader("Register OAuth Grant")
    with st.form("oauth_form"):
        oa_member   = st.text_input("Member ID")
        oa_provider = st.selectbox("Provider", [
            "chatgpt_plugin", "openai_api", "copilot", "github_copilot",
            "zapier", "make", "jasper", "notion_ai", "otter_ai",
            "anthropic_app", "cohere", "perplexity", "grammarly", "other",
        ])
        oa_scopes   = st.multiselect("Scopes", ["read", "write", "admin", "delete", "publish", "calendar", "code"])
        if st.form_submit_button("Register"):
            try:
                from warden.communities.oauth_discovery import register_oauth_grant
                grant = register_oauth_grant(community_id, oa_member, oa_provider, oa_scopes)
                st.markdown(
                    f"Registered {badge(grant.risk_level, grant.risk_level)} "
                    f"{badge(grant.verdict, grant.verdict)} `{grant.grant_id}`",
                    unsafe_allow_html=True,
                )
                st.rerun()
            except Exception as exc:
                st.error(str(exc))


# ─── TAB 7: Export ───────────────────────────────────────────────────────────
with tab7:
    st.subheader("Full Intelligence Report")
    st.json(report)
    st.download_button(
        label="⬇ Download JSON",
        data=json.dumps(report, indent=2),
        file_name=f"community_intel_{community_id}.json",
        mime="application/json",
    )
