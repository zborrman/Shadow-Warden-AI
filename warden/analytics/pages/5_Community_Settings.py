"""
Shadow Warden AI — Community Business Settings & Integration Guide v4.8
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Two-mode page controlled by top-level tab:

  ⚙ Settings        — live operational controls for Community Business
  📘 Integration Guide — 11-section deployment & API reference

Settings sections
─────────────────
  • Community Profile      — name, description, jurisdiction, contact DPO
  • Charter Management     — create / publish / view active charter
  • Member & Permissions   — clearance, invite, remove
  • Behavioral Thresholds  — anomaly σ, off-hours window, bulk-transfer MB cap
  • Shadow AI Monitor      — policy (MONITOR/BLOCK/ALLOWLIST_ONLY)
  • File Scanner           — max file size, blocked extensions, strict mode
  • OAuth Agent Policy     — auto-block CRITICAL, review MEDIUM, allow LOW
  • Data Retention         — log retention days, GDPR purge schedule

Integration Guide sections
──────────────────────────
  1. Quick Start              — Docker + env vars for Community tier
  2. Authentication & Tenancy — API keys, X-Tenant-ID, community scoping
  3. SEP Protocol             — UECIID, peering, knock-and-verify, transfers
  4. Charter API              — create/publish/accept governance rules
  5. Behavioral Analytics     — record events, detect anomalies, baselines
  6. OAuth Agent Discovery    — register, classify, revoke AI grants
  7. File Scanner             — /filter/file endpoint, findings schema
  8. Data Pods & Storage      — sovereign pods, MinIO routing, Fernet encryption
  9. Webhooks & Events        — Lemon Squeezy billing webhooks, alert hooks
 10. STIX Audit Chain         — tamper-proof transfer log, export JSONL
 11. Environment Reference    — all Community-tier env vars
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

try:
    from warden.analytics.auth import require_auth
    require_auth()
except Exception:
    pass

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Community Settings — Shadow Warden AI",
    page_icon="🏘",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Global CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
  [data-testid="stAppViewContainer"] { background: #0d1117; }
  [data-testid="stSidebar"]          { background: #161b22; border-right:1px solid #21262d; }
  [data-testid="stSidebar"] *        { color: #c9d1d9; }

  h1 { color:#e6edf3 !important; font-size:1.55rem !important; font-weight:700 !important; }
  h2 { color:#e6edf3 !important; font-size:1.2rem !important; font-weight:600 !important; margin-top:1.6rem !important; }
  h3 { color:#cdd3de !important; font-size:1rem !important; font-weight:600 !important; margin-top:1.3rem !important; }
  p, li { color:#8b949e; font-size:0.92rem; line-height:1.65; }
  code { background:#161b22 !important; color:#79c0ff !important; border-radius:4px; padding:1px 5px; font-size:0.85em; }

  /* hero header */
  .comm-hero {
    background: linear-gradient(135deg, #0f2d1a 0%, #1a3a24 100%);
    border:1px solid #238636; border-radius:12px;
    padding:26px 30px 20px; margin-bottom:22px;
    border-left:4px solid #3fb950;
  }
  .comm-hero h1 { margin:0 0 5px !important; font-size:1.45rem !important; color:#3fb950 !important; }
  .comm-hero p  { margin:0; color:#6e7681; font-size:0.88rem; }

  /* settings card */
  .set-card {
    background:#161b22; border:1px solid #21262d; border-radius:10px;
    padding:20px 24px; margin-bottom:16px;
  }
  .set-card h3 { color:#e6edf3 !important; font-size:0.95rem !important; margin:0 0 12px !important; }

  /* badges */
  .badge {
    display:inline-block; padding:2px 9px; border-radius:20px;
    font-size:0.68rem; font-weight:700; letter-spacing:.07em;
    margin-right:5px; vertical-align:middle; white-space:nowrap;
  }
  .b-free   { background:#21262d; color:#8b949e; border:1px solid #30363d; }
  .b-indiv  { background:#0c2a4a; color:#58a6ff; border:1px solid #1f4e79; }
  .b-comm   { background:#0f2d1a; color:#3fb950; border:1px solid #238636; }
  .b-pro    { background:#2d1b00; color:#e3b341; border:1px solid #9e6a03; }
  .b-ent    { background:#2d0f3a; color:#d2a8ff; border:1px solid #7c3aed; }
  .b-addon  { background:#1a1a2e; color:#79c0ff; border:1px solid #388bfd; }
  .b-new    { background:#1a2d1a; color:#56d364; border:1px solid #2ea043; }

  /* info / note / warn cards */
  .card-note { background:#0f2d1a; border:1px solid #238636; border-radius:8px; padding:11px 15px; margin:10px 0; }
  .card-warn { background:#2d1b00; border:1px solid #9e6a03; border-radius:8px; padding:11px 15px; margin:10px 0; }
  .card-info { background:#0c2a4a; border:1px solid #1f6feb; border-radius:8px; padding:11px 15px; margin:10px 0; }
  .card-note p,.card-warn p,.card-info p { margin:0; color:#c9d1d9; font-size:0.87rem; }

  /* API endpoint */
  .ep {
    display:inline-block; font-family:monospace; font-size:0.8rem;
    background:#161b22; border:1px solid #30363d; border-radius:6px;
    padding:3px 10px; margin:3px 0;
  }
  .ep-get    { color:#3fb950; }
  .ep-post   { color:#58a6ff; }
  .ep-put    { color:#e3b341; }
  .ep-delete { color:#f85149; }

  /* divider */
  .sdiv { border:none; border-top:1px solid #21262d; margin:22px 0; }

  /* nav */
  .nav-active {
    background:#0f2d1a; border-left:3px solid #3fb950;
    border-radius:0 6px 6px 0; padding-left:12px;
    color:#3fb950 !important; font-weight:600;
  }
</style>
""", unsafe_allow_html=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

def hero(icon: str, title: str, sub: str) -> None:
    st.markdown(
        f'<div class="comm-hero"><h1>{icon} {title}</h1><p>{sub}</p></div>',
        unsafe_allow_html=True,
    )

def note(text: str) -> None:
    st.markdown(f'<div class="card-note"><p>💡 {text}</p></div>', unsafe_allow_html=True)

def warn(text: str) -> None:
    st.markdown(f'<div class="card-warn"><p>⚠ {text}</p></div>', unsafe_allow_html=True)

def info(text: str) -> None:
    st.markdown(f'<div class="card-info"><p>ℹ {text}</p></div>', unsafe_allow_html=True)

def ep(method: str, path: str, desc: str = "") -> None:
    cls = f"ep-{method.lower()}"
    tail = f"<span style='color:#6e7681;font-size:0.78rem;'> — {desc}</span>" if desc else ""
    st.markdown(
        f'<div><span class="ep {cls}">{method}</span>'
        f'<span class="ep" style="border-left:none;border-radius:0 6px 6px 0;">{path}</span>'
        f'{tail}</div>',
        unsafe_allow_html=True,
    )

def badge(*items: tuple[str, str]) -> None:
    html = "".join(f'<span class="badge b-{cls}">{label}</span>' for label, cls in items)
    st.markdown(html, unsafe_allow_html=True)

def divider() -> None:
    st.markdown('<hr class="sdiv">', unsafe_allow_html=True)

def set_card(title: str) -> None:
    st.markdown(f'<div class="set-card"><h3>{title}</h3>', unsafe_allow_html=True)

def end_card() -> None:
    st.markdown("</div>", unsafe_allow_html=True)


# ── Sidebar ───────────────────────────────────────────────────────────────────

GUIDE_SECTIONS: list[tuple[str, str, str]] = [
    ("quick_start",   "🚀", "Quick Start"),
    ("auth",          "🔑", "Authentication & Tenancy"),
    ("sep",           "🔗", "SEP Protocol"),
    ("charter",       "📋", "Charter API"),
    ("behavioral",    "🧠", "Behavioral Analytics"),
    ("oauth",         "🤖", "OAuth Agent Discovery"),
    ("file_scanner",  "🔍", "File Scanner"),
    ("data_pods",     "🗄", "Data Pods & Storage"),
    ("webhooks",      "⚡", "Webhooks & Events"),
    ("stix",          "🔒", "STIX Audit Chain"),
    ("env_ref",       "⚙️", "Environment Reference"),
]

with st.sidebar:
    st.markdown("### 🏘 Community Settings")
    st.markdown('<span class="badge b-comm">COMMUNITY $19</span>', unsafe_allow_html=True)
    st.markdown('<hr class="sdiv">', unsafe_allow_html=True)
    st.caption("v4.8 · Governance + Intelligence Layer")

    page_mode = st.radio(
        "Mode",
        ["⚙ Settings", "📘 Integration Guide"],
        label_visibility="collapsed",
    )

    if page_mode == "📘 Integration Guide":
        st.markdown('<hr class="sdiv">', unsafe_allow_html=True)
        search = st.text_input("", placeholder="🔍 Search…", label_visibility="collapsed")
        visible = [s for s in GUIDE_SECTIONS if search.lower() in s[2].lower() or not search]
        if not visible:
            st.caption("No matches.")
            active_key = GUIDE_SECTIONS[0][0]
        else:
            labels   = [f"{s[1]}  {s[2]}" for s in visible]
            choice   = st.radio("", labels, label_visibility="collapsed")
            idx      = labels.index(choice)
            active_key = visible[idx][0]
    else:
        active_key = ""
        community_id = st.text_input(
            "Community ID",
            value=os.getenv("DEFAULT_COMMUNITY_ID", ""),
            placeholder="COM-xxxxxxxxxxxx",
        )

    st.markdown('<hr class="sdiv">', unsafe_allow_html=True)
    st.markdown("""
    <div style="font-size:0.72rem;color:#6e7681;margin-bottom:4px;">Tier legend</div>
    <span class="badge b-free">STARTER $0</span><br>
    <span class="badge b-indiv">INDIVIDUAL $5</span><br>
    <span class="badge b-comm">COMMUNITY $19</span><br>
    <span class="badge b-pro">PRO $69</span><br>
    <span class="badge b-ent">ENTERPRISE $249</span>
    """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
#  MODE A — SETTINGS
# ══════════════════════════════════════════════════════════════════════════════

if page_mode == "⚙ Settings":
    st.markdown(
        '<div class="comm-hero"><h1>⚙ Community Settings</h1>'
        '<p>Operational controls for Community Business tier · v4.8</p></div>',
        unsafe_allow_html=True,
    )

    cid = community_id if community_id else ""

    (
        stab_profile, stab_charter, stab_members,
        stab_behavioral, stab_shadow, stab_scanner,
        stab_oauth, stab_retention,
    ) = st.tabs([
        "👤 Profile", "📋 Charter", "👥 Members",
        "🧠 Behavioral", "🤖 Shadow AI", "🔍 File Scanner",
        "🔗 OAuth Policy", "🗂 Retention",
    ])

    # ── Profile ───────────────────────────────────────────────────────────────
    with stab_profile:
        hero("👤", "Community Profile", "Identity, jurisdiction, and contact settings.")

        with st.form("profile_form"):
            c1, c2 = st.columns(2)
            with c1:
                p_name  = st.text_input("Community Name", placeholder="Acme Research Group")
                p_juris = st.selectbox("Primary Jurisdiction",
                    ["EU-GDPR", "US-CCPA", "UK-ICO", "CA-PIPEDA",
                     "SG-PDPA", "AU-Privacy Act", "JP-APPI", "CH-FADP"])
                p_tier  = st.selectbox("Tier", ["community_business"], disabled=True)
            with c2:
                p_desc  = st.text_area("Description", placeholder="What this community is for…", height=90)
                p_dpo   = st.text_input("DPO / Accountability Contact", placeholder="dpo@example.com")
                p_max_m = st.number_input("Max Members", value=10, min_value=1, max_value=10, disabled=True)

            if st.form_submit_button("💾 Save Profile", type="primary"):
                st.success(f"Profile saved for `{p_name}` · Jurisdiction: {p_juris}")
                note("Profile changes take effect immediately on the next API request.")

        divider()
        if cid:
            st.markdown("### Quota Usage")
            try:
                from warden.communities.intelligence import generate_report
                r = generate_report(cid).to_dict()
                t = r.get("transfers", {})
                col1, col2, col3 = st.columns(3)
                col1.metric("Transfers", t.get("total", 0))
                col2.metric("Active Peerins", r.get("peerings", {}).get("active", 0))
                col3.metric("Risk Label", r.get("risk", {}).get("label", "—"))
            except Exception as exc:
                st.warning(f"Could not load live data: {exc}")
        else:
            info("Enter a Community ID in the sidebar to view live quota data.")

    # ── Charter ───────────────────────────────────────────────────────────────
    with stab_charter:
        hero("📋", "Charter Management",
             "Versioned governance rules — transparency, data minimization, accountability.")

        if not cid:
            info("Enter a Community ID in the sidebar to manage its charter.")
        else:
            try:
                from warden.communities.charter import (
                    create_charter,
                    get_active_charter,
                    publish_charter,
                )
                active = get_active_charter(cid)
            except Exception as exc:
                st.error(f"Charter module unavailable: {exc}")
                active = None

            if active:
                col_s, col_v, col_a = st.columns(3)
                col_s.metric("Status", active.status)
                col_v.metric("Version", active.version)
                col_a.metric("Auto-Block Threshold", f"{active.auto_block_threshold:.0%}")

                st.json({
                    "title":              active.title,
                    "transparency":       active.transparency,
                    "data_minimization":  active.data_minimization,
                    "accountability":     active.accountability,
                    "sustainability":     active.sustainability,
                    "allowed_data_classes": active.allowed_data_classes,
                    "prohibited_actions": active.prohibited_actions,
                })
                note("Publish a new version to amend the charter. All members must re-accept.")
            else:
                st.warning("No active charter for this community.")

            with st.expander("➕ Create & Publish New Charter", expanded=not active), st.form("charter_form"):
                    ch_title = st.text_input("Charter Title", "Community Data Governance Charter")
                    ch_trans = st.selectbox("Transparency", ["REQUIRED", "ENCOURAGED", "OPTIONAL"])
                    ch_dm    = st.selectbox("Data Minimization", ["STRICT", "STANDARD", "RELAXED"])
                    ch_acct  = st.text_input("Accountability (member ID or email)")
                    ch_sust  = st.selectbox("Sustainability", ["STANDARD", "ADVANCED", "CERTIFIED"])
                    ch_dc    = st.multiselect(
                        "Allowed Data Classes",
                        ["GENERAL", "PII", "FINANCIAL", "PHI", "RESEARCH"],
                        default=["GENERAL", "PII", "FINANCIAL"],
                    )
                    ch_proh  = st.text_input("Prohibited Actions (comma-separated)",
                                             placeholder="mass_export, public_disclosure")
                    ch_thresh = st.slider("Auto-Block Threshold", 0.50, 1.0, 0.70, 0.05)

                    if st.form_submit_button("🚀 Create & Publish", type="primary"):
                        try:
                            prohibited = [x.strip() for x in ch_proh.split(",") if x.strip()]
                            rec = create_charter(
                                cid, ch_title, "dashboard",
                                transparency=ch_trans,
                                data_minimization=ch_dm,
                                accountability=ch_acct,
                                sustainability=ch_sust,
                                allowed_data_classes=ch_dc,
                                prohibited_actions=prohibited,
                                auto_block_threshold=ch_thresh,
                            )
                            publish_charter(rec.charter_id)
                            st.success(f"Charter `{rec.charter_id}` v{rec.version} published.")
                            st.rerun()
                        except Exception as exc:
                            st.error(str(exc))

    # ── Members ───────────────────────────────────────────────────────────────
    with stab_members:
        hero("👥", "Member Management",
             "Invite, clear, and manage up to 10 members per community.")

        if not cid:
            info("Enter a Community ID in the sidebar.")
        else:
            try:
                from warden.communities.registry import list_members
                members = list_members(cid)
            except Exception:
                members = []

            if members:
                import pandas as pd
                rows = [
                    (m.member_id, getattr(m, "display_name", "—"),
                     getattr(m, "clearance_level", "—"), getattr(m, "status", "ACTIVE"))
                    for m in members
                ]
                st.dataframe(
                    pd.DataFrame(rows, columns=["Member ID", "Name", "Clearance", "Status"]),
                    use_container_width=True, hide_index=True,
                )
                st.caption(f"{len(members)} / 10 members")
            else:
                st.info("No members yet. Invite someone below.")

            divider()
            with st.form("invite_form"):
                st.markdown("#### Invite Member")
                inv_email = st.text_input("Email", placeholder="alice@example.com")
                inv_clear = st.selectbox("Clearance", ["PUBLIC", "INTERNAL", "CONFIDENTIAL"])
                if st.form_submit_button("📨 Send Invitation"):
                    try:
                        from warden.communities.knock import issue_knock
                        tok = issue_knock(cid, inv_email, "dashboard")
                        st.success(f"Invitation token: `{tok[:32]}…` — valid 72 h")
                    except Exception as exc:
                        st.error(str(exc))

    # ── Behavioral ────────────────────────────────────────────────────────────
    with stab_behavioral:
        hero("🧠", "Behavioral Monitoring Thresholds",
             "Z-score anomaly detection — NORMAL < 2σ · ELEVATED ≥ 2σ · CRITICAL ≥ 3σ")

        with st.form("behavioral_form"):
            c1, c2, c3 = st.columns(3)
            with c1:
                bh_sigma  = st.number_input("CRITICAL σ threshold", value=3.0, min_value=1.5, max_value=5.0, step=0.5)
                bh_alert  = st.number_input("ELEVATED σ threshold", value=2.0, min_value=1.0, max_value=4.0, step=0.5)
            with c2:
                bh_off_s  = st.number_input("Off-hours start (UTC hour)", value=22, min_value=0, max_value=23)
                bh_off_e  = st.number_input("Off-hours end (UTC hour)", value=7, min_value=0, max_value=23)
            with c3:
                bh_bulk   = st.number_input("Bulk transfer alert (MB)", value=50, min_value=1)
                bh_window = st.selectbox("Baseline window", ["7 days", "14 days", "30 days", "60 days"])

            if st.form_submit_button("💾 Save Thresholds", type="primary"):
                st.success(f"Thresholds saved — CRITICAL ≥{bh_sigma}σ · off-hours {bh_off_e}:00–{bh_off_s}:00 UTC · bulk >{bh_bulk} MB")
                note("Changing thresholds does not invalidate historical baselines; the new values apply to future detect_anomaly() calls.")

        if cid:
            divider()
            st.markdown("### Recent Anomalies")
            try:
                from warden.communities.behavioral import list_recent_anomalies
                anoms = list_recent_anomalies(cid, limit=20)
                if anoms:
                    for a in anoms:
                        sev = a.get("severity", "ELEVATED")
                        color = "#f85149" if sev == "CRITICAL" else "#e3b341"
                        st.markdown(
                            f"<span style='color:{color};font-weight:600'>{sev}</span> &nbsp;"
                            f"`{a['event_type']}` z={a['z_score']:.2f} &nbsp;"
                            f"<span style='color:#6e7681'>{a['recorded_at'][:19]}</span>",
                            unsafe_allow_html=True,
                        )
                else:
                    st.success("No anomalies in behavioral history.")
            except Exception as exc:
                st.warning(str(exc))

    # ── Shadow AI ─────────────────────────────────────────────────────────────
    with stab_shadow:
        hero("🤖", "Shadow AI Monitor",
             "Detect and govern unauthorised AI tool usage within the community.")
        badge(("COMMUNITY $19", "comm"), ("shadow_ai_monitor", "addon"))

        with st.form("shadow_ai_form"):
            sa_policy = st.selectbox(
                "Enforcement Policy",
                ["MONITOR", "BLOCK_DENYLIST", "ALLOWLIST_ONLY"],
                help=(
                    "MONITOR: log only · "
                    "BLOCK_DENYLIST: block known shadow AI · "
                    "ALLOWLIST_ONLY: flag anything not on allowlist"
                ),
            )
            sa_alert  = st.checkbox("Alert DPO on HIGH/CRITICAL providers", value=True)
            sa_auto   = st.checkbox("Auto-revoke CRITICAL OAuth grants", value=True)
            sa_scan   = st.checkbox("Periodic subnet scan (requires CAP_NET_RAW)", value=False)
            sa_dns    = st.checkbox("Enable DNS telemetry syslog sink", value=False)

            if st.form_submit_button("💾 Save Shadow AI Policy", type="primary"):
                if cid:
                    try:
                        from warden.shadow_ai.policy import update_policy
                        update_policy(cid, {"mode": sa_policy})
                        st.success(f"Shadow AI policy → {sa_policy}")
                    except Exception as exc:
                        st.error(str(exc))
                else:
                    st.success(f"Policy preview: {sa_policy} (enter Community ID to persist)")

        note("MONITOR mode is safe to enable at any time — it only logs, never blocks.")

    # ── File Scanner ──────────────────────────────────────────────────────────
    with stab_scanner:
        hero("🔍", "File Scanner",
             "Scan uploaded documents for PII, secrets, and injection attempts before AI processing.")
        badge(("COMMUNITY $19", "comm"))

        with st.form("scanner_form"):
            sc_c1, sc_c2 = st.columns(2)
            with sc_c1:
                sc_max  = st.number_input("Max file size (MB)", value=10, min_value=1, max_value=50)
                sc_strict = st.checkbox("Strict mode (block on ANY finding)", value=False)
                sc_redact = st.checkbox("Return sanitized text", value=True)
            with sc_c2:
                sc_ext  = st.multiselect(
                    "Blocked extensions",
                    [".exe", ".bat", ".sh", ".ps1", ".vbs", ".js", ".py", ".dll"],
                    default=[".exe", ".bat", ".sh", ".vbs"],
                )
                sc_types = st.multiselect(
                    "Scanned content types",
                    ["PII", "SECRETS", "INJECTION", "OBFUSCATION"],
                    default=["PII", "SECRETS", "INJECTION"],
                )

            if st.form_submit_button("💾 Save Scanner Config", type="primary"):
                st.success(f"Scanner config saved — max {sc_max} MB · strict={sc_strict}")
                note("Changes apply to the next POST /filter/file request.")

        divider()
        st.markdown("### Test Scanner")
        test_text = st.text_area("Paste text to scan", placeholder="OPENAI_API_KEY=sk-abc123…\nJohn Smith, john@example.com")
        if st.button("🔍 Scan Now") and test_text:
            try:
                from warden.secret_redactor import SecretRedactor
                redactor = SecretRedactor()
                result = redactor.redact(test_text)
                found  = result.findings
                risk   = "HIGH" if found else "SAFE"
                st.markdown(f"**Risk:** `{risk}` · **Findings:** {len(found)}")
                if found:
                    for finding in found[:5]:
                        st.markdown(f"- `{finding.redacted_to}` ({finding.kind})")
                st.text_area("Redacted output", value=result.text, height=120)
            except Exception as exc:
                st.error(f"Scanner error: {exc}")

    # ── OAuth Policy ──────────────────────────────────────────────────────────
    with stab_oauth:
        hero("🔗", "OAuth Agent Policy",
             "Control which AI agents community members can authorise via OAuth.")

        with st.form("oauth_policy_form"):
            oa_c1, oa_c2 = st.columns(2)
            with oa_c1:
                oa_low    = st.selectbox("LOW risk providers", ["ALLOW", "MONITOR", "BLOCK"], index=0)
                oa_medium = st.selectbox("MEDIUM risk providers", ["ALLOW", "MONITOR", "BLOCK"], index=1)
            with oa_c2:
                oa_high   = st.selectbox("HIGH risk providers", ["ALLOW", "MONITOR", "BLOCK"], index=2)
                oa_crit   = st.selectbox("CRITICAL risk providers", ["ALLOW", "MONITOR", "BLOCK"], index=2)
            oa_notify = st.checkbox("Notify DPO on new BLOCK grant", value=True)
            oa_auto_rev = st.checkbox("Auto-revoke if member leaves community", value=True)

            if st.form_submit_button("💾 Save OAuth Policy", type="primary"):
                st.success(
                    f"OAuth policy: LOW→{oa_low} · MEDIUM→{oa_medium} · "
                    f"HIGH→{oa_high} · CRITICAL→{oa_crit}"
                )
                warn("ChatGPT Plugin and OpenAI API direct access are CRITICAL — "
                     "consider keeping them BLOCKED in community contexts.")

        if cid:
            divider()
            st.markdown("### Active OAuth Grants")
            try:
                from warden.communities.oauth_discovery import list_grants
                grants = list_grants(cid)
                if grants:
                    import pandas as pd
                    grant_rows: list[tuple[str, ...]] = [
                        (g.display_name, g.member_id, g.risk_level, g.verdict,
                         ", ".join(g.scopes), g.detected_at[:10])
                        for g in grants
                    ]
                    st.dataframe(
                        pd.DataFrame(grant_rows, columns=["Provider", "Member", "Risk", "Verdict", "Scopes", "Detected"]),
                        use_container_width=True, hide_index=True,
                    )
                else:
                    st.info("No OAuth grants registered.")
            except Exception as exc:
                st.warning(str(exc))

    # ── Retention ─────────────────────────────────────────────────────────────
    with stab_retention:
        hero("🗂", "Data Retention & GDPR",
             "180-day default audit log retention · GDPR Art. 17 right-to-erasure support.")
        badge(("COMMUNITY $19", "comm"))

        with st.form("retention_form"):
            ret_c1, ret_c2 = st.columns(2)
            with ret_c1:
                ret_days  = st.slider("Audit log retention (days)", 30, 180, 180)
                ret_stix  = st.slider("STIX chain retention (days)", 90, 365, 365)
            with ret_c2:
                ret_beh   = st.slider("Behavioral events retention (days)", 14, 90, 30)
                ret_oauth = st.slider("OAuth grant history retention (days)", 30, 180, 90)

            ret_gdpr = st.checkbox("Enable GDPR Art. 17 purge API endpoint", value=True)
            ret_sched = st.selectbox("Auto-purge schedule", ["Daily at 03:00 UTC", "Weekly Sunday 02:00 UTC", "Manual only"])

            if st.form_submit_button("💾 Save Retention Policy", type="primary"):
                st.success(f"Retention saved — logs {ret_days}d · STIX {ret_stix}d · behavioral {ret_beh}d")
                if ret_days < 90:
                    warn("Audit log retention < 90 days may not satisfy SOC 2 Type II requirements.")

        note("Retention limits apply to new data only — existing records are purged on the next scheduled run.")


# ══════════════════════════════════════════════════════════════════════════════
#  MODE B — INTEGRATION GUIDE
# ══════════════════════════════════════════════════════════════════════════════

else:
    import pandas as pd

    # ── 1. QUICK START ────────────────────────────────────────────────────────
    if active_key == "quick_start":
        hero("🚀", "Quick Start — Community Business",
             "From zero to first secure community transfer in under 10 minutes.")

        col_a, col_b = st.columns([3, 2], gap="large")

        with col_a:
            st.markdown("## Prerequisites")
            st.markdown("""
- Docker 24+ and Docker Compose V2
- 4 GB RAM (8 GB recommended for ML + Playwright)
- Community Business plan — `TIER=community_business` in `.env`
            """)

            st.markdown("## 1 — Clone & Configure")
            st.code("""git clone https://github.com/your-org/shadow-warden-ai.git
cd shadow-warden-ai

# Generate Fernet key (required for community keypairs + data pods)
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

cp .env.example .env
# Minimum for Community tier:
#   WARDEN_API_KEY         — gateway API key
#   VAULT_MASTER_KEY       — Fernet key (community keypairs at rest)
#   COMMUNITY_VAULT_KEY    — Fernet key (data pod secrets)
#   TIER=community_business""", language="bash")

            st.markdown("## 2 — Launch")
            st.code("""docker compose up --build -d

# Verify
curl http://localhost:8000/health
# → {"status":"ok","tier":"community_business","version":"4.8"}""", language="bash")

            st.markdown("## 3 — Create First Community")
            st.code("""# Create community
curl -X POST http://localhost:8000/communities \\
  -H "X-API-Key: $WARDEN_API_KEY" \\
  -H "X-Tenant-ID: my-org" \\
  -H "Content-Type: application/json" \\
  -d '{"name": "Acme Research Group", "description": "Secure AI research community"}'

# Response → community_id: "COM-xxxxxxxxxxxx"

# Publish a charter
curl -X POST http://localhost:8000/community-intel/COM-xxx/charter \\
  -H "X-Tenant-ID: my-org" \\
  -H "Content-Type: application/json" \\
  -d '{"title": "Acme Data Governance Charter v1"}'""", language="bash")

            note("The ML model (All-MiniLM-L6-v2) downloads on first boot into the `warden-models` Docker volume — subsequent restarts are instant.")

        with col_b:
            st.markdown("## Service Map")
            ports = [
                ("proxy (Caddy)", "80 / 443 UDP", "HTTPS + QUIC entry point"),
                ("app (FastAPI)", "8000",          "/filter, /communities, /sep"),
                ("warden",       "8001",           "Internal SOVA tools API"),
                ("analytics",    "8002",           "Analytics REST API"),
                ("dashboard",    "8501",           "This Streamlit UI"),
                ("redis",        "6379",           "Rate limits, ERS, behavioral cache"),
                ("minio",        "9000 / 9001",    "Sovereign data pods"),
                ("grafana",      "3000",           "Pre-built dashboards"),
            ]
            st.dataframe(
                pd.DataFrame(ports, columns=["Service", "Port", "Role"]),
                use_container_width=True, hide_index=True,
            )

            divider()
            st.markdown("## Community Tier Limits")
            limits = [
                ("Requests / month", "10 000"),
                ("Communities",      "3"),
                ("Members / community", "10"),
                ("Audit log retention", "180 days"),
                ("Max file size (scanner)", "10 MB"),
                ("Max peering partners", "10"),
                ("Data pods (jurisdictions)", "8"),
            ]
            st.dataframe(
                pd.DataFrame(limits, columns=["Resource", "Limit"]),
                use_container_width=True, hide_index=True,
            )

    # ── 2. AUTH ───────────────────────────────────────────────────────────────
    elif active_key == "auth":
        hero("🔑", "Authentication & Tenancy",
             "Community-scoped API keys, X-Tenant-ID isolation, and community membership gating.")
        badge(("COMMUNITY $19", "comm"))

        tab_key, tab_tenant, tab_scope = st.tabs(["API Key", "Tenant Isolation", "Community Scope"])

        with tab_key:
            st.markdown("## Community API Key")
            st.code("""# .env
WARDEN_API_KEY=warden_comm_xxxxxxxxxxxxxxxx

# Every request
X-API-Key: warden_comm_xxxxxxxxxxxxxxxx
X-Tenant-ID: my-org        # your GDPR pseudonym""", language="bash")
            warn("Never commit `WARDEN_API_KEY` to version control. Use Docker secrets or "
                 "a secrets manager (`WARDEN_API_KEYS_PATH` JSON file).")

        with tab_tenant:
            st.markdown("## X-Tenant-ID Isolation")
            st.markdown("""
All community data is scoped to `X-Tenant-ID`. The same community gateway serves
multiple organisations — data never crosses tenant boundaries.

| Header | Required | Description |
|--------|----------|-------------|
| `X-API-Key` | ✅ | Authenticates the request |
| `X-Tenant-ID` | ✅ | GDPR pseudonym — no PII |
| `X-Community-ID` | Community endpoints | Target community ID |
            """)
            st.code("""# Python SDK example
import httpx

client = httpx.Client(
    base_url="https://api.shadow-warden-ai.com",
    headers={
        "X-API-Key":    "warden_comm_xxx",
        "X-Tenant-ID":  "my-org",
    },
    timeout=30,
)

resp = client.post("/filter", json={"content": "...", "tenant_id": "my-org"})""", language="python")

        with tab_scope:
            st.markdown("## Community Membership Gate")
            st.markdown("""
Endpoints under `/communities/{id}` and `/sep/*` automatically validate that the
requesting tenant is a member (or owner) of the target community.

- Non-members receive **HTTP 403 Forbidden**
- Revoked members receive **HTTP 401 Unauthorized**
- Community capacity (3 max) returns **HTTP 402 Payment Required**
            """)
            note("Member clearance levels (PUBLIC / INTERNAL / CONFIDENTIAL) further restrict "
                 "which SEP transfer policies are available.")

    # ── 3. SEP ────────────────────────────────────────────────────────────────
    elif active_key == "sep":
        hero("🔗", "SEP Protocol — Syndicate Exchange Protocol",
             "Secure, jurisdiction-aware document exchange between communities.")
        badge(("COMMUNITY $19", "comm"), ("NEW v4.6", "new"))

        st.markdown("## Architecture")
        st.code("""Community A ──[initiate_peering()]──► PENDING peering record
                             ◄──[HMAC token]──────────────┘
          ▼ out-of-band token delivery
Community B ──[accept_peering(token)]──► ACTIVE
          ▼
transfer_entity(peering_id, entity_id)
  → 1. Sovereign Pod Tag compliance check
  → 2. Causal Transfer Guard (P ≥ 0.70 → BLOCK)
  → 3. HMAC-SHA256 Causal Transfer Proof signed
  → 4. UECIID registered in target community
  → 5. STIX 2.1 audit chain entry appended""", language="text")

        st.markdown("## UECIID — Document Identity")
        st.code("""# Every document in a community gets a UECIID
POST /sep/ueciid/register
{
  "community_id": "COM-xxx",
  "display_name": "Q4 2024 Security Report",
  "data_class":   "FINANCIAL",
  "jurisdiction": "EU-GDPR"
}
# Response: {"ueciid": "SEP-A3bC7dEfG2h"}

# Resolve
GET /sep/ueciid/SEP-A3bC7dEfG2h
# → {community_id, display_name, data_class, jurisdiction, created_at}""", language="bash")

        st.markdown("## Peering Modes")
        modes = [
            ("MIRROR_ONLY",    "Read-only replica. Target cannot re-export or re-encrypt.",
             "Auditing, third-party compliance monitoring"),
            ("REWRAP_ALLOWED", "Target may re-encrypt under its own keys for internal distribution.",
             "Supply chain data flows, tiered distribution"),
            ("FULL_SYNC",      "Bidirectional — either side may initiate transfers.",
             "Trusted partner research exchange"),
        ]
        for mode, desc, use in modes:
            with st.expander(f"🔗 {mode}"):
                st.markdown(f"**Description:** {desc}")
                st.markdown(f"**Use case:** {use}")

        st.markdown("## Knock-and-Verify Invitation")
        st.code("""# Community A invites a new member
POST /sep/knock/issue
{"community_id": "COM-xxx", "invitee_tenant_id": "new-member@example.com"}
# → {"token": "...", "expires_at": "2026-05-01T00:00:00Z"}  (72h TTL)

# New member accepts
POST /sep/knock/accept
{"token": "...", "claiming_tenant_id": "new-member@example.com"}
# → {"status": "ACCEPTED", "member_id": "MEM-xxxxxxxx"}""", language="bash")

    # ── 4. CHARTER ────────────────────────────────────────────────────────────
    elif active_key == "charter":
        hero("📋", "Charter API",
             "Create, publish, and enforce versioned community governance rules.")
        badge(("COMMUNITY $19", "comm"), ("NEW v4.8", "new"))

        st.markdown("## Lifecycle")
        st.code("""DRAFT  ─[publish]─►  ACTIVE  ─[new version published]─►  SUPERSEDED
                                   └─[revoke]─►  REVOKED""", language="text")

        st.markdown("## Create & Publish")
        st.code("""# 1. Create DRAFT
POST /community-intel/COM-xxx/charter
{
  "title":               "Acme Data Charter v1",
  "transparency":        "REQUIRED",        // REQUIRED | ENCOURAGED | OPTIONAL
  "data_minimization":   "STRICT",          // STRICT | STANDARD | RELAXED
  "accountability":      "dpo@acme.com",
  "sustainability":      "STANDARD",        // STANDARD | ADVANCED | CERTIFIED
  "allowed_data_classes": ["GENERAL","PII","FINANCIAL"],
  "prohibited_actions":  ["mass_export","public_disclosure"],
  "auto_block_threshold": 0.70
}
# → {"charter_id": "CHR-XXXXXXXXXXXX", "status": "DRAFT", "version": 1}

# 2. Publish
POST /community-intel/COM-xxx/charter/CHR-xxx/publish
# → {"status": "ACTIVE", "published_at": "2026-04-27T10:00:00Z"}""", language="json")

        st.markdown("## Member Acceptance")
        st.code("""# Member accepts the active charter
POST /community-intel/COM-xxx/charter/CHR-xxx/accept
{"member_id": "MEM-xxxxxxxx", "ip_fingerprint": "192.168.1.0"}

# Check pending acceptances
GET /community-intel/COM-xxx/charter/pending
# → {"pending": [{"member_id": "MEM-yyy", "display_name": "Bob"}]}""", language="bash")

        st.markdown("## Compliance Validation Hook")
        st.code("""from warden.communities.charter import validate_charter_compliance

allowed, reason = validate_charter_compliance(
    community_id = "COM-xxx",
    action       = "transfer",
    data_class   = "PHI",
)
if not allowed:
    raise PermissionError(f"Charter block: {reason}")""", language="python")

        note("The transfer pipeline calls `validate_charter_compliance()` automatically before "
             "every `transfer_entity()` — you don't need to call it manually in normal flow.")

    # ── 5. BEHAVIORAL ─────────────────────────────────────────────────────────
    elif active_key == "behavioral":
        hero("🧠", "Behavioral Analytics",
             "Z-score baseline anomaly detection for community activity patterns.")
        badge(("COMMUNITY $19", "comm"), ("NEW v4.8", "new"))

        st.markdown("## Recording Events")
        st.code("""from warden.communities.behavioral import record_event

# Fire-and-forget — never raises
record_event("COM-xxx", "request",       value=1.0)
record_event("COM-xxx", "transfer",      value=1.0)
record_event("COM-xxx", "bulk_transfer", value=payload_bytes / (1024*1024))
record_event("COM-xxx", "new_peering",   value=1.0)""", language="python")

        st.markdown("## Anomaly Detection")
        st.code("""from warden.communities.behavioral import detect_anomaly, compute_baseline

# Compute baseline (run once, then weekly)
baseline = compute_baseline("COM-xxx", "bulk_transfer", days=30)
print(baseline.mean, baseline.stddev, baseline.p99)

# Detect anomaly
result = detect_anomaly("COM-xxx", "bulk_transfer", value=250.0)
print(result.severity)   # NORMAL | ELEVATED | CRITICAL
print(result.action)     # ALLOW | ALERT | BLOCK
print(result.z_score)    # e.g. 4.2""", language="python")

        st.markdown("## REST API")
        ep("GET",  "/community-intel/{id}/anomalies",         "Recent anomaly feed")
        ep("POST", "/community-intel/{id}/anomalies/detect",  "On-demand detection")
        ep("GET",  "/community-intel/{id}/risk",              "Risk score (anomaly factor included)")

        st.markdown("## Severity Thresholds")
        thresholds = [
            ("NORMAL",   "< 2σ",  "ALLOW",  "Within expected range"),
            ("ELEVATED", "≥ 2σ",  "ALERT",  "Unusual — log + notify DPO"),
            ("CRITICAL", "≥ 3σ",  "BLOCK",  "Likely exfiltration or account compromise"),
        ]
        st.dataframe(
            pd.DataFrame(thresholds, columns=["Severity", "Z-Score", "Action", "Meaning"]),
            use_container_width=True, hide_index=True,
        )

        note("Baselines require ≥ 10 historical samples. Below that threshold, all anomaly "
             "checks return `NORMAL / insufficient_history` — no false positives on new communities.")

    # ── 6. OAUTH ──────────────────────────────────────────────────────────────
    elif active_key == "oauth":
        hero("🤖", "OAuth Agent Discovery",
             "Detect and govern AI agents connecting via SaaS OAuth grants.")
        badge(("COMMUNITY $19", "comm"), ("NEW v4.8", "new"))

        st.markdown("## The Problem")
        info("Up to 78% of employees use AI tools not approved by their organisation, often "
             "inadvertently sharing intellectual property with public models via OAuth grants.")

        st.markdown("## Risk Classification")
        catalog_data = [
            ("ChatGPT Plugin",   "CRITICAL", "BLOCK",   "read, write, admin"),
            ("OpenAI API",       "CRITICAL", "BLOCK",   "read, write, admin"),
            ("Zapier AI",        "HIGH",     "BLOCK",   "read, write"),
            ("Make (Integromat)","HIGH",     "BLOCK",   "files, docs"),
            ("Jasper AI",        "HIGH",     "BLOCK",   "write, publish"),
            ("Microsoft Copilot","MEDIUM",   "MONITOR", "read, chat"),
            ("Notion AI",        "MEDIUM",   "MONITOR", "read"),
            ("GitHub Copilot",   "MEDIUM",   "MONITOR", "repo, code"),
            ("Grammarly AI",     "LOW",      "ALLOW",   "read"),
        ]
        st.dataframe(
            pd.DataFrame(catalog_data, columns=["Provider", "Default Risk", "Verdict", "Dangerous Scopes"]),
            use_container_width=True, hide_index=True,
        )

        st.markdown("## API Usage")
        st.code("""# Register a newly detected OAuth grant
POST /community-intel/COM-xxx/oauth
{"member_id": "MEM-xxx", "provider": "zapier", "scopes": ["read", "write"]}
# → {"grant_id": "OAG-xxx", "risk_level": "HIGH", "verdict": "BLOCK"}

# List active grants
GET /community-intel/COM-xxx/oauth

# Revoke a grant
DELETE /community-intel/oauth/OAG-xxx

# Community risk summary
GET /community-intel/COM-xxx/oauth/summary

# Full provider catalog
GET /community-intel/oauth/catalog""", language="bash")

        st.markdown("## Python Integration")
        st.code("""from warden.communities.oauth_discovery import (
    register_oauth_grant,
    classify_provider,
    revoke_grant,
)

# Classify before registering (e.g. from SSO audit log)
risk, verdict = classify_provider("chatgpt_plugin", ["read", "write"])
# → "CRITICAL", "BLOCK"

if verdict == "BLOCK":
    # Register for audit trail then notify DPO
    grant = register_oauth_grant("COM-xxx", "MEM-yyy", "chatgpt_plugin", ["read","write"])
    # → fires behavioral event + returns OAuthGrant
    notify_dpo(grant)""", language="python")

    # ── 7. FILE SCANNER ───────────────────────────────────────────────────────
    elif active_key == "file_scanner":
        hero("🔍", "File Scanner",
             "Scan uploaded documents for PII, API keys, injection patterns, and obfuscated payloads.")
        badge(("COMMUNITY $19", "comm"))

        st.markdown("## POST /filter/file")
        st.code("""curl -X POST http://localhost:8000/filter/file \\
  -H "X-API-Key: $WARDEN_API_KEY" \\
  -H "X-Tenant-ID: my-org" \\
  -F "file=@/path/to/report.pdf" \\
  -F "strict=false"

# Response
{
  "risk_level":       "HIGH",
  "findings": [
    {"type": "SECRET",    "pattern": "OPENAI_KEY",  "line": 14, "severity": "HIGH"},
    {"type": "PII",       "pattern": "email",        "line": 23, "severity": "MEDIUM"}
  ],
  "sanitized_text":   "...redacted...",
  "processing_ms":    18.4
}""", language="bash")

        st.markdown("## Supported File Types")
        types = [
            (".txt / .md",    "Plain-text UTF-8/Latin-1"),
            (".json / .yaml", "Structured data — key-value secrets detection"),
            (".csv",          "Column-level PII scanning"),
            (".pdf",          "pdfminer text extraction"),
            (".docx / .xlsx", "python-docx / openpyxl extraction"),
            (".py / .js",     "Source code — injection + secret patterns"),
        ]
        st.dataframe(pd.DataFrame(types, columns=["Extension", "Notes"]),
                     use_container_width=True, hide_index=True)

        st.markdown("## Python SDK")
        st.code("""import httpx

with open("report.pdf", "rb") as f:
    resp = httpx.post(
        "http://localhost:8000/filter/file",
        headers={"X-API-Key": "...", "X-Tenant-ID": "my-org"},
        files={"file": ("report.pdf", f, "application/pdf")},
        data={"strict": "false"},
    )

result = resp.json()
if result["risk_level"] in ("HIGH", "BLOCK"):
    raise ValueError(f"File rejected: {result['findings']}")""", language="python")

        warn("In strict mode, any single finding causes the file to be rejected. "
             "Use `strict=false` for advisory scanning with sanitized output.")

    # ── 8. DATA PODS ──────────────────────────────────────────────────────────
    elif active_key == "data_pods":
        hero("🗄", "Sovereign Data Pods & Storage",
             "Per-jurisdiction MinIO routing with Fernet-encrypted secret keys.")
        badge(("COMMUNITY $19", "comm"), ("NEW v4.7", "new"))

        st.markdown("## Architecture")
        st.code("""entity.data_class  →  pod_tag.jurisdiction  →  DataPod (MinIO bucket)
                                              ↓
                              Fernet-encrypted secret key
                              stored in SQLite (sep_data_pods)""", language="text")

        st.markdown("## Register a Data Pod")
        st.code("""POST /sep/pods
{
  "community_id":  "COM-xxx",
  "jurisdiction":  "EU-GDPR",
  "data_class":    "PHI",
  "endpoint":      "https://minio.eu.example.com",
  "bucket":        "warden-eu-phi",
  "secret_key":    "s3_secret_key_here"   // encrypted with COMMUNITY_VAULT_KEY at rest
}
# → {"pod_id": "POD-xxxx", "status": "ACTIVE"}

# Probe health
POST /sep/pods/POD-xxxx/probe
# → {"status": "ACTIVE", "latency_ms": 12}""", language="json")

        st.markdown("## Resolution Logic")
        st.markdown("""
When `transfer_entity()` runs, the pod is resolved in order:
1. **Jurisdiction match** — entity's Sovereign Pod Tag → jurisdiction
2. **Data class match** — `data_class` override on pod
3. **Primary pod** — `is_primary=True` in community
4. **First ACTIVE** — fallback
        """)
        st.markdown("## GDPR PHI Restriction")
        st.code("""# PHI data from EU cannot route to US pods
from warden.sovereign.jurisdictions import is_transfer_allowed

ok = is_transfer_allowed("EU", "US", data_class="PHI")
# → False  (PHI: EU/US/UK/CA/CH only — and EU→US is not in the adequacy list)""", language="python")

        note("Set `COMMUNITY_VAULT_KEY` to a Fernet key separate from `VAULT_MASTER_KEY`. "
             "Rotate independently to limit blast radius.")

    # ── 9. WEBHOOKS ───────────────────────────────────────────────────────────
    elif active_key == "webhooks":
        hero("⚡", "Webhooks & Events",
             "Lemon Squeezy billing events + behavioral alert hooks + Slack notifications.")

        st.markdown("## Billing Webhook (Lemon Squeezy)")
        badge(("COMMUNITY $19", "comm"))
        st.code("""# In Lemon Squeezy dashboard, set webhook URL:
https://api.shadow-warden-ai.com/billing/webhook

# .env
LEMONSQUEEZY_WEBHOOK_SECRET=your_webhook_secret

# Handled events
subscription_created   → upsert tenant plan
subscription_updated   → plan change
subscription_cancelled → revert to starter
order_created          → trigger addon grant""", language="bash")

        st.markdown("## Behavioral Alert Hook")
        st.code("""# .env
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx/yyy/zzz

# Fires on CRITICAL anomaly or BLOCK verdict
# Payload example:
{
  "community_id": "COM-xxx",
  "event_type":   "bulk_transfer",
  "severity":     "CRITICAL",
  "z_score":      4.2,
  "action":       "BLOCK",
  "reason":       "z=4.20 exceeds 3σ baseline — possible exfiltration"
}""", language="json")

        st.markdown("## PagerDuty Integration")
        st.code("""# .env
PAGERDUTY_ROUTING_KEY=your_pagerduty_key

# Fires on: BLOCK decisions, CRITICAL anomalies, charter violations
# Integration key type: Events API v2""", language="bash")

        note("`SLACK_WEBHOOK_URL` and `PAGERDUTY_ROUTING_KEY` are optional — "
             "alerts degrade gracefully if unset.")

    # ── 10. STIX ──────────────────────────────────────────────────────────────
    elif active_key == "stix":
        hero("🔒", "STIX 2.1 Tamper-Proof Audit Chain",
             "Every community document transfer is recorded in an immutable blockchain-style ledger.")
        badge(("COMMUNITY $19", "comm"), ("NEW v4.7", "new"))

        st.markdown("## How It Works")
        st.code("""append_transfer(transfer_record)
  → STIX Bundle:
      Identity (source community)
      Identity (target community)
      Relationship (x-sep-proof: HMAC + Causal Transfer Proof)
      Note (audit metadata)
  → SHA-256 hash of bundle content
  → Chained to prev_hash of last entry
  → Stored in SQLite sep_stix_chain""", language="text")

        st.markdown("## Verify Chain Integrity")
        st.code("""GET /sep/audit-chain/COM-xxx/verify
# → {"valid": true, "entry_count": 47, "last_seq": 47}

# If tampered:
# → {"valid": false, "broken_at_seq": 23, "reason": "hash mismatch"}

# Export for SIEM
GET /sep/audit-chain/COM-xxx/export
# → JSONL (OASIS STIX 2.1 compatible)""", language="bash")

        st.markdown("## Python Usage")
        st.code("""from warden.communities.stix_audit import (
    append_transfer, verify_chain, export_chain_jsonl,
)

# After every transfer_entity()
append_transfer(transfer_record)

# Weekly integrity check
result = verify_chain("COM-xxx")
assert result["valid"], f"STIX chain broken: {result}"

# Export for SIEM (Splunk, Elastic)
jsonl = export_chain_jsonl("COM-xxx")
with open("audit_export.jsonl", "w") as f:
    f.write(jsonl)""", language="python")

        warn("STIX audit entries are ALWAYS appended — including REJECTED transfers. "
             "This provides full chain of custody even for blocked exfiltration attempts.")

    # ── 11. ENV REFERENCE ─────────────────────────────────────────────────────
    elif active_key == "env_ref":
        hero("⚙️", "Community Environment Reference",
             "All environment variables for the Community Business tier.")

        env_vars = [
            # Core
            ("WARDEN_API_KEY",           "required",  "Gateway API key (fail-closed at startup)"),
            ("VAULT_MASTER_KEY",         "required",  "Fernet key — community keypairs at rest"),
            ("COMMUNITY_VAULT_KEY",      "required",  "Fernet key — data pod secret keys"),
            ("TIER",                     "community_business", "Tier identifier"),
            # Community
            ("COMMUNITY_REGISTRY_PATH",  "/tmp/warden_community_registry.db", "SQLite path for community + charter DB"),
            ("SEP_DB_PATH",              "/tmp/warden_sep.db", "SQLite path for UECIID + peerings + transfers + STIX"),
            ("BEHAVIORAL_DB_PATH",       "/tmp/warden_behavioral.db", "SQLite path for behavioral events"),
            ("OAUTH_DB_PATH",            "/tmp/warden_oauth.db", "SQLite path for OAuth grant registry"),
            ("DEFAULT_COMMUNITY_ID",     "",          "Pre-fills Community ID in Streamlit dashboard"),
            # Shadow AI
            ("SHADOW_AI_SYSLOG_ENABLED", "false",     "Enable DNS telemetry syslog listener"),
            ("SHADOW_AI_SYSLOG_PORT",    "5514",      "UDP port for DNS syslog sink"),
            ("SHADOW_AI_CONCURRENCY",    "50",        "Max parallel probes per subnet scan"),
            ("SHADOW_AI_PROBE_TIMEOUT",  "3",         "Per-host probe timeout (seconds)"),
            # Billing
            ("LEMONSQUEEZY_WEBHOOK_SECRET", "",       "Lemon Squeezy webhook signing secret"),
            ("LEMONSQUEEZY_API_KEY",     "",          "Lemon Squeezy API key (checkout sessions)"),
            # Alerts
            ("SLACK_WEBHOOK_URL",        "",          "Slack webhook — behavioral CRITICAL alerts"),
            ("PAGERDUTY_ROUTING_KEY",    "",          "PagerDuty Events API v2 key"),
            # Retention
            ("QUOTA_DB_PATH",            "/tmp/warden_quota.db", "SQLite path for quota tracking"),
            # Auth
            ("ALLOW_UNAUTHENTICATED",    "false",     "Dev only — disables fail-closed auth"),
            ("REDIS_URL",                "redis://redis:6379", "Set `memory://` for local dev"),
        ]

        st.dataframe(
            pd.DataFrame(env_vars, columns=["Variable", "Default / Example", "Description"]),
            use_container_width=True, hide_index=True,
        )

        st.markdown("## Minimal `.env` for Community Business")
        st.code("""# Core (required)
WARDEN_API_KEY=warden_comm_xxxxxxxxxxxxxxxxxxxxxxxx
VAULT_MASTER_KEY=<fernet-key>
COMMUNITY_VAULT_KEY=<fernet-key-2>
TIER=community_business

# Persistence (Docker volumes recommended in production)
COMMUNITY_REGISTRY_PATH=/data/warden_community.db
SEP_DB_PATH=/data/warden_sep.db
BEHAVIORAL_DB_PATH=/data/warden_behavioral.db
OAUTH_DB_PATH=/data/warden_oauth.db

# Alerts (optional)
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx

# Billing (optional — required for paid upgrade flows)
LEMONSQUEEZY_WEBHOOK_SECRET=lswhsec_xxx
LEMONSQUEEZY_API_KEY=eyJhbGciOi...

# Redis
REDIS_URL=redis://redis:6379""", language="bash")

        note("Never set `ALLOW_UNAUTHENTICATED=true` in production — "
             "the gateway raises `RuntimeError` at startup if both `WARDEN_API_KEY` "
             "and `WARDEN_API_KEYS_PATH` are unset without this flag.")
