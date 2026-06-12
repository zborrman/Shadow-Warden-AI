"""
warden/analytics/pages/21_Compliance_Dashboard.py
───────────────────────────────────────────────────
Real-time Compliance Gap Dashboard (CP-30).

Distinct from page 17 (which shows the ring-buffer posture scores):
this page shows LIVE multi-source gap analysis with remediation guidance.

Tabs: Overview · GDPR · SOC 2 · ISO 27001 · HIPAA
"""
from __future__ import annotations

import contextlib
import time

import requests
import streamlit as st

st.set_page_config(
    page_title="Compliance Dashboard — Shadow Warden AI",
    page_icon="🛡️",
    layout="wide",
)

WARDEN_URL = "http://localhost:8001"
HEADERS    = {"X-API-Key": "", "X-Tenant-Tier": "pro"}

_STATUS_COLOR = {
    "compliant":     "#10b981",
    "at_risk":       "#f59e0b",
    "non_compliant": "#ef4444",
}
_SEV_COLOR = {"high": "#ef4444", "medium": "#f59e0b", "low": "#94a3b8"}
_FW_LABEL  = {"gdpr": "GDPR", "soc2": "SOC 2", "iso27001": "ISO 27001", "hipaa": "HIPAA"}


@st.cache_data(ttl=30, show_spinner=False)
def _fetch(tenant_id: str) -> dict | None:
    try:
        r = requests.get(
            f"{WARDEN_URL}/compliance/posture/gaps",
            params={"tenant_id": tenant_id},
            headers=HEADERS,
            timeout=5,
        )
        if r.ok:
            return r.json()
    except Exception:
        pass
    return None


@st.cache_data(ttl=30, show_spinner=False)
def _fetch_report(tenant_id: str) -> dict | None:
    try:
        r = requests.post(
            f"{WARDEN_URL}/compliance/posture/recalculate",
        )
        if not r.ok:
            r = requests.get(
                f"{WARDEN_URL}/compliance/posture",
                params={"days": 7},
                headers=HEADERS,
                timeout=5,
            )
        if r.ok:
            return r.json()
    except Exception:
        pass
    return None


@st.cache_data(ttl=30, show_spinner=False)
def _fetch_framework(tenant_id: str, framework: str) -> dict | None:
    try:
        r = requests.get(
            f"{WARDEN_URL}/compliance/posture/{framework}",
            params={"tenant_id": tenant_id},
            headers=HEADERS,
            timeout=5,
        )
        if r.ok:
            return r.json()
    except Exception:
        pass
    return None


# ── Header ────────────────────────────────────────────────────────────────────

st.title("Real-time Compliance Dashboard")
st.caption("Live gap analysis — GDPR · SOC 2 · ISO 27001 · HIPAA  |  CP-30 · v5.5")

col_tid, col_ref, col_auto = st.columns([3, 1, 1])
tenant_id = col_tid.text_input("Tenant ID", value="default", label_visibility="collapsed")
if col_ref.button("Recalculate"):
    _fetch.clear()
    _fetch_report.clear()
    _fetch_framework.clear()
    with contextlib.suppress(Exception):
        requests.post(
            f"{WARDEN_URL}/compliance/posture/recalculate",
            params={"tenant_id": tenant_id},
            headers=HEADERS,
            timeout=5,
        )
    st.rerun()
auto_refresh = col_auto.checkbox("Auto-refresh 30s", value=True)

# ── Fetch data ────────────────────────────────────────────────────────────────

with st.spinner("Fetching compliance posture…"):
    gaps_data = _fetch(tenant_id)

if not gaps_data:
    st.warning("Compliance service unavailable. Make sure the gateway is running on port 8001.")
    st.stop()

all_gaps = gaps_data.get("gaps", [])

# ── Overview metrics ──────────────────────────────────────────────────────────

high   = sum(1 for g in all_gaps if g["severity"] == "high")
medium = sum(1 for g in all_gaps if g["severity"] == "medium")
low    = sum(1 for g in all_gaps if g["severity"] == "low")

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Gaps",   len(all_gaps))
c2.metric("HIGH",         high,   delta=-high   if high   else None, delta_color="inverse")
c3.metric("MEDIUM",       medium, delta=-medium if medium else None, delta_color="inverse")
c4.metric("LOW",          low)

if all_gaps:
    st.error(f"{high} HIGH-severity gap(s) require immediate attention.") if high else None
    st.warning(f"{medium} MEDIUM-severity gap(s) should be addressed.") if medium else None
else:
    st.success("No compliance gaps detected. All controls are passing.")

st.divider()

# ── Tabs ──────────────────────────────────────────────────────────────────────

tab_overview, tab_gdpr, tab_soc2, tab_iso, tab_hipaa = st.tabs(
    ["Overview", "GDPR", "SOC 2", "ISO 27001", "HIPAA"]
)

def _render_gaps(fw: str) -> None:
    fw_gaps = [g for g in all_gaps if g["control_id"].lower().startswith(fw.lower())]
    detail  = _fetch_framework(tenant_id, fw)

    if detail:
        score  = detail.get("score", 0)
        status = detail.get("status", "unknown")
        col_s, col_p, col_t = st.columns(3)
        col_s.metric("Score", f"{score:.1f}%")
        col_p.metric("Passed", f"{detail.get('passed_controls', '?')} / {detail.get('total_controls', '?')}")
        col_t.metric("Status", status.upper().replace("_", " "))
        st.progress(int(score) / 100)
    else:
        st.info("Framework detail unavailable — gateway may be unreachable.")

    if not fw_gaps:
        st.success("All controls passing for this framework.")
        return

    for gap in fw_gaps:
        sev   = gap["severity"]
        with st.expander(f"🔴 {gap['control_id']} — {gap['description']}" if sev == "high"
                         else f"🟡 {gap['control_id']} — {gap['description']}", expanded=sev == "high"):
            st.markdown(f"**Severity:** :{('red' if sev == 'high' else 'orange' if sev == 'medium' else 'grey')}[{sev.upper()}]")
            st.markdown(f"**Module:** `{gap['affected_module']}`")
            st.markdown(f"**Remediation:** {gap['remediation']}")


with tab_overview:
    st.subheader("Compliance Gaps by Framework")
    for fw, label in _FW_LABEL.items():
        fw_gaps = [g for g in all_gaps if g["control_id"].lower().startswith(fw.replace("iso27001", "iso").lower())]
        badge   = f"{len(fw_gaps)} gap(s)" if fw_gaps else "✅ Compliant"
        st.markdown(f"**{label}** — {badge}")

    if all_gaps:
        st.subheader("All Gaps")
        for gap in sorted(all_gaps, key=lambda g: {"high": 0, "medium": 1, "low": 2}.get(g["severity"], 3)):
            icon = "🔴" if gap["severity"] == "high" else "🟡" if gap["severity"] == "medium" else "⚪"
            st.markdown(f"{icon} **{gap['control_id']}** — {gap['description']}  \n"
                        f"&nbsp;&nbsp;&nbsp;&nbsp;↳ *{gap['remediation']}*")

with tab_gdpr:
    _render_gaps("gdpr")

with tab_soc2:
    _render_gaps("soc2")

with tab_iso:
    _render_gaps("iso")

with tab_hipaa:
    _render_gaps("hipaa")

# ── Auto-refresh ──────────────────────────────────────────────────────────────

if auto_refresh:
    time.sleep(30)
    st.rerun()
