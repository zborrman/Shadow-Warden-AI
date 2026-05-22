"""
warden/analytics/pages/10_SMB_Governance.py
SMB AI Governance Suite — 6-tab Streamlit dashboard.

Tabs: Incidents | Vendors | Training | Prompt Library | Supplier Risk | Budget
"""
from __future__ import annotations

import os
from typing import Any

import streamlit as st

st.set_page_config(page_title="SMB Governance", layout="wide")

_API = os.getenv("WARDEN_API_URL", "http://localhost:8001")
_KEY = os.getenv("WARDEN_API_KEY", "")


def _headers() -> dict:
    return {"X-API-Key": _KEY} if _KEY else {}


def _get(path: str) -> dict[str, Any] | None:
    import requests  # noqa: PLC0415
    try:
        r = requests.get(f"{_API}{path}", headers=_headers(), timeout=5)
        r.raise_for_status()
        result = r.json()
        return result if isinstance(result, dict) else None
    except Exception as exc:
        st.error(f"API error ({path}): {exc}")
        return None


def _post(path: str, body: dict) -> dict | None:
    import requests  # noqa: PLC0415
    try:
        r = requests.post(f"{_API}{path}", json=body, headers=_headers(), timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        st.error(f"API error ({path}): {exc}")
        return None


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.title("SMB Governance")
    tenant_id    = st.text_input("Tenant ID",    value="default")
    community_id = st.text_input("Community ID", value="")

st.title("SMB AI Governance Suite")

tab_inc, tab_ven, tab_tra, tab_prl, tab_sup, tab_bud = st.tabs([
    "Incidents", "Vendors", "Training", "Prompt Library", "Supplier Risk", "Budget",
])


# ── Tab 1: Incidents ──────────────────────────────────────────────────────────
with tab_inc:
    st.subheader("AI Incident Register")
    data = _get(f"/incidents/stats?tenant_id={tenant_id}")
    if data:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total",       data.get("total", 0))
        c2.metric("Open",        data.get("by_status", {}).get("open", 0))
        c3.metric("Critical",    data.get("by_severity", {}).get("CRITICAL", 0))
        c4.metric("Resolved",    data.get("by_status", {}).get("resolved", 0))

    inc_data = _get(f"/incidents?tenant_id={tenant_id}&limit=20")
    if inc_data:
        items = inc_data.get("incidents", [])
        if items:
            import pandas as pd  # noqa: PLC0415
            df = pd.DataFrame(items)[["incident_id", "title", "severity", "category", "status", "created_at"]]
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No incidents recorded.")

    with st.expander("Log New Incident"):
        title    = st.text_input("Title")
        severity = st.selectbox("Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        category = st.selectbox("Category", ["JAILBREAK", "PII_LEAK", "HALLUCINATION", "ABUSE", "COMPLIANCE", "OTHER"])
        desc     = st.text_area("Description")
        if st.button("Log Incident"):
            result = _post("/incidents", {
                "tenant_id": tenant_id, "title": title,
                "severity": severity, "category": category, "description": desc,
            })
            if result:
                st.success(f"Incident logged: {result.get('incident_id')}")
                st.rerun()


# ── Tab 2: Vendors ────────────────────────────────────────────────────────────
with tab_ven:
    st.subheader("AI Vendor Governance Register")
    stats = _get(f"/vendor-gov/stats?tenant_id={tenant_id}")
    if stats:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Vendors",  stats.get("total_vendors", 0))
        c2.metric("Active",         stats.get("by_status", {}).get("active", 0))
        c3.metric("High Risk",      stats.get("by_risk_tier", {}).get("HIGH", 0))
        c4.metric("DPAs Expiring",  stats.get("expiring_dpas_30d", 0))

    vendors = _get(f"/vendor-gov/vendors?tenant_id={tenant_id}")
    if vendors:
        items = vendors.get("vendors", [])
        if items:
            import pandas as pd  # noqa: PLC0415
            df = pd.DataFrame(items)[["vendor_id", "display_name", "provider_type", "risk_tier", "status"]]
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No vendors registered.")

    with st.expander("Register Vendor"):
        name   = st.text_input("Display Name")
        web    = st.text_input("Website")
        ptype  = st.selectbox("Provider Type", ["LLM", "EMBEDDING", "TOOL", "AGENT", "OTHER"])
        if st.button("Register"):
            result = _post("/vendor-gov/vendors", {
                "tenant_id": tenant_id, "display_name": name,
                "website": web, "provider_type": ptype,
            })
            if result:
                st.success(f"Vendor registered: {result.get('vendor_id')}")
                st.rerun()


# ── Tab 3: Training ───────────────────────────────────────────────────────────
with tab_tra:
    st.subheader("Employee AI Training Records")
    programs = _get(f"/training/programs?community_id={community_id or tenant_id}")
    if programs:
        items = programs.get("programs", [])
        c1, c2 = st.columns(2)
        c1.metric("Programs", len(items))
        if items:
            import pandas as pd  # noqa: PLC0415
            df = pd.DataFrame(items)[["program_id", "title", "passing_score", "valid_days"]]
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No training programs.")

    report = _get(f"/training/compliance-report?community_id={community_id or tenant_id}")
    if report:
        c1, c2, c3 = st.columns(3)
        c1.metric("Total Completions", report.get("total_completions", 0))
        c2.metric("Passed",            report.get("passed", 0))
        c3.metric("Expiring 30d",      report.get("expiring_30d", 0))


# ── Tab 4: Prompt Library ─────────────────────────────────────────────────────
with tab_prl:
    st.subheader("Shared Prompt Library")
    stats = _get(f"/prompt-library/stats?community_id={community_id or tenant_id}")
    if stats:
        c1, c2, c3 = st.columns(3)
        c1.metric("Total Prompts",  stats.get("total_prompts", 0))
        c2.metric("Active",         stats.get("active_prompts", 0))
        c3.metric("Total Uses",     stats.get("total_uses", 0))

    prompts = _get(f"/prompt-library?community_id={community_id or tenant_id}")
    if prompts:
        items = prompts.get("prompts", [])
        if items:
            import pandas as pd  # noqa: PLC0415
            df = pd.DataFrame(items)[["prompt_id", "title", "category", "use_count", "status"]]
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No prompts in library.")


# ── Tab 5: Supplier Risk ──────────────────────────────────────────────────────
with tab_sup:
    st.subheader("Supplier AI Risk Assessment")
    cid = community_id or tenant_id
    report = _get(f"/supplier-risk/report/{cid}")
    if report:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Vendors",  report.get("total_vendors", 0))
        by_label = report.get("by_risk_label", {})
        c2.metric("Critical",       by_label.get("CRITICAL", 0))
        c3.metric("High",           by_label.get("HIGH", 0))
        c4.metric("Low",            by_label.get("LOW", 0))

        top = report.get("top_risky_vendors", [])
        if top:
            st.write("**Top Risky Vendors**")
            import pandas as pd  # noqa: PLC0415
            st.dataframe(pd.DataFrame(top), use_container_width=True)

    assessments = _get(f"/supplier-risk/assessments?community_id={cid}")
    if assessments:
        items = assessments.get("assessments", [])
        if items:
            import pandas as pd  # noqa: PLC0415
            df = pd.DataFrame(items)[["assessment_id", "vendor_id", "composite_score", "risk_label", "assessed_at"]]
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No assessments yet.")


# ── Tab 6: Budget ─────────────────────────────────────────────────────────────
with tab_bud:
    st.subheader("AI Budget Dashboard")
    status = _get(f"/financial/budget/status?tenant_id={tenant_id}")
    if status:
        c1, c2, c3 = st.columns(3)
        c1.metric("Budget Caps",    status.get("total_caps", 0))
        c2.metric("Period",         status.get("period_month", ""))
        depts = status.get("departments", [])
        over  = sum(1 for d in depts if d.get("status") == "over_budget")
        c3.metric("Over Budget",    over)

        for dept in depts:
            pct = dept.get("pct_used", 0)
            col  = "🔴" if pct >= 1.0 else "🟡" if pct >= dept.get("alert_pct", 0.8) else "🟢"
            st.write(f"{col} **{dept['department']}** — ${dept.get('current_spend',0):.2f} / ${dept.get('cap_usd',0):.2f} ({pct*100:.0f}%)")
            st.progress(min(pct, 1.0))

    approvals = _get(f"/financial/budget/approvals?tenant_id={tenant_id}&status=pending")
    if approvals:
        pending = approvals.get("approvals", [])
        if pending:
            st.warning(f"{len(pending)} pending budget approval(s)")
            import pandas as pd  # noqa: PLC0415
            df = pd.DataFrame(pending)[["approval_id", "requested_by", "department", "amount_usd", "reason"]]
            st.dataframe(df, use_container_width=True)
