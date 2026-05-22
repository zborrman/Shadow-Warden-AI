"""
warden/analytics/pages/12_Business_Intelligence.py  (CM-39)
─────────────────────────────────────────────────────────────
Streamlit Business Intelligence dashboard — 8 tabs.
"""
from __future__ import annotations

import os

import requests
import streamlit as st

st.set_page_config(page_title="Business Intelligence", page_icon="📊", layout="wide")

_BASE = os.getenv("WARDEN_API_URL", "http://localhost:8001")
_KEY  = os.getenv("WARDEN_API_KEY", "")
_HEADERS = {"X-API-Key": _KEY} if _KEY else {}


def _get(path: str, params: dict | None = None) -> dict:
    try:
        r = requests.get(f"{_BASE}{path}", params=params, headers=_HEADERS, timeout=10)
        if r.ok:
            return r.json()
        return {"error": r.text}
    except Exception as exc:
        return {"error": str(exc)}


def _post(path: str, payload: dict) -> dict:
    try:
        r = requests.post(f"{_BASE}{path}", json=payload, headers=_HEADERS, timeout=10)
        if r.ok:
            return r.json()
        return {"error": r.text}
    except Exception as exc:
        return {"error": str(exc)}


# ── Sidebar ────────────────────────────────────────────────────────────────────
st.sidebar.title("Business Intelligence")
tenant_id    = st.sidebar.text_input("Tenant ID", value="default")
community_id = st.sidebar.text_input("Community ID", value="")
period_days  = st.sidebar.slider("Period (days)", 7, 90, 30)

tabs = st.tabs([
    "Usage",
    "Threats",
    "Vendors",
    "Costs",
    "Compliance",
    "Benchmarks",
    "Predictions",
    "Report Builder",
])

# ── Tab 1 — Usage Analytics ────────────────────────────────────────────────────
with tabs[0]:
    st.header("AI Usage Analytics")
    data = _get("/business-intelligence/usage", {"tenant_id": tenant_id})
    if "error" in data:
        st.error(data["error"])
    else:
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Requests",   data.get("total_requests", 0))
        col2.metric("Blocked",          data.get("blocked_requests", 0))
        col3.metric("Block Rate",       f"{data.get('block_rate_pct', 0):.1f}%")
        col4.metric("Avg Latency",      f"{data.get('avg_latency_ms', 0):.0f}ms")
        if data.get("daily_trend"):
            import pandas as pd
            df = pd.DataFrame(data["daily_trend"])
            st.line_chart(df.set_index("date")["count"] if "date" in df.columns else df)
        if data.get("top_categories"):
            st.subheader("Top Request Categories")
            st.table(data["top_categories"])

# ── Tab 2 — Threats ────────────────────────────────────────────────────────────
with tabs[1]:
    st.header("Threat Intelligence Dashboard")
    data = _get("/business-intelligence/threats", {"tenant_id": tenant_id, "period_days": period_days})
    if "error" in data:
        st.error(data["error"])
    else:
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Threats",   data.get("total_threats", 0))
        col2.metric("MTTR (hours)",    f"{data.get('mttr_hours', 0):.1f}h")
        col3.metric("Top Attack",      data.get("top_attack_vectors", ["—"])[0])
        if data.get("by_severity"):
            st.subheader("By Severity")
            import pandas as pd
            sev = data["by_severity"]
            st.bar_chart(pd.Series(sev))
        if data.get("incident_trend"):
            st.subheader("Incident Trend")
            import pandas as pd
            df = pd.DataFrame(data["incident_trend"])
            if "date" in df.columns:
                st.line_chart(df.set_index("date"))

# ── Tab 3 — Vendors ────────────────────────────────────────────────────────────
with tabs[2]:
    st.header("Vendor Performance & Risk")
    data = _get("/business-intelligence/vendors", {"tenant_id": tenant_id})
    if "error" in data:
        st.error(data["error"])
    else:
        scorecards = data.get("scorecards", [])
        st.metric("Total Vendors", len(scorecards))
        if scorecards:
            import pandas as pd
            df = pd.DataFrame(scorecards)
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No active vendors found. Register vendors via /vendor-gov/vendors.")

# ── Tab 4 — Costs ──────────────────────────────────────────────────────────────
with tabs[3]:
    st.header("Cost Optimization Insights")
    months = st.slider("Months", 1, 12, 3, key="cost_months")
    data = _get("/business-intelligence/costs", {"tenant_id": tenant_id, "months": months})
    if "error" in data:
        st.error(data["error"])
    else:
        st.metric("Total Spend", f"${data.get('total_spend_usd', 0):.2f}")
        if data.get("by_department"):
            st.subheader("By Department")
            import pandas as pd
            df = pd.DataFrame(data["by_department"])
            st.bar_chart(df.set_index("department")["amount_usd"] if "department" in df.columns else df)
        if data.get("optimization_tips"):
            st.subheader("Optimization Tips")
            for tip in data["optimization_tips"]:
                st.info(tip)
        if data.get("anomalous_departments"):
            st.warning(f"Anomalous spend detected: {', '.join(data['anomalous_departments'])}")

# ── Tab 5 — Compliance ─────────────────────────────────────────────────────────
with tabs[4]:
    st.header("Compliance Posture")
    data = _get("/business-intelligence/compliance", {"tenant_id": tenant_id, "community_id": community_id})
    if "error" in data:
        st.error(data["error"])
    else:
        grade = data.get("grade", "F")
        score = data.get("overall_score", 0) * 100
        color = {"A": "green", "B": "blue", "C": "orange", "D": "red", "F": "red"}.get(grade, "gray")
        st.markdown(f"### Grade: :{color}[{grade}] ({score:.1f}%)")
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Training",        f"{data.get('training_pct', 0):.1f}%")
        col2.metric("Vendor DPA",      f"{data.get('vendor_dpa_pct', 0):.1f}%")
        col3.metric("Incident Closure",f"{data.get('incident_closure_pct', 0):.1f}%")
        col4.metric("Budget Adherence",f"{data.get('budget_adherence_pct', 0):.1f}%")

# ── Tab 6 — Benchmarks ─────────────────────────────────────────────────────────
with tabs[5]:
    st.header("Community Benchmarking")
    data = _get("/business-intelligence/benchmarks", {"tenant_id": tenant_id, "community_id": community_id})
    if "error" in data:
        st.error(data["error"])
    else:
        benchmarks = data.get("benchmarks", [])
        if benchmarks:
            import pandas as pd
            df = pd.DataFrame(benchmarks)[["metric", "tenant_value", "community_avg", "percentile_rank", "status"]]
            st.dataframe(df, use_container_width=True)
        else:
            st.info("Benchmark data not available.")

# ── Tab 7 — Predictions ────────────────────────────────────────────────────────
with tabs[6]:
    st.header("Predictive Incident Analytics")
    horizon = st.slider("Prediction horizon (days)", 7, 90, 30, key="pred_horizon")
    data = _get("/business-intelligence/predictions", {"tenant_id": tenant_id, "horizon_days": horizon})
    if "error" in data:
        st.error(data["error"])
    else:
        col1, col2, col3 = st.columns(3)
        col1.metric("Predicted Incidents", data.get("predicted_count", 0))
        col2.metric("Confidence",          f"{data.get('confidence', 0)*100:.0f}%")
        direction = data.get("trend_direction", "stable")
        icon = {"rising": "↑", "falling": "↓", "stable": "→"}.get(direction, "→")
        col3.metric("Trend", f"{icon} {direction.title()}")
        if data.get("risk_factors"):
            st.subheader("Risk Factors")
            for rf in data["risk_factors"]:
                st.warning(rf)
        if data.get("recommendations"):
            st.subheader("Recommendations")
            for rec in data["recommendations"]:
                st.info(rec)

# ── Tab 8 — Report Builder ─────────────────────────────────────────────────────
with tabs[7]:
    st.header("Custom Report Builder")
    with st.form("report_form"):
        report_type = st.selectbox("Report Type", ["full", "executive", "compliance", "vendor", "cost"])
        p_months    = st.slider("Period (months)", 1, 12, 3)
        submitted   = st.form_submit_button("Generate Report")
    if submitted:
        payload = {
            "tenant_id":     tenant_id,
            "community_id":  community_id,
            "report_type":   report_type,
            "period_months": p_months,
        }
        with st.spinner("Generating report..."):
            data = _post("/business-intelligence/report", payload)
        if "error" in data:
            st.error(data["error"])
        else:
            st.success("Report generated")
            for section_name, section_data in data.get("sections", {}).items():
                with st.expander(section_name.title(), expanded=False):
                    st.json(section_data)
