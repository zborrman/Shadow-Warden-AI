"""
Streamlit GSAM Marketplace — 3 tabs: Demand Heatmap, Agent Stats,
Compliance Score. Reads the /gsam/* read APIs (Pro+). English-only.
"""
from __future__ import annotations

import os

import httpx
import pandas as pd
import streamlit as st

BASE = os.getenv("WARDEN_API_URL", "http://localhost:8001")
HEADERS = {
    "X-API-Key":      os.getenv("WARDEN_API_KEY", ""),
    "X-Tenant-Tier":  os.getenv("DEFAULT_TENANT_TIER", "pro"),
}

st.set_page_config(page_title="GSAM Marketplace", page_icon="📊", layout="wide")

st.markdown("""
<style>
  [data-testid="stAppViewContainer"] { background: #07090f; }
  [data-testid="stSidebar"] { background: #0a0f1e; }
  .block-container { padding-top: 1.5rem; }
</style>
""", unsafe_allow_html=True)

st.title("📊 GSAM — Global Statistic Agentic Marketplace")
st.caption("Marketplace-wide agent economics, behavioural drift, and anti-inflation compliance.")


def _get(path: str, params: dict | None = None) -> dict | None:
    try:
        resp = httpx.get(f"{BASE}{path}", headers=HEADERS, params=params or {}, timeout=10.0)
        if resp.status_code == 403:
            st.warning("GSAM analytics require a Pro or Enterprise plan.")
            return None
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:  # noqa: BLE001
        st.error(f"Request failed: {exc}")
        return None


tab_heatmap, tab_agent, tab_compliance = st.tabs(
    ["Demand Heatmap", "Agent Stats", "Compliance Score"]
)

# ── Demand Heatmap ────────────────────────────────────────────────────────────

with tab_heatmap:
    hours = st.slider("Window (hours)", min_value=1, max_value=168, value=24)
    data = _get("/gsam/heatmap", {"hours": hours})
    if data:
        st.caption(f"Source: **{data.get('source')}** · grouped by **{data.get('group_by')}**")
        buckets = data.get("buckets", [])
        if buckets:
            df = pd.DataFrame(buckets)
            st.bar_chart(df.set_index("category")["events"])
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("No marketplace activity in the selected window.")

# ── Agent Stats ───────────────────────────────────────────────────────────────

with tab_agent:
    agent_id = st.text_input("Agent ID", placeholder="agent-…")
    if agent_id:
        data = _get(f"/gsam/agents/{agent_id}/stats")
        if data:
            if data.get("quarantined"):
                st.error("🚫 This agent is currently under GSAM drift quarantine.")
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Events", f"{data.get('events', 0):,}")
            c2.metric("Cost (USD)", f"${data.get('cost_usd', 0.0):.4f}")
            c3.metric("ROI", f"{data.get('roi', 0.0):.2f}")
            c4.metric("Drift", f"{data.get('drift', 0.0):.3f}")
            c5, c6 = st.columns(2)
            c5.metric("Trust", f"{data.get('trust', 0.0):.2f}")
            c6.metric("Tokens (in/out)",
                      f"{data.get('tokens_in', 0):,} / {data.get('tokens_out', 0):,}")
            verdicts = data.get("verdicts", {})
            if verdicts:
                st.subheader("Scan verdicts")
                st.dataframe(pd.DataFrame(
                    [{"verdict": k, "count": v} for k, v in verdicts.items()],
                ), use_container_width=True, hide_index=True)

# ── Compliance Score ──────────────────────────────────────────────────────────

with tab_compliance:
    data = _get("/gsam/compliance/score")
    if data:
        score = data.get("score", 1.0)
        c1, c2, c3 = st.columns(3)
        c1.metric("Compliance Score", f"{score:.2f}")
        c2.metric("Agents Scanned", data.get("agents_scanned", 0))
        c3.metric("Quarantined", data.get("quarantined_count", 0))
        if data.get("critical"):
            st.error("🔴 CRITICAL: co-occurring strong inflation signals detected.")
        elif score < 1.0:
            st.warning("🟡 Anti-inflation signals present.")
        else:
            st.success("🟢 No anti-inflation signals — marketplace is clean.")
        strong = data.get("strong_patterns", [])
        weak = data.get("weak_patterns", [])
        if strong:
            st.subheader("Strong patterns")
            st.write(", ".join(strong))
        if weak:
            st.subheader("Weak patterns")
            st.write(", ".join(weak))
