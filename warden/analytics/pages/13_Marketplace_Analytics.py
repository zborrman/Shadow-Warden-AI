"""
warden/analytics/pages/13_Marketplace_Analytics.py
────────────────────────────────────────────────────
Streamlit M2M Marketplace Analytics dashboard — 5 tabs.
"""
from __future__ import annotations

import os

import requests
import streamlit as st

st.set_page_config(page_title="Marketplace Analytics", page_icon="🛒", layout="wide")

_BASE = os.getenv("WARDEN_API_URL", "http://localhost:8001")
_KEY  = os.getenv("WARDEN_API_KEY", "")
_HEADERS = {"X-API-Key": _KEY} if _KEY else {}


def _get(path: str, params: dict | None = None) -> dict | list:
    try:
        r = requests.get(f"{_BASE}{path}", params=params, headers=_HEADERS, timeout=10)
        if r.ok:
            return r.json()
        return {"error": r.text}
    except Exception as exc:
        return {"error": str(exc)}


# ── Sidebar ────────────────────────────────────────────────────────────────────
st.sidebar.title("Marketplace Analytics")
tenant_id    = st.sidebar.text_input("Tenant ID", value="default")
community_id = st.sidebar.text_input("Community ID", value="")
period_days  = st.sidebar.slider("Period (days)", 7, 90, 30)

tabs = st.tabs(["Overview", "Volume", "Pricing", "Agents", "Escrow"])


# ── Shared params helper ───────────────────────────────────────────────────────
def _params(**extra) -> dict:
    p: dict = {"tenant_id": tenant_id, "period_days": str(period_days)}
    if community_id:
        p["community_id"] = community_id
    p.update(extra)
    return p


# ── Tab 1 — Overview ───────────────────────────────────────────────────────────
with tabs[0]:
    st.header("Marketplace Overview")
    data = _get("/marketplace/analytics/summary", _params())
    if isinstance(data, dict) and "error" in data:
        st.error(data["error"])
    elif isinstance(data, dict):
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Volume (USD)",   f"${data.get('total_volume_usd', 0):,.2f}")
        col2.metric("Trades",         data.get("total_trades", 0))
        col3.metric("Avg Price",      f"${data.get('avg_price_usd', 0):,.2f}")
        col4.metric("Dispute Rate",   f"{data.get('dispute_rate', 0) * 100:.1f}%")

        col5, col6 = st.columns(2)
        col5.metric("Active Listings",   data.get("active_listings", 0))
        col6.metric("Registered Agents", data.get("registered_agents", 0))

        top = data.get("top_asset_types", [])
        if top:
            st.subheader("Trade Count by Asset Type")
            import pandas as pd
            df = pd.DataFrame(top).set_index("type")
            st.bar_chart(df["count"])


# ── Tab 2 — Volume ─────────────────────────────────────────────────────────────
with tabs[1]:
    st.header("Trading Volume Over Time")
    series = _get("/marketplace/analytics/volume", _params())
    if isinstance(series, dict) and "error" in series:
        st.error(series["error"])
    elif isinstance(series, list) and series:
        import pandas as pd
        df = pd.DataFrame(series).set_index("date")
        st.subheader("Daily Volume (USD)")
        st.area_chart(df["volume_usd"])
        st.subheader("Daily Trade Count")
        st.line_chart(df["trades"])
    else:
        st.info("No trading data for selected period.")


# ── Tab 3 — Pricing ────────────────────────────────────────────────────────────
with tabs[2]:
    st.header("Pricing Analytics")
    data = _get("/marketplace/analytics/summary", _params())
    if isinstance(data, dict) and "error" not in data:
        top = data.get("top_asset_types", [])
        if top:
            import pandas as pd
            st.subheader("Avg Price by Asset Type (USD)")
            df = pd.DataFrame(top)
            if not df.empty:
                df["avg_price"] = df["volume_usd"] / df["count"].replace(0, 1)
                st.bar_chart(df.set_index("type")["avg_price"])

        strategy = data.get("pricing_strategy_dist", {})
        if strategy:
            st.subheader("Pricing Strategy Distribution")
            import pandas as pd
            df_s = pd.DataFrame(
                list(strategy.items()), columns=["strategy", "count"]
            ).set_index("strategy")
            st.bar_chart(df_s)
        else:
            st.info("No pricing strategy data available.")
    elif isinstance(data, dict) and "error" in data:
        st.error(data["error"])


# ── Tab 4 — Agents ─────────────────────────────────────────────────────────────
with tabs[3]:
    st.header("Agent Leaderboard")
    data = _get("/marketplace/analytics/agents", {"tenant_id": tenant_id})
    if isinstance(data, dict) and "error" in data:
        st.error(data["error"])
    elif isinstance(data, dict):
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Top Sellers")
            sellers = data.get("top_sellers", [])
            if sellers:
                import pandas as pd
                df = pd.DataFrame(sellers)
                df["agent_id"] = df["agent_id"].str[:24] + "…"
                st.dataframe(df, use_container_width=True)
            else:
                st.info("No seller data.")
        with col2:
            st.subheader("Top Buyers")
            buyers = data.get("top_buyers", [])
            if buyers:
                import pandas as pd
                df = pd.DataFrame(buyers)
                df["agent_id"] = df["agent_id"].str[:24] + "…"
                st.dataframe(df, use_container_width=True)
            else:
                st.info("No buyer data.")


# ── Tab 5 — Escrow ─────────────────────────────────────────────────────────────
with tabs[4]:
    st.header("Escrow Pipeline")
    data = _get("/marketplace/analytics/summary", _params())
    if isinstance(data, dict) and "error" in data:
        st.error(data["error"])
    elif isinstance(data, dict):
        dispute_rate = data.get("dispute_rate", 0)
        st.metric("Dispute Rate", f"{dispute_rate * 100:.1f}%")
        pipeline = data.get("escrow_pipeline", {})
        if pipeline:
            import pandas as pd
            df = pd.DataFrame(
                [{"stage": k, "count": v} for k, v in pipeline.items()]
            ).set_index("stage")
            st.bar_chart(df)
        else:
            st.info("No escrow data.")
