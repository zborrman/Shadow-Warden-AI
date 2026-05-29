"""
warden/analytics/pages/14_Agentic_Commerce.py  (CM-40)
Streamlit dashboard — E-commerce AI / Agentic Commerce
Tabs: Mandates | Orders | Auctions | Risk Analysis | Spend Analytics
"""
from __future__ import annotations

import asyncio
import os

import streamlit as st

st.set_page_config(page_title="Agentic Commerce", page_icon="🛒", layout="wide")

TENANT = os.getenv("DEFAULT_TENANT_ID", "default")


def _proc():
    from warden.business_community.agentic_commerce.ap2 import AP2Processor
    return AP2Processor()


def _svc():
    from warden.business_community.agentic_commerce.service import AgenticCommerceService
    return AgenticCommerceService()


st.title("🛒 Agentic Commerce")
st.caption("UCP · AP2 · MCP — AI-driven procurement with mandate controls")

tab_mandates, tab_orders, tab_auctions, tab_risk, tab_spend = st.tabs(
    ["Mandates", "Orders", "Auctions", "Risk Analysis", "Spend Analytics"]
)

# ── Mandates ──────────────────────────────────────────────────────────────────
with tab_mandates:
    st.subheader("Spending Mandates")

    col_list, col_new = st.columns([2, 1])

    with col_list:
        try:
            mandates = _proc().list_mandates(TENANT)
            if mandates:
                import pandas as pd
                rows = [
                    {
                        "ID": m.id[:12] + "…",
                        "Max ($)": f"{m.max_amount:.2f}",
                        "Spent ($)": f"{m.spent_so_far:.2f}",
                        "Remaining ($)": f"{m.remaining():.2f}",
                        "Status": m.status,
                        "Valid Until": m.valid_until[:10],
                    }
                    for m in mandates
                ]
                st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
            else:
                st.info("No mandates yet. Create one to enable AI-driven purchases.")
        except Exception as e:
            st.error(f"Error loading mandates: {e}")

    with col_new:
        st.markdown("**Create Mandate**")
        with st.form("new_mandate"):
            max_amt = st.number_input("Max Amount ($)", min_value=1.0, value=100.0, step=10.0)
            currency = st.selectbox("Currency", ["USD", "EUR", "GBP"])
            merchants = st.text_input("Allowed Merchants (comma-separated)", placeholder="shop.com, store.io")
            submit = st.form_submit_button("Create", type="primary")
            if submit:
                allowed = [m.strip() for m in merchants.split(",") if m.strip()]
                try:
                    m = _proc().create_mandate(TENANT, max_amount=max_amt, currency=currency,
                                               allowed_merchants=allowed)
                    st.success(f"Mandate created: {m.id[:16]}…")
                    st.rerun()
                except Exception as e:
                    st.error(str(e))

# ── Orders ────────────────────────────────────────────────────────────────────
with tab_orders:
    st.subheader("Purchase Orders")
    try:
        import pandas as pd
        orders = _svc().get_order_history(TENANT, limit=100)
        if orders:
            rows = [
                {
                    "Order ID": o["id"][:12] + "…",
                    "Store": o.get("store_url", "")[:40],
                    "Total ($)": f"{o.get('total', 0):.2f}",
                    "Status": o.get("status", ""),
                    "UECIID": o.get("ueciid", "")[:14],
                    "Created": o.get("created_at", "")[:10],
                    "MCP Intent": (o.get("mcp_intent") or "")[:60],
                }
                for o in orders
            ]
            df = pd.DataFrame(rows)
            st.dataframe(df, use_container_width=True, hide_index=True)

            csv = df.to_csv(index=False).encode()
            st.download_button("Export CSV", csv, "orders.csv", "text/csv")
        else:
            st.info("No orders yet.")
    except Exception as e:
        st.error(f"Error loading orders: {e}")

# ── Auctions ─────────────────────────────────────────────────────────────────
with tab_auctions:
    st.subheader("Multi-Agent Procurement Auctions")
    st.caption("Claude · Gemini · GPT compete to find the best vendor for your purchase")

    col_new, col_list = st.columns([1, 2])

    with col_new:
        st.markdown("**Launch Auction**")
        with st.form("new_auction"):
            request = st.text_area("Purchase request", placeholder="Buy a cloud monitoring subscription under $100/mo", height=100)
            budget  = st.number_input("Budget (USD)", min_value=0.0, value=0.0, step=10.0)
            submit  = st.form_submit_button("Launch", type="primary")
            if submit and request:
                try:
                    from warden.business_community.agentic_commerce.multi_agent.orchestrator import (
                        MultiAgentOrchestrator,
                    )
                    orch = MultiAgentOrchestrator()
                    with st.spinner("Running auction across AI agents…"):
                        aid = asyncio.get_event_loop().run_until_complete(
                            orch.run_auction(TENANT, request, budget_usd=budget or None)
                        )
                    result = orch.get_auction(aid, TENANT)
                    winner = result.get("winner")
                    if winner:
                        st.success(f"Winner: **{winner.get('recommended_vendor', 'N/A')}** — ${winner.get('estimated_price_usd', 0):.2f}")
                    else:
                        st.info("Auction complete — no AI agents available (configure API keys to enable).")
                    st.rerun()
                except Exception as e:
                    st.error(str(e))

    with col_list:
        st.markdown("**Recent Auctions**")
        try:
            import pandas as pd

            from warden.business_community.agentic_commerce.multi_agent.orchestrator import (
                MultiAgentOrchestrator,
            )
            auctions = MultiAgentOrchestrator().list_auctions(TENANT, limit=20)
            if auctions:
                rows = [
                    {
                        "ID": a["id"][:12] + "…",
                        "Status": a["status"],
                        "Request": (a.get("request") or "")[:50],
                        "Winner": (a.get("winner") or {}).get("recommended_vendor", "—") if a.get("winner") else "—",
                        "Created": (a.get("created_at") or "")[:10],
                    }
                    for a in auctions
                ]
                st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
            else:
                st.info("No auctions yet.")
        except Exception as e:
            st.error(str(e))


# ── Risk Analysis ─────────────────────────────────────────────────────────────
with tab_risk:
    st.subheader("Merchant Risk Analysis")
    st.caption("Check a merchant domain against Vendor Governance before authorizing purchases.")

    domain = st.text_input("Merchant domain", placeholder="shop.example.com")
    if st.button("Check Risk") and domain:
        try:
            from urllib.parse import urlparse

            from warden.vendor_gov.registry import list_vendors
            parsed = urlparse(domain if "://" in domain else f"https://{domain}")
            check_domain = parsed.netloc or domain
            vendors = list_vendors(TENANT)
            match = next((v for v in vendors if check_domain in (v.website or "")), None)
            if match:
                color = {"LOW": "green", "MEDIUM": "orange", "HIGH": "red"}.get(match.risk_tier, "gray")
                st.markdown(f"**Status:** {match.status}  **Risk:** :{color}[{match.risk_tier}]  **DPA:** {match.dpa_status if hasattr(match, 'dpa_status') else 'unknown'}")
            else:
                st.warning(f"Merchant **{check_domain}** is NOT registered in Vendor Governance. "
                           "Purchase will be blocked until registered.")
        except Exception as e:
            st.error(str(e))

    st.divider()
    st.markdown("**Auto-block rules:**")
    st.markdown("- Merchant not in Vendor Governance registry → blocked\n"
                "- Merchant domain not in mandate allowlist → blocked\n"
                "- Active DPA required for PHI/PII data transfers")

# ── Spend Analytics ───────────────────────────────────────────────────────────
with tab_spend:
    st.subheader("Spend Analytics")
    try:
        usage = _svc().get_mandate_usage(TENANT)

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Authorized", f"${usage.get('total_authorized', 0):.2f}")
        col2.metric("Total Spent", f"${usage.get('total_spent', 0):.2f}")
        col3.metric("Active Mandates", usage.get("active", 0))

        mandates_data = usage.get("mandates", [])
        if mandates_data:
            import pandas as pd
            import plotly.express as px

            df = pd.DataFrame(mandates_data)
            df = df.rename(columns={"max_amount": "Authorized", "spent": "Spent", "remaining": "Remaining"})
            fig = px.bar(df, x="id", y=["Spent", "Remaining"],
                         title="Mandate Utilization", barmode="stack",
                         color_discrete_map={"Spent": "#ef4444", "Remaining": "#10b981"})
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No mandate data to visualize yet.")
    except Exception as e:
        st.error(f"Analytics error: {e}")
