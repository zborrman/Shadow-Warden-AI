"""
Streamlit page: M2M Commerce Store

Tabs
────
  Catalog   — browse products, add new (admin)
  Offers    — generate offers, active reservations
  Orders    — order table with statuses
  Analytics — sales via Semantic Layer agentic_orders model
"""
from __future__ import annotations

import os

import requests
import streamlit as st

st.set_page_config(page_title="M2M Store", page_icon="🏪", layout="wide")

_BASE    = os.getenv("WARDEN_INTERNAL_URL", "http://localhost:8001")
_API_KEY = os.getenv("WARDEN_API_KEY", "")
_HDRS    = {"X-API-Key": _API_KEY} if _API_KEY else {}

st.title("🏪 M2M Commerce Store")
st.caption("Seller-side architecture for autonomous AI agent trading. Enterprise tier.")

tab_catalog, tab_offers, tab_orders, tab_analytics = st.tabs([
    "📦 Catalog", "💬 Offers", "📋 Orders", "📊 Analytics"
])

# ── Tab: Catalog ──────────────────────────────────────────────────────────────
with tab_catalog:
    col_search, col_cat = st.columns([3, 1])
    with col_search:
        q = st.text_input("Search products", placeholder="security scan, API token…")
    with col_cat:
        cat_filter = st.text_input("Category filter")

    params: dict[str, str] = {"q": q, "category": cat_filter, "in_stock_only": "false"}
    try:
        r = requests.get(f"{_BASE}/m2m-store/catalog", headers=_HDRS, params=params, timeout=5)
        products = r.json() if r.status_code == 200 else []
    except Exception:
        products = []

    if products:
        import pandas as pd
        df = pd.DataFrame(products)[["id", "name", "category", "price_base", "stock", "reserved", "active"]]
        df["available"] = df["stock"] - df["reserved"]
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No products found. Add some below.")

    st.divider()
    st.subheader("Add Product (Admin)")
    with st.form("add_product"):
        c1, c2, c3, c4 = st.columns(4)
        name    = c1.text_input("Name")
        cat     = c2.text_input("Category", "general")
        price   = c3.number_input("Base price (USD)", min_value=0.01, value=9.99, step=1.0)
        stock   = c4.number_input("Initial stock", min_value=1, value=100, step=10)
        desc    = st.text_area("Description", height=60)
        if st.form_submit_button("Add Product") and name:
            payload = {"name": name, "description": desc, "category": cat,
                       "price_base": price, "stock": stock}
            try:
                r = requests.post(f"{_BASE}/m2m-store/products", json=payload, headers=_HDRS, timeout=5)
                if r.status_code == 201:
                    st.success(f"Product added: {r.json()['name']}")
                    st.rerun()
                else:
                    st.error(f"Error: {r.text[:200]}")
            except Exception as exc:
                st.error(str(exc))

# ── Tab: Offers ───────────────────────────────────────────────────────────────
with tab_offers:
    st.subheader("Request an Offer")
    with st.form("offer_form"):
        c1, c2, c3 = st.columns(3)
        product_id = c1.text_input("Product ID")
        agent_id   = c2.text_input("Agent ID", value="agent-demo")
        qty        = c3.number_input("Quantity", min_value=1, value=1)
        if st.form_submit_button("Get Offer") and product_id:
            try:
                r = requests.post(
                    f"{_BASE}/m2m-store/offers",
                    json={"product_id": product_id, "agent_id": agent_id, "qty": qty},
                    headers=_HDRS, timeout=10,
                )
                if r.status_code == 201:
                    offer = r.json()
                    st.success(f"Offer created — ${offer['price_final']:.2f} ({offer['discount_percent']:.1f}% off)")
                    st.json(offer)
                elif r.status_code == 409:
                    st.warning("Product unavailable or insufficient stock.")
                elif r.status_code == 422:
                    st.error(f"Validation error: {r.json().get('detail','')}")
                else:
                    st.error(f"Error {r.status_code}: {r.text[:200]}")
            except Exception as exc:
                st.error(str(exc))

# ── Tab: Orders ───────────────────────────────────────────────────────────────
with tab_orders:
    agent_id_filter = st.text_input("Filter by agent ID", value="agent-demo", key="ord_agent")
    try:
        r = requests.get(
            f"{_BASE}/m2m-store/orders/history",
            headers=_HDRS, params={"agent_id": agent_id_filter, "limit": "50"}, timeout=5,
        )
        orders = r.json() if r.status_code == 200 else []
    except Exception:
        orders = []

    if orders:
        import pandas as pd
        df = pd.DataFrame(orders)[["id", "product_id", "qty", "total", "status", "created_at"]]
        df["total"] = df["total"].apply(lambda x: f"${x:.2f}")
        st.dataframe(df, use_container_width=True, hide_index=True)
        st.caption(f"{len(orders)} orders")
    else:
        st.info("No orders yet for this agent.")

# ── Tab: Analytics ────────────────────────────────────────────────────────────
with tab_analytics:
    st.subheader("Sales Analytics — Semantic Layer")
    st.caption("Queries the `agentic_orders` semantic model for real-time spend data.")

    try:
        r = requests.post(
            f"{_BASE}/semantic-layer/query",
            json={
                "model_id": "agentic_orders",
                "metrics":  ["order_count", "total_spent_usd", "avg_order_usd"],
                "dimensions": ["status"],
                "limit": 100,
            },
            headers=_HDRS, timeout=10,
        )
        if r.status_code == 200:
            result = r.json()
            st.success(f"SQL generated in {result['generation_ms']} ms")
            st.code(result["sql"], language="sql")
        else:
            st.info("Semantic Layer not available or agentic_orders model not populated.")
    except Exception as exc:
        st.warning(f"Semantic Layer query failed: {exc}")

    st.divider()
    st.subheader("Budget Summary")
    try:
        r = requests.get(
            f"{_BASE}/business-community/commerce/budget",
            headers=_HDRS, params={"tenant_id": "demo"}, timeout=5,
        )
        if r.status_code == 200:
            summary = r.json()
            c1, c2, c3 = st.columns(3)
            c1.metric("MTD Spend", f"${summary.get('mtd_spend_usd', 0):.2f}")
            c2.metric("Monthly Budget", f"${summary.get('monthly_budget_usd', 0):.2f}")
            c3.metric("Remaining", f"${summary.get('remaining_usd', 0):.2f}")
            pct = summary.get("utilisation_pct", 0)
            st.progress(min(pct / 100, 1.0), text=f"Budget utilisation: {pct:.1f}%")
        else:
            st.info("Commerce budget not configured.")
    except Exception as exc:
        st.warning(f"Budget fetch failed: {exc}")
