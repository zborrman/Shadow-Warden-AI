"""
warden/analytics/pages/23_Marketplace_Admin.py
─────────────────────────────────────────────────
Streamlit admin page for the Community M2M Agentic Marketplace.

Tabs
────
  Agent Registry  — all registered marketplace agents
  Assets          — tokenized rules / models / signals
"""
import json
import os
import sqlite3

import streamlit as st

st.set_page_config(page_title="Marketplace Admin", page_icon="🏪", layout="wide")
st.title("🏪 M2M Agentic Marketplace")

_DB_PATH = os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")


def _conn():
    con = sqlite3.connect(_DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def _agents():
    try:
        with _conn() as con:
            rows = con.execute(
                "SELECT agent_id, community_id, tenant_id, capabilities, status, mandate_id, created_at"
                " FROM marketplace_agents ORDER BY created_at DESC LIMIT 200"
            ).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []


def _assets():
    try:
        with _conn() as con:
            rows = con.execute(
                "SELECT asset_id, asset_type, ipfs_hash, seller_agent_id, community_id, created_at"
                " FROM marketplace_assets ORDER BY created_at DESC LIMIT 200"
            ).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []


tab_agents, tab_assets = st.tabs(["Agent Registry", "Assets"])

# ── Agent Registry ─────────────────────────────────────────────────────────
with tab_agents:
    agents = _agents()
    st.metric("Total Agents", len(agents))

    if not agents:
        st.info("No marketplace agents registered yet.")
    else:
        import pandas as pd
        df = pd.DataFrame(agents)
        df["agent_id_short"] = df["agent_id"].str[len("did:shadow:"):][:8] + "…"
        df["capabilities"] = df["capabilities"].apply(
            lambda v: ", ".join(json.loads(v)) if isinstance(v, str) else str(v)
        )
        st.dataframe(
            df[["agent_id_short", "community_id", "tenant_id", "capabilities", "status", "mandate_id", "created_at"]],
            use_container_width=True,
        )

# ── Assets ─────────────────────────────────────────────────────────────────
with tab_assets:
    assets = _assets()
    col1, col2, col3 = st.columns(3)
    type_counts = {}
    for a in assets:
        type_counts[a["asset_type"]] = type_counts.get(a["asset_type"], 0) + 1
    col1.metric("Rules",   type_counts.get("rule",    0))
    col2.metric("Models",  type_counts.get("model",   0))
    col3.metric("Signals", type_counts.get("signals", 0))

    if not assets:
        st.info("No marketplace assets registered yet.")
    else:
        import pandas as pd
        df = pd.DataFrame(assets)
        df["asset_id_short"] = df["asset_id"].str[:14] + "…"
        df["ipfs_short"] = df["ipfs_hash"].str[:12] + "…"
        st.dataframe(
            df[["asset_id_short", "asset_type", "seller_agent_id", "community_id", "ipfs_short", "created_at"]],
            use_container_width=True,
        )
