"""
warden/analytics/pages/24_Agentic_Trading.py
──────────────────────────────────────────────
Streamlit admin page — Agentic Trading Monitor (Phase 2).

Tabs
────
  Active Agents   — seller + buyer agents and their configuration
  Negotiations    — open/completed negotiation sessions
  Escrow Monitor  — escrow lifecycle table with status badges
"""
import json
import os

import streamlit as st

from warden.db.connect import open_db_readonly

st.set_page_config(page_title="Agentic Trading", page_icon="⚡", layout="wide")
st.title("⚡ Agentic Trading Monitor")

_DB_PATH = os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")

_STATUS_COLORS = {
    "active":           "#22c55e",
    "purchased":        "#22c55e",
    "confirmed":        "#22c55e",
    "accepted":         "#22c55e",
    "funded":           "#3b82f6",
    "delivered":        "#8b5cf6",
    "pending_deposit":  "#f59e0b",
    "negotiating":      "#f59e0b",
    "open":             "#f59e0b",
    "disputed":         "#ef4444",
    "rejected":         "#ef4444",
    "stale":            "#6b7280",
    "sold":             "#6b7280",
    "cancelled":        "#6b7280",
    "resolved_buyer":   "#06b6d4",
    "resolved_seller":  "#06b6d4",
}


def _badge(status: str) -> str:
    color = _STATUS_COLORS.get(status.lower(), "#6b7280")
    return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">{status}</span>'


def _conn():
    return open_db_readonly(_DB_PATH)


def _query(sql: str, params: tuple = ()) -> list[dict]:
    try:
        with _conn() as con:
            return [dict(r) for r in con.execute(sql, params).fetchall()]
    except Exception:
        return []


# ── Tab 1: Active Agents ─────────────────────────────────────────────────────
# ── Tab 2: Negotiations ──────────────────────────────────────────────────────
# ── Tab 3: Escrow Monitor ────────────────────────────────────────────────────

tab_agents, tab_negs, tab_escrow, tab_imports = st.tabs(
    ["Active Agents", "Negotiations", "Escrow Monitor", "Imported Assets"]
)


with tab_agents:
    agents = _query(
        "SELECT agent_id, community_id, capabilities, status, mandate_id, created_at"
        " FROM marketplace_agents ORDER BY created_at DESC LIMIT 200"
    )

    seller_count = sum(1 for a in agents if "marketplace_sell" in (a.get("capabilities") or ""))
    buyer_count  = sum(1 for a in agents if "marketplace_buy"  in (a.get("capabilities") or ""))

    c1, c2, c3 = st.columns(3)
    c1.metric("Total Agents",  len(agents))
    c2.metric("Seller Agents", seller_count)
    c3.metric("Buyer Agents",  buyer_count)

    if agents:
        import pandas as pd
        df = pd.DataFrame(agents)
        df["agent_short"] = df["agent_id"].str[len("did:shadow:"):len("did:shadow:")+12] + "…"
        df["capabilities"] = df["capabilities"].apply(
            lambda v: ", ".join(json.loads(v)) if isinstance(v, str) else str(v)
        )
        st.dataframe(
            df[["agent_short", "community_id", "capabilities", "status", "mandate_id", "created_at"]],
            use_container_width=True,
        )
    else:
        st.info("No agents registered yet.")


with tab_negs:
    negs = _query(
        "SELECT n.negotiation_id, n.listing_id, n.buyer_agent, n.seller_agent,"
        " n.status, n.current_price, n.round_count, n.updated_at,"
        " COUNT(o.offer_id) AS offer_count"
        " FROM marketplace_negotiations n"
        " LEFT JOIN marketplace_offers o ON o.negotiation_id = n.negotiation_id"
        " GROUP BY n.negotiation_id ORDER BY n.updated_at DESC LIMIT 200"
    )

    total  = len(negs)
    open_  = sum(1 for n in negs if n.get("status") == "open")
    accept = sum(1 for n in negs if n.get("status") == "accepted")

    c1, c2, c3 = st.columns(3)
    c1.metric("Total",    total)
    c2.metric("Open",     open_)
    c3.metric("Accepted", accept)

    if negs:
        import pandas as pd
        df = pd.DataFrame(negs)
        df["neg_short"] = df["negotiation_id"].str[:14] + "…"
        st.dataframe(
            df[["neg_short", "listing_id", "status", "current_price",
                "round_count", "offer_count", "updated_at"]],
            use_container_width=True,
        )
    else:
        st.info("No negotiations recorded yet.")


with tab_escrow:
    escrows = _query(
        "SELECT escrow_id, listing_id, buyer_agent, seller_agent,"
        " amount_usd, status, contract_address, dispute_reason, created_at, confirmed_at"
        " FROM marketplace_escrow ORDER BY created_at DESC LIMIT 200"
    )

    active_   = sum(1 for e in escrows if e.get("status") in ("funded", "delivered"))
    disputed_ = sum(1 for e in escrows if e.get("status") == "disputed")
    done_     = sum(1 for e in escrows if e.get("status") == "confirmed")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total",     len(escrows))
    c2.metric("Active",    active_)
    c3.metric("Disputed",  disputed_)
    c4.metric("Confirmed", done_)

    if escrows:
        import pandas as pd
        df = pd.DataFrame(escrows)
        df["escrow_short"]   = df["escrow_id"].str[:14] + "…"
        df["contract_short"] = df["contract_address"].str[:10] + "…"
        st.dataframe(
            df[["escrow_short", "listing_id", "status", "amount_usd",
                "contract_short", "dispute_reason", "created_at"]],
            use_container_width=True,
        )
    else:
        st.info("No escrows created yet.")

    if disputed_:
        st.warning(f"{disputed_} escrow(s) in DISPUTED state — review required.")


with tab_imports:
    imports = _query(
        "SELECT import_id, purchase_id, asset_id, asset_type, buyer_agent,"
        " tenant_id, status, module, error, imported_at"
        " FROM marketplace_imports ORDER BY imported_at DESC LIMIT 200"
    )

    success_ = sum(1 for i in imports if i.get("status") == "success")
    failed_  = sum(1 for i in imports if i.get("status") == "failed")
    rule_c   = sum(1 for i in imports if i.get("asset_type") == "rule")
    model_c  = sum(1 for i in imports if i.get("asset_type") == "model")
    signal_c = sum(1 for i in imports if i.get("asset_type") == "signals")

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total",   len(imports))
    c2.metric("Success", success_)
    c3.metric("Failed",  failed_)
    c4.metric("Rules",   rule_c)
    c5.metric("Signals", signal_c)

    if imports:
        import pandas as pd
        df = pd.DataFrame(imports)
        df["imp_short"] = df["import_id"].str[:14] + "…"
        df["asset_short"] = df["asset_id"].str[:12] + "…"
        df["status_badge"] = df["status"].apply(_badge)
        st.dataframe(
            df[["imp_short", "asset_short", "asset_type", "module",
                "status", "error", "imported_at"]],
            use_container_width=True,
        )
        if failed_:
            st.error(f"{failed_} import(s) failed — check 'error' column for details.")
    else:
        st.info("No asset imports recorded yet. Imports are triggered automatically on escrow confirmation.")
