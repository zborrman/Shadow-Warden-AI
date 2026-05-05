"""
Streamlit page: Billing & Subscriptions (Phase 5)

Tabs
────
  Overview       — current plan tile, quota gauge, renewal date
  Subscriptions  — all tenants + their plan / status / renewal
  Webhook Log    — recent Lemon Squeezy events from SQLite
  Dunning        — past_due tenants + days until auto-downgrade
  Upgrade        — checkout links for every plan
"""
from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pandas as pd
import streamlit as st

st.set_page_config(page_title="Billing", page_icon="💳", layout="wide")

# ── CSS ───────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
.plan-badge {
    display: inline-block; padding: 3px 10px; border-radius: 12px;
    font-weight: 600; font-size: 0.8rem;
}
.plan-starter    { background:#e5e7eb; color:#374151; }
.plan-individual { background:#dbeafe; color:#1d4ed8; }
.plan-community  { background:#d1fae5; color:#065f46; }
.plan-pro        { background:#ede9fe; color:#5b21b6; }
.plan-enterprise { background:#fef3c7; color:#92400e; }
.status-active   { color:#16a34a; font-weight:600; }
.status-past_due { color:#dc2626; font-weight:600; }
.status-cancelled{ color:#6b7280; font-weight:600; }
.status-expired  { color:#9ca3af; font-weight:600; }
.metric-box { background:#1e293b; border-radius:8px; padding:16px; text-align:center; }
</style>
""", unsafe_allow_html=True)

st.title("💳 Billing & Subscriptions")

# ── Data helpers ──────────────────────────────────────────────────────────────

_DB_PATH   = Path(os.getenv("LEMONSQUEEZY_DB_PATH", "/warden/data/lemon.db"))
_GRACE_DAYS = int(os.getenv("DUNNING_GRACE_DAYS", "7"))
_BASE       = os.getenv("WARDEN_INTERNAL_URL", "http://localhost:8001")
_PORTAL     = os.getenv("PORTAL_BASE_URL", "https://app.shadowwarden.ai")


@st.cache_data(ttl=30)
def _load_subscriptions() -> pd.DataFrame:
    if not _DB_PATH.exists():
        return pd.DataFrame()
    import sqlite3
    conn = sqlite3.connect(str(_DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT tenant_id, ls_customer_id, ls_sub_id, plan, status, renews_at, updated_at "
        "FROM subscriptions ORDER BY updated_at DESC"
    ).fetchall()
    conn.close()
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame([dict(r) for r in rows])


@st.cache_data(ttl=30)
def _load_webhook_events(limit: int = 100) -> pd.DataFrame:
    if not _DB_PATH.exists():
        return pd.DataFrame()
    import sqlite3
    conn = sqlite3.connect(str(_DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT event_id, event_name, processed_at FROM webhook_events "
        "ORDER BY processed_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame([dict(r) for r in rows])


def _plan_badge(plan: str) -> str:
    css = {
        "starter":            "plan-starter",
        "individual":         "plan-individual",
        "community_business": "plan-community",
        "pro":                "plan-pro",
        "enterprise":         "plan-enterprise",
    }.get(plan, "plan-starter")
    return f'<span class="plan-badge {css}">{plan.upper()}</span>'


def _status_html(status: str) -> str:
    return f'<span class="status-{status}">{status}</span>'


def _days_past_due(updated_at: str) -> int:
    try:
        dt = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
        return (datetime.now(UTC) - dt).days
    except Exception:
        return 0


# ── Tabs ──────────────────────────────────────────────────────────────────────

tab_overview, tab_subs, tab_webhooks, tab_dunning, tab_upgrade = st.tabs([
    "📊 Overview", "🗂️ Subscriptions", "🔔 Webhook Log", "⚠️ Dunning", "🚀 Upgrade",
])

# ── Overview ──────────────────────────────────────────────────────────────────

with tab_overview:
    df = _load_subscriptions()

    if df.empty:
        st.info("No subscription data yet. Lemon Squeezy webhooks will populate this once live.")
    else:
        total    = len(df)
        active   = len(df[df["status"].isin(["active", "on_trial"])])
        past_due = len(df[df["status"] == "past_due"])
        paid     = len(df[df["plan"] != "starter"])

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total tenants",   total)
        c2.metric("Active",          active,   delta=None)
        c3.metric("Past due",        past_due, delta=None, delta_color="inverse")
        c4.metric("Paid plans",      paid)

        st.divider()
        st.subheader("Plan distribution")
        plan_counts = df["plan"].value_counts().reset_index()
        plan_counts.columns = ["Plan", "Count"]
        st.bar_chart(plan_counts.set_index("Plan"))

        st.divider()
        st.subheader("Recent subscription changes")
        recent = df.head(10)[["tenant_id", "plan", "status", "renews_at", "updated_at"]]
        st.dataframe(recent, use_container_width=True)

    col_r, _ = st.columns([1, 3])
    with col_r:
        if st.button("Refresh", key="ov_refresh"):
            st.cache_data.clear()
            st.rerun()

# ── Subscriptions ─────────────────────────────────────────────────────────────

with tab_subs:
    df = _load_subscriptions()

    if df.empty:
        st.info("No subscriptions in the database.")
    else:
        # Search / filter
        search = st.text_input("Filter by tenant ID or plan", key="sub_search")
        if search:
            mask = (
                df["tenant_id"].str.contains(search, case=False, na=False) |
                df["plan"].str.contains(search, case=False, na=False) |
                df["status"].str.contains(search, case=False, na=False)
            )
            df = df[mask]

        st.markdown(f"**{len(df)} subscription(s)**")

        # Render as HTML table for coloured badges
        rows_html = ""
        for _, row in df.iterrows():
            rows_html += (
                f"<tr>"
                f"<td>{row['tenant_id']}</td>"
                f"<td>{_plan_badge(row['plan'])}</td>"
                f"<td>{_status_html(row['status'])}</td>"
                f"<td>{row.get('renews_at') or '—'}</td>"
                f"<td>{row.get('updated_at','')[:19]}</td>"
                f"</tr>"
            )
        st.markdown(
            f"""<table style="width:100%; border-collapse:collapse;">
            <thead><tr style="border-bottom:1px solid #334155;">
            <th align="left">Tenant</th><th align="left">Plan</th>
            <th align="left">Status</th><th align="left">Renews at</th>
            <th align="left">Updated</th></tr></thead>
            <tbody>{rows_html}</tbody></table>""",
            unsafe_allow_html=True,
        )

    col_r, _ = st.columns([1, 3])
    with col_r:
        if st.button("Refresh", key="sub_refresh"):
            st.cache_data.clear()
            st.rerun()

# ── Webhook Log ───────────────────────────────────────────────────────────────

with tab_webhooks:
    limit = st.slider("Events to show", 10, 200, 50, key="wh_limit")
    df_wh = _load_webhook_events(limit)

    if df_wh.empty:
        st.info("No webhook events recorded yet.")
    else:
        # Colour-code event types
        def _event_colour(name: str) -> str:
            if "created" in name or "resumed" in name:
                return "background-color: #052e16; color: #86efac"
            if "cancelled" in name or "expired" in name:
                return "background-color: #450a0a; color: #fca5a5"
            if "failed" in name:
                return "background-color: #431407; color: #fdba74"
            return ""

        styled = df_wh.style.applymap(
            lambda v: _event_colour(v) if isinstance(v, str) else "",
            subset=["event_name"],
        )
        st.dataframe(styled, use_container_width=True)

    ls_secret_set = bool(os.getenv("LEMONSQUEEZY_WEBHOOK_SECRET"))
    if ls_secret_set:
        st.success("LEMONSQUEEZY_WEBHOOK_SECRET is configured.")
    else:
        st.warning("LEMONSQUEEZY_WEBHOOK_SECRET not set — signature verification is disabled (dev mode).")

    col_r, _ = st.columns([1, 3])
    with col_r:
        if st.button("Refresh", key="wh_refresh"):
            st.cache_data.clear()
            st.rerun()

# ── Dunning ───────────────────────────────────────────────────────────────────

with tab_dunning:
    st.markdown(
        f"Subscriptions in **past_due** status will be downgraded to starter "
        f"after the **{_GRACE_DAYS}-day grace period** (`DUNNING_GRACE_DAYS`)."
    )

    df = _load_subscriptions()
    past_due_df = df[df["status"] == "past_due"] if not df.empty else pd.DataFrame()

    if past_due_df.empty:
        st.success("No past-due subscriptions. All good.")
    else:
        cutoff = datetime.now(UTC) - timedelta(days=_GRACE_DAYS)
        rows = []
        for _, row in past_due_df.iterrows():
            days   = _days_past_due(row.get("updated_at", ""))
            remaining = max(0, _GRACE_DAYS - days)
            rows.append({
                "tenant_id":       row["tenant_id"],
                "plan":            row["plan"],
                "days_past_due":   days,
                "grace_remaining": remaining,
                "auto_downgrade":  "IMMINENT" if remaining == 0 else f"in {remaining}d",
            })

        dunning_df = pd.DataFrame(rows)

        def _grace_color(val):
            if val == 0:
                return "background-color:#450a0a; color:#fca5a5"
            if val <= 2:
                return "background-color:#431407; color:#fdba74"
            return ""

        styled = dunning_df.style.applymap(
            _grace_color, subset=["grace_remaining"]
        )
        st.dataframe(styled, use_container_width=True)

        st.markdown(
            "_The ARQ dunning worker (`process_dunning`) runs at 06:00 and 18:00 UTC "
            "and auto-downgrades rows with grace_remaining = 0._"
        )

    col_r, _ = st.columns([1, 3])
    with col_r:
        if st.button("Refresh", key="dn_refresh"):
            st.cache_data.clear()
            st.rerun()

# ── Upgrade ───────────────────────────────────────────────────────────────────

with tab_upgrade:
    st.subheader("Checkout links")
    st.markdown(
        "Share these links with tenants or embed them in upgrade flows. "
        "Tenant ID is passed as `custom_data.tenant_id` and preserved through checkout."
    )

    plans = [
        ("Individual",          "individual",         "$5 / month",   "5 000 req/mo"),
        ("Community Business",  "community_business", "$19 / month",  "10 000 req/mo + Communities"),
        ("Pro",                 "pro",                "$69 / month",  "50 000 req/mo + MasterAgent"),
        ("Enterprise",          "enterprise",         "$249 / month", "Unlimited + PQC + Sovereign"),
    ]

    cols = st.columns(len(plans))
    for col, (name, key, price, desc) in zip(cols, plans, strict=False):
        with col:
            st.markdown(f"### {name}")
            st.markdown(f"**{price}**  \n{desc}")
            st.code(f"GET /billing/upgrade?plan={key}", language="http")

    st.divider()
    st.subheader("Add-on checkout links")
    addons = [
        ("Shadow AI Discovery", "shadow_ai_discovery", "$15 / month"),
        ("XAI Audit Reports",   "xai_audit",           "$9 / month"),
        ("Secrets Vault",       "secrets_vault",        "$12 / month"),
    ]
    for name, key, price in addons:
        st.markdown(f"- **{name}** ({price}): `GET /billing/addons/{key}/checkout`")

    st.divider()
    st.subheader("Webhook endpoint")
    warden_url = os.getenv("WARDEN_BASE_URL", "https://api.shadow-warden-ai.com")
    st.code(f"POST {warden_url}/billing/webhook", language="http")
    st.markdown(
        "Configure this URL in Lemon Squeezy → Settings → Webhooks. "
        "Required events: `subscription_*`, `order_created`."
    )

    ls_configured = all([
        os.getenv("LEMONSQUEEZY_API_KEY"),
        os.getenv("LEMONSQUEEZY_STORE_ID"),
        os.getenv("LEMONSQUEEZY_WEBHOOK_SECRET"),
    ])
    if ls_configured:
        st.success("Lemon Squeezy is fully configured (API key, store ID, webhook secret).")
    else:
        missing = [k for k in ["LEMONSQUEEZY_API_KEY", "LEMONSQUEEZY_STORE_ID", "LEMONSQUEEZY_WEBHOOK_SECRET"] if not os.getenv(k)]
        st.warning(f"Missing Lemon Squeezy env vars: {', '.join(missing)}")
