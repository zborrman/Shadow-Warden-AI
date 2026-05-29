"""
Streamlit page: Settings Hub

Tabs
────
  API Keys & FIDO   — tenant API keys overview, passkey status
  Secrets           — metadata list from /secrets
  Agents            — SOVA + MasterAgent runtime config
  Notifications     — channel CRUD, test fire
  Commerce          — Agentic Commerce budget + approved stores
  Semantic          — Semantic Layer config + registered models
"""
from __future__ import annotations

import os

import requests
import streamlit as st

st.set_page_config(page_title="Settings Hub", page_icon="⚙️", layout="wide")

_BASE    = os.getenv("WARDEN_INTERNAL_URL", "http://localhost:8001")
_API_KEY = os.getenv("WARDEN_API_KEY", "")
_HDRS    = {"X-API-Key": _API_KEY} if _API_KEY else {}

# ── CSS ───────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
.section-badge {
    display:inline-block; background:#1e293b; color:#94a3b8;
    border-radius:6px; padding:2px 8px; font-size:0.72rem; margin:2px; font-family:monospace;
}
.ok-chip   { background:#16a34a22; color:#4ade80; border:1px solid #4ade8040; border-radius:10px; padding:2px 8px; font-size:0.72rem; }
.warn-chip { background:#d9770622; color:#fb923c; border:1px solid #fb923c40; border-radius:10px; padding:2px 8px; font-size:0.72rem; }
</style>
""", unsafe_allow_html=True)

st.title("⚙️ Settings Hub")
st.caption("Unified control panel for all tenant configuration.")

# ── Tabs ──────────────────────────────────────────────────────────────────────

tab_keys, tab_secrets, tab_agents, tab_notif, tab_commerce, tab_semantic = st.tabs([
    "🔑 API Keys & FIDO",
    "🔐 Secrets",
    "🤖 Agents",
    "🔔 Notifications",
    "🛒 Commerce",
    "🗃️ Semantic",
])

# ── Tab: API Keys & FIDO ──────────────────────────────────────────────────────
with tab_keys:
    st.subheader("API Keys")
    try:
        r = requests.get(f"{_BASE}/keys", headers=_HDRS, timeout=5)
        if r.status_code == 200:
            keys = r.json()
            if keys:
                import pandas as pd
                df = pd.DataFrame(keys)[["id", "label", "key_prefix", "active", "created_at"]]
                st.dataframe(df, use_container_width=True, hide_index=True)
            else:
                st.info("No API keys yet.")
        else:
            st.warning(f"Keys endpoint returned {r.status_code}. Showing stub.")
            st.info("API key management is available at `/keys` endpoint.")
    except Exception as exc:
        st.warning(f"Could not reach warden API: {exc}")

    st.divider()
    st.subheader("FIDO2 / Passkeys")
    try:
        r = requests.get(f"{_BASE}/auth/fido/status", headers=_HDRS, timeout=5)
        if r.status_code == 200:
            status = r.json()
            if status.get("registered"):
                st.markdown('<span class="ok-chip">✓ Passkey registered</span>', unsafe_allow_html=True)
            else:
                st.markdown('<span class="warn-chip">No passkey</span>', unsafe_allow_html=True)
                st.info("Register a FIDO2 passkey via the Tenant Portal → Settings → FIDO.")
        else:
            st.info("FIDO2 status not available — use the Tenant Portal to manage passkeys.")
    except Exception:
        st.info("FIDO2 management is available in the Tenant Portal at `/settings/`.")

# ── Tab: Secrets ──────────────────────────────────────────────────────────────
with tab_secrets:
    st.subheader("Secrets Inventory")
    try:
        r = requests.get(f"{_BASE}/secrets/inventory", headers=_HDRS, timeout=5)
        if r.status_code == 200:
            secrets = r.json().get("secrets", [])
            if secrets:
                import pandas as pd
                cols = ["id", "name", "type", "risk_score", "expires_at", "active"]
                df = pd.DataFrame([{c: s.get(c, "") for c in cols} for s in secrets])
                st.dataframe(df, use_container_width=True, hide_index=True)
            else:
                st.info("No secrets in inventory.")
        else:
            st.info("Secrets endpoint returned non-200. Ensure the secrets governance module is enabled.")
    except Exception as exc:
        st.warning(f"Could not reach secrets API: {exc}")

    st.divider()
    st.subheader("Add Secret (metadata only)")
    with st.form("add_secret"):
        sname = st.text_input("Secret name")
        stype = st.selectbox("Type", ["api_key", "oauth_token", "db_password", "signing_key", "other"])
        svault = st.selectbox("Vault", ["env", "aws_sm", "azure_kv", "hashicorp", "gcp_sm"])
        submitted = st.form_submit_button("Add")
        if submitted and sname:
            try:
                r = requests.post(
                    f"{_BASE}/secrets/inventory",
                    json={"name": sname, "type": stype, "vault_type": svault},
                    headers=_HDRS, timeout=5,
                )
                if r.status_code in (200, 201):
                    st.success("Secret added.")
                    st.rerun()
                else:
                    st.error(f"Error {r.status_code}: {r.text[:200]}")
            except Exception as exc:
                st.error(str(exc))

# ── Tab: Agents ───────────────────────────────────────────────────────────────
with tab_agents:
    st.subheader("SOVA & MasterAgent Config")

    @st.cache_data(ttl=15)
    def _load_agent_cfg():
        try:
            r = requests.get(f"{_BASE}/settings/agents", headers=_HDRS, timeout=5)
            return r.json() if r.status_code == 200 else {}
        except Exception:
            return {}

    cfg = _load_agent_cfg()

    if cfg:
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**SOVA Agent**")
            sova_en = st.toggle("Enabled", value=cfg.get("sova_enabled", True), key="sova_en")
            sova_iter = st.slider("Max iterations", 1, 30, cfg.get("sova_max_iterations", 10), key="sova_iter")
            sova_ttl = st.slider("Memory TTL (hrs)", 1, 72, cfg.get("sova_memory_ttl_hours", 6), key="sova_ttl")
        with c2:
            st.markdown("**MasterAgent**")
            master_en = st.toggle("Enabled", value=cfg.get("master_enabled", True), key="master_en")
            master_iter = st.slider("Sub-agent max iterations", 1, 15, cfg.get("master_max_sub_iter", 5), key="master_iter")
            healer_thresh = st.slider("Healer bypass threshold", 0.0, 1.0, float(cfg.get("healer_bypass_threshold", 0.15)), step=0.01, key="healer_thresh")
        auto_approve = st.toggle("Auto-approve low-risk actions", value=cfg.get("auto_approve_low_risk", False), key="auto_approve")

        if st.button("Save Agent Config"):
            payload = {
                "sova_enabled": sova_en,
                "sova_max_iterations": sova_iter,
                "sova_memory_ttl_hours": sova_ttl,
                "master_enabled": master_en,
                "master_max_sub_iter": master_iter,
                "healer_bypass_threshold": healer_thresh,
                "auto_approve_low_risk": auto_approve,
            }
            try:
                r = requests.patch(f"{_BASE}/settings/agents", json=payload, headers=_HDRS, timeout=5)
                if r.status_code == 200:
                    st.success("Saved.")
                    st.cache_data.clear()
                else:
                    st.error(f"Error {r.status_code}: {r.text[:200]}")
            except Exception as exc:
                st.error(str(exc))
    else:
        st.warning("Could not load agent config — ensure warden API is running.")

# ── Tab: Notifications ────────────────────────────────────────────────────────
with tab_notif:
    st.subheader("Notification Channels")

    @st.cache_data(ttl=10)
    def _load_channels():
        try:
            r = requests.get(f"{_BASE}/settings/notifications", headers=_HDRS, timeout=5)
            return r.json() if r.status_code == 200 else []
        except Exception:
            return []

    channels = _load_channels()

    if channels:
        for ch in channels:
            with st.expander(f"{ch.get('label', '?')} — `{ch.get('kind', '?')}`"):
                st.json(ch)
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("Test", key=f"test_{ch['id']}"):
                        r = requests.post(f"{_BASE}/settings/notifications/{ch['id']}/test", headers=_HDRS, timeout=10)
                        st.json(r.json())
                with col2:
                    if st.button("Delete", key=f"del_{ch['id']}"):
                        requests.delete(f"{_BASE}/settings/notifications/{ch['id']}", headers=_HDRS, timeout=5)
                        st.rerun()
    else:
        st.info("No notification channels configured.")

    st.divider()
    st.subheader("Add Channel")
    with st.form("add_channel"):
        kind = st.selectbox("Kind", ["slack", "teams", "email", "webhook"])
        label = st.text_input("Label", placeholder="e.g. Security Ops Slack")
        url   = st.text_input("URL / Endpoint", placeholder="https://hooks.slack.com/...")
        on_high  = st.checkbox("On HIGH risk", value=True)
        on_block = st.checkbox("On BLOCK", value=True)
        if st.form_submit_button("Add Channel"):
            payload = {"kind": kind, "label": label, "url": url, "on_high": on_high, "on_block": on_block}
            try:
                r = requests.post(f"{_BASE}/settings/notifications", json=payload, headers=_HDRS, timeout=5)
                if r.status_code in (200, 201):
                    st.success("Channel added.")
                    st.cache_data.clear()
                    st.rerun()
                else:
                    st.error(f"Error {r.status_code}: {r.text[:200]}")
            except Exception as exc:
                st.error(str(exc))

# ── Tab: Commerce ─────────────────────────────────────────────────────────────
with tab_commerce:
    st.subheader("Agentic Commerce")
    st.caption("Control budgets and approved stores for autonomous agent purchasing (Pro+).")

    @st.cache_data(ttl=15)
    def _load_commerce():
        try:
            r = requests.get(f"{_BASE}/settings/commerce", headers=_HDRS, timeout=5)
            return r.json() if r.status_code == 200 else {}
        except Exception:
            return {}

    com = _load_commerce()

    enabled = st.toggle("Enable Agentic Commerce", value=com.get("enabled", False), key="com_en")
    c1, c2, c3 = st.columns(3)
    with c1:
        monthly = st.number_input("Monthly budget (USD)", min_value=0.0, value=float(com.get("monthly_budget_usd", 0)), step=50.0, key="com_budget")
    with c2:
        per_tx  = st.number_input("Per-transaction limit", min_value=0.0, value=float(com.get("per_transaction_limit_usd", 50)), step=5.0, key="com_per_tx")
    with c3:
        approval_thresh = st.number_input("Approval threshold (USD)", min_value=0.0, value=float(com.get("require_approval_above_usd", 25)), step=5.0, key="com_thresh")

    audit_all = st.toggle("Audit all transactions", value=com.get("audit_all_transactions", True), key="com_audit")

    st.markdown("**Approved Stores**")
    stores: list[str] = com.get("approved_stores", [])
    store_text = st.text_area("One domain per line", value="\n".join(stores), height=120, key="com_stores")

    if st.button("Save Commerce Settings"):
        new_stores = [s.strip() for s in store_text.splitlines() if s.strip()]
        payload = {
            "enabled": enabled,
            "monthly_budget_usd": monthly,
            "per_transaction_limit_usd": per_tx,
            "require_approval_above_usd": approval_thresh,
            "audit_all_transactions": audit_all,
            "approved_stores": new_stores,
        }
        try:
            r = requests.patch(f"{_BASE}/settings/commerce", json=payload, headers=_HDRS, timeout=5)
            if r.status_code == 200:
                st.success("Saved.")
                st.cache_data.clear()
            else:
                st.error(f"Error {r.status_code}: {r.text[:200]}")
        except Exception as exc:
            st.error(str(exc))

# ── Tab: Semantic Layer ───────────────────────────────────────────────────────
with tab_semantic:
    st.subheader("Semantic Layer Settings")

    @st.cache_data(ttl=15)
    def _load_semantic_cfg():
        try:
            r = requests.get(f"{_BASE}/settings/semantic", headers=_HDRS, timeout=5)
            return r.json() if r.status_code == 200 else {}
        except Exception:
            return {}

    @st.cache_data(ttl=30)
    def _load_sem_models():
        try:
            r = requests.get(f"{_BASE}/semantic-layer/models", headers=_HDRS, timeout=5)
            return r.json() if r.status_code == 200 else []
        except Exception:
            return []

    sem_cfg = _load_semantic_cfg()
    sem_models = _load_sem_models()

    c1, c2, c3 = st.columns(3)
    with c1:
        ai_q  = st.toggle("AI Query enabled", value=sem_cfg.get("ai_query_enabled", True), key="sem_ai")
    with c2:
        osi   = st.toggle("OSI Export enabled", value=sem_cfg.get("osi_export_enabled", False), key="sem_osi")
    with c3:
        limit = st.number_input("Default row limit", min_value=1, max_value=10000, value=int(sem_cfg.get("default_row_limit", 1000)), step=100, key="sem_limit")

    if st.button("Save Semantic Settings"):
        payload = {"ai_query_enabled": ai_q, "osi_export_enabled": osi, "default_row_limit": limit}
        try:
            r = requests.patch(f"{_BASE}/settings/semantic", json=payload, headers=_HDRS, timeout=5)
            if r.status_code == 200:
                st.success("Saved.")
                st.cache_data.clear()
            else:
                st.error(f"Error {r.status_code}: {r.text[:200]}")
        except Exception as exc:
            st.error(str(exc))

    st.divider()
    st.subheader(f"Registered Models ({len(sem_models)})")
    if sem_models:
        import pandas as pd
        df = pd.DataFrame(sem_models)[["id", "name", "source_table", "metric_count", "dimension_count", "description"]]
        st.dataframe(df, use_container_width=True, hide_index=True)
        st.caption("Full query builder available in **15 Semantic Layer** page.")
    else:
        st.info("No models loaded — ensure warden API is running.")
