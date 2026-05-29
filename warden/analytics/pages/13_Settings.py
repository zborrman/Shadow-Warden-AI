"""
warden/analytics/pages/13_Settings.py  (FE-41)
────────────────────────────────────────────────
Streamlit Settings dashboard — 4 tabs:
  API Keys · Secrets Vault · Agent Config · Notifications
"""
from __future__ import annotations

import os
from datetime import UTC

import requests
import streamlit as st

st.set_page_config(page_title="Settings", page_icon="⚙️", layout="wide")

_BASE    = os.getenv("WARDEN_API_URL", "http://localhost:8001")
_KEY     = os.getenv("WARDEN_API_KEY", "")
_HEADERS = {"X-API-Key": _KEY} if _KEY else {}


def _get(path: str) -> dict | list:
    try:
        r = requests.get(f"{_BASE}{path}", headers=_HEADERS, timeout=10)
        return r.json() if r.ok else {"error": r.text}
    except Exception as exc:
        return {"error": str(exc)}


def _post(path: str, payload: dict) -> dict:
    try:
        r = requests.post(f"{_BASE}{path}", json=payload, headers=_HEADERS, timeout=10)
        return r.json() if r.ok else {"error": r.text}
    except Exception as exc:
        return {"error": str(exc)}


def _delete(path: str) -> bool:
    try:
        r = requests.delete(f"{_BASE}{path}", headers=_HEADERS, timeout=10)
        return r.ok
    except Exception:
        return False


def _patch(path: str, payload: dict) -> dict:
    try:
        r = requests.patch(f"{_BASE}{path}", json=payload, headers=_HEADERS, timeout=10)
        return r.json() if r.ok else {"error": r.text}
    except Exception as exc:
        return {"error": str(exc)}


# ── Sidebar ────────────────────────────────────────────────────────────────────
st.sidebar.title("⚙️ Settings")
st.sidebar.caption("Manage API keys, secrets, agent config, and notification channels.")
tenant_id = st.sidebar.text_input("Tenant ID", value="default")

tabs = st.tabs(["🔑 API Keys", "🔒 Secrets Vault", "🤖 Agent Config", "🔔 Notifications"])

# ── Tab 1 — API Keys ──────────────────────────────────────────────────────────
with tabs[0]:
    st.header("API Keys")

    keys = _get("/settings/api-keys")
    if isinstance(keys, dict) and "error" in keys:
        st.error(f"API error: {keys['error']}")
    else:
        active  = [k for k in keys if k.get("active", True)]
        revoked = [k for k in keys if not k.get("active", True)]

        col_a, col_b = st.columns([3, 1])
        with col_a:
            st.metric("Active Keys", len(active))
        with col_b:
            if st.button("➕ Create New Key", use_container_width=True):
                st.session_state["show_create_key"] = True

        if st.session_state.get("show_create_key"):
            with st.form("create_key_form"):
                label = st.text_input("Key label", placeholder="e.g. Production, CI/CD")
                submitted = st.form_submit_button("Generate")
                if submitted and label.strip():
                    result = _post("/settings/api-keys", {"label": label.strip()})
                    if "key" in result:
                        st.success("Created! Key (copy now — shown once):")
                        st.code(result["key"], language=None)
                        st.session_state["show_create_key"] = False
                        st.rerun()
                    else:
                        st.error(f"Failed: {result.get('error', 'unknown error')}")

        if active:
            st.subheader("Active", divider="blue")
            rows = [{
                "Label":    k.get("label", "—"),
                "Prefix":   k.get("prefix", ""),
                "Created":  k.get("created_at", "")[:10],
                "Last Used": k.get("last_used_at", "never") or "never",
                "Requests": k.get("request_count", 0),
                "ID":       k.get("id", ""),
            } for k in active]
            st.dataframe(rows, use_container_width=True, hide_index=True,
                         column_config={"ID": st.column_config.Column(width="small")})

            revoke_id = st.selectbox("Revoke key →", ["— select —"] + [k["id"] for k in active],
                                     format_func=lambda x: x if x == "— select —" else
                                     next((k["label"] for k in active if k["id"] == x), x))
            if revoke_id != "— select —" and st.button("Revoke selected key", type="primary"):
                if _delete(f"/settings/api-keys/{revoke_id}"):
                    st.success("Key revoked.")
                    st.rerun()
                else:
                    st.error("Revoke failed.")

        if revoked:
            with st.expander(f"Revoked keys ({len(revoked)})"):
                st.dataframe([{
                    "Label":   k.get("label", "—"),
                    "Prefix":  k.get("prefix", ""),
                    "Revoked": k.get("updated_at", "")[:10],
                } for k in revoked], use_container_width=True, hide_index=True)

# ── Tab 2 — Secrets Vault ─────────────────────────────────────────────────────
with tabs[1]:
    st.header("Secrets Vault")
    st.caption("Fernet-encrypted at rest. Values are never returned via API.")

    secrets = _get("/settings/secrets")
    if isinstance(secrets, dict) and "error" in secrets:
        st.error(f"API error: {secrets['error']}")
    else:
        from datetime import datetime

        def _status(s: dict) -> str:
            exp = s.get("expires_at")
            if not exp:
                return "✅ Active"
            dt = datetime.fromisoformat(exp.rstrip("Z")).replace(tzinfo=UTC)
            diff = (dt - datetime.now(UTC)).days
            if diff < 0:
                return "🔴 Expired"
            if diff < 30:
                return f"⚠️ Expiring in {diff}d"
            return "✅ Active"

        # Expiry alerts
        expired  = [s for s in secrets if "Expired"  in _status(s)]
        expiring = [s for s in secrets if "Expiring" in _status(s)]
        if expired:
            st.error(f"🔴 {len(expired)} secret(s) expired — rotate immediately.")
        if expiring:
            st.warning(f"⚠️ {len(expiring)} secret(s) expiring within 30 days.")

        col_s, col_btn = st.columns([3, 1])
        with col_s:
            st.metric("Total Secrets", len(secrets))
        with col_btn:
            if st.button("➕ Add Secret", use_container_width=True):
                st.session_state["show_add_secret"] = True

        if st.session_state.get("show_add_secret"):
            with st.form("add_secret_form"):
                s_name  = st.text_input("Name (e.g. MY_API_KEY)", placeholder="LETTERS_digits_dash")
                s_value = st.text_input("Value", type="password")
                s_desc  = st.text_input("Description (optional)")
                s_exp   = st.date_input("Expiry (optional)", value=None)
                if st.form_submit_button("Save Secret"):
                    payload: dict = {"name": s_name, "value": s_value}
                    if s_desc:
                        payload["description"] = s_desc
                    if s_exp:
                        payload["expires_at"] = str(s_exp)
                    res = _post("/settings/secrets", payload)
                    if "error" not in res:
                        st.success("Secret saved.")
                        st.session_state["show_add_secret"] = False
                        st.rerun()
                    else:
                        st.error(f"Failed: {res['error']}")

        if secrets:
            st.dataframe([{
                "Name":        s.get("name", ""),
                "Description": s.get("description", ""),
                "Status":      _status(s),
                "Created":     s.get("created_at", "")[:10],
                "Expires":     s.get("expires_at", "—") or "—",
                "ID":          s.get("id", ""),
            } for s in secrets], use_container_width=True, hide_index=True)

            del_id = st.selectbox("Delete secret →", ["— select —"] + [s["id"] for s in secrets],
                                  format_func=lambda x: x if x == "— select —" else
                                  next((s["name"] for s in secrets if s["id"] == x), x))
            if del_id != "— select —" and st.button("Delete selected secret", type="primary"):
                if _delete(f"/settings/secrets/{del_id}"):
                    st.success("Secret deleted.")
                    st.rerun()
                else:
                    st.error("Delete failed.")
        else:
            st.info("No secrets yet.")

# ── Tab 3 — Agent Config ──────────────────────────────────────────────────────
with tabs[2]:
    st.header("Agent Config")

    cfg = _get("/settings/agents")
    cfg = cfg if isinstance(cfg, dict) else {}
    if "error" in cfg:
        st.error(f"API error: {cfg['error']}")
    else:
        with st.form("agent_config_form"):
            st.subheader("Risk Thresholds")
            col1, col2 = st.columns(2)
            with col1:
                high_thr = st.slider(
                    "HIGH risk threshold",
                    min_value=0.50, max_value=0.95, step=0.01,
                    value=float(cfg.get("high_risk_threshold", 0.72)),
                    format="%.2f",
                )
            with col2:
                block_thr = st.slider(
                    "BLOCK threshold",
                    min_value=0.50, max_value=1.00, step=0.01,
                    value=float(cfg.get("block_threshold", 0.90)),
                    format="%.2f",
                )

            if block_thr < high_thr:
                st.warning("BLOCK threshold must be ≥ HIGH threshold.")

            col3, col4 = st.columns(2)
            with col3:
                max_iter = st.number_input(
                    "SOVA max iterations", min_value=1, max_value=25,
                    value=int(cfg.get("sova_max_iterations", 10)),
                )
            with col4:
                scan_min = st.number_input(
                    "Scan interval (minutes)", min_value=1, max_value=1440,
                    value=int(cfg.get("scan_interval_minutes", 5)),
                )

            st.subheader("Agent Modules")
            modules = {
                "sova_enabled":             ("SOVA Agent",       "Autonomous operator — 30 tools, cron jobs, Redis memory"),
                "master_agent_enabled":     ("MasterAgent",      "Multi-agent SOC coordinator (Pro+)"),
                "evolution_engine_enabled": ("Evolution Engine", "Auto-generates detection rules via Claude Opus"),
                "causal_arbiter_enabled":   ("Causal Arbiter",   "Bayesian DAG for gray-zone decisions"),
                "phish_guard_enabled":      ("PhishGuard",       "URL phishing + social engineering detection"),
            }
            toggles: dict[str, bool] = {}
            for key, (label, desc) in modules.items():
                col_lbl, col_tog = st.columns([4, 1])
                with col_lbl:
                    st.markdown(f"**{label}** — <small>{desc}</small>", unsafe_allow_html=True)
                with col_tog:
                    toggles[key] = st.checkbox("", value=bool(cfg.get(key, False)), key=f"mod_{key}")

            if st.form_submit_button("💾 Save Config", type="primary"):
                if block_thr < high_thr:
                    st.error("Fix threshold order before saving.")
                else:
                    payload = {
                        "high_risk_threshold":      high_thr,
                        "block_threshold":          block_thr,
                        "sova_max_iterations":      int(max_iter),
                        "scan_interval_minutes":    int(scan_min),
                        **toggles,
                    }
                    res = _patch("/settings/agents", payload)
                    if "error" not in res:
                        st.success("Agent config saved — thresholds hot-reload in <100ms.")
                        st.rerun()
                    else:
                        st.error(f"Failed: {res['error']}")

# ── Tab 4 — Notifications ─────────────────────────────────────────────────────
with tabs[3]:
    st.header("Notification Channels")

    channels = _get("/settings/notifications")
    ch_list: list[dict] = channels if isinstance(channels, list) else channels.get("channels", []) if isinstance(channels, dict) and "channels" in channels else []

    unverified = [c for c in ch_list if not c.get("verified")]
    if unverified:
        st.warning(f"⚠️ {len(unverified)} channel(s) not yet verified — use the Test button to confirm delivery.")

    col_ch, col_add = st.columns([3, 1])
    with col_ch:
        st.metric("Total Channels", len(ch_list))
    with col_add:
        if st.button("➕ Add Channel", use_container_width=True):
            st.session_state["show_add_channel"] = True

    CHANNEL_TYPES = ["slack", "teams", "webhook", "pagerduty", "telegram", "email"]
    ICONS = {"slack": "💬", "teams": "💼", "webhook": "🔗", "pagerduty": "🚨", "telegram": "✈️", "email": "📧"}

    if st.session_state.get("show_add_channel"):
        with st.form("add_channel_form"):
            ch_type  = st.selectbox("Channel type", CHANNEL_TYPES,
                                    format_func=lambda x: f"{ICONS.get(x, '')} {x.capitalize()}")
            ch_label = st.text_input("Label", placeholder="e.g. SOC Alerts")
            config: dict = {}
            if ch_type in ("slack", "teams", "webhook"):
                config["url"] = st.text_input("Webhook URL", placeholder="https://...")
            elif ch_type == "pagerduty":
                config["routing_key"] = st.text_input("Routing Key")
            elif ch_type == "telegram":
                config["bot_token"] = st.text_input("Bot Token")
                config["chat_id"]   = st.text_input("Chat ID")
            elif ch_type == "email":
                config["email"] = st.text_input("Email address")

            if st.form_submit_button("Add Channel"):
                res = _post("/settings/notifications/channels", {
                    "type": ch_type, "label": ch_label, "config": config,
                })
                if "error" not in res:
                    st.success("Channel added.")
                    st.session_state["show_add_channel"] = False
                    st.rerun()
                else:
                    st.error(f"Failed: {res['error']}")

    if ch_list:
        for ch in ch_list:
            col_i, col_info, col_test, col_del = st.columns([0.5, 5, 1.5, 1])
            ch_type = ch.get("type", "webhook")
            icon    = ICONS.get(ch_type, "🔗")
            verified_badge = "✅" if ch.get("verified") else "⚠️"
            with col_i:
                st.write(icon)
            with col_info:
                st.markdown(
                    f"**{ch.get('label', '—')}** "
                    f"<small style='color:gray'>{ch_type.upper()} {verified_badge}</small>",
                    unsafe_allow_html=True,
                )
                cfg_summary = " · ".join(f"{k}: {v}" for k, v in ch.get("config", {}).items())
                if cfg_summary:
                    st.caption(cfg_summary)
            with col_test:
                if st.button("⚡ Test", key=f"test_{ch['id']}"):
                    res = _post(f"/settings/notifications/channels/{ch['id']}/test", {})
                    if res.get("ok"):
                        st.success(f"Sent ({res.get('latency_ms', 0)}ms)")
                    else:
                        st.error(res.get("message", "Test failed"))
            with col_del:
                if st.button("🗑", key=f"del_{ch['id']}") and _delete(f"/settings/notifications/channels/{ch['id']}"):
                    st.rerun()
    else:
        st.info("No channels yet. Add Slack, Teams, PagerDuty, or any webhook.")
