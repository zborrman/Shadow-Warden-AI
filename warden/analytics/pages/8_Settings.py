"""
Settings & Configuration Dashboard
Tabs: Live Config · Hot Reload · Tier-1 Approvals · Drift · Watcher
"""
from __future__ import annotations

import os
import sys

import streamlit as st

sys.path.insert(0, "/warden")

st.set_page_config(
    page_title="Settings — Shadow Warden",
    page_icon="⚙️",
    layout="wide",
)

try:
    from warden.analytics.accessibility import inject_accessibility_widget
    inject_accessibility_widget()
except Exception:
    pass

# ── Config ────────────────────────────────────────────────────────────────────
_WARDEN_URL = os.environ.get("WARDEN_URL",    "http://warden:8001")
_API_KEY    = os.environ.get("WARDEN_API_KEY", "")
_ADMIN_KEY  = os.environ.get("ADMIN_KEY",      "")

# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
  .cfg-card{background:#1a1f2e;border:1px solid #2d3748;border-radius:10px;
            padding:14px 18px;margin-bottom:8px}
  .cfg-key{font-size:.75rem;color:#718096;text-transform:uppercase;letter-spacing:.07em}
  .cfg-val{font-size:1.1rem;font-weight:600;color:#e2e8f0;margin-top:2px}
  .cfg-bool-on{color:#48bb78;font-weight:700}
  .cfg-bool-off{color:#fc8181;font-weight:700}
  .drift-ok{color:#48bb78;font-weight:700}
  .drift-warn{color:#ecc94b;font-weight:700}
  .tier1-badge{background:#3a1010;color:#fc8181;padding:2px 10px;
               border-radius:9999px;font-size:.75rem;font-weight:700}
  .hot-badge{background:#1a3a2a;color:#48bb78;padding:2px 10px;
             border-radius:9999px;font-size:.75rem;font-weight:700}
</style>
""", unsafe_allow_html=True)


# ── Helpers ───────────────────────────────────────────────────────────────────
def _h(admin: bool = False) -> dict:
    h = {"Content-Type": "application/json"}
    if _API_KEY:
        h["X-API-Key"] = _API_KEY
    if admin and _ADMIN_KEY:
        h["X-Admin-Key"] = _ADMIN_KEY
    return h


@st.cache_data(ttl=15)
def _get(path: str) -> dict | None:
    import httpx
    try:
        r = httpx.get(f"{_WARDEN_URL}{path}", headers=_h(), timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"_error": str(e)}


def _post(path: str, body: dict, admin: bool = False) -> dict | None:
    import httpx
    try:
        r = httpx.post(f"{_WARDEN_URL}{path}", json=body, headers=_h(admin=admin), timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.error(f"API error: {e}")
        return None


def _bool_badge(val: bool) -> str:
    cls = "cfg-bool-on" if val else "cfg-bool-off"
    txt = "ON" if val else "OFF"
    return f'<span class="{cls}">{txt}</span>'


# ── Page ─────────────────────────────────────────────────────────────────────
st.title("⚙️ Settings & Configuration")
st.caption("Live config · Hot reload · Tier-1 approvals · Drift detection")

TABS = st.tabs(["📋 Live Config", "🔥 Hot Reload", "🔑 Tier-1 Approvals", "📊 Drift", "🔭 Watcher"])


# ══════════════════════════════════════════════════════════════════════════════
# TAB 0 — LIVE CONFIG
# ══════════════════════════════════════════════════════════════════════════════
with TABS[0]:
    col_r, _ = st.columns([1, 3])
    with col_r:
        if st.button("🔄 Refresh", key="cfg_refresh"):
            st.cache_data.clear()

    cfg = _get("/api/settings")
    if not cfg or "_error" in cfg:
        st.error(f"Cannot load config: {cfg}")
    else:
        # ── Pipeline section ──────────────────────────────────────────────────
        st.subheader("Filter Pipeline")
        cols = st.columns(4)
        pipeline_keys = [
            ("semantic_threshold", "Semantic Threshold"),
            ("strict_mode", "Strict Mode"),
            ("rate_limit_per_minute", "Rate Limit/min"),
            ("uncertainty_lower_threshold", "Uncertainty Lower"),
        ]
        for col, (k, label) in zip(cols, pipeline_keys, strict=False):
            v = cfg.get(k)
            display = _bool_badge(v) if isinstance(v, bool) else str(v)
            col.markdown(
                f'<div class="cfg-card"><div class="cfg-key">{label}</div>'
                f'<div class="cfg-val">{display}</div></div>',
                unsafe_allow_html=True,
            )

        st.divider()
        st.subheader("Features")
        feat_keys = [
            ("topology_enabled", "Topology"), ("entropy_scan_enabled", "Entropy Scan"),
            ("browser_enabled", "Browser"), ("mtls_enabled", "mTLS"),
            ("otel_enabled", "OTel"), ("audit_trail_enabled", "Audit Trail"),
            ("prompt_shield_enabled", "Prompt Shield"), ("intel_ops_enabled", "Intel Ops"),
        ]
        fcols = st.columns(4)
        for i, (k, label) in enumerate(feat_keys):
            v = cfg.get(k, False)
            fcols[i % 4].markdown(
                f'<div class="cfg-card"><div class="cfg-key">{label}</div>'
                f'<div class="cfg-val">{_bool_badge(v)}</div></div>',
                unsafe_allow_html=True,
            )

        st.divider()
        st.subheader("Integrations (presence only)")
        int_keys = [
            ("anthropic_api_key_set", "Anthropic API Key"),
            ("nvidia_api_key_set",    "NVIDIA API Key"),
            ("admin_key_set",         "Admin Key"),
            ("vault_master_key_set",  "Vault Master Key"),
            ("slack_webhook_set",     "Slack Webhook"),
        ]
        icols = st.columns(5)
        for col, (k, label) in zip(icols, int_keys, strict=False):
            v = cfg.get(k, False)
            col.markdown(
                f'<div class="cfg-card"><div class="cfg-key">{label}</div>'
                f'<div class="cfg-val">{_bool_badge(v)}</div></div>',
                unsafe_allow_html=True,
            )

        with st.expander("Full config JSON"):
            st.json(cfg)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — HOT RELOAD
# ══════════════════════════════════════════════════════════════════════════════
with TABS[1]:
    st.markdown(
        'Hot-reload keys apply immediately without restart. '
        '<span class="hot-badge">HOT</span>&nbsp; '
        'Tier-1 keys require Slack approval. '
        '<span class="tier1-badge">TIER-1</span>',
        unsafe_allow_html=True,
    )
    st.divider()

    cfg2 = _get("/api/settings") or {}

    with st.form("hot_reload_form"):
        st.subheader("Pipeline Thresholds")
        c1, c2 = st.columns(2)

        sem = c1.slider(
            "semantic_threshold 🔥",
            0.1, 1.0,
            float(cfg2.get("semantic_threshold", 0.72)),
            step=0.01,
            help="MiniLM cosine similarity gate. Hot-reload.",
        )
        unc = c2.slider(
            "uncertainty_lower_threshold 🔥",
            0.0, 0.99,
            float(cfg2.get("uncertainty_lower_threshold", 0.3)),
            step=0.01,
        )
        rl = c1.number_input(
            "rate_limit_per_minute 🔥",
            1, 10000,
            int(cfg2.get("rate_limit_per_minute", 60)),
        )
        healer = c2.slider(
            "healer_bypass_threshold 🔥",
            0.0, 1.0,
            float(cfg2.get("healer_bypass_threshold", 0.15)),
            step=0.01,
        )
        strict = c1.checkbox(
            "strict_mode 🔥",
            value=bool(cfg2.get("strict_mode", False)),
        )
        intel = c2.checkbox(
            "intel_ops_enabled 🔥",
            value=bool(cfg2.get("intel_ops_enabled", False)),
        )

        submitted = st.form_submit_button("⚡ Apply hot-reload changes", type="primary")
        if submitted:
            payload = {
                "changes": {
                    "semantic_threshold":          sem,
                    "uncertainty_lower_threshold": unc,
                    "rate_limit_per_minute":       rl,
                    "healer_bypass_threshold":     healer,
                    "strict_mode":                 strict,
                    "intel_ops_enabled":           intel,
                },
                "requested_by": "streamlit-dashboard",
            }
            result = _post("/api/settings", payload)
            if result:
                applied  = result.get("applied", [])
                ignored  = result.get("ignored", [])
                pending  = result.get("pending_approval", [])
                if applied:
                    st.success(f"Applied immediately: {', '.join(applied)}")
                if pending:
                    st.warning(f"Tier-1 pending approval: {[p['key'] for p in pending]}")
                if ignored:
                    st.info(f"Ignored (unknown keys): {', '.join(ignored)}")
                st.cache_data.clear()


# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — TIER-1 APPROVALS
# ══════════════════════════════════════════════════════════════════════════════
with TABS[2]:
    st.subheader("Pending Tier-1 Approvals")
    st.caption(
        "These changes require admin approval before they are applied. "
        "Tokens expire after 1 hour."
    )

    col_r2, _ = st.columns([1, 5])
    with col_r2:
        if st.button("🔄 Refresh", key="t1_refresh"):
            st.cache_data.clear()

    pending_data = _get("/api/settings/pending") or {}
    pending_list = pending_data.get("pending", []) if isinstance(pending_data, dict) else []

    if not pending_list:
        st.success("No pending approvals.")
    else:
        for p in pending_list:
            with st.expander(f"🔑 `{p['key']}` — requested by `{p['requested_by']}`"):
                st.markdown(f"**Token:** `{p['token'][:30]}…`")
                st.markdown(f"**Issued:** `{p.get('issued_at','')[:19]}`")
                st.markdown(f"**Status:** `{p.get('status','')}`")

                col_a, col_r = st.columns(2)
                if col_a.button("✅ Approve", key=f"approve_{p['token'][:10]}", type="primary"):
                    if not _ADMIN_KEY:
                        st.error("ADMIN_KEY not set in environment.")
                    else:
                        import httpx
                        try:
                            r = httpx.post(
                                f"{_WARDEN_URL}/api/settings/approve/{p['token']}?action=approve",
                                headers=_h(admin=True), timeout=10,
                            )
                            r.raise_for_status()
                            st.success(f"Approved! {r.json()}")
                            st.cache_data.clear()
                            st.rerun()
                        except Exception as e:
                            st.error(str(e))

                if col_r.button("❌ Reject", key=f"reject_{p['token'][:10]}"):
                    if not _ADMIN_KEY:
                        st.error("ADMIN_KEY not set.")
                    else:
                        import httpx
                        try:
                            r = httpx.post(
                                f"{_WARDEN_URL}/api/settings/approve/{p['token']}?action=reject",
                                headers=_h(admin=True), timeout=10,
                            )
                            r.raise_for_status()
                            st.info(f"Rejected. {r.json()}")
                            st.cache_data.clear()
                            st.rerun()
                        except Exception as e:
                            st.error(str(e))

    st.divider()
    st.subheader("Submit Tier-1 Change")
    with st.form("tier1_form"):
        t1_key = st.selectbox(
            "Key",
            ["anthropic_api_key", "warden_api_key", "vault_master_key",
             "nvidia_api_key", "admin_key"],
        )
        t1_val = st.text_input("New value", type="password", placeholder="Enter new value")
        t1_by  = st.text_input("Requested by", value="admin")
        t1_sub = st.form_submit_button("🔑 Submit for approval", type="primary")
        if t1_sub:
            if not t1_val:
                st.error("Value is required.")
            else:
                result = _post("/api/settings", {
                    "changes": {t1_key: t1_val},
                    "requested_by": t1_by,
                })
                if result:
                    pending = result.get("pending_approval", [])
                    if pending:
                        st.success(f"Queued for approval. Token: `{pending[0]['token'][:30]}…`")
                        st.info("A Slack message has been sent to the approver.")
                        st.cache_data.clear()


# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 — DRIFT
# ══════════════════════════════════════════════════════════════════════════════
with TABS[3]:
    st.subheader("Configuration Drift")
    st.caption("Compares current live config against the last saved snapshot (admin-approved baseline).")

    col_r3, col_snap, _ = st.columns([1, 2, 5])
    with col_r3:
        if st.button("🔄 Refresh", key="drift_refresh"):
            st.cache_data.clear()
    with col_snap:
        if st.button("📸 Save snapshot now", key="save_snap"):
            if not _ADMIN_KEY:
                st.error("ADMIN_KEY not set.")
            else:
                import httpx
                try:
                    r = httpx.post(
                        f"{_WARDEN_URL}/api/settings/snapshot",
                        headers=_h(admin=True), timeout=10, json={},
                    )
                    r.raise_for_status()
                    st.success(f"Snapshot saved: {r.json()}")
                    st.cache_data.clear()
                except Exception as e:
                    st.error(str(e))

    drift = _get("/api/settings/drift") or {}

    baseline_at = drift.get("baseline_at")
    checked_at  = drift.get("checked_at")
    count       = drift.get("drift_count", 0)
    drifted     = drift.get("drifted_keys", [])

    col_m1, col_m2, col_m3 = st.columns(3)
    col_m1.metric("Drift count", count)
    col_m2.markdown(
        f'<div style="margin-top:24px">'
        f'<span class="{"drift-ok" if count == 0 else "drift-warn"}">'
        f'{"✅ Clean" if count == 0 else "⚠️ Drifted"}</span></div>',
        unsafe_allow_html=True,
    )
    col_m3.caption(f"Baseline: {(baseline_at or 'none')[:19]}")

    if drifted:
        import pandas as pd
        df = pd.DataFrame(drifted)
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.success("Configuration matches baseline.")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 4 — WATCHER
# ══════════════════════════════════════════════════════════════════════════════
with TABS[4]:
    st.subheader("Settings Watcher")
    st.caption(
        "The `watch_config_drift` ARQ cron runs every 15 minutes. "
        "It checks drift AND runs a canary probe (known jailbreak → must be blocked)."
    )

    col_trigger, _ = st.columns([2, 6])
    with col_trigger:
        if st.button("▶️ Run watcher now", type="primary", key="run_watcher"):
            with st.spinner("Running watch_config_drift…"):
                try:
                    import asyncio
                    import os

                    from arq import create_pool  # type: ignore
                    from arq.connections import RedisSettings

                    redis_url = os.environ.get("REDIS_URL", "redis://redis:6379")

                    async def _enqueue():
                        pool = await create_pool(RedisSettings.from_dsn(redis_url))
                        job  = await pool.enqueue_job("watch_config_drift")
                        await pool.aclose()
                        return job

                    asyncio.run(_enqueue())
                    st.success("Watcher queued in ARQ. Check Slack / logs for results.")
                except Exception:
                    # Fallback: run inline
                    try:
                        from warden.workers.settings_watcher import watch_config_drift
                        result = asyncio.run(watch_config_drift({}))
                        st.json(result)
                    except Exception as e2:
                        st.error(f"Inline run failed: {e2}")

    st.divider()
    st.subheader("Cron Schedule")
    st.markdown("""
| Job | Cadence | Timeout |
|-----|---------|---------|
| `watch_config_drift` | Every 15 min (:00/:15/:30/:45) | 60s |
| Checks | Drift vs snapshot + canary probe | — |
| Alert | Slack on drift OR canary miss | — |
""")
    st.subheader("Canary Probe")
    st.info(
        "The watcher sends a known jailbreak payload to `/filter`. "
        "If the pipeline does NOT block it, an urgent Slack alert fires. "
        "This validates that hot-reloaded `semantic_threshold` changes "
        "are actually honoured."
    )
