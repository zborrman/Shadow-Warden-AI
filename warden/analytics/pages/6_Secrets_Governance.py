"""Secrets Governance Dashboard — vault inventory, lifecycle, compliance."""
import os
import sys

import streamlit as st

sys.path.insert(0, "/warden")

st.set_page_config(page_title="Secrets Governance", page_icon="🔐", layout="wide")

try:
    from warden.analytics.accessibility import inject_accessibility_widget
    inject_accessibility_widget()
except Exception:
    pass

st.title("🔐 Secrets Governance")

_DB = os.environ.get("SECRETS_DB_PATH", "/tmp/warden_secrets.db")
_WARDEN_URL = os.environ.get("WARDEN_URL", "http://warden:8001")
_API_KEY = os.environ.get("WARDEN_API_KEY", "")

TABS = st.tabs(["Overview", "Inventory", "Expiring Soon", "Vaults", "Policy", "Audit Report"])


def _headers():
    h = {"Content-Type": "application/json"}
    if _API_KEY:
        h["X-API-Key"] = _API_KEY
    return h


def _get(path: str):
    import httpx
    try:
        r = httpx.get(f"{_WARDEN_URL}/secrets{path}", headers=_headers(), timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        st.error(f"API error: {exc}")
        return None


def _post(path: str, body: dict):
    import httpx
    try:
        r = httpx.post(f"{_WARDEN_URL}/secrets{path}", json=body,
                       headers=_headers(), timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        st.error(f"API error: {exc}")
        return None


# ── Overview ──────────────────────────────────────────────────────────────────
with TABS[0]:
    stats = _get("/stats")
    report = _get("/report")
    if stats:
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Secrets", stats.get("total", 0))
        col2.metric("High Risk", stats.get("high_risk_count", 0))
        col3.metric("Vaults Connected", stats.get("vaults", 0))
        if report:
            score = report.get("compliance", {}).get("compliance_score", 0)
            col4.metric("Compliance Score", f"{score}%",
                        delta_color="normal" if score >= 80 else "inverse")

    if stats and stats.get("by_status"):
        import pandas as pd
        st.subheader("Secrets by Status")
        df_status = pd.DataFrame(
            list(stats["by_status"].items()), columns=["Status", "Count"]
        )
        st.bar_chart(df_status.set_index("Status"))

    if stats and stats.get("by_vault_type"):
        import pandas as pd
        st.subheader("Secrets by Vault Type")
        df_vault = pd.DataFrame(
            list(stats["by_vault_type"].items()), columns=["Vault Type", "Count"]
        )
        st.bar_chart(df_vault.set_index("Vault Type"))

    if report:
        lifecycle = report.get("lifecycle", {})
        st.subheader("Lifecycle Health")
        lc1, lc2, lc3 = st.columns(3)
        lc1.metric("Overdue Rotation", lifecycle.get("overdue_rotation", 0))
        lc2.metric("Due in 7 Days", lifecycle.get("due_within_7_days", 0))
        lc3.metric("Expiring in 30 Days", report.get("expiring_within_30_days", 0))


# ── Inventory ─────────────────────────────────────────────────────────────────
with TABS[1]:
    import pandas as pd

    status_filter = st.selectbox(
        "Filter by status",
        ["All", "active", "expiring_soon", "expired", "retired"],
    )
    inv_path = "/inventory"
    if status_filter != "All":
        inv_path += f"?status={status_filter}"
    inventory = _get(inv_path)
    if inventory is not None:
        if not inventory:
            st.info("No secrets found. Register a vault and sync to populate.")
        else:
            df = pd.DataFrame(inventory)
            display_cols = [c for c in
                            ["name", "vault_type", "status", "risk_score",
                             "last_rotated", "expires_at"] if c in df.columns]
            st.dataframe(df[display_cols], use_container_width=True)


# ── Expiring Soon ─────────────────────────────────────────────────────────────
with TABS[2]:
    import pandas as pd

    days = st.slider("Show expiring within (days)", 7, 90, 30)
    expiring = _get(f"/inventory/expiring?within_days={days}")
    if expiring is not None:
        if not expiring:
            st.success(f"No secrets expiring within {days} days.")
        else:
            st.warning(f"{len(expiring)} secret(s) expiring soon!")
            df = pd.DataFrame(expiring)
            st.dataframe(df, use_container_width=True)


# ── Vaults ────────────────────────────────────────────────────────────────────
with TABS[3]:
    vaults = _get("/vaults")
    if vaults is not None:
        if not vaults:
            st.info("No vaults registered yet.")
        else:
            import pandas as pd
            st.dataframe(pd.DataFrame(vaults), use_container_width=True)

        st.divider()
        st.subheader("Register New Vault")
        with st.form("register_vault"):
            vault_type = st.selectbox(
                "Vault Type", ["env", "aws_sm", "azure_kv", "hashicorp", "gcp_sm"]
            )
            display_name = st.text_input("Display Name")
            config_json = st.text_area("Config (JSON)", value="{}", height=100)
            submitted = st.form_submit_button("Register Vault")
            if submitted and display_name:
                import json
                try:
                    config = json.loads(config_json)
                except json.JSONDecodeError:
                    st.error("Invalid JSON config")
                    config = None
                if config is not None:
                    result = _post("/vaults", {
                        "vault_type": vault_type,
                        "display_name": display_name,
                        "config": config,
                    })
                    if result:
                        st.success(f"Vault registered: {result.get('vault_id')}")
                        st.rerun()

        if vaults:
            st.divider()
            st.subheader("Sync Vault")
            vault_options = {v["display_name"]: v["vault_id"] for v in vaults}
            selected = st.selectbox("Select vault to sync", list(vault_options))
            if st.button("Sync Now"):
                vid = vault_options[selected]
                result = _post(f"/vaults/{vid}/sync", {})
                if result:
                    st.success(f"Synced {result.get('synced_count', 0)} secrets")
                    st.rerun()


# ── Policy ────────────────────────────────────────────────────────────────────
with TABS[4]:
    policy = _get("/policy")
    if policy:
        with st.form("policy_form"):
            max_age = st.number_input("Max secret age (days)", 1, 365, policy["max_age_days"])
            rot_interval = st.number_input("Rotation interval (days)", 1, 365,
                                           policy["rotation_interval_days"])
            alert_days = st.number_input("Alert before expiry (days)", 1, 90,
                                         policy["alert_days_before_expiry"])
            require_expiry = st.checkbox("Require expiry date on all secrets",
                                         value=policy["require_expiry_date"])
            auto_retire = st.checkbox("Auto-retire expired secrets",
                                      value=policy["auto_retire_expired"])
            forbidden = st.text_input(
                "Forbidden name patterns (comma-separated)",
                value=", ".join(policy["forbidden_name_patterns"]),
            )
            require_tags = st.text_input(
                "Required tags (comma-separated)",
                value=", ".join(policy["require_tags"]),
            )
            if st.form_submit_button("Save Policy"):
                import httpx
                forbidden_list = [p.strip() for p in forbidden.split(",") if p.strip()]
                tags_list = [t.strip() for t in require_tags.split(",") if t.strip()]
                try:
                    r = httpx.put(
                        f"{_WARDEN_URL}/secrets/policy",
                        json={
                            "max_age_days": max_age,
                            "rotation_interval_days": rot_interval,
                            "alert_days_before_expiry": alert_days,
                            "auto_retire_expired": auto_retire,
                            "require_expiry_date": require_expiry,
                            "forbidden_name_patterns": forbidden_list,
                            "require_tags": tags_list,
                        },
                        headers=_headers(),
                        timeout=10,
                    )
                    r.raise_for_status()
                    st.success("Policy saved.")
                except Exception as exc:
                    st.error(f"Failed: {exc}")


# ── Audit Report ──────────────────────────────────────────────────────────────
with TABS[5]:
    if st.button("Run Compliance Audit"):
        audit = _get("/policy/audit")
        if audit:
            score = audit.get("compliance_score", 0)
            color = "green" if score >= 80 else "orange" if score >= 50 else "red"
            st.markdown(
                f"### Compliance Score: :{color}[{score}%]"
            )
            cols = st.columns(4)
            sev = audit.get("violations_by_severity", {})
            cols[0].metric("Critical", sev.get("critical", 0))
            cols[1].metric("High", sev.get("high", 0))
            cols[2].metric("Medium", sev.get("medium", 0))
            cols[3].metric("Low", sev.get("low", 0))

            violations = audit.get("violations", [])
            if violations:
                import pandas as pd
                st.subheader(f"{len(violations)} Violation(s)")
                df = pd.DataFrame(violations)
                st.dataframe(df, use_container_width=True)
            else:
                st.success("No violations found.")
