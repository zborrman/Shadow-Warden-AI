"""
Shadow Warden AI — Admin UI
Streamlit app for managing tenants and dynamic rules.

Pages
─────
  Dynamic Rules     — view / add / delete evolved rules (dynamic_rules.json + API)
  Tenant Management — create / rotate / activate / deactivate / set quota
  Rule Ledger       — approve / retire / report false-positives on evolution rules
  Event Log         — recent filter events from data/logs.json
  System Health     — status cards for all Docker services
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import requests
import streamlit as st

# ── Config ────────────────────────────────────────────────────────────────────

WARDEN_URL    = os.getenv("WARDEN_URL",       "http://warden:8001")
ANALYTICS_URL = os.getenv("ANALYTICS_URL",    "http://analytics:8002")
DYNAMIC_RULES = Path(os.getenv("DYNAMIC_RULES_PATH", "/warden/data/dynamic_rules.json"))
LOGS_PATH     = Path(os.getenv("LOGS_PATH",          "/warden/data/logs.json"))
ADMIN_API_KEY = os.getenv("WARDEN_API_KEY",   "")
MAX_LOG_ROWS  = int(os.getenv("ADMIN_MAX_LOG_ROWS", "200"))

_AUTH = {"X-API-Key": ADMIN_API_KEY} if ADMIN_API_KEY else {}

# ── Page config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="Shadow Warden — Admin",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _api(method: str, path: str, **kwargs) -> requests.Response | None:
    """Call warden REST API. Returns Response or None on network error."""
    try:
        resp = requests.request(
            method, f"{WARDEN_URL}{path}",
            headers=_AUTH, timeout=8, **kwargs
        )
        return resp
    except Exception as exc:
        st.error(f"Network error: {exc}")
        return None


def _load_rules() -> dict:
    if DYNAMIC_RULES.exists():
        try:
            return json.loads(DYNAMIC_RULES.read_text())
        except Exception:
            pass
    return {"rules": []}


def _save_rules(data: dict) -> None:
    tmp = tempfile.NamedTemporaryFile(
        mode="w", dir=DYNAMIC_RULES.parent,
        suffix=".tmp", delete=False,
    )
    json.dump(data, tmp, ensure_ascii=False, indent=2)
    tmp.close()
    Path(tmp.name).replace(DYNAMIC_RULES)


def _load_recent_events(n: int = MAX_LOG_ROWS) -> list[dict]:
    if not LOGS_PATH.exists():
        return []
    try:
        lines = LOGS_PATH.read_text().strip().splitlines()
        rows = []
        for line in reversed(lines):
            try:
                rows.append(json.loads(line))
                if len(rows) >= n:
                    break
            except Exception:
                continue
        return rows
    except Exception:
        return []


def _status_badge(ok: bool) -> str:
    return "🟢 OK" if ok else "🔴 DOWN"


def _risk_badge(risk: str) -> str:
    return {"block": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(risk.lower(), "⚪") + f" {risk}"


# ── Sidebar nav ───────────────────────────────────────────────────────────────

st.sidebar.image(
    "https://raw.githubusercontent.com/phosphoricons/phosphor-icons/master/assets/phosphor-mark-tight-yellow.svg",
    width=48,
)
st.sidebar.title("Shadow Warden")
st.sidebar.caption("Admin Panel")
page = st.sidebar.radio(
    "Navigate",
    ["Dynamic Rules", "Tenant Management", "Rule Ledger", "Event Log", "System Health"],
    label_visibility="collapsed",
)

if ADMIN_API_KEY:
    st.sidebar.success("API key configured")
else:
    st.sidebar.warning("No API key — dev mode")

# ══════════════════════════════════════════════════════════════════════════════
# PAGE: Dynamic Rules
# ══════════════════════════════════════════════════════════════════════════════
if page == "Dynamic Rules":
    st.title("🧠 Dynamic Rules")
    st.caption(
        "Rules evolved automatically by the EvolutionEngine (Claude Opus). "
        "Semantic examples are fed into the ML brain on restart."
    )

    data  = _load_rules()
    rules: list[dict] = data.get("rules", [])

    _, col_refresh = st.columns([4, 1])
    with col_refresh:
        if st.button("↻ Reload", use_container_width=True):
            data  = _load_rules()
            rules = data.get("rules", [])
            st.rerun()

    if not rules:
        st.info(
            "No evolved rules yet. Rules are added automatically when HIGH/BLOCK events "
            "occur and ANTHROPIC_API_KEY is set."
        )
    else:
        # Summary metrics
        type_counts: dict[str, int] = {}
        for r in rules:
            rt = r.get("new_rule", {}).get("rule_type", "unknown")
            type_counts[rt] = type_counts.get(rt, 0) + 1

        m_cols = st.columns(len(type_counts) + 1)
        m_cols[0].metric("Total rules", len(rules))
        for col, (rtype, cnt) in zip(m_cols[1:], type_counts.items()):
            col.metric(rtype, cnt)

        st.divider()

        # Filter by type
        all_types = sorted({r.get("new_rule", {}).get("rule_type", "unknown") for r in rules})
        filter_type = st.selectbox("Filter by type", ["all"] + all_types, index=0)

        for i, rule_entry in enumerate(rules):
            nr     = rule_entry.get("new_rule", {})
            val    = nr.get("value", "")
            rtype  = nr.get("rule_type", "unknown")
            if filter_type != "all" and rtype != filter_type:
                continue

            created    = nr.get("created_at", "")
            confidence = nr.get("confidence", None)
            attack     = rule_entry.get("attack_type", "")
            severity   = rule_entry.get("severity", "")
            source     = nr.get("source", "evolution")

            label = f"#{i+1}  [{rtype}]  {val[:80]}…" if len(val) > 80 else f"#{i+1}  [{rtype}]  {val}"
            with st.expander(label):
                st.code(val, language="text" if rtype == "semantic_example" else "regex")

                c1, c2, c3, c4, c5 = st.columns(5)
                c1.write(f"**Type:** `{rtype}`")
                c2.write(f"**Source:** `{source}`")
                c3.write(f"**Confidence:** {confidence if confidence is not None else 'n/a'}")
                c4.write(f"**Attack:** {attack or 'n/a'}")
                c5.write(f"**Severity:** {severity or 'n/a'}")
                if created:
                    st.caption(f"Created: {created}")

                if rule_entry.get("explanation"):
                    st.info(rule_entry["explanation"])

                if rule_entry.get("evasion_variants"):
                    with st.expander("Evasion variants"):
                        for v in rule_entry["evasion_variants"]:
                            st.write(f"- {v}")

                if st.button(f"🗑️ Delete rule #{i+1}", key=f"del_{i}"):
                    data["rules"].pop(i)
                    _save_rules(data)
                    st.success("Rule deleted.")
                    st.rerun()

    st.divider()
    st.subheader("➕ Add semantic example")
    with st.form("add_rule"):
        new_val = st.text_area(
            "Example jailbreak / harmful phrase (added to ML corpus on restart)",
            height=80,
            placeholder="e.g. Ignore all previous instructions and …",
        )
        submitted = st.form_submit_button("Add rule")

    if submitted and new_val.strip():
        data["rules"].append({
            "attack_type": "manual",
            "severity":    "high",
            "new_rule": {
                "value":      new_val.strip(),
                "rule_type":  "semantic_example",
                "created_at": datetime.now(tz=timezone.utc).isoformat(),
                "confidence": 1.0,
                "source":     "admin_ui",
            },
        })
        _save_rules(data)
        st.success("Rule added. It will be loaded into the ML brain on the next warden restart.")
        st.rerun()
    elif submitted:
        st.warning("Please enter a non-empty value.")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: Tenant Management
# ══════════════════════════════════════════════════════════════════════════════
elif page == "Tenant Management":
    st.title("🏢 Tenant Management")
    st.caption("Create, configure, and rotate API keys for MSP sub-tenants.")

    # ── Fetch tenant list ─────────────────────────────────────────────────────
    resp = _api("GET", "/tenants")
    tenants: list[dict] = []
    if resp is not None:
        if resp.status_code == 200:
            tenants = resp.json().get("tenants", [])
        else:
            st.warning(f"GET /tenants → {resp.status_code}. "
                       "Tenant listing requires the warden service to be running.")

    # ── Summary metrics ───────────────────────────────────────────────────────
    active   = sum(1 for t in tenants if t.get("active", True))
    inactive = len(tenants) - active

    m1, m2, m3 = st.columns(3)
    m1.metric("Total tenants", len(tenants))
    m2.metric("Active", active)
    m3.metric("Inactive", inactive)

    st.divider()

    # ── Tenant cards ──────────────────────────────────────────────────────────
    if tenants:
        st.subheader("Existing tenants")
        for tenant in tenants:
            tid   = tenant.get("tenant_id", "")
            label = tenant.get("label", tid)
            plan  = tenant.get("plan", "—")
            is_active = tenant.get("active", True)
            email = tenant.get("contact_email", "")
            rl    = tenant.get("rate_limit", "—")
            quota = tenant.get("quota_usd", "—")
            created = tenant.get("created_at", "")

            status_icon = "🟢" if is_active else "🔴"
            with st.expander(f"{status_icon} **{label}** · `{tid}` · {plan}"):
                info_cols = st.columns(4)
                info_cols[0].write(f"**Email:** {email or '—'}")
                info_cols[1].write(f"**Rate limit:** {rl} req/min")
                info_cols[2].write(f"**Quota:** ${quota}")
                info_cols[3].write(f"**Status:** {'Active' if is_active else 'Inactive'}")
                if created:
                    st.caption(f"Created: {created}")

                # Action buttons
                act_cols = st.columns(4)

                # Rotate key
                with act_cols[0]:
                    if st.button("🔑 Rotate key", key=f"rot_{tid}", use_container_width=True):
                        r = _api("POST", f"/onboard/{tid}/rotate-key")
                        if r is not None and r.status_code == 200:
                            result = r.json()
                            new_key = result.get("api_key", "")
                            st.success("Key rotated — save this key now, it will not be shown again:")
                            st.code(new_key, language=None)
                        elif r is not None:
                            st.error(f"Rotate failed: {r.status_code} — {r.text[:200]}")

                # Activate / Deactivate
                with act_cols[1]:
                    if is_active:
                        if st.button("⏸ Deactivate", key=f"deact_{tid}", use_container_width=True):
                            r = _api("PUT", f"/onboard/{tid}/status", params={"active": "false"})
                            if r is not None and r.status_code == 200:
                                st.success("Tenant deactivated.")
                                st.rerun()
                            elif r is not None:
                                st.error(f"{r.status_code} — {r.text[:200]}")
                    else:
                        if st.button("▶ Activate", key=f"act_{tid}", use_container_width=True):
                            r = _api("PUT", f"/onboard/{tid}/status", params={"active": "true"})
                            if r is not None and r.status_code == 200:
                                st.success("Tenant activated.")
                                st.rerun()
                            elif r is not None:
                                st.error(f"{r.status_code} — {r.text[:200]}")

                # Set quota
                with act_cols[2]:
                    new_quota = st.number_input(
                        "Quota (USD/mo)", min_value=0.0, value=float(quota) if isinstance(quota, (int, float)) else 0.0,
                        step=5.0, key=f"quota_{tid}",
                    )
                    if st.button("💰 Set quota", key=f"setquota_{tid}", use_container_width=True):
                        r = _api("POST", f"/billing/{tid}/quota", json={"quota_usd": new_quota})
                        if r is not None and r.status_code == 200:
                            st.success(f"Quota set to ${new_quota:.2f}")
                        elif r is not None:
                            st.error(f"{r.status_code} — {r.text[:200]}")

                # Billing summary
                with act_cols[3]:
                    if st.button("📊 View billing", key=f"bill_{tid}", use_container_width=True):
                        r = _api("GET", f"/billing/{tid}")
                        if r is not None and r.status_code == 200:
                            st.json(r.json())
                        elif r is not None:
                            st.error(f"{r.status_code} — {r.text[:200]}")
    else:
        st.info("No tenants provisioned yet. Create the first one below.")

    # ── Create new tenant ─────────────────────────────────────────────────────
    st.divider()
    st.subheader("➕ Provision new tenant")
    with st.form("new_tenant"):
        c1, c2 = st.columns(2)
        company = c1.text_input("Company name *", placeholder="Acme Corp")
        email   = c2.text_input("Contact email *", placeholder="admin@acme.com")

        c3, c4 = st.columns(2)
        plan    = c3.selectbox("Plan", ["free", "pro", "msp"], index=1)
        quota   = c4.number_input("Billing quota (USD/mo)", min_value=0.0, value=50.0, step=5.0)

        telegram = st.text_input(
            "Telegram chat ID (optional)",
            placeholder="-1001234567890",
            help="Receive per-tenant block alerts on Telegram",
        )

        submit_new = st.form_submit_button("Create tenant", type="primary")

    if submit_new:
        if not company.strip() or not email.strip():
            st.warning("Company name and contact email are required.")
        else:
            payload = {
                "company_name":    company.strip(),
                "contact_email":   email.strip(),
                "plan":            plan,
                "custom_quota_usd": quota,
            }
            if telegram.strip():
                payload["telegram_chat_id"] = telegram.strip()

            r = _api("POST", "/onboard", json=payload)
            if r is not None and r.status_code == 201:
                kit = r.json()
                st.success(f"Tenant **{kit.get('tenant_id')}** created!")
                st.warning("Save the API key below — it will never be shown again.")
                st.code(kit.get("api_key", ""), language=None)
                with st.expander("Full onboarding kit"):
                    st.json(kit)
                st.rerun()
            elif r is not None:
                st.error(f"Onboarding failed: {r.status_code} — {r.text[:400]}")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: Rule Ledger
# ══════════════════════════════════════════════════════════════════════════════
elif page == "Rule Ledger":
    st.title("📜 Rule Ledger")
    st.caption(
        "Lifecycle view of evolution-generated detection rules. "
        "Approve pending rules, retire false positives, track activation counts."
    )

    # ── Filters ───────────────────────────────────────────────────────────────
    fc1, fc2, fc3 = st.columns([2, 2, 1])
    status_filter = fc1.selectbox(
        "Status", ["all", "pending_review", "active", "retired"], index=0
    )
    limit = fc2.number_input("Max rows", min_value=10, max_value=500, value=100, step=10)
    refresh = fc3.button("↻ Refresh", use_container_width=True)

    # ── Fetch rules from ledger ───────────────────────────────────────────────
    params = {"limit": limit}
    if status_filter != "all":
        params["rule_status"] = status_filter

    resp = _api("GET", "/rules", params=params)
    ledger_rules: list[dict] = []
    if resp is not None:
        if resp.status_code == 200:
            ledger_rules = resp.json().get("rules", [])
        else:
            st.warning(f"GET /rules → {resp.status_code}. Is the warden service running?")

    if refresh:
        st.rerun()

    # ── Summary ───────────────────────────────────────────────────────────────
    if ledger_rules:
        pending  = sum(1 for r in ledger_rules if r.get("status") == "pending_review")
        active_c = sum(1 for r in ledger_rules if r.get("status") == "active")
        retired  = sum(1 for r in ledger_rules if r.get("status") == "retired")
        fp_total = sum(r.get("fp_reports", 0) for r in ledger_rules)

        ms1, ms2, ms3, ms4, ms5 = st.columns(5)
        ms1.metric("Shown", len(ledger_rules))
        ms2.metric("Pending review", pending)
        ms3.metric("Active", active_c)
        ms4.metric("Retired", retired)
        ms5.metric("Total FP reports", fp_total)

        st.divider()

    # ── Rule cards ────────────────────────────────────────────────────────────
    if not ledger_rules:
        if status_filter == "pending_review":
            st.success("No rules awaiting review.")
        else:
            st.info("No rules found in the ledger.")
    else:
        # Group by status for visual separation
        status_order = {"pending_review": 0, "active": 1, "retired": 2}
        sorted_rules = sorted(
            ledger_rules,
            key=lambda r: (status_order.get(r.get("status", ""), 99), r.get("created_at", "")),
        )

        for rule in sorted_rules:
            rule_id   = rule.get("rule_id", "")
            snippet   = rule.get("pattern_snippet", rule_id)
            status    = rule.get("status", "")
            act_count = rule.get("activation_count", 0)
            fp_count  = rule.get("fp_reports", 0)
            created   = rule.get("created_at", "")
            last_fired = rule.get("last_fired_at", "")
            rule_type  = rule.get("rule_type", "")
            source     = rule.get("source", "evolution")

            status_icon = {
                "pending_review": "🟡",
                "active":         "🟢",
                "retired":        "🔴",
            }.get(status, "⚪")

            label = f"{status_icon} [{status}]  {snippet[:90]}…" if len(snippet) > 90 else f"{status_icon} [{status}]  {snippet}"
            with st.expander(label):
                st.code(snippet, language=None)

                r1, r2, r3, r4 = st.columns(4)
                r1.write(f"**Type:** `{rule_type or 'n/a'}`")
                r2.write(f"**Source:** `{source}`")
                r3.metric("Activations", act_count)
                r4.metric("FP reports", fp_count)

                if created:
                    info_parts = [f"Created: {created}"]
                    if last_fired:
                        info_parts.append(f"Last fired: {last_fired}")
                    st.caption(" · ".join(info_parts))

                # Action buttons
                btn_cols = st.columns(3)

                # Approve (only for pending_review)
                with btn_cols[0]:
                    if status == "pending_review":
                        if st.button("✅ Approve", key=f"approve_{rule_id}", use_container_width=True):
                            r = _api("POST", f"/admin/rules/{rule_id}/approve")
                            if r is not None and r.status_code == 200:
                                st.success("Rule approved and activated.")
                                st.rerun()
                            elif r is not None:
                                st.error(f"{r.status_code} — {r.text[:200]}")
                    else:
                        st.write("")  # spacer

                # Retire (not for already retired)
                with btn_cols[1]:
                    if status != "retired":
                        if st.button("🗑️ Retire", key=f"retire_{rule_id}", use_container_width=True):
                            r = _api("DELETE", f"/admin/rules/{rule_id}")
                            if r is not None and r.status_code == 200:
                                st.success("Rule retired.")
                                st.rerun()
                            elif r is not None:
                                st.error(f"{r.status_code} — {r.text[:200]}")

                # Report FP
                with btn_cols[2]:
                    if status == "active":
                        with st.popover("⚠️ Report FP"):
                            fp_reason = st.text_input(
                                "Reason (optional)",
                                key=f"fpreason_{rule_id}",
                                placeholder="e.g. fires on legitimate security queries",
                            )
                            if st.button("Submit FP report", key=f"fp_{rule_id}"):
                                r = _api(
                                    "POST",
                                    f"/rules/{rule_id}/report-fp",
                                    json={"reason": fp_reason},
                                )
                                if r is not None and r.status_code == 200:
                                    result = r.json()
                                    new_fp = result.get("fp_reports", fp_count + 1)
                                    new_status = result.get("status", status)
                                    st.success(f"FP reported. Total: {new_fp} / Status: {new_status}")
                                    st.rerun()
                                elif r is not None:
                                    st.error(f"{r.status_code} — {r.text[:200]}")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: Event Log
# ══════════════════════════════════════════════════════════════════════════════
elif page == "Event Log":
    st.title("📋 Event Log")
    st.caption(f"Last {MAX_LOG_ROWS} filter events (GDPR: content is never logged — metadata only).")

    events = _load_recent_events()
    if not events:
        st.info("No events found. Events are written after the first /filter call.")
    else:
        import pandas as pd

        rows = []
        for ev in events:
            rows.append({
                "time":       ev.get("timestamp", ""),
                "request_id": ev.get("request_id", "")[:8] + "…",
                "tenant":     ev.get("tenant_id", "default"),
                "allowed":    "✅" if ev.get("allowed") else "❌",
                "risk":       ev.get("risk_level", ""),
                "flags":      ", ".join(ev.get("flags", [])) or "—",
                "secrets":    ", ".join(ev.get("secrets_found", [])) or "—",
                "len":        ev.get("payload_len", ""),
                "ms":         ev.get("elapsed_ms", ""),
            })

        df = pd.DataFrame(rows)

        # Filters
        filter_cols = st.columns([2, 2, 2, 4])
        tenant_opts = ["all"] + sorted(df["tenant"].unique().tolist())
        tenant_filt = filter_cols[0].selectbox("Tenant", tenant_opts)
        risk_opts   = ["all"] + sorted(df["risk"].unique().tolist())
        risk_filt   = filter_cols[1].selectbox("Risk level", risk_opts)
        allow_opts  = ["all", "✅ allowed", "❌ blocked"]
        allow_filt  = filter_cols[2].selectbox("Result", allow_opts)

        if tenant_filt != "all":
            df = df[df["tenant"] == tenant_filt]
        if risk_filt != "all":
            df = df[df["risk"] == risk_filt]
        if allow_filt == "✅ allowed":
            df = df[df["allowed"] == "✅"]
        elif allow_filt == "❌ blocked":
            df = df[df["allowed"] == "❌"]

        st.dataframe(df, use_container_width=True, height=480)

        col_dl, _ = st.columns([2, 8])
        with col_dl:
            st.download_button(
                "⬇ Export CSV",
                data=df.to_csv(index=False),
                file_name="warden_events.csv",
                mime="text/csv",
                use_container_width=True,
            )

        blocked = sum(1 for e in events if not e.get("allowed"))
        allowed = len(events) - blocked
        st.subheader("Summary")
        m1, m2, m3 = st.columns(3)
        m1.metric("Total events", len(events))
        m2.metric("Allowed", allowed)
        m3.metric("Blocked", blocked)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: System Health
# ══════════════════════════════════════════════════════════════════════════════
elif page == "System Health":
    st.title("🖥️ System Health")

    services = {
        "warden":    (WARDEN_URL,    "/health"),
        "analytics": (ANALYTICS_URL, "/health"),
    }

    cols = st.columns(len(services))
    for col, (svc_name, (base, path)) in zip(cols, services.items()):
        try:
            r   = requests.get(f"{base}{path}", headers=_AUTH, timeout=3)
            ok  = r.status_code == 200
            lat = round(r.elapsed.total_seconds() * 1000, 1)
            col.metric(svc_name, _status_badge(ok), f"{lat} ms")
        except Exception as exc:
            col.metric(svc_name, "🔴 DOWN", str(exc)[:40])

    st.divider()
    st.subheader("Warden detail")
    health_resp = _api("GET", "/health")
    if health_resp is not None and health_resp.status_code == 200:
        health = health_resp.json()

        # Extract key stats
        h1, h2, h3, h4 = st.columns(4)
        h1.metric("Gateway", _status_badge(health.get("status") == "ok"))
        h2.metric("EvolutionEngine", "🟢 online" if health.get("evolution") else "🟡 offline")
        h3.metric("Strict mode", "🔴 ON" if health.get("strict") else "🟢 OFF")
        cache = health.get("cache", {})
        cache_ok = cache.get("status") == "ok"
        h4.metric("Redis cache", f"{'🟢' if cache_ok else '🔴'} {cache.get('latency_ms', '?')} ms")

        tenants = health.get("tenants", [])
        if tenants:
            st.divider()
            st.subheader(f"Loaded tenant guards ({len(tenants)})")
            badge_cols = st.columns(min(len(tenants), 6))
            for i, t in enumerate(tenants):
                badge_cols[i % 6].success(t)

        st.divider()
        with st.expander("Raw health JSON"):
            st.json(health)
    else:
        st.error(f"Warden unreachable at {WARDEN_URL}.")
