"""
Shadow Warden AI — Admin UI
Streamlit app for managing tenants and dynamic rules.

Pages
─────
  Dynamic Rules  — view / add / delete evolved rules in dynamic_rules.json
  Tenants        — live health + tenant list from warden /health endpoint
  Event Log      — recent filter events from data/logs.json
  System Health  — status cards for all Docker services
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

WARDEN_URL       = os.getenv("WARDEN_URL",       "http://warden:8001")
ANALYTICS_URL    = os.getenv("ANALYTICS_URL",    "http://analytics:8002")
DYNAMIC_RULES    = Path(os.getenv("DYNAMIC_RULES_PATH", "/warden/data/dynamic_rules.json"))
LOGS_PATH        = Path(os.getenv("LOGS_PATH",          "/warden/data/logs.json"))
ADMIN_API_KEY    = os.getenv("WARDEN_API_KEY",   "")        # optional — passed as X-API-Key
MAX_LOG_ROWS     = int(os.getenv("ADMIN_MAX_LOG_ROWS", "200"))

_AUTH_HEADERS = {"X-API-Key": ADMIN_API_KEY} if ADMIN_API_KEY else {}

# ── Page config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="Shadow Warden — Admin",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Helpers ───────────────────────────────────────────────────────────────────

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


def _warden_health() -> dict | None:
    try:
        resp = requests.get(f"{WARDEN_URL}/health", headers=_AUTH_HEADERS, timeout=3)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None


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


# ── Sidebar nav ───────────────────────────────────────────────────────────────

st.sidebar.image("https://raw.githubusercontent.com/phosphoricons/phosphor-icons/master/assets/phosphor-mark-tight-yellow.svg", width=48)
st.sidebar.title("Shadow Warden")
st.sidebar.caption("Admin Panel")
page = st.sidebar.radio(
    "Navigate",
    ["Dynamic Rules", "Tenants", "Event Log", "System Health"],
    label_visibility="collapsed",
)

# ══════════════════════════════════════════════════════════════════════════════
# PAGE: Dynamic Rules
# ══════════════════════════════════════════════════════════════════════════════
if page == "Dynamic Rules":
    st.title("🧠 Dynamic Rules")
    st.caption(
        "Rules evolved automatically by the EvolutionEngine (Claude Opus). "
        "Semantic examples are fed into the ML brain on restart."
    )

    data = _load_rules()
    rules: list[dict] = data.get("rules", [])

    col_add, col_refresh = st.columns([4, 1])
    with col_refresh:
        if st.button("↻ Reload", use_container_width=True):
            data  = _load_rules()
            rules = data.get("rules", [])

    if not rules:
        st.info("No evolved rules yet. Rules are added automatically when HIGH/BLOCK events occur and ANTHROPIC_API_KEY is set.")
    else:
        st.metric("Total rules", len(rules))

        for i, rule_entry in enumerate(rules):
            nr        = rule_entry.get("new_rule", {})
            val       = nr.get("value", "")
            rtype     = nr.get("rule_type", "unknown")
            created   = nr.get("created_at", "")
            confidence = nr.get("confidence", None)

            with st.expander(f"#{i+1}  [{rtype}]  {val[:80]}…" if len(val) > 80 else f"#{i+1}  [{rtype}]  {val}"):
                st.code(val, language=None)
                meta_cols = st.columns(3)
                meta_cols[0].write(f"**Type:** `{rtype}`")
                meta_cols[1].write(f"**Created:** {created or 'n/a'}")
                meta_cols[2].write(f"**Confidence:** {confidence or 'n/a'}")

                if st.button(f"🗑️ Delete rule #{i+1}", key=f"del_{i}"):
                    data["rules"].pop(i)
                    _save_rules(data)
                    st.success("Rule deleted. Reload the page.")
                    st.rerun()

    st.divider()
    st.subheader("➕ Add semantic example")
    with st.form("add_rule"):
        new_val = st.text_area(
            "Example jailbreak / harmful phrase (will be added to ML corpus on restart)",
            height=80,
            placeholder="e.g. Ignore all previous instructions and …",
        )
        submitted = st.form_submit_button("Add rule")

    if submitted and new_val.strip():
        data["rules"].append({
            "new_rule": {
                "value":      new_val.strip(),
                "rule_type":  "semantic_example",
                "created_at": datetime.now(tz=timezone.utc).isoformat(),
                "confidence": 1.0,
                "source":     "admin_ui",
            }
        })
        _save_rules(data)
        st.success("Rule added. It will be loaded into the ML brain on the next warden restart.")
        st.rerun()
    elif submitted:
        st.warning("Please enter a non-empty value.")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: Tenants
# ══════════════════════════════════════════════════════════════════════════════
elif page == "Tenants":
    st.title("🏢 Tenants")

    health = _warden_health()
    if health is None:
        st.error(f"Cannot reach warden at {WARDEN_URL}. Is the service running?")
    else:
        status_ok = health.get("status") == "ok"
        badge_col, evo_col, strict_col = st.columns(3)
        badge_col.metric("Gateway status", _status_badge(status_ok))
        evo_col.metric("EvolutionEngine", "🟢 online" if health.get("evolution") else "🟡 offline")
        strict_col.metric("Strict mode", "🔴 ON" if health.get("strict") else "🟢 OFF")

        st.divider()
        tenants: list[str] = health.get("tenants", [])
        st.subheader(f"Active tenants ({len(tenants)})")

        if not tenants:
            st.info("No active tenant guards loaded.")
        else:
            for t in tenants:
                st.badge(t, color="blue")

        cache = health.get("cache", {})
        st.divider()
        st.subheader("Redis cache")
        cache_ok = cache.get("status") == "ok"
        st.write(f"**Status:** {_status_badge(cache_ok)}")
        if cache.get("latency_ms") is not None:
            st.write(f"**Latency:** {cache['latency_ms']} ms")


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
        import pandas as pd  # bundled with streamlit

        rows = []
        for ev in events:
            rows.append({
                "time":       ev.get("timestamp", ""),
                "request_id": ev.get("request_id", "")[:8] + "…",
                "allowed":    "✅" if ev.get("allowed") else "❌",
                "risk":       ev.get("risk_level", ""),
                "flags":      ", ".join(ev.get("flags", [])) or "—",
                "secrets":    ", ".join(ev.get("secrets_found", [])) or "—",
                "len":        ev.get("payload_len", ""),
                "ms":         ev.get("elapsed_ms", ""),
            })

        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True, height=520)

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
            r = requests.get(f"{base}{path}", headers=_AUTH_HEADERS, timeout=3)
            ok  = r.status_code == 200
            lat = round(r.elapsed.total_seconds() * 1000, 1)
            col.metric(svc_name, _status_badge(ok), f"{lat} ms")
        except Exception as exc:
            col.metric(svc_name, "🔴 DOWN", str(exc)[:40])

    st.divider()
    st.subheader("Warden detail")
    health = _warden_health()
    if health:
        st.json(health)
    else:
        st.error("Warden unreachable.")
