"""
Digital Staff Dashboard — STAFF-06.

Tabs:
  1. Roster      — all agents, status badges, autonomy level, spend vs cap
  2. Activity    — velocity events (rate exceeded / loop detected)
  3. Boundaries  — view and edit allowed_tools, caps, thresholds
  4. Veto Panel  — suspend / restore agents (requires confirmation)
"""
from __future__ import annotations

import os
import time

import requests
import streamlit as st

_API = os.getenv("WARDEN_API_URL", "http://localhost:8001")
_KEY = os.getenv("WARDEN_API_KEY", "")
_HDR = {"X-API-Key": _KEY} if _KEY else {}

st.set_page_config(page_title="Digital Staff", page_icon="🤖", layout="wide")
st.title("Digital Staff — 20x Company Roster")

ROLE_EMOJI = {"BDR": "📊", "GROWTH": "📣", "COMPLIANCE": "🔍", "QA": "🧪", "SUPPORT": "🎧"}
LEVEL_LABEL = {1: "L1 Supervised", 2: "L2 Semi-Auto", 3: "L3 Full-Auto"}
LEVEL_COLOR = {1: "🟡", 2: "🟠", 3: "🔴"}


def _api(path: str) -> dict | list | None:
    try:
        r = requests.get(f"{_API}{path}", headers=_HDR, timeout=5)
        if r.ok:
            return r.json()
    except Exception:  # noqa: BLE001
        pass
    return None


def _post(path: str, **kw) -> dict | None:
    try:
        r = requests.post(f"{_API}{path}", headers=_HDR, timeout=5, **kw)
        if r.ok:
            return r.json()
    except Exception:  # noqa: BLE001
        pass
    return None


tab1, tab2, tab3, tab4 = st.tabs(["Roster", "Activity", "Boundaries", "Veto Panel"])

# ── Roster ────────────────────────────────────────────────────────────────────
with tab1:
    st.subheader("Agent Roster")
    boundaries = _api("/staff/boundaries") or []
    if not boundaries:
        st.info("No agent boundaries registered or API unavailable.")
    else:
        cols = st.columns([2, 1, 1, 1, 1, 1, 1])
        cols[0].markdown("**Agent**")
        cols[1].markdown("**Role**")
        cols[2].markdown("**Status**")
        cols[3].markdown("**Autonomy**")
        cols[4].markdown("**Spend Cap/day**")
        cols[5].markdown("**Refund Cap**")
        cols[6].markdown("**Escalation**")
        st.divider()
        for b in boundaries:
            role = b["role"]
            emoji = ROLE_EMOJI.get(role, "🤖")
            status = "🔴 SUSPENDED" if b["suspended"] else "🟢 ACTIVE"
            level = b["autonomy_level"]
            cols = st.columns([2, 1, 1, 1, 1, 1, 1])
            cols[0].write(f"{emoji} **{b['agent_id']}**")
            cols[1].write(role)
            cols[2].write(status)
            cols[3].write(f"{LEVEL_COLOR.get(level, '⚪')} {LEVEL_LABEL.get(level, level)}")
            cols[4].write(f"${b['spend_ceiling_usd_daily']}")
            cols[5].write(f"${b['refund_cap_usd']}")
            cols[6].write(b["escalation_threshold"])

# ── Activity ──────────────────────────────────────────────────────────────────
with tab2:
    st.subheader("Velocity & Loop Events")
    if st.button("Refresh"):
        st.rerun()
    activity = _api("/staff/activity?limit=100") or []
    if not activity:
        st.success("No velocity alerts — all agents operating within bounds.")
    else:
        for ev in activity:
            key = ev.get("key", "")
            count = ev.get("count", 0)
            if "loop" in key:
                st.warning(f"🔁 Loop signal: `{key}` — {count} identical calls in window")
            else:
                st.info(f"📈 Rate: `{key}` — {count} calls in window")

# ── Boundaries ────────────────────────────────────────────────────────────────
with tab3:
    st.subheader("Boundary Configuration")
    boundaries = _api("/staff/boundaries") or []
    if not boundaries:
        st.info("API unavailable.")
    else:
        agent_ids = [b["agent_id"] for b in boundaries]
        selected = st.selectbox("Select agent", agent_ids)
        b = next((x for x in boundaries if x["agent_id"] == selected), None)
        if b:
            st.json(b)
            with st.expander("Edit spend ceiling"):
                new_cap = st.text_input("New daily spend ceiling (USD)", value=b["spend_ceiling_usd_daily"])
                new_refund = st.text_input("New refund cap (USD)", value=b["refund_cap_usd"])
                new_level = st.selectbox("Autonomy level", [1, 2, 3], index=b["autonomy_level"] - 1)
                if st.button("Save changes"):
                    payload = {
                        "spend_ceiling_usd_daily": new_cap,
                        "refund_cap_usd": new_refund,
                        "autonomy_level": new_level,
                    }
                    r = _post(f"/staff/boundaries/{selected}", json=payload)
                    if r and r.get("updated"):
                        st.success("Boundary updated.")
                    else:
                        st.error("Update failed or API unavailable.")

# ── Veto Panel ────────────────────────────────────────────────────────────────
with tab4:
    st.subheader("Emergency Veto")
    st.warning(
        "Suspending an agent takes effect on the NEXT tool call. "
        "In-flight actions already in Claude's context complete normally."
    )
    boundaries = _api("/staff/boundaries") or []
    for b in boundaries:
        agent_id = b["agent_id"]
        emoji = ROLE_EMOJI.get(b["role"], "🤖")
        col1, col2 = st.columns([3, 1])
        status = "SUSPENDED" if b["suspended"] else "ACTIVE"
        col1.write(f"{emoji} `{agent_id}` — {status}")
        if b["suspended"]:
            if col2.button("Restore", key=f"restore_{agent_id}"):
                r = _post(f"/staff/boundaries/{agent_id}/restore")
                if r:
                    st.success(f"{agent_id} restored.")
                    st.rerun()
        else:
            if col2.button("Suspend", key=f"suspend_{agent_id}", type="primary"):
                r = _post(f"/staff/boundaries/{agent_id}/suspend")
                if r:
                    st.error(f"{agent_id} suspended.")
                    st.rerun()
