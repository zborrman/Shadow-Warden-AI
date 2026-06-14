"""
warden/analytics/pages/25_Onboarding.py
AI-Assisted Onboarding — Streamlit page (ONB-01).
"""
from __future__ import annotations

import os

import httpx
import streamlit as st

from warden.integrations.onboarding import OnboardingWizard

_BASE    = os.getenv("WARDEN_API_URL", "http://localhost:8001")
_API_KEY = os.getenv("WARDEN_API_KEY", "")
_HEADERS = {"X-API-Key": _API_KEY, "Content-Type": "application/json"}

_STEPS = ["community", "members", "marketplace", "compliance", "integrations"]
_STEP_LABELS = {
    "community":    "Community Setup",
    "members":      "Invite Members",
    "marketplace":  "Marketplace",
    "compliance":   "Compliance",
    "integrations": "Integrations",
}


def _post(path: str, body: dict) -> dict:
    try:
        r = httpx.post(f"{_BASE}{path}", json=body, headers=_HEADERS, timeout=10)
        return r.json()
    except Exception as exc:
        return {"error": str(exc)}


def _sova_tool(tool: str, params: dict) -> dict:
    return _post("/agent/sova", {"query": f"__tool:{tool}", "params": params})


st.set_page_config(page_title="AI Onboarding", page_icon="🚀", layout="centered")
st.title("🚀 AI-Assisted Onboarding")
st.caption("A 5-step guided setup for your Shadow Warden workspace.")

# ── Session state ─────────────────────────────────────────────────────────────
if "onboarding_id" not in st.session_state:
    st.session_state.onboarding_id = ""
if "step_results" not in st.session_state:
    st.session_state.step_results = {}
if "completed" not in st.session_state:
    st.session_state.completed = False

oid = st.session_state.onboarding_id


# ── Start ─────────────────────────────────────────────────────────────────────
if not oid:
    st.info("Click **Start Onboarding** to begin your guided 5-step workspace setup.")
    tenant_id = st.text_input("Tenant ID", value="default")
    if st.button("Start Onboarding", type="primary"):
        result = OnboardingWizard().start_onboarding(tenant_id)
        if "error" in result:
            st.error(result["error"])
        else:
            st.session_state.onboarding_id = result["onboarding_id"]
            st.rerun()
    st.stop()


# ── Status bar ────────────────────────────────────────────────────────────────
status = OnboardingWizard().get_status(oid)
if "error" in status:
    st.error(status["error"])
    if st.button("Restart"):
        st.session_state.onboarding_id = ""
        st.rerun()
    st.stop()

current_step = status.get("current_step", "community")
progress_pct = status.get("progress", {}).get("percent", 0) / 100

st.progress(progress_pct, text=f"Step: **{_STEP_LABELS.get(current_step, current_step)}**")

cols = st.columns(len(_STEPS))
for i, (s, col) in enumerate(zip(_STEPS, cols, strict=False)):
    done = status.get("steps", [])[i]["done"] if i < len(status.get("steps", [])) else False
    icon = "✅" if done else ("▶" if s == current_step else "○")
    col.markdown(f"<div style='text-align:center'>{icon}<br><small>{_STEP_LABELS[s]}</small></div>",
                 unsafe_allow_html=True)

if status.get("completed"):
    st.success("Onboarding complete! Your workspace is ready.")
    st.balloons()
    if st.button("Start New Onboarding"):
        st.session_state.onboarding_id = ""
        st.rerun()
    st.stop()

st.divider()

# ── Step forms ────────────────────────────────────────────────────────────────

def _run_step(step: str, params: dict) -> None:
    result = OnboardingWizard().execute_step(oid, step, params)
    if result.get("ok"):
        st.session_state.step_results[step] = result
        st.success(result.get("message", "Step complete."))
        st.rerun()
    else:
        st.error(result.get("error", "Step failed."))


if current_step == "community":
    st.subheader("Step 1 — Community Setup")
    name        = st.text_input("Community Name *")
    description = st.text_area("Description (optional)", height=80)
    visibility  = st.selectbox("Visibility", ["private", "public", "invite_only"])
    if st.button("Continue →", type="primary"):
        _run_step("community", {"name": name, "description": description, "visibility": visibility})

elif current_step == "members":
    st.subheader("Step 2 — Invite Members")
    st.caption("Enter email addresses separated by commas.")
    raw    = st.text_area("Email addresses (optional)", height=80)
    role   = st.selectbox("Default role", ["member", "admin", "observer"])
    emails = [e.strip() for e in raw.split(",") if e.strip()]
    if st.button("Continue →", type="primary"):
        _run_step("members", {"emails": emails, "role": role})

elif current_step == "marketplace":
    st.subheader("Step 3 — Marketplace")
    enabled = st.toggle("Enable M2M Agentic Marketplace", value=False)
    chain   = st.selectbox("Blockchain network", ["sepolia", "polygon_amoy", "arbitrum_sepolia"])
    if st.button("Continue →", type="primary"):
        _run_step("marketplace", {"enabled": enabled, "chain": chain})

elif current_step == "compliance":
    st.subheader("Step 4 — Compliance Frameworks")
    gdpr   = st.checkbox("GDPR", value=True)
    soc2   = st.checkbox("SOC 2")
    iso    = st.checkbox("ISO 27001")
    hipaa  = st.checkbox("HIPAA")
    fws    = [f for f, on in [("gdpr", gdpr), ("soc2", soc2), ("iso27001", iso), ("hipaa", hipaa)] if on]
    if not fws:
        fws = ["gdpr"]
    if st.button("Continue →", type="primary"):
        _run_step("compliance", {"frameworks": fws})

elif current_step == "integrations":
    st.subheader("Step 5 — Integrations")
    slack = st.text_input("Slack Webhook URL (optional)")
    evo   = st.toggle("Enable Evolution Engine (auto-improve detection)", value=True)
    if st.button("Complete Setup", type="primary"):
        _run_step("integrations", {"slack_webhook": slack, "evolution_enabled": evo})

# ── Step history ──────────────────────────────────────────────────────────────
if st.session_state.step_results:
    with st.expander("Completed steps"):
        for s, r in st.session_state.step_results.items():
            st.markdown(f"**{_STEP_LABELS.get(s, s)}**: {r.get('message', '')}")
