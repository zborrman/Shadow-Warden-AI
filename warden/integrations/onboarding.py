"""
warden/integrations/onboarding.py
AI-assisted onboarding wizard (ONB-01).

Five-step guided setup: Community → Members → Marketplace → Compliance → Integrations.
Session state is stored in Redis with a 24h TTL; falls back to in-process dict.
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone

log = logging.getLogger("warden.onboarding")

_STEPS = ["community", "members", "marketplace", "compliance", "integrations"]
_REDIS_TTL = 86400  # 24 h
_ONBOARDING_DB: dict[str, dict] = {}  # in-process fallback


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Redis helpers (fail-open) ─────────────────────────────────────────────────

def _redis():
    try:
        import redis as _r
        url = os.getenv("REDIS_URL", "redis://localhost:6379")
        if url.startswith("memory://"):
            return None
        return _r.from_url(url, decode_responses=True)
    except Exception:
        return None


def _store(onboarding_id: str, data: dict) -> None:
    try:
        r = _redis()
        if r:
            r.setex(f"onb:{onboarding_id}", _REDIS_TTL, json.dumps(data))
            return
    except Exception:
        pass
    _ONBOARDING_DB[onboarding_id] = data


def _load(onboarding_id: str) -> dict | None:
    try:
        r = _redis()
        if r:
            raw = r.get(f"onb:{onboarding_id}")
            return json.loads(raw) if raw else None
    except Exception:
        pass
    return _ONBOARDING_DB.get(onboarding_id)


# ── Step executors ────────────────────────────────────────────────────────────

def _exec_community(state: dict, params: dict) -> dict:
    name        = params.get("name", "").strip()
    visibility  = params.get("visibility", "private")
    description = params.get("description", "")
    if not name:
        return {"ok": False, "error": "Community name is required."}
    state["community_name"]       = name
    state["community_visibility"] = visibility
    state["community_description"] = description
    return {
        "ok":      True,
        "message": f"Community '{name}' configured. Next: invite your first members.",
        "created": {"name": name, "visibility": visibility},
    }


def _exec_members(state: dict, params: dict) -> dict:
    emails = [e.strip() for e in params.get("emails", []) if e.strip()]
    role   = params.get("role", "member")
    if not emails:
        return {"ok": True, "message": "No members added. You can add them later.", "invited": 0}
    state["invited_emails"] = emails
    state["default_role"]   = role
    return {
        "ok":      True,
        "message": f"Queued {len(emails)} invite(s) as '{role}'. Tokens will be issued after community creation.",
        "invited": len(emails),
    }


def _exec_marketplace(state: dict, params: dict) -> dict:
    enabled = params.get("enabled", False)
    chain   = params.get("chain", "sepolia")
    state["marketplace_enabled"] = enabled
    state["marketplace_chain"]   = chain
    msg = (
        f"Marketplace enabled on {chain}. Agent DID registration will run at first use."
        if enabled else
        "Marketplace skipped. Enable later via Settings → Marketplace."
    )
    return {"ok": True, "message": msg, "enabled": enabled, "chain": chain}


def _exec_compliance(state: dict, params: dict) -> dict:
    frameworks = params.get("frameworks", ["gdpr"])
    state["compliance_frameworks"] = frameworks
    return {
        "ok":        True,
        "message":   f"Compliance frameworks configured: {', '.join(f.upper() for f in frameworks)}.",
        "frameworks": frameworks,
    }


def _exec_integrations(state: dict, params: dict) -> dict:
    slack = params.get("slack_webhook", "").strip()
    evo   = params.get("evolution_enabled", True)
    state["slack_webhook"]       = slack
    state["evolution_enabled"]   = evo
    state["completed"]           = True
    state["completed_at"]        = _now()
    return {
        "ok":      True,
        "message": "Onboarding complete! Your workspace is ready.",
        "summary": {
            "community":   state.get("community_name"),
            "members":     len(state.get("invited_emails", [])),
            "marketplace": state.get("marketplace_enabled", False),
            "frameworks":  state.get("compliance_frameworks", []),
            "slack":       bool(slack),
            "evolution":   evo,
        },
    }


_STEP_FNS = {
    "community":    _exec_community,
    "members":      _exec_members,
    "marketplace":  _exec_marketplace,
    "compliance":   _exec_compliance,
    "integrations": _exec_integrations,
}


# ── Public API ────────────────────────────────────────────────────────────────

class OnboardingWizard:
    """Stateful 5-step onboarding guide for new Shadow Warden tenants."""

    def start_onboarding(self, tenant_id: str) -> dict:
        oid = str(uuid.uuid4())
        state = {
            "onboarding_id": oid,
            "tenant_id":     tenant_id,
            "current_step":  "community",
            "completed":     False,
            "started_at":    _now(),
            "completed_at":  None,
        }
        _store(oid, state)
        return {
            "onboarding_id": oid,
            "tenant_id":     tenant_id,
            "current_step":  "community",
            "steps":         _STEPS,
            "message":       "Onboarding started. Begin with the 'community' step.",
        }

    def get_status(self, onboarding_id: str) -> dict:
        state = _load(onboarding_id)
        if not state:
            return {"error": "Onboarding session not found or expired."}
        current_idx = _STEPS.index(state.get("current_step", "community")) if state.get("current_step") in _STEPS else 0
        return {
            "onboarding_id": onboarding_id,
            "tenant_id":     state.get("tenant_id"),
            "current_step":  state.get("current_step"),
            "completed":     state.get("completed", False),
            "started_at":    state.get("started_at"),
            "completed_at":  state.get("completed_at"),
            "progress": {
                "done":    current_idx,
                "total":   len(_STEPS),
                "percent": round(current_idx / len(_STEPS) * 100),
            },
            "steps": [
                {"name": s, "done": i < current_idx}
                for i, s in enumerate(_STEPS)
            ],
        }

    def execute_step(self, onboarding_id: str, step: str, params: dict) -> dict:
        state = _load(onboarding_id)
        if not state:
            return {"error": "Onboarding session not found or expired."}
        if step not in _STEPS:
            return {"error": f"Unknown step '{step}'. Valid steps: {_STEPS}"}
        if state.get("completed"):
            return {"error": "Onboarding already completed.", "summary": state}

        fn = _STEP_FNS[step]
        result = fn(state, params)
        if result.get("ok"):
            cur_idx = _STEPS.index(step)
            next_idx = cur_idx + 1
            state["current_step"] = _STEPS[next_idx] if next_idx < len(_STEPS) else step
            _store(onboarding_id, state)
        return {**result, "next_step": state.get("current_step")}
